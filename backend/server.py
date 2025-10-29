from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request, File, UploadFile, Form
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Dict, Optional
import os
import re
import json
import csv
import io
import asyncio
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
from dotenv import load_dotenv
load_dotenv()

# Local imports
from database import get_db, User, Node, create_tables, hash_password, verify_password, SessionLocal
from auth import (
    create_access_token, authenticate_user, get_current_user, 
    get_current_user_optional, ACCESS_TOKEN_EXPIRE_MINUTES
)
from schemas import (
    UserCreate, NodeCreate, NodeUpdate, LoginRequest, ChangePasswordRequest,
    BulkImport, ImportNodesSchema, ExportRequest, Token, ServiceAction, TestRequest
)
from services import service_manager, network_tester
from socks_server import start_socks_service, stop_socks_service, get_socks_stats
from socks_monitor import start_socks_monitoring, get_proxy_file_content, get_monitoring_stats

# Progress Tracking System
import uuid
progress_store = {}
import_progress = {}  # For chunked import progress tracking

# Global testing concurrency controls (АГРЕССИВНО увеличено для скорости)
MAX_PING_GLOBAL = 20   # МАКСИМАЛЬНО увеличено для скорости ping
MAX_SPEED_GLOBAL = 10  # МАКСИМАЛЬНО увеличено для скорости speed

# СПЕЦИАЛЬНЫЕ ЛИМИТЫ ДЛЯ PING LIGHT (ТЗ требование)
MAX_PING_LIGHT_GLOBAL = 100  # Увеличенный параллелизм для быстрой проверки портов без авторизации

global_ping_sem = asyncio.Semaphore(MAX_PING_GLOBAL)
global_speed_sem = asyncio.Semaphore(MAX_SPEED_GLOBAL)
global_ping_light_sem = asyncio.Semaphore(MAX_PING_LIGHT_GLOBAL)

# Система защиты от перегрузки (увеличена для скорости)
active_sessions = set()
MAX_CONCURRENT_SESSIONS = 5  # Увеличено до 5 тестовых сессий для скорости

def can_start_new_session() -> bool:
    """Проверка возможности запуска новой сессии"""
    return len(active_sessions) < MAX_CONCURRENT_SESSIONS

class ProgressTracker:
    def __init__(self, session_id: str, total_items: int):
        self.session_id = session_id
        self.total_items = total_items
        self.processed_items = 0
        self.current_task = ""
        self.status = "running"
        self.results = []
        
    def update(self, processed: int, current_task: str = "", add_result: dict = None):
        self.processed_items = processed
        self.current_task = current_task
        if add_result:
            self.results.append(add_result)
        progress_store[self.session_id] = self
    
    def complete(self, status: str = "completed"):
        self.status = status
        progress_store[self.session_id] = self
    
    def to_dict(self):
        return {
            "session_id": self.session_id,
            "total_items": self.total_items,
            "processed_items": self.processed_items,
            "current_task": self.current_task,
            "status": self.status,
            "progress_percent": int((self.processed_items / self.total_items) * 100) if self.total_items > 0 else 0,
            "results": self.results
        }

# Progress safe increment helper
progress_locks = {}

def progress_increment(session_id: str, current_task: str = "", add_result: dict | None = None):
    tracker = progress_store.get(session_id)
    if not tracker:
        return
    # No real per-session lock to avoid overhead; ensure monotonic increment
    new_val = min(tracker.total_items, (tracker.processed_items or 0) + 1)
    tracker.update(new_val, current_task, add_result)

async def cleanup_stuck_nodes():
    """Clean up nodes stuck in 'checking' status on startup"""
    try:
        db = next(get_db())
        stuck_nodes = db.query(Node).filter(Node.status == "checking").all()
        if stuck_nodes:
            for node in stuck_nodes:
                node.status = "not_tested"
                node.last_update = datetime.utcnow()
            db.commit()
            logger.info(f"🧹 Cleaned up {len(stuck_nodes)} nodes stuck in 'checking' status on startup")
        else:
            logger.info("✅ No stuck nodes found during startup cleanup")
    except Exception as e:
        logger.error(f"❌ Error during stuck nodes cleanup: {str(e)}")

# Setup
ROOT_DIR = Path(__file__).parent

app = FastAPI(title="Connexa Admin Panel", version="1.7")
api_router = APIRouter(prefix="/api")

# Middleware
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "connexa-secret"), same_site="lax", session_cookie="connexa", max_age=60*60*8)
# CORS: support wildcard with credentials via regex
_cors_env = os.getenv('CORS_ORIGINS', '*')
if _cors_env.strip() == '*':
    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_origin_regex=r".*",
        allow_methods=["*"],
        allow_headers=["*"]
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_origins=_cors_env.split(','),
        allow_methods=["*"],
        allow_headers=["*"]
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Status helpers according to new business rules (sticky PING OK baseline)

def has_ping_baseline(status: str) -> bool:
    return status in ("ping_ok", "speed_ok", "online")


# Create tables on startup
create_tables()

# Create default admin user if not exists
@app.on_event("startup")
async def startup_event():
    db = next(get_db())
    try:
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                password=hash_password("admin")
            )
            db.add(admin_user)
            db.commit()
            logger.info("Default admin user created with username: admin, password: admin")
    except Exception as e:
        logger.error(f"Startup admin check/create error: {e}")
    # Clean up any nodes stuck in 'checking' status on startup
    await cleanup_stuck_nodes()
    # Start background monitoring with improved protection
    start_background_monitoring()
    logger.info("✅ Background monitoring RE-ENABLED with enhanced speed_ok protection")
    
    # Start SOCKS monitoring system
    start_socks_monitoring()
    logger.info("✅ SOCKS monitoring service started - checking every 30 seconds")

# Deduplication registry to avoid duplicate tests and reduce load
# Раздельные TTL для разных типов тестов
TEST_DEDUPE_TTL_PING = 60   # seconds - для PING тестов (быстрее)
TEST_DEDUPE_TTL_SPEED = 120  # seconds - для SPEED тестов (медленнее, тяжелее)
TEST_DEDUPE_TTL_DEFAULT = 60 # seconds - для остальных тестов
_test_recent: dict = {}  # key: (node_id, mode) -> expires timestamp (epoch)
_test_inflight: set = set()  # node_ids currently being tested

def test_dedupe_should_skip(node_id: int, mode: str) -> bool:
    now = datetime.utcnow().timestamp()
    exp = _test_recent.get((node_id, mode))
    if exp and exp > now:
        return True
    if node_id in _test_inflight:
        return True
    return False

def test_dedupe_get_remaining_time(node_id: int, mode: str) -> int:
    """Получить оставшееся время блокировки в секундах"""
    now = datetime.utcnow().timestamp()
    exp = _test_recent.get((node_id, mode))
    if exp and exp > now:
        return int(exp - now)
    return 0

def test_dedupe_mark_enqueued(node_id: int, mode: str):
    now = datetime.utcnow().timestamp()
    
    # Выбор TTL в зависимости от типа теста
    if mode == "ping":
        ttl = TEST_DEDUPE_TTL_PING
    elif mode == "speed":
        ttl = TEST_DEDUPE_TTL_SPEED
    else:
        ttl = TEST_DEDUPE_TTL_DEFAULT
    
    _test_recent[(node_id, mode)] = now + ttl
    _test_inflight.add(node_id)

def test_dedupe_mark_finished(node_id: int):
    _test_inflight.discard(node_id)

def test_dedupe_cleanup():
    now = datetime.utcnow().timestamp()
    to_del = [k for k, exp in _test_recent.items() if exp <= now]
    for k in to_del:
        _test_recent.pop(k, None)

# Helper to apply filters to SQLAlchemy query
def apply_node_filters(query, filters: dict):
    """Apply filters to a Node query. Returns filtered query."""
    if not filters:
        return query
    
    # Status filter
    if 'status' in filters and filters['status']:
        query = query.filter(Node.status == filters['status'])
    
    # Protocol filter
    if 'protocol' in filters and filters['protocol']:
        query = query.filter(Node.protocol == filters['protocol'])
    
    # Search filter (IP, login, password)
    if 'search' in filters and filters['search']:
        search_term = filters['search']
        query = query.filter(
            (Node.ip.contains(search_term)) |
            (Node.login.contains(search_term)) |
            (Node.password.contains(search_term))
        )
    
    # Country filter
    if 'country' in filters and filters['country']:
        query = query.filter(Node.country == filters['country'])
    
    # State filter
    if 'state' in filters and filters['state']:
        query = query.filter(Node.state == filters['state'])
    
    # City filter
    if 'city' in filters and filters['city']:
        query = query.filter(Node.city == filters['city'])
    
    # IP Address filter
    if 'ip' in filters and filters['ip']:
        query = query.filter(Node.ip.contains(filters['ip']))
    
    # Provider filter
    if 'provider' in filters and filters['provider']:
        query = query.filter(Node.provider.contains(filters['provider']))
    
    # Login filter
    if 'login' in filters and filters['login']:
        query = query.filter(Node.login.contains(filters['login']))
    
    # ZIP code filter
    if 'zip' in filters and filters['zip']:
        query = query.filter(Node.zip.contains(filters['zip']))
    
    # Comment filter
    if 'comment' in filters and filters['comment']:
        query = query.filter(Node.comment.contains(filters['comment']))
    
    # Speed filters (новые)
    if 'speed_min' in filters and filters['speed_min']:
        try:
            from sqlalchemy import func, Float
            speed_min = float(filters['speed_min'])
            query = query.filter(Node.speed != None).filter(Node.speed != "")
            query = query.filter(func.cast(Node.speed, Float) >= speed_min)
        except:
            pass
    
    if 'speed_max' in filters and filters['speed_max']:
        try:
            from sqlalchemy import func, Float
            speed_max = float(filters['speed_max'])
            query = query.filter(Node.speed != None).filter(Node.speed != "")
            query = query.filter(func.cast(Node.speed, Float) <= speed_max)
        except:
            pass
    
    # Scamalytics fraud score filters (новые)
    if 'scam_fraud_score_min' in filters and filters['scam_fraud_score_min']:
        try:
            fraud_min = int(filters['scam_fraud_score_min'])
            query = query.filter(Node.scamalytics_fraud_score >= fraud_min)
        except:
            pass
    
    if 'scam_fraud_score_max' in filters and filters['scam_fraud_score_max']:
        try:
            fraud_max = int(filters['scam_fraud_score_max'])
            query = query.filter(Node.scamalytics_fraud_score <= fraud_max)
        except:
            pass
    
    # Scamalytics risk filter (новый)
    if 'scam_risk' in filters and filters['scam_risk'] and filters['scam_risk'] != 'all':
        risk_value = filters['scam_risk'].lower()
        query = query.filter(Node.scamalytics_risk == risk_value)
    
    return query

# Helper to choose ping ports based on node configuration
# B) Keep general TCP ping (no protocol handshake) but use DB-configured ports with fallbacks

def get_ping_ports_for_node(node: Node) -> list[int]:
    """Return optimal ports per protocol with common fallbacks for better success rates.
    - pptp: node.port else [1723, 443, 80] (PPTP + common fallbacks)
    - socks: socks_port else [1080, 8080, 3128] (SOCKS + proxy ports)
    - ovpn: node.port else [1194, 443, 80] (OpenVPN + HTTPS fallback)
    - ssh: node.port else [22, 2222, 443] (SSH + alt ports)
    - unknown: node.port else [80, 443, 8080] (HTTP/HTTPS)
    """
    try:
        proto = (node.protocol or "").lower()
        
        # Prefer explicit node.port when present
        if node.port:
            return [int(node.port)]
            
        # Protocol-specific ports with intelligent fallbacks
        if proto == "pptp":
            return [1723, 443, 80]  # PPTP + common accessible ports
        elif proto == "socks":
            sp = getattr(node, "socks_port", None)
            if sp:
                return [int(sp)]
            return [1080, 8080, 3128]  # Common SOCKS/proxy ports
        elif proto == "ovpn" or proto == "openvpn":
            return [1194, 443, 80]  # OpenVPN + HTTPS fallback
        elif proto == "ssh":
            return [22, 2222, 443]  # SSH + common alt ports
        else:
            # Unknown protocol - try common accessible ports
            return [80, 443, 8080]
    except Exception:
        return [80, 443]  # Safe fallback to web ports


# ===== BACKGROUND MONITORING SYSTEM =====
# This system monitors ONLY online nodes every 5 minutes as per user requirements

monitoring_active = False

async def monitor_online_nodes():
    """
    Background monitoring task for online nodes ONLY
    CRITICAL: This function MUST NEVER touch nodes with speed_ok, ping_ok, or any non-online status
    """
    global monitoring_active
    
    while monitoring_active:
        try:
            # Create separate session to avoid transaction conflicts
            db = SessionLocal()
            
            # CRITICAL: Query ONLY nodes with 'online' status
            # This ensures we NEVER touch speed_ok or other statuses
            online_count = db.query(Node).filter(Node.status == "online").count()
            
            if online_count > 0:
                logger.info(f"🔍 Background monitor cycle starting - {online_count} online nodes found")
                
                # Get fresh list of online nodes
                online_nodes = db.query(Node).filter(Node.status == "online").all()
                
                for node in online_nodes:
                    # ABSOLUTE SAFETY: Re-query node to ensure status hasn't changed
                    fresh_node = db.query(Node).filter(Node.id == node.id).first()
                    
                    if not fresh_node:
                        logger.warning(f"⚠️ Monitor: Node {node.id} no longer exists")
                        continue
                    
                    # CRITICAL PROTECTION: If status is NOT online, skip it completely
                    if fresh_node.status != "online":
                        logger.info(f"🛡️ Monitor: Node {node.id} status changed to {fresh_node.status} - SKIPPING (only monitor online nodes)")
                        continue
                    
                    try:
                        # Check if services are still running
                        service_status = await service_manager.get_service_status(node.id)
                        
                        if not service_status.get('active', False):
                            # Double-check status before changing
                            if fresh_node.status == "online":
                                logger.warning(f"❌ Monitor: Node {node.id} services failed - reverting to ping_ok baseline")
                                fresh_node.status = "ping_ok"
                                fresh_node.last_update = datetime.utcnow()
                            else:
                                logger.warning(f"⚠️ Monitor: Node {node.id} status already {fresh_node.status} - not changing")
                    
                    except Exception as node_error:
                        logger.error(f"❌ Monitor: Error checking node {node.id}: {node_error}")
                        # NEVER change status on monitoring errors
            else:
                logger.debug("🔍 Background monitor cycle - no online nodes to monitor")
            
            # Commit changes for this monitoring cycle
            db.commit()
            db.close()
            logger.debug("✅ Background monitor cycle complete")
            
        except Exception as e:
            logger.error(f"❌ Background monitoring error: {e}")
            try:
                db.rollback()
                db.close()
            except Exception:
                pass
        
        # Wait 5 minutes before next check
        await asyncio.sleep(300)  # 300 seconds = 5 minutes
        
        # Periodic cleanup of stuck nodes (every 5 minutes)
        try:
            await cleanup_stuck_nodes()
        except Exception as cleanup_error:
            logger.error(f"❌ Error during periodic stuck nodes cleanup: {cleanup_error}")

def run_monitoring_loop():
    """Run the monitoring loop in a separate thread"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitor_online_nodes())

def start_background_monitoring():
    """Start the background monitoring service"""
    global monitoring_active
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=run_monitoring_loop, daemon=True)
        monitoring_thread.start()
        logger.info("✅ Background monitoring service started - checking online nodes every 5 minutes")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop monitoring on app shutdown"""
    global monitoring_active
    monitoring_active = False
    logger.info("Background monitoring service stopped")

# Authentication Routes
@api_router.post("/auth/login", response_model=Token)
async def login(login_request: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Safety: auto-create admin if users table empty
    try:
        ensure_admin_user(db)
    except Exception as e:
        logger.error(f"ensure_admin_user failed: {e}")

    user = authenticate_user(db, login_request.username, login_request.password)
    if not user:
        # Re-check after creating admin
        try:
            ensure_admin_user(db)
            user = authenticate_user(db, login_request.username, login_request.password)
        except Exception:
            user = None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Also set session for web UI
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    
    return {"access_token": access_token, "token_type": "bearer"}

# Safety: ensure admin exists if empty users table during login
def ensure_admin_user(db: Session):
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(username="admin", password=hash_password("admin"))
        db.add(admin_user)
        db.commit()
        logger.info("✅ Admin user auto-created during login path")

@api_router.post("/auth/logout")
async def logout(request: Request):
    request.session.clear()
    return {"message": "Logged out successfully"}

@api_router.post("/auth/change-password")
async def change_password(
    change_request: ChangePasswordRequest, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(change_request.old_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect old password"
        )
    
    if change_request.new_password != change_request.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match"
        )
    
    current_user.password = hash_password(change_request.new_password)
    db.commit()
    
    return {"message": "Password changed successfully"}

@api_router.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "id": current_user.id}

# Node CRUD Routes
def apply_node_filters_kwargs(query, **filters):
    """Helper function to apply filters to node queries - reduces code duplication"""
    ip = filters.get('ip')
    provider = filters.get('provider')
    country = filters.get('country')
    state = filters.get('state')
    city = filters.get('city')
    zipcode = filters.get('zipcode')
    login = filters.get('login')
    comment = filters.get('comment')
    status = filters.get('status')
    protocol = filters.get('protocol')
    only_online = filters.get('only_online')
    speed_min = filters.get('speed_min')
    speed_max = filters.get('speed_max')
    scam_fraud_score_min = filters.get('scam_fraud_score_min')
    scam_fraud_score_max = filters.get('scam_fraud_score_max')
    scam_risk = filters.get('scam_risk')
    
    # Apply filters - optimize for exact matches first, then partial
    if ip:
        # Try exact match first, then partial
        if '.' in ip and len(ip) > 7:  # Looks like a full IP
            query = query.filter(Node.ip == ip)
        else:
            query = query.filter(Node.ip.ilike(f"%{ip}%"))
    
    # Exact matches for these fields are faster with indexes
    if provider:
        query = query.filter(Node.provider.ilike(f"%{provider}%"))
    if country:
        query = query.filter(Node.country.ilike(f"%{country}%"))
    if state:
        query = query.filter(Node.state.ilike(f"%{state}%"))
    if city:
        query = query.filter(Node.city.ilike(f"%{city}%"))
    if zipcode:
        # Zipcode is usually exact
        if len(zipcode) >= 4:  # Likely full zipcode
            query = query.filter(Node.zipcode == zipcode)
        else:
            query = query.filter(Node.zipcode.ilike(f"%{zipcode}%"))
    if login:
        query = query.filter(Node.login.ilike(f"%{login}%"))
    if comment:
        query = query.filter(Node.comment.ilike(f"%{comment}%"))
    
    # These use indexes for fast exact match
    if status:
        query = query.filter(Node.status == status)
    if protocol:
        query = query.filter(Node.protocol == protocol)
    if only_online:
        query = query.filter(Node.status == "online")
    
    # Speed filters (новые)
    if speed_min:
        try:
            from sqlalchemy import func, Float
            speed_min_val = float(speed_min)
            query = query.filter(Node.speed != None).filter(Node.speed != "")
            query = query.filter(func.cast(Node.speed, Float) >= speed_min_val)
        except:
            pass
    
    if speed_max:
        try:
            from sqlalchemy import func, Float
            speed_max_val = float(speed_max)
            query = query.filter(Node.speed != None).filter(Node.speed != "")
            query = query.filter(func.cast(Node.speed, Float) <= speed_max_val)
        except:
            pass
    
    # Scamalytics fraud score filters (новые)
    if scam_fraud_score_min:
        try:
            fraud_min = int(scam_fraud_score_min)
            query = query.filter(Node.scamalytics_fraud_score >= fraud_min)
        except:
            pass
    
    if scam_fraud_score_max:
        try:
            fraud_max = int(scam_fraud_score_max)
            query = query.filter(Node.scamalytics_fraud_score <= fraud_max)
        except:
            pass
    
    # Scamalytics risk filter (новый)
    if scam_risk and scam_risk != 'all':
        risk_value = scam_risk.lower()
        query = query.filter(Node.scamalytics_risk == risk_value)
    
    return query

@api_router.get("/nodes")
async def get_nodes(
    page: int = 1,
    limit: int = 200,
    ip: Optional[str] = None,
    provider: Optional[str] = None,
    country: Optional[str] = None,
    state: Optional[str] = None,
    city: Optional[str] = None,
    zipcode: Optional[str] = None,
    login: Optional[str] = None,
    comment: Optional[str] = None,
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    only_online: Optional[bool] = False,
    speed_min: Optional[str] = None,
    speed_max: Optional[str] = None,
    scam_fraud_score_min: Optional[str] = None,
    scam_fraud_score_max: Optional[str] = None,
    scam_risk: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Build filters dict
    filters = {k: v for k, v in locals().items() 
              if k not in ['page', 'limit', 'current_user', 'db'] and v is not None}
    
    # Apply filters using helper function
    query = apply_node_filters_kwargs(db.query(Node), **filters)
    
    # Use a single query for count to improve performance
    total_count = query.count()
    nodes = query.offset((page - 1) * limit).limit(limit).all()
    
    return {
        "nodes": nodes,
        "total": total_count,
        "page": page,
        "limit": limit,
        "total_pages": (total_count + limit - 1) // limit
    }

@api_router.get("/nodes/all-ids")
async def get_all_node_ids(
    ip: Optional[str] = None,
    provider: Optional[str] = None,
    country: Optional[str] = None,
    state: Optional[str] = None,
    city: Optional[str] = None,
    zipcode: Optional[str] = None,
    login: Optional[str] = None,
    comment: Optional[str] = None,
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    only_online: Optional[bool] = False,
    speed_min: Optional[str] = None,
    speed_max: Optional[str] = None,
    scam_fraud_score_min: Optional[str] = None,
    scam_fraud_score_max: Optional[str] = None,
    scam_risk: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all node IDs that match the filters (for Select All functionality)"""
    # Build filters dict
    filters = {k: v for k, v in locals().items() 
              if k not in ['current_user', 'db'] and v is not None}
    
    # Apply filters using helper function - only select ID for performance
    query = apply_node_filters_kwargs(db.query(Node.id), **filters)
    
    # Get all IDs (no pagination) - more efficient list comprehension
    node_ids = [row[0] for row in query.all()]
    
    return {
        "node_ids": node_ids,
        "total_count": len(node_ids)
    }

@api_router.get("/nodes/count")
async def get_nodes_count(
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get count of nodes matching filters - for performance"""
    query = db.query(Node)
    
    if status:
        query = query.filter(Node.status == status)
    if protocol:
        query = query.filter(Node.protocol == protocol)
    if search:
        query = query.filter(
            (Node.ip.contains(search)) |
            (Node.login.contains(search)) |
            (Node.password.contains(search))
        )
    
    count = query.count()
    return {"count": count}

@api_router.delete("/nodes/bulk")
async def bulk_delete_nodes(
    status: Optional[str] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    delete_all: Optional[bool] = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Bulk delete nodes by filters"""
    query = db.query(Node)
    
    # Apply filters
    filters_applied = False
    if status:
        query = query.filter(Node.status == status)
        filters_applied = True
    if protocol:
        query = query.filter(Node.protocol == protocol)
        filters_applied = True
    if search:
        query = query.filter(
            (Node.ip.contains(search)) |
            (Node.login.contains(search)) |
            (Node.password.contains(search))
        )
        filters_applied = True
    
    # Safety check - require either filters or explicit delete_all=True
    if not filters_applied and not delete_all:
        raise HTTPException(
            status_code=400, 
            detail="Must specify filters (status, protocol, search) or set delete_all=true to delete all nodes"
        )
    
    # Get count first
    count_to_delete = query.count()
    
    if count_to_delete == 0:
        return {
            "message": "No nodes found matching the criteria",
            "deleted_count": 0
        }
    
    # Delete all matching nodes
    deleted_count = query.delete(synchronize_session=False)
    db.commit()
    
    logger.info(f"Bulk deleted {deleted_count} nodes with filters: status={status}, protocol={protocol}, search={search}, delete_all={delete_all}")
    
    return {
        "message": f"Successfully deleted {deleted_count} nodes",
        "deleted_count": deleted_count
    }

@api_router.get("/nodes/{node_id}")
async def get_node_by_id(
    node_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a single node by ID"""
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    logger.info(f"🔍 GET /nodes/{node_id} - Returning node with status: {node.status}")
    return node

@api_router.post("/nodes")
async def create_node(
    node: NodeCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logger.info(f"🔍 Creating node with input status: {node.dict().get('status', 'not specified')}")
    db_node = Node(**node.dict())
    db_node.last_update = datetime.utcnow()  # Set current time on creation
    logger.info(f"🔍 Node object status before add: {db_node.status}")
    db.add(db_node)
    # Remove explicit commit - let get_db() handle it
    db.flush()  # Flush to get the ID
    logger.info(f"🔍 Node object status after flush: {db_node.status}")
    db.refresh(db_node)
    logger.info(f"🔍 Node object status after refresh: {db_node.status}")
    
    # Double-check by querying the database directly
    check_node = db.query(Node).filter(Node.id == db_node.id).first()
    logger.info(f"🔍 Node status from direct DB query: {check_node.status if check_node else 'not found'}")
    logger.info(f"✅ Returning created node with status: {db_node.status}")
    
    return db_node

@api_router.put("/nodes/{node_id}")
async def update_node(
    node_id: int,
    node_update: NodeUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_node = db.query(Node).filter(Node.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    update_data = node_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_node, field, value)
    
    db.commit()
    db.refresh(db_node)
    return db_node

@api_router.delete("/nodes/{node_id}")
async def delete_node(
    node_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_node = db.query(Node).filter(Node.id == node_id).first()
    if not db_node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    db.delete(db_node)
    db.commit()
    return {"message": "Node deleted successfully"}

@api_router.delete("/nodes/batch")
async def delete_nodes_batch(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete multiple nodes by IDs"""
    node_ids = data.get("node_ids", [])
    if not node_ids:
        raise HTTPException(status_code=400, detail="No node IDs provided")
    
    deleted_count = db.query(Node).filter(Node.id.in_(node_ids)).delete(synchronize_session=False)
    db.commit()
    
    logger.info(f"Batch deleted {deleted_count} nodes by IDs: {node_ids}")
    
    return {
        "message": f"Successfully deleted {deleted_count} nodes",
        "deleted_count": deleted_count
    }

@api_router.delete("/nodes")
async def delete_multiple_nodes(
    request: dict,  # Accept JSON body
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    node_ids = request.get("node_ids", [])
    if not node_ids:
        raise HTTPException(status_code=400, detail="No node IDs provided")
    
    deleted_count = db.query(Node).filter(Node.id.in_(node_ids)).delete(synchronize_session=False)
    db.commit()
    return {"message": f"Deleted {deleted_count} nodes successfully"}

@api_router.post("/nodes/import")
async def import_nodes(
    data: ImportNodesSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Simplified import - always assigns 'not_tested' status, no automatic testing"""
    
    # Check file size and decide processing method
    data_size = len(data.data.encode('utf-8'))  # Get size in bytes
    
    # If file is large (>500KB), redirect to chunked processing
    if data_size > 500 * 1024:  # 500KB threshold
        logger.info(f"Large file detected ({data_size/1024:.1f}KB) - redirecting to chunked processing")
        return await import_nodes_chunked(data, current_user, db)
    
    # Force no_test mode - user will run tests manually through Testing modal
    testing_mode = "no_test"
    
    try:
        logger.info("Import request - simplified mode (no automatic testing)")
        
        # Parse text data with enhanced parser
        parsed_data = parse_nodes_text(data.data, data.protocol)
        
        # Process nodes with deduplication logic - always use no_test
        results = process_parsed_nodes(db, parsed_data, testing_mode)
        
        # No automatic testing - user will start tests manually through Testing modal
        
        # Create detailed report with smart summary
        added_count = len(results['added'])
        skipped_count = len(results['skipped'])
        replaced_count = len(results['replaced'])
        queued_count = len(results['queued'])
        format_errors_count = len(results['format_errors'])
        processing_errors_count = len(results['errors'])
        
        # Generate smart message based on results
        if added_count == 0 and skipped_count > 0:
            # All duplicates - nothing new added
            if skipped_count == parsed_data['successfully_parsed']:
                smart_message = f"Ничего не добавлено: все {skipped_count} конфигураций уже существуют в базе данных. Дубликаты не добавляются автоматически."
            else:
                smart_message = f"Импорт завершён: {added_count} добавлено, {skipped_count} пропущено (уже в базе)"
        elif added_count > 0 and skipped_count > 0:
            # Mixed: some new, some duplicates
            smart_message = f"Импорт завершён: {added_count} новых конфигураций добавлено, {skipped_count} дубликатов пропущено"
            if replaced_count > 0:
                smart_message += f", {replaced_count} старых заменено"
        elif added_count > 0 and skipped_count == 0:
            # All new
            smart_message = f"Успешно добавлено {added_count} новых конфигураций"
        else:
            # Nothing processed successfully
            smart_message = f"Импорт не выполнен: {format_errors_count} ошибок формата"
        
        # Add additional info if needed
        if queued_count > 0:
            smart_message += f", {queued_count} отправлено на проверку"
        if format_errors_count > 0:
            smart_message += f", {format_errors_count} ошибок формата"
        
        report = {
            "total_processed": parsed_data['total_processed'],
            "successfully_parsed": parsed_data['successfully_parsed'],
            "added": added_count,
            "skipped_duplicates": skipped_count,
            "replaced_old": replaced_count,
            "queued_for_verification": queued_count,
            "format_errors": format_errors_count,
            "processing_errors": processing_errors_count,
            "testing_mode": "no_test",  # Always no_test in simplified mode
            "smart_summary": smart_message,
            "details": results
        }
        
        return {
            "success": True,
            "message": smart_message,
            "report": report,
            "session_id": None  # No session_id in simplified mode
        }
        
    except Exception as e:
        logger.error(f"Import error: {str(e)}", exc_info=True)
        
        return {
            "success": False, 
            "message": f"Import failed: {str(e)}",
            "report": {
                "total_processed": 0,
                "successfully_parsed": 0,
                "added": 0,
                "skipped_duplicates": 0,
                "replaced_old": 0,
                "queued_for_verification": 0,
                "format_errors": 0,
                "processing_errors": 1,
                "testing_mode": "no_test",
                "details": {"errors": [{"general": str(e)}]}
            },
            "session_id": None  # No session_id in simplified mode
        }

@api_router.post("/nodes/import-chunked")
async def import_nodes_chunked(
    data: ImportNodesSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Chunked import for large files with progress tracking"""
    import asyncio
    
    # Create unique session for this import
    import uuid
    session_id = str(uuid.uuid4())
    
    # Split data into chunks by lines for processing
    lines = data.data.strip().split('\n')
    
    # Optimized chunk sizes for maximum speed
    if len(lines) > 50000:
        chunk_size = 10000  # Large files: 10K lines per chunk (faster)
    elif len(lines) > 10000:
        chunk_size = 5000   # Medium files: 5K lines per chunk (faster)
    else:
        chunk_size = 2500   # Small files: 2.5K lines per chunk (faster)
    
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    
    logger.info(f"Dynamic chunking: {len(lines)} lines -> {len(chunks)} chunks of {chunk_size} lines each")
    
    total_chunks = len(chunks)
    total_lines = len(lines)
    
    logger.info(f"Starting chunked import - {total_lines} lines in {total_chunks} chunks, session: {session_id}")
    
    # Initialize progress tracking
    progress_data = {
        'session_id': session_id,
        'total_chunks': total_chunks,
        'processed_chunks': 0,
        'total_nodes': 0,
        'added': 0,
        'skipped': 0,
        'replaced': 0,
        'errors': 0,
        'status': 'processing',
        'current_operation': 'Preparing import...'
    }
    
    # Store progress in memory (you could use Redis for production)
    import_progress[session_id] = progress_data
    
    # Start background processing
    asyncio.create_task(process_chunks_async(chunks, data.protocol, session_id, current_user.id))
    
    return {
        'success': True,
        'session_id': session_id,
        'total_chunks': total_chunks,
        'message': f'Large file import started. Processing {total_lines} lines in {total_chunks} chunks.',
        'progress_url': f'/api/import/progress/{session_id}'
    }

async def process_chunks_async(chunks: list, protocol: str, session_id: str, user_id: int):
    """Process chunks asynchronously in background"""
    try:
        # Create new database session for background processing
        db = SessionLocal()
        # Begin explicit transaction for better SQLite handling
        db.begin()
        
        total_added = 0
        total_skipped = 0
        total_replaced = 0
        total_errors = 0
        
        for chunk_index, chunk in enumerate(chunks):
            # Quick cancellation check only every 5th chunk for performance
            if chunk_index % 5 == 0:
                current_progress = import_progress.get(session_id, {})
                if current_progress.get('status') == 'cancelled':
                    logger.info(f"Import session {session_id} was cancelled, stopping processing")
                    db.rollback()
                    db.close()
                    return
            
            # Update progress every 3rd chunk to reduce overhead
            if chunk_index % 3 == 0:
                progress_data = import_progress.get(session_id, {})
                progress_data.update({
                    'processed_chunks': chunk_index + 1,
                    'total_chunks': len(chunks),
                    'added': total_added,
                    'skipped': total_skipped,
                    'replaced': total_replaced,
                    'errors': total_errors,
                    'current_operation': f'Processing chunk {chunk_index + 1}/{len(chunks)}'
                })
                import_progress[session_id] = progress_data
            
            # Process chunk
            chunk_text = '\n'.join(chunk)
            if chunk_text.strip():
                try:
                    # Parse chunk
                    parsed_data = parse_nodes_text(chunk_text, protocol)
                    
                    # Process nodes with BULK optimization (always use bulk for speed)
                    if len(parsed_data['nodes']) > 100:  # Lower threshold for bulk mode
                        results = process_parsed_nodes_bulk(db, parsed_data, "no_test")
                    else:
                        results = process_parsed_nodes(db, parsed_data, "no_test")
                    
                    # Update totals
                    total_added += len(results['added'])
                    total_skipped += len(results['skipped'])
                    total_replaced += len(results['replaced'])
                    total_errors += len(results['errors'])
                    
                    # No delay for maximum speed
                    
                except Exception as chunk_error:
                    logger.error(f"Error processing chunk {chunk_index}: {chunk_error}")
                    total_errors += 1
        
        # Final progress update with detailed report
        progress_data = import_progress.get(session_id, {})
        progress_data.update({
            'processed_chunks': len(chunks),
            'added': total_added,
            'skipped': total_skipped,
            'replaced': total_replaced,
            'errors': total_errors,
            'status': 'completed',
            'current_operation': 'Import completed',
            'final_report': {
                'total_processed': total_added + total_skipped + total_replaced + total_errors,
                'added': total_added,
                'skipped_duplicates': total_skipped,
                'replaced_old': total_replaced,
                'format_errors': total_errors,
                'success_rate': round((total_added / max(1, total_added + total_errors)) * 100, 1)
            }
        })
        import_progress[session_id] = progress_data
        
        # CRITICAL FIX: Commit all changes before closing
        try:
            db.commit()
            logger.info(f"✅ Chunked import committed to database - session: {session_id}")
            logger.info(f"📊 Final results: {total_added} added, {total_skipped} skipped, {total_replaced} replaced, {total_errors} errors")
        except Exception as commit_error:
            logger.error(f"❌ CRITICAL: Failed to commit chunked import: {commit_error}")
            db.rollback()
        finally:
            db.close()
        
    except Exception as e:
        logger.error(f"Error in chunked import processing: {e}")
        # Mark as failed
        progress_data = import_progress.get(session_id, {})
        progress_data.update({
            'status': 'failed',
            'current_operation': f'Failed: {str(e)}'
        })
        import_progress[session_id] = progress_data

@api_router.get("/import/progress/{session_id}")
async def get_import_progress(
    session_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get progress of chunked import"""
    progress_data = import_progress.get(session_id)
    if not progress_data:
        raise HTTPException(status_code=404, detail="Import session not found")
    
    return progress_data

@api_router.delete("/import/progress/all")
async def clear_all_import_sessions(current_user: User = Depends(get_current_user)):
    """Clear all import sessions - emergency recovery"""
    global import_progress
    count = len(import_progress)
    import_progress.clear()
    logger.info(f"Cleared {count} import sessions for recovery")
    return {"message": f"Cleared {count} import sessions", "success": True}

@api_router.delete("/import/cancel/{session_id}")
async def cancel_import_session(session_id: str, current_user: User = Depends(get_current_user)):
    """Cancel specific import session"""
    global import_progress
    
    if session_id not in import_progress:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Mark session as cancelled
    progress_data = import_progress.get(session_id, {})
    progress_data.update({
        'status': 'cancelled',
        'current_operation': 'Import cancelled by user'
    })
    import_progress[session_id] = progress_data
    
    logger.info(f"Import session {session_id} cancelled by user {current_user.username}")
    
    return {
        "message": f"Import session {session_id} cancelled successfully",
        "session_id": session_id,
        "success": True
    }

async def process_import_testing_batches(session_id: str, node_ids: list, testing_mode: str, db_session: Session):
    """Process node testing in batches to prevent hanging and preserve results"""
    
    # Just delegate to the unified testing batches function with default parameters
    await process_testing_batches(
        session_id, node_ids, testing_mode, db_session,
        ping_concurrency=50,
        speed_concurrency=8,
        ping_timeouts=[0.8,1.2,1.6],
        speed_sample_kb=512,
        speed_timeout=15
    )

# Import/Export Routes
@api_router.post("/import")
async def import_nodes_legacy(
    data: BulkImport,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Parse and import nodes from text data"""
    parsed_result = parse_nodes_text(data.data, data.protocol)
    
    # Handle both old and new format returns
    if isinstance(parsed_result, dict) and 'nodes' in parsed_result:
        nodes_data = parsed_result['nodes']
    else:
        nodes_data = parsed_result
    
    created_nodes = []
    errors = []
    duplicates = 0
    
    for node_data in nodes_data:
        try:
            # Check for duplicates
            existing = db.query(Node).filter(
                and_(Node.ip == node_data['ip'], Node.login == node_data.get('login', ''))
            ).first()
            
            if existing:
                duplicates += 1
                continue
            
            node = Node(**node_data)
            db.add(node)
            created_nodes.append(node_data)
        except Exception as e:
            errors.append(f"Error processing {node_data.get('ip', 'unknown')}: {str(e)}")
    
    db.commit()
    
    return {
        "created": len(created_nodes),
        "duplicates": duplicates,
        "errors": errors,
        "total_processed": len(nodes_data) if isinstance(nodes_data, list) else parsed_result.get('total_processed', 0)
    }

@api_router.post("/export")
async def export_nodes(
    export_request: ExportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Export selected nodes"""
    nodes = db.query(Node).filter(Node.id.in_(export_request.node_ids)).all()
    
    if export_request.format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "Login", "Password", "Protocol", "Provider", "Country", "State", "City", "ZIP", "Comment"])
        
        for node in nodes:
            writer.writerow([
                node.ip, node.login, node.password, node.protocol,
                node.provider, node.country, node.state, node.city,
                node.zipcode, node.comment
            ])
        
        return JSONResponse(
            content={"data": output.getvalue(), "filename": f"connexa_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    else:  # txt format (default)
        lines = []
        for node in nodes:
            if export_request.format == "socks":
                lines.append(f"{node.ip}:1080:{node.login}:{node.password}")
            else:
                lines.append(f"{node.ip} {node.login} {node.password} {node.country or 'N/A'}")
        
        return JSONResponse(
            content={"data": "\n".join(lines), "filename": f"connexa_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"}
        )

def clean_text_data(text: str) -> str:
    """Clean and normalize text data - remove headers, mentions, comments"""
    lines = []
    for line in text.split('\n'):
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # Skip comment lines (starting with # or //)
        if line.startswith('#') or line.startswith('//'):
            continue
        
        # Skip Telegram channel mentions (lines starting with @)
        if line.startswith('@'):
            continue
        
        # Skip channel/group names (short lines with only letters/spaces, no colons or IPs)
        # Examples: "StealUrVPN", "GVBot", "Worldwide VPN Hub", "PPTP INFINITY"
        if len(line) < 50 and ':' not in line and not any(char.isdigit() for char in line):
            # Check if it looks like a header (mostly uppercase or title case)
            if line.isupper() or line.istitle() or all(c.isalpha() or c.isspace() for c in line):
                continue
        
        # Remove inline comments (text after # or // in single-line formats)
        if '  #' in line:
            line = line.split('  #')[0].strip()
        elif '  //' in line:
            line = line.split('  //')[0].strip()
        
        # Remove multiple spaces, tabs, and normalize
        cleaned_line = ' '.join(line.split())
        
        if cleaned_line:
            lines.append(cleaned_line)
    
    return '\n'.join(lines)

def detect_format(block: str) -> str:
    """Detect which format the block matches"""
    lines = block.split('\n')
    
    # Format 6: Multi-line with PPTP header (ignore first 2 lines) - Check first
    if len(lines) >= 6 and ('PPTP_SVOIM_VPN' in lines[0] or 'PPTP Connection' in lines[1]):
        return "format_6"
    
    # Format 5: Multi-line with IP:, Credentials:, Location:, ZIP: - Check before Format 1
    if len(lines) >= 4 and any('IP:' in line for line in lines) and any('Credentials:' in line for line in lines):
        return "format_5"
    
    # Format 1: Key-value with colons (Ip: xxx, Login: xxx, Pass: xxx) - More specific check
    if any(line.strip().startswith(('Ip:', 'Login:', 'Pass:')) for line in lines):
        return "format_1"
    
    # Single line formats
    single_line = block.strip()
    
    # Format 3: With - and | separators
    if ' - ' in single_line and (' | ' in single_line or re.search(r'\d{4}-\d{2}-\d{2}', single_line)):
        return "format_3"
    
    # Format 7: Simple IP:Login:Pass (exactly 2 colons)
    if single_line.count(':') == 2:
        parts = single_line.split(':')
        if len(parts) == 3 and is_valid_ip(parts[0].strip()):
            return "format_7"
    
    # Format 4: Colon separated (5+ colons for full format)
    if single_line.count(':') >= 4:
        return "format_4"
    
    # Format 2: Single line with spaces (IP Login Password State)
    parts = single_line.split()
    if len(parts) >= 4 and is_valid_ip(parts[0]):
        return "format_2"
    
    return "unknown"

def parse_nodes_text(text: str, protocol: str = "pptp") -> dict:
    """Enhanced parser with TWO-PASS smart block splitting algorithm"""
    # Clean input text (removes headers, @mentions, comments)
    text = clean_text_data(text)
    
    parsed_nodes = []
    duplicates = []
    format_errors = []
    blocks = []
    
    # PASS 1: Split by explicit separator '---------------------' first
    if '---------------------' in text:
        pre_blocks = text.split('---------------------')
    else:
        pre_blocks = [text]
    
    # PASS 2: Process each pre_block with TWO-PASS algorithm
    for pre_block in pre_blocks:
        pre_block = pre_block.strip()
        if not pre_block:
            continue
        
        # SUB-PASS 1: Extract all single-line formats first (Format 2, 3, 4)
        lines = pre_block.split('\n')
        single_line_blocks = []
        remaining_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            is_single_line = False
            
            # Check Format 7: Simple IP:Login:Pass (exactly 2 colons)
            parts_colon = line.split(':')
            if len(parts_colon) == 3 and is_valid_ip(parts_colon[0].strip()):
                single_line_blocks.append(line)
                is_single_line = True
            
            # Check Format 4: Colon-separated (at least 5 colons, starts with IP)
            elif len(parts_colon) >= 6 and is_valid_ip(parts_colon[0].strip()):
                single_line_blocks.append(line)
                is_single_line = True
            
            # Check Format 3: Dash format (IP - login:pass - State/City)
            elif ' - ' in line:
                parts_space = line.split()
                if parts_space and is_valid_ip(parts_space[0]):
                    single_line_blocks.append(line)
                    is_single_line = True
            
            # Check Format 2: Space-separated (IP Login Password State)
            elif not is_single_line:
                parts_space = line.split()
                if len(parts_space) >= 3 and is_valid_ip(parts_space[0]):
                    # Make sure it's not a line like "IP: xxx" (Format 1/5/6)
                    if ':' not in line or line.count(':') < 2:
                        single_line_blocks.append(line)
                        is_single_line = True
            
            # If not a single-line format, add to remaining for multi-line processing
            if not is_single_line:
                remaining_lines.append(line)
        
        # Add all extracted single-line blocks
        blocks.extend(single_line_blocks)
        
        # SUB-PASS 2: Process remaining lines for multi-line formats (Format 1, 5, 6)
        if remaining_lines:
            remaining_text = '\n'.join(remaining_lines)
            
            # PRIORITY 1: Check for Format 6 entries and extract them first
            if '> PPTP_SVOIM_VPN:' in remaining_text or '🚨 PPTP Connection' in remaining_text:
                # Extract Format 6 blocks
                format6_blocks = []
                non_format6_entries = []  # Collect non-Format-6 content
                
                # Split by Format 6 markers
                if remaining_text.count('> PPTP_SVOIM_VPN:') > 1:
                    entries = re.split(r'(?=> PPTP_SVOIM_VPN:)', remaining_text)
                    for entry in entries:
                        entry = entry.strip()
                        if entry and '> PPTP_SVOIM_VPN:' in entry:
                            # This entry has Format 6 marker, but might also contain Format 5 after it
                            # Check if it's ONLY Format 6 (small block) or mixed (huge block)
                            if len(entry) < 1000:  # Small block - likely pure Format 6
                                format6_blocks.append(entry)
                            else:
                                # Large block - likely Format 6 + Format 5
                                # Split into Format 6 part and rest
                                entry_lines = entry.split('\n')
                                format6_lines = []
                                format5_start_index = None
                                
                                # Find where Format 6 ends (typically 6-7 lines)
                                for i, line in enumerate(entry_lines):
                                    if i < 10:  # Format 6 is typically first 6-7 lines
                                        format6_lines.append(line)
                                    else:
                                        # Check if this looks like start of Format 5
                                        if line.strip().startswith('IP:') and i > 6:
                                            format5_start_index = i
                                            break
                                
                                if format5_start_index:
                                    # Split: Format 6 part + Format 5 part
                                    format6_text = '\n'.join(entry_lines[:format5_start_index])
                                    format5_text = '\n'.join(entry_lines[format5_start_index:])
                                    format6_blocks.append(format6_text)
                                    non_format6_entries.append(format5_text)
                                else:
                                    # Can't find clear split, treat as Format 6
                                    format6_blocks.append(entry)
                        elif entry and 'IP:' in entry:
                            # This is not Format 6, save for later processing
                            non_format6_entries.append(entry)
                elif remaining_text.count('🚨 PPTP Connection') > 1:
                    entries = re.split(r'(?=🚨 PPTP Connection)', remaining_text)
                    for entry in entries:
                        entry = entry.strip()
                        if entry and '🚨 PPTP Connection' in entry:
                            # Same logic as above
                            if len(entry) < 1000:
                                format6_blocks.append(entry)
                            else:
                                entry_lines = entry.split('\n')
                                format6_lines = entry_lines[:10]
                                format5_start_index = None
                                
                                for i, line in enumerate(entry_lines[10:], start=10):
                                    if line.strip().startswith('IP:'):
                                        format5_start_index = i
                                        break
                                
                                if format5_start_index:
                                    format6_text = '\n'.join(entry_lines[:format5_start_index])
                                    format5_text = '\n'.join(entry_lines[format5_start_index:])
                                    format6_blocks.append(format6_text)
                                    non_format6_entries.append(format5_text)
                                else:
                                    format6_blocks.append(entry)
                        elif entry and 'IP:' in entry:
                            non_format6_entries.append(entry)
                else:
                    # Single Format 6 block - check if it's really Format 6
                    if '> PPTP_SVOIM_VPN:' in remaining_text[:100] or '🚨 PPTP Connection' in remaining_text[:100]:
                        format6_blocks.append(remaining_text.strip())
                        non_format6_entries = []
                    else:
                        # Format 6 markers are somewhere in the middle, not at start
                        # This is likely mixed content - keep all for Format 5 processing
                        non_format6_entries = [remaining_text]
                
                # Add Format 6 blocks
                blocks.extend(format6_blocks)
                
                # Reassemble remaining text from non-Format-6 entries
                remaining_text = '\n'.join(non_format6_entries) if non_format6_entries else ''
            
            # PRIORITY 2: Check for multiple Format 1 entries (multiple "Ip:" with lowercase 'p')
            if remaining_text and remaining_text.count('Ip:') > 1:
                # Split by "Ip:" with lowercase 'p' only
                entries = re.split(r'(?=\bIp:)', remaining_text)
                for entry in entries:
                    entry = entry.strip()
                    if entry and 'Ip:' in entry:
                        blocks.append(entry)
            
            # PRIORITY 3: Check for Format 5 entries (IP: with uppercase, but NOT Format 6)
            # Only if no Format 6 markers present
            if remaining_text and remaining_text.count('IP:') > 1:
                # Check if this is Format 5 (has "Credentials:" but no Format 6 markers)
                if 'Credentials:' in remaining_text and '> PPTP_SVOIM_VPN:' not in remaining_text:
                    entries = re.split(r'(?=\bIP:)', remaining_text)
                    for entry in entries:
                        entry = entry.strip()
                        if entry and 'IP:' in entry:
                            blocks.append(entry)
                else:
                    # Treat as single block
                    blocks.append(remaining_text.strip())
            
            # Single multi-line block
            elif remaining_text and remaining_text.strip():
                blocks.append(remaining_text.strip())
    
    # PASS 3: Parse each block
    for block_index, block in enumerate(blocks):
        block = block.strip()
        if not block or len(block) < 5:
            continue
        
        try:
            format_type = detect_format(block)
            node_data = {"protocol": protocol}  # Don't set status - let Node model default to "not_tested"
            
            if format_type == "format_1":
                node_data = parse_format_1(block, node_data)
            elif format_type == "format_2":
                node_data = parse_format_2(block, node_data)
            elif format_type == "format_3":
                node_data = parse_format_3(block, node_data)
            elif format_type == "format_4":
                node_data = parse_format_4(block, node_data)
            elif format_type == "format_5":
                node_data = parse_format_5(block, node_data)
            elif format_type == "format_6":
                node_data = parse_format_6(block, node_data)
            elif format_type == "format_7":
                node_data = parse_format_7(block, node_data)
            else:
                # Try regex-based smart parsing as fallback
                node_data = parse_with_smart_regex(block, node_data)
                if not node_data.get('ip'):
                    format_errors.append(f"Block {block_index + 1}: {block[:100]}")
                    continue
            
            # Validate required fields
            if not node_data.get('ip') or not is_valid_ip(node_data['ip']):
                format_errors.append(f"Invalid IP in block {block_index + 1}: {block[:100]}")
                continue
                
            if not node_data.get('login') or not node_data.get('password'):
                format_errors.append(f"Missing credentials in block {block_index + 1}: {block[:100]}")
                continue
            
            # Normalize data
            if node_data.get('state'):
                node_data['state'] = normalize_state_country(node_data['state'], node_data.get('country', ''))
            if node_data.get('country'):
                node_data['country'] = normalize_country_code(node_data['country'])
            
            parsed_nodes.append(node_data)
            
        except Exception as e:
            format_errors.append(f"Parse error in block {block_index + 1}: {str(e)} - {block[:100]}")
            continue
    
    return {
        'nodes': parsed_nodes,
        'duplicates': duplicates,
        'format_errors': format_errors,
        'total_processed': len(blocks),
        'successfully_parsed': len(parsed_nodes)
    }

def parse_format_1(block: str, node_data: dict) -> dict:
    """Format 1: Ip: xxx, Login: xxx, Pass: xxx, State: xxx, City: xxx, Zip: xxx"""
    lines = block.split('\n')
    for line in lines:
        if ':' not in line:
            continue
        
        # Split only on first colon to handle values with colons
        parts = line.split(':', 1)
        if len(parts) < 2:
            continue
            
        key = parts[0].strip().lower()
        value = parts[1].strip()
        
        # Remove extra text after IP (e.g., "71.84.237.32 a_reg_107" -> "71.84.237.32")
        if key in ['ip', 'host']:
            # Extract only the IP part (first word if multiple words)
            ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', value)
            if ip_match:
                node_data['ip'] = ip_match.group(1)
            else:
                # Just take first word
                node_data['ip'] = value.split()[0] if value else value
        elif key == 'login':
            node_data['login'] = value
        elif key in ['pass', 'password']:
            node_data['password'] = value
        elif key == 'state':
            node_data['state'] = value
        elif key == 'city':
            node_data['city'] = value
        elif key in ['zip', 'zipcode']:
            node_data['zipcode'] = value
        elif key == 'country':
            node_data['country'] = value
        elif key == 'provider':
            node_data['provider'] = value
    
    return node_data

def parse_with_smart_regex(block: str, node_data: dict) -> dict:
    """Smart regex-based parser as fallback when format detection fails"""
    # Try to extract IP address
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ip_match = re.search(ip_pattern, block)
    if ip_match:
        node_data['ip'] = ip_match.group(1)
    
    # Try to extract login and password
    # Pattern 1: "Login: xxx" and "Pass: xxx"
    login_match = re.search(r'(?:Login|login|USERNAME|username):\s*(\S+)', block)
    if login_match:
        node_data['login'] = login_match.group(1)
    
    pass_match = re.search(r'(?:Pass|pass|Password|password|PASS):\s*(\S+)', block)
    if pass_match:
        node_data['password'] = pass_match.group(1)
    
    # Pattern 2: "Credentials: login:password"
    cred_match = re.search(r'Credentials:\s*(\S+):(\S+)', block)
    if cred_match:
        node_data['login'] = cred_match.group(1)
        node_data['password'] = cred_match.group(2)
    
    # Pattern 3: Space-separated "IP login password state"
    if not node_data.get('login') and node_data.get('ip'):
        # Try to find login/pass after IP
        parts = block.split()
        for i, part in enumerate(parts):
            if part == node_data['ip'] and i + 2 < len(parts):
                node_data['login'] = parts[i + 1]
                node_data['password'] = parts[i + 2]
                if i + 3 < len(parts):
                    node_data['state'] = parts[i + 3]
                break
    
    # Try to extract state
    state_match = re.search(r'(?:State|state|STATE):\s*(\S+)', block)
    if state_match:
        node_data['state'] = state_match.group(1)
    
    # Try to extract city
    city_match = re.search(r'(?:City|city|CITY):\s*([^\n]+)', block)
    if city_match:
        node_data['city'] = city_match.group(1).strip()
    
    # Try to extract ZIP
    zip_match = re.search(r'(?:Zip|ZIP|zipcode|Zipcode):\s*(\d{5})', block)
    if zip_match:
        node_data['zipcode'] = zip_match.group(1)
    
    # Try to extract Location: "State (City)"
    location_match = re.search(r'Location:\s*([^(]+)\(([^)]+)\)', block)
    if location_match:
        node_data['state'] = location_match.group(1).strip()
        node_data['city'] = location_match.group(2).strip()
    
    return node_data

def parse_format_2(block: str, node_data: dict) -> dict:
    """Format 2: IP Login Password State (single line with spaces)"""
    parts = block.split()
    if len(parts) >= 4:
        node_data['ip'] = parts[0]
        node_data['login'] = parts[1]  # Correct order: IP Login Password State
        node_data['password'] = parts[2]
        node_data['state'] = parts[3]
    return node_data

def parse_format_3(block: str, node_data: dict) -> dict:
    """Format 3: IP - Login:Pass - State/City Zip | Last Update"""
    # Remove timestamp part
    main_part = block.split(' | ')[0] if ' | ' in block else block
    parts = main_part.split(' - ')
    
    if len(parts) >= 3:
        node_data['ip'] = parts[0].strip()
        
        # Parse credentials
        creds = parts[1].strip()
        if ':' in creds:
            login, password = creds.split(':', 1)
            node_data['login'] = login.strip()
            node_data['password'] = password.strip()
        
        # Parse location
        location = parts[2].strip()
        if '/' in location:
            state_part, city_part = location.split('/', 1)
            node_data['state'] = state_part.strip()
            
            # Extract city (before ZIP)
            city_and_zip = city_part.strip().split()
            if city_and_zip:
                node_data['city'] = city_and_zip[0]
                # Look for ZIP in remaining parts
                for part in city_and_zip[1:]:
                    if re.match(r'^\d{5}(-\d{4})?$', part):
                        node_data['zipcode'] = part
                        break
    return node_data

def parse_format_4(block: str, node_data: dict) -> dict:
    """Format 4: IP:Login:Pass:Country:State:Zip"""
    parts = block.split(':')
    if len(parts) >= 6:
        node_data['ip'] = parts[0].strip()
        node_data['login'] = parts[1].strip()
        node_data['password'] = parts[2].strip()
        node_data['country'] = parts[3].strip()
        node_data['state'] = parts[4].strip()
        node_data['zipcode'] = parts[5].strip()
    return node_data

def parse_format_5(block: str, node_data: dict) -> dict:
    """Format 5: Multi-line with IP:, Credentials:, Location:, ZIP:"""
    lines = block.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith("IP:"):
            node_data['ip'] = line.split(':', 1)[1].strip()
        elif line.startswith("Credentials:"):
            creds = line.split(':', 1)[1].strip()
            if ':' in creds:
                login, password = creds.split(':', 1)
                node_data['login'] = login.strip()
                node_data['password'] = password.strip()
        elif line.startswith("Location:"):
            location = line.split(':', 1)[1].strip()
            # Используем умный парсер Location
            location_data = parse_location_smart(location)
            if location_data['country']:
                node_data['country'] = location_data['country']
            if location_data['state']:
                node_data['state'] = location_data['state']
            if location_data['city']:
                node_data['city'] = location_data['city']
        elif line.startswith("ZIP:"):
            node_data['zipcode'] = line.split(':', 1)[1].strip()
        elif line.startswith("Scamalytics Fraud Score:"):
            try:
                node_data['scamalytics_fraud_score'] = int(line.split(':', 1)[1].strip())
            except:
                pass
        elif line.startswith("Scamalytics Risk:"):
            node_data['scamalytics_risk'] = line.split(':', 1)[1].strip().lower()
    return node_data

def parse_format_6(block: str, node_data: dict) -> dict:
    """Format 6: Multi-line with first 2 lines ignored"""
    lines = block.split('\n')
    # Skip first 2 lines
    relevant_lines = lines[2:] if len(lines) > 2 else lines
    
    for line in relevant_lines:
        line = line.strip()
        if line.startswith("IP:"):
            node_data['ip'] = line.split(':', 1)[1].strip()
        elif line.startswith("Credentials:"):
            creds = line.split(':', 1)[1].strip()
            if ':' in creds:
                login, password = creds.split(':', 1)
                node_data['login'] = login.strip()
                node_data['password'] = password.strip()
        elif line.startswith("Location:"):
            location = line.split(':', 1)[1].strip()
            # Используем умный парсер Location
            location_data = parse_location_smart(location)
            if location_data['country']:
                node_data['country'] = location_data['country']
            if location_data['state']:
                node_data['state'] = location_data['state']
            if location_data['city']:
                node_data['city'] = location_data['city']
        elif line.startswith("ZIP:"):
            node_data['zipcode'] = line.split(':', 1)[1].strip()
        elif line.startswith("Scamalytics Fraud Score:"):
            try:
                node_data['scamalytics_fraud_score'] = int(line.split(':', 1)[1].strip())
            except:
                pass
        elif line.startswith("Scamalytics Risk:"):
            node_data['scamalytics_risk'] = line.split(':', 1)[1].strip().lower()
    return node_data

def parse_format_7(block: str, node_data: dict) -> dict:
    """Format 7: Simple IP:Login:Pass"""
    parts = block.split(':')
    if len(parts) == 3:
        node_data['ip'] = parts[0].strip()
        node_data['login'] = parts[1].strip()
        node_data['password'] = parts[2].strip()
    return node_data


def normalize_state_country(state_code: str, country: str = "") -> str:
    """Convert state codes to full names for multiple countries"""
    
    # USA States
    usa_states = {
        "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
        "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
        "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
        "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
        "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
        "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
        "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
        "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
        "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
        "VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
        "DC": "District of Columbia"
    }
    
    # Canada Provinces
    canada_provinces = {
        "AB": "Alberta", "BC": "British Columbia", "MB": "Manitoba", "NB": "New Brunswick",
        "NL": "Newfoundland and Labrador", "NS": "Nova Scotia", "ON": "Ontario", "PE": "Prince Edward Island",
        "QC": "Quebec", "SK": "Saskatchewan", "NT": "Northwest Territories", "NU": "Nunavut", "YT": "Yukon"
    }
    
    # Australia States
    australia_states = {
        "ACT": "Australian Capital Territory", "NSW": "New South Wales", "NT": "Northern Territory",
        "QLD": "Queensland", "SA": "South Australia", "TAS": "Tasmania", "VIC": "Victoria", "WA": "Western Australia"
    }
    
    # Germany States (Länder)
    germany_states = {
        "BW": "Baden-Württemberg", "BY": "Bavaria", "BE": "Berlin", "BB": "Brandenburg", "HB": "Bremen",
        "HH": "Hamburg", "HE": "Hesse", "MV": "Mecklenburg-Vorpommern", "NI": "Lower Saxony",
        "NW": "North Rhine-Westphalia", "RP": "Rhineland-Palatinate", "SL": "Saarland", "SN": "Saxony",
        "ST": "Saxony-Anhalt", "SH": "Schleswig-Holstein", "TH": "Thuringia"
    }
    
    # UK Counties/Regions
    uk_regions = {
        "ENG": "England", "SCT": "Scotland", "WLS": "Wales", "NIR": "Northern Ireland",
        "LON": "London", "MAN": "Manchester", "BIR": "Birmingham", "LIV": "Liverpool"
    }
    
    # France Regions
    france_regions = {
        "ARA": "Auvergne-Rhône-Alpes", "BFC": "Bourgogne-Franche-Comté", "BRE": "Brittany",
        "CVL": "Centre-Val de Loire", "COR": "Corsica", "GES": "Grand Est", "HDF": "Hauts-de-France",
        "IDF": "Île-de-France", "NOR": "Normandy", "NAQ": "Nouvelle-Aquitaine", "OCC": "Occitanie",
        "PDL": "Pays de la Loire", "PAC": "Provence-Alpes-Côte d'Azur"
    }
    
    # Italy Regions
    italy_regions = {
        "ABR": "Abruzzo", "BAS": "Basilicata", "CAL": "Calabria", "CAM": "Campania", "EMR": "Emilia-Romagna",
        "FVG": "Friuli-Venezia Giulia", "LAZ": "Lazio", "LIG": "Liguria", "LOM": "Lombardy", "MAR": "Marche",
        "MOL": "Molise", "PIE": "Piedmont", "PUG": "Puglia", "SAR": "Sardinia", "SIC": "Sicily",
        "TOS": "Tuscany", "TAA": "Trentino-Alto Adige", "UMB": "Umbria", "VDA": "Valle d'Aosta", "VEN": "Veneto"
    }
    
    # Brazil States
    brazil_states = {
        "AC": "Acre", "AL": "Alagoas", "AP": "Amapá", "AM": "Amazonas", "BA": "Bahia", "CE": "Ceará",
        "DF": "Distrito Federal", "ES": "Espírito Santo", "GO": "Goiás", "MA": "Maranhão", "MT": "Mato Grosso",
        "MS": "Mato Grosso do Sul", "MG": "Minas Gerais", "PA": "Pará", "PB": "Paraíba", "PR": "Paraná",
        "PE": "Pernambuco", "PI": "Piauí", "RJ": "Rio de Janeiro", "RN": "Rio Grande do Norte",
        "RS": "Rio Grande do Sul", "RO": "Rondônia", "RR": "Roraima", "SC": "Santa Catarina",
        "SP": "São Paulo", "SE": "Sergipe", "TO": "Tocantins"
    }
    
    # India States
    india_states = {
        "AP": "Andhra Pradesh", "AR": "Arunachal Pradesh", "AS": "Assam", "BR": "Bihar", "CT": "Chhattisgarh",
        "GA": "Goa", "GJ": "Gujarat", "HR": "Haryana", "HP": "Himachal Pradesh", "JK": "Jammu and Kashmir",
        "JH": "Jharkhand", "KA": "Karnataka", "KL": "Kerala", "MP": "Madhya Pradesh", "MH": "Maharashtra",
        "MN": "Manipur", "ML": "Meghalaya", "MZ": "Mizoram", "NL": "Nagaland", "OR": "Odisha",
        "PB": "Punjab", "RJ": "Rajasthan", "SK": "Sikkim", "TN": "Tamil Nadu", "TG": "Telangana",
        "TR": "Tripura", "UP": "Uttar Pradesh", "UT": "Uttarakhand", "WB": "West Bengal"
    }
    
    state_upper = state_code.upper().strip()
    
    # Determine which database to use based on country
    country_lower = country.lower().strip()
    
    if country_lower in ['us', 'usa', 'united states', 'america'] or not country:
        return usa_states.get(state_upper, state_code)
    elif country_lower in ['ca', 'canada']:
        return canada_provinces.get(state_upper, state_code)
    elif country_lower in ['au', 'australia']:
        return australia_states.get(state_upper, state_code)
    elif country_lower in ['de', 'germany', 'deutschland']:
        return germany_states.get(state_upper, state_code)
    elif country_lower in ['uk', 'gb', 'great britain', 'united kingdom']:
        return uk_regions.get(state_upper, state_code)
    elif country_lower in ['fr', 'france']:
        return france_regions.get(state_upper, state_code)
    elif country_lower in ['it', 'italy', 'italia']:
        return italy_regions.get(state_upper, state_code)
    elif country_lower in ['br', 'brazil', 'brasil']:
        return brazil_states.get(state_upper, state_code)
    elif country_lower in ['in', 'india']:
        return india_states.get(state_upper, state_code)
    
    # Default fallback: try USA first, then return original
    return usa_states.get(state_upper, state_code)

def normalize_country_code(code: str) -> str:
    """Convert country codes to full names - comprehensive list"""
    countries = {
        # Major countries
        "US": "United States", "USA": "United States", "AMERICA": "United States",
        "GB": "Great Britain", "UK": "United Kingdom", "BRITAIN": "Great Britain",
        "CA": "Canada", "CANADA": "Canada",
        "AU": "Australia", "AUSTRALIA": "Australia",
        "DE": "Germany", "GERMANY": "Germany", "DEUTSCHLAND": "Germany",
        "FR": "France", "FRANCE": "France",
        "IT": "Italy", "ITALY": "Italy", "ITALIA": "Italy",
        "ES": "Spain", "SPAIN": "Spain", "ESPANA": "Spain",
        "NL": "Netherlands", "NETHERLANDS": "Netherlands", "HOLLAND": "Netherlands",
        "BE": "Belgium", "BELGIUM": "Belgium",
        "CH": "Switzerland", "SWITZERLAND": "Switzerland",
        "AT": "Austria", "AUSTRIA": "Austria",
        "SE": "Sweden", "SWEDEN": "Sweden",
        "NO": "Norway", "NORWAY": "Norway",
        "DK": "Denmark", "DENMARK": "Denmark",
        "FI": "Finland", "FINLAND": "Finland",
        "IE": "Ireland", "IRELAND": "Ireland",
        "PT": "Portugal", "PORTUGAL": "Portugal",
        "GR": "Greece", "GREECE": "Greece",
        "PL": "Poland", "POLAND": "Poland",
        "CZ": "Czech Republic", "CZECH": "Czech Republic",
        "HU": "Hungary", "HUNGARY": "Hungary",
        "RO": "Romania", "ROMANIA": "Romania",
        "BG": "Bulgaria", "BULGARIA": "Bulgaria",
        "HR": "Croatia", "CROATIA": "Croatia",
        "SI": "Slovenia", "SLOVENIA": "Slovenia",
        "SK": "Slovakia", "SLOVAKIA": "Slovakia",
        "LT": "Lithuania", "LITHUANIA": "Lithuania",
        "LV": "Latvia", "LATVIA": "Latvia",
        "EE": "Estonia", "ESTONIA": "Estonia",
        
        # Asian countries
        "JP": "Japan", "JAPAN": "Japan",
        "CN": "China", "CHINA": "China",
        "IN": "India", "INDIA": "India",
        "KR": "South Korea", "KOREA": "South Korea", "SOUTH KOREA": "South Korea",
        "TH": "Thailand", "THAILAND": "Thailand",
        "VN": "Vietnam", "VIETNAM": "Vietnam",
        "SG": "Singapore", "SINGAPORE": "Singapore",
        "MY": "Malaysia", "MALAYSIA": "Malaysia",
        "ID": "Indonesia", "INDONESIA": "Indonesia",
        "PH": "Philippines", "PHILIPPINES": "Philippines",
        "TW": "Taiwan", "TAIWAN": "Taiwan",
        "HK": "Hong Kong", "HONG KONG": "Hong Kong",
        
        # American countries
        "BR": "Brazil", "BRAZIL": "Brazil", "BRASIL": "Brazil",
        "MX": "Mexico", "MEXICO": "Mexico",
        "AR": "Argentina", "ARGENTINA": "Argentina",
        "CL": "Chile", "CHILE": "Chile",
        "CO": "Colombia", "COLOMBIA": "Colombia",
        "PE": "Peru", "PERU": "Peru",
        "VE": "Venezuela", "VENEZUELA": "Venezuela",
        
        # Middle East & Africa
        "IL": "Israel", "ISRAEL": "Israel",
        "TR": "Turkey", "TURKEY": "Turkey",
        "SA": "Saudi Arabia", "SAUDI ARABIA": "Saudi Arabia",
        "AE": "United Arab Emirates", "UAE": "United Arab Emirates",
        "EG": "Egypt", "EGYPT": "Egypt",
        "ZA": "South Africa", "SOUTH AFRICA": "South Africa",
        
        # Oceania
        "NZ": "New Zealand", "NEW ZEALAND": "New Zealand",
        
        # Others
        "RU": "Russia", "RUSSIA": "Russia",
        "UA": "Ukraine", "UKRAINE": "Ukraine",
        "BY": "Belarus", "BELARUS": "Belarus"
    }
    
    return countries.get(code.upper().strip(), code)

def write_format_errors(errors: list[str]) -> str:
    """Write format errors to file"""
    error_file_path = "/app/Format_error.txt"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    error_content = f"\n\n=== Format Errors - {timestamp} ===\n"
    for i, error in enumerate(errors, 1):
        error_content += f"{i}. {error}\n"
    
    # Append to file
    try:
        with open(error_file_path, "a", encoding="utf-8") as f:
            f.write(error_content)
        return error_file_path
    except Exception as e:
        print(f"Error writing to format error file: {e}")
        return ""

def check_node_duplicate(db: Session, ip: str, login: str, password: str) -> dict:
    """Check for duplicates and handle according to business rules"""
    # Find nodes with same IP
    ip_matches = db.query(Node).filter(Node.ip == ip).all()
    
    if not ip_matches:
        return {"action": "add", "reason": "new_node"}
    
    # Check for exact match (IP + Login + Pass)
    exact_match = db.query(Node).filter(
        Node.ip == ip,
        Node.login == login,
        Node.password == password
    ).first()
    
    if exact_match:
        return {"action": "skip", "reason": "duplicate", "existing_node": exact_match.id}
    
    # Check for IP match with different credentials
    different_creds = [node for node in ip_matches if node.login != login or node.password != password]
    
    if different_creds:
        # Check last update time (4 weeks = 28 days)
        four_weeks_ago = datetime.now() - timedelta(days=28)
        
        old_nodes = [node for node in different_creds if node.last_update < four_weeks_ago]
        recent_nodes = [node for node in different_creds if node.last_update >= four_weeks_ago]
        
        if old_nodes and not recent_nodes:
            # Delete old nodes and add new one
            for old_node in old_nodes:
                db.delete(old_node)
            return {"action": "replace", "reason": "replaced_old", "deleted_nodes": [n.id for n in old_nodes]}
        
        elif recent_nodes:
            # Send to verification queue
            return {"action": "queue", "reason": "verification_needed", "conflicting_nodes": [n.id for n in recent_nodes]}
    
    return {"action": "add", "reason": "unique_credentials"}

def create_verification_queue_entry(db: Session, node_data: dict, conflicting_nodes: list[int]) -> int:
    """Create entry in verification queue"""
    # For now, store in a simple JSON file. Can be upgraded to database table later
    queue_file = "/app/verification_queue.json"
    
    entry = {
        "id": int(datetime.now().timestamp()),
        "timestamp": datetime.now().isoformat(),
        "node_data": node_data,
        "conflicting_node_ids": conflicting_nodes,
        "status": "pending"
    }
    
    try:
        # Load existing queue
        queue_data = []
        if os.path.exists(queue_file):
            with open(queue_file, "r", encoding="utf-8") as f:
                queue_data = json.load(f)
        
        # Add new entry
        queue_data.append(entry)
        
        # Save updated queue
        with open(queue_file, "w", encoding="utf-8") as f:
            json.dump(queue_data, f, indent=2)
        
        return entry["id"]
    except Exception as e:
        print(f"Error creating verification queue entry: {e}")
        return 0

def process_parsed_nodes_bulk(db: Session, parsed_data: dict, testing_mode: str) -> dict:
    """OPTIMIZED BULK version - fast but with proper duplicate checking and reporting"""
    from sqlalchemy import text
    from datetime import datetime, timedelta
    
    added_nodes = []
    skipped_nodes = []
    replaced_nodes = []
    error_nodes = []
    
    # Get existing IPs in batches for performance (FIXED: process in chunks to avoid huge queries)
    existing_ips = {}
    is_empty_db = False
    try:
        # First check if database is empty for optimization
        total_count = db.execute(text("SELECT COUNT(*) FROM nodes")).scalar()
        is_empty_db = (total_count == 0)
        
        if is_empty_db:
            logger.info("Empty database detected - using optimized INSERT mode")
        
        # Get all IPs to check
        
        ip_list = [node.get('ip', '').strip() for node in parsed_data.get('nodes', [])]
        
        if ip_list:
            # Process in batches of 1000 IPs to avoid SQLite query size limits
            batch_size = 1000
            for batch_start in range(0, len(ip_list), batch_size):
                batch_ips = ip_list[batch_start:batch_start + batch_size]
                
                # Create placeholders for this batch
                placeholders = ','.join(f':ip{i}' for i in range(len(batch_ips)))
                params = {f'ip{i}': ip for i, ip in enumerate(batch_ips)}
                
                result = db.execute(text(f"""
                    SELECT ip, login, password, last_update 
                    FROM nodes 
                    WHERE ip IN ({placeholders})
                """), params)
                
                for row in result.fetchall():
                    existing_ips[row[0]] = {
                        'login': row[1], 
                        'password': row[2], 
                        'last_update': row[3]
                    }
    except Exception as e:
        logger.error(f"Error getting existing IPs: {e}")
        # Continue without duplicate checking if query fails
    
    # Process nodes with smart duplicate handling
    bulk_insert_data = []
    
    for node_data in parsed_data.get('nodes', []):
        try:
            ip = node_data.get('ip', '').strip()
            login = node_data.get('login', 'admin')
            password = node_data.get('password', 'admin')
            protocol = node_data.get('protocol', 'pptp')
            
            if not ip:
                error_nodes.append({"error": "Missing IP", "data": node_data})
                continue
            
            # Smart duplicate checking
            if ip in existing_ips:
                existing = existing_ips[ip]
                
                # Check if exact duplicate (same IP + login + password)
                if existing['login'] == login and existing['password'] == password:
                    skipped_nodes.append({
                        "ip": ip, 
                        "reason": "Exact duplicate",
                        "existing_login": existing['login']
                    })
                    continue
                
                # Check if old record (>4 weeks) - replace it
                try:
                    if existing['last_update']:
                        last_update_date = datetime.fromisoformat(existing['last_update'].replace('Z', '+00:00'))
                        if datetime.utcnow() - last_update_date > timedelta(weeks=4):
                            # Will be replaced by INSERT OR REPLACE
                            replaced_nodes.append({
                                "ip": ip,
                                "reason": "Replaced old record",
                                "old_login": existing['login'],
                                "new_login": login
                            })
                        else:
                            # Recent duplicate with different credentials
                            skipped_nodes.append({
                                "ip": ip,
                                "reason": "Recent duplicate with different credentials",
                                "existing_login": existing['login']
                            })
                            continue
                except:
                    pass  # If date parsing fails, treat as replaceable
            
            # Add to bulk insert - ИСПРАВЛЕНО: добавлены ВСЕ поля
            bulk_insert_data.append({
                'ip': ip,
                'login': login,
                'password': password,
                'protocol': protocol,
                'status': 'not_tested',
                'port': node_data.get('port'),
                'country': node_data.get('country'),
                'state': node_data.get('state'),
                'city': node_data.get('city'),
                'zipcode': node_data.get('zipcode'),
                'provider': node_data.get('provider'),
                'comment': node_data.get('comment'),
                'scamalytics_fraud_score': node_data.get('scamalytics_fraud_score'),
                'scamalytics_risk': node_data.get('scamalytics_risk')
            })
            
            if ip not in existing_ips:
                added_nodes.append({"ip": ip, "login": login})
            
        except Exception as e:
            logger.error(f"Error processing node in bulk mode: {e}")
            error_nodes.append({"error": str(e), "data": node_data})
    
    # Optimized bulk insert with duplicate handling
    if bulk_insert_data:
        try:
            # CRITICAL FIX: Deduplicate bulk_insert_data BEFORE inserting
            # This prevents UNIQUE constraint violations from duplicates within the import batch
            seen_keys = set()
            deduplicated_data = []
            duplicates_removed = 0
            
            for item in bulk_insert_data:
                key = (item['ip'], item['login'], item['password'])
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduplicated_data.append(item)
                else:
                    duplicates_removed += 1
            
            if duplicates_removed > 0:
                logger.info(f"🔍 Removed {duplicates_removed} duplicates from bulk insert data")
            
            # Use INSERT OR REPLACE to update existing nodes
            # ИСПРАВЛЕНО: добавлены ВСЕ поля
            insert_stmt = text("""
                INSERT OR REPLACE INTO nodes (
                    ip, login, password, protocol, status, port,
                    country, state, city, zipcode, provider, comment,
                    scamalytics_fraud_score, scamalytics_risk, last_update
                )
                VALUES (
                    :ip, :login, :password, :protocol, :status, :port,
                    :country, :state, :city, :zipcode, :provider, :comment,
                    :scamalytics_fraud_score, :scamalytics_risk, datetime('now')
                )
            """)
            
            db.execute(insert_stmt, deduplicated_data)
            db.commit()
            
            logger.info(f"✅ OPTIMIZED BULK INSERT: {len(added_nodes)} added, {len(skipped_nodes)} skipped, {len(replaced_nodes)} replaced")
            
        except Exception as e:
            logger.error(f"Bulk insert error: {e}")
            db.rollback()
            error_nodes.extend([{"error": f"Bulk insert failed: {e}", "data": item} for item in deduplicated_data])
            added_nodes = []
    
    return {
        'added': added_nodes,
        'skipped': skipped_nodes,
        'replaced': replaced_nodes,
        'errors': error_nodes
    }

def process_parsed_nodes(db: Session, parsed_data: dict, testing_mode: str = "no_test") -> dict:
    """Process parsed nodes with IN-IMPORT and DB deduplication logic"""
    results = {
        "added": [],
        "skipped": [],
        "replaced": [],
        "queued": [],
        "errors": [],
        "format_errors": parsed_data['format_errors']
    }
    
    # Log initial parsing stats
    logger.info(f"📊 Import Statistics - Total parsed: {len(parsed_data['nodes'])}, Format errors: {len(parsed_data.get('format_errors', []))}")
    
    # STEP 1: Deduplicate WITHIN the import batch (before checking DB)
    seen_in_import = set()  # Track (ip, login, password) tuples in this import
    unique_nodes = []
    duplicates_in_import_count = 0
    
    for node_data in parsed_data['nodes']:
        node_key = (node_data['ip'], node_data.get('login', ''), node_data.get('password', ''))
        
        if node_key in seen_in_import:
            # Skip duplicate within import
            duplicates_in_import_count += 1
            results["skipped"].append({
                "ip": node_data['ip'],
                "existing_id": None,
                "reason": "duplicate_in_import"
            })
            continue
        
        seen_in_import.add(node_key)
        unique_nodes.append(node_data)
    
    logger.info(f"🔍 Deduplication - Unique configs: {len(unique_nodes)}, Duplicates removed: {duplicates_in_import_count}")
    
    # STEP 2: Process unique nodes against database
    for node_data in unique_nodes:
        try:
            # Check for duplicates in database
            dup_result = check_node_duplicate(
                db, 
                node_data['ip'], 
                node_data['login'], 
                node_data['password']
            )
            
            if dup_result["action"] == "add":
                # Create new node - ensure default status is not_tested
                node_data_with_defaults = {**node_data}
                if 'status' not in node_data_with_defaults:
                    node_data_with_defaults['status'] = 'not_tested'
                
                try:
                    new_node = Node(**node_data_with_defaults)
                    new_node.last_update = datetime.utcnow()  # Set current time on creation
                    db.add(new_node)
                    db.flush()  # Get ID without committing
                    results["added"].append({
                        "id": new_node.id,
                        "ip": node_data['ip'],
                        "reason": dup_result["reason"]
                    })
                except Exception as e:
                    # Handle UNIQUE constraint violation (duplicate caught by DB)
                    if "UNIQUE constraint failed" in str(e) or "unique" in str(e).lower():
                        logger.warning(f"⚠️ DB rejected duplicate: {node_data['ip']}:{node_data['login']} (caught by UNIQUE constraint)")
                        results["skipped"].append({
                            "ip": node_data['ip'],
                            "existing_id": None,
                            "reason": "duplicate_caught_by_db"
                        })
                        db.rollback()
                    else:
                        raise
            
            elif dup_result["action"] == "skip":
                results["skipped"].append({
                    "ip": node_data['ip'],
                    "existing_id": dup_result["existing_node"],
                    "reason": dup_result["reason"]
                })
            
            elif dup_result["action"] == "replace":
                # Create new node (old ones already deleted) - ensure default status is not_tested
                node_data_with_defaults = {**node_data}
                if 'status' not in node_data_with_defaults:
                    node_data_with_defaults['status'] = 'not_tested'
                
                try:
                    new_node = Node(**node_data_with_defaults)
                    new_node.last_update = datetime.utcnow()  # Set current time on creation
                    db.add(new_node)
                    db.flush()
                    results["replaced"].append({
                        "id": new_node.id,
                        "ip": node_data['ip'],
                        "deleted_nodes": dup_result["deleted_nodes"],
                        "reason": dup_result["reason"]
                    })
                except Exception as e:
                    # Handle UNIQUE constraint violation
                    if "UNIQUE constraint failed" in str(e) or "unique" in str(e).lower():
                        logger.warning(f"⚠️ DB rejected replacement: {node_data['ip']}:{node_data['login']} (caught by UNIQUE constraint)")
                        results["skipped"].append({
                            "ip": node_data['ip'],
                            "existing_id": None,
                            "reason": "duplicate_caught_by_db"
                        })
                        db.rollback()
                    else:
                        raise
            
            elif dup_result["action"] == "queue":
                # Add to verification queue
                queue_id = create_verification_queue_entry(
                    db, node_data, dup_result["conflicting_nodes"]
                )
                results["queued"].append({
                    "queue_id": queue_id,
                    "ip": node_data['ip'],
                    "conflicting_nodes": dup_result["conflicting_nodes"],
                    "reason": dup_result["reason"]
                })
        
        except Exception as e:
            logger.error(f"Error processing node {node_data.get('ip', 'unknown')}: {str(e)}")
            results["errors"].append({
                "ip": node_data.get('ip', 'unknown'),
                "error": str(e)
            })
    
    # Write format errors to file
    if results['format_errors']:
        try:
            write_format_errors(results['format_errors'])
        except Exception as e:
            logger.error(f"Error writing format errors: {str(e)}")
    
    # Commit all changes
    try:
        db.commit()
        # Log final statistics
        logger.info(f"✅ Import Complete - Added: {len(results['added'])}, Skipped: {len(results['skipped'])}, Replaced: {len(results['replaced'])}, Queued: {len(results['queued'])}, Errors: {len(results['errors'])}")
    except Exception as e:
        logger.error(f"Database commit error: {str(e)}")
        db.rollback()
        results["errors"].append({"general": f"Database commit error: {str(e)}"})
    
    return results
def parse_location_smart(location: str) -> dict:
    """
    Умный парсинг Location с поддержкой ЛЮБЫХ форматов и вариаций
    
    Поддерживаемые форматы:
    1. US (Washington, Mill Creek)     - Country (State, City)
    2. Washington, Mill Creek          - State, City
    3. Texas (Austin)                  - State (City)
    4. US Washington, Mill Creek       - Country State, City (без скобок)
    5. US (Washington. Mill Creek)     - точка вместо запятой
    6. US Washington Mill Creek        - только пробелы
    7. US: Washington: Mill Creek      - через двоеточия
    8. US, Washington, Mill Creek      - через запятые
    9. Washington. Mill Creek          - точка как разделитель
    10. Washington Mill Creek          - только пробелы
    11. US (Washington  Mill Creek)    - двойной/множественный пробел
    
    Возвращает: {'country': ..., 'state': ..., 'city': ...}
    """
    location = location.strip()
    result = {'country': None, 'state': None, 'city': None}
    
    if not location:
        return result
    
    # PATTERN 1: Со скобками - Country (State, City) или State (City)
    # Поддерживает любые разделители внутри: запятая, точка, двоеточие, пробел (включая множественные)
    bracket_match = re.match(r'^([^(]+)\(([^)]+)\)$', location)
    if bracket_match:
        before_bracket = bracket_match.group(1).strip()
        inside_bracket = bracket_match.group(2).strip()
        
        # Внутри скобок ищем разделители: запятая, точка, двоеточие
        # ВАЖНО: Если нет явных разделителей - НЕ разбиваем по пробелу!
        # "Costa Mesa" должно остаться как один город, а не разбиваться
        if ',' in inside_bracket:
            # Запятая - приоритет 1
            inside_parts = [p.strip() for p in inside_bracket.split(',') if p.strip()]
        elif '.' in inside_bracket and inside_bracket.count('.') >= 1:
            # Точка - приоритет 2
            inside_parts = [p.strip() for p in inside_bracket.split('.') if p.strip()]
        elif ':' in inside_bracket:
            # Двоеточие - приоритет 3
            inside_parts = [p.strip() for p in inside_bracket.split(':') if p.strip()]
        else:
            # НЕТ явных разделителей - значит это ОДИН город
            # "Costa Mesa", "Wappingers Falls" - оставляем как есть
            inside_parts = [inside_bracket]
        
        if len(inside_parts) >= 2:
            # Country (State, City) - формат с несколькими частями в скобках
            result['country'] = before_bracket
            result['state'] = inside_parts[0]
            result['city'] = ' '.join(inside_parts[1:])  # Объединяем остальное как город
        elif len(inside_parts) == 1:
            # State (City) - формат с одной частью в скобках
            result['state'] = before_bracket
            result['city'] = inside_parts[0]
        else:
            # Внутри скобок ничего нет или не распарсилось - пробуем как State (полный текст)
            result['state'] = before_bracket
            result['city'] = inside_bracket
        
        return result
    
    # PATTERN 2: Без скобок - пробуем разделители
    # Приоритет разделителей: запятая > точка > двоеточие > пробелы
    
    # Пробуем запятую как основной разделитель
    if ',' in location:
        parts = [p.strip() for p in location.split(',') if p.strip()]
        if len(parts) >= 3:
            # Country, State, City
            result['country'] = parts[0]
            result['state'] = parts[1]
            result['city'] = ' '.join(parts[2:])
        elif len(parts) == 2:
            # State, City
            result['state'] = parts[0]
            result['city'] = parts[1]
        return result
    
    # Пробуем точку как разделитель (но не если это просто окончание предложения)
    if '.' in location and location.count('.') >= 1:
        parts = [p.strip() for p in location.split('.') if p.strip()]
        if len(parts) >= 3:
            result['country'] = parts[0]
            result['state'] = parts[1]
            result['city'] = ' '.join(parts[2:])
        elif len(parts) == 2:
            result['state'] = parts[0]
            result['city'] = parts[1]
        return result
    
    # Пробуем двоеточие как разделитель (но НЕ если это часть "Location:")
    colon_count = location.count(':')
    if colon_count >= 1:
        parts = [p.strip() for p in location.split(':') if p.strip()]
        if len(parts) >= 3:
            result['country'] = parts[0]
            result['state'] = parts[1]
            result['city'] = ' '.join(parts[2:])
        elif len(parts) == 2:
            result['state'] = parts[0]
            result['city'] = parts[1]
        return result
    
    # PATTERN 3: Только пробелы - умное разделение
    # Ищем паттерн: "US Washington Mill Creek" или "Washington Mill Creek"
    parts = location.split()
    
    if len(parts) >= 3:
        # Проверяем первую часть - это код страны (2-3 буквы ВСЕ ЗАГЛАВНЫЕ)?
        if len(parts[0]) <= 3 and parts[0].isupper():
            # Country State City
            result['country'] = parts[0]
            result['state'] = parts[1]
            result['city'] = ' '.join(parts[2:])
        else:
            # State City (несколько слов для города)
            result['state'] = parts[0]
            result['city'] = ' '.join(parts[1:])
    elif len(parts) == 2:
        # State City
        result['state'] = parts[0]
        result['city'] = parts[1]
    elif len(parts) == 1:
        # Только State
        result['state'] = parts[0]
    
    return result

def is_valid_ip(ip: str) -> bool:
    """Basic IP validation"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

@api_router.get("/format-errors")
async def get_format_errors(
    current_user: User = Depends(get_current_user)
):
    """Get format errors from file"""
    error_file_path = "/app/Format_error.txt"
    
    try:
        if not os.path.exists(error_file_path):
            return {"content": "", "message": "No format errors found"}
        
        with open(error_file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        return {"content": content, "message": "Format errors loaded successfully"}
    
    except Exception as e:
        return {"content": "", "message": f"Error reading format errors: {str(e)}"}

@api_router.delete("/format-errors")
async def clear_format_errors(
    current_user: User = Depends(get_current_user)
):
    """Clear format errors file"""
    error_file_path = "/app/Format_error.txt"
    
    try:
        if os.path.exists(error_file_path):
            os.remove(error_file_path)
        return {"message": "Format errors cleared successfully"}
    
    except Exception as e:
        return {"message": f"Error clearing format errors: {str(e)}"}
@api_router.get("/autocomplete/countries")
async def get_countries(
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Node.country).filter(Node.country != "").distinct()
    if q:
        query = query.filter(Node.country.ilike(f"%{q}%"))
    countries = [row[0] for row in query.limit(10).all()]
    return countries

@api_router.get("/autocomplete/states")
async def get_states(
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Node.state).filter(Node.state != "").distinct()
    if q:
        query = query.filter(Node.state.ilike(f"%{q}%"))
    states = [row[0] for row in query.limit(10).all()]
    return states

@api_router.get("/autocomplete/cities")
async def get_cities(
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Node.city).filter(Node.city != "").distinct()
    if q:
        query = query.filter(Node.city.ilike(f"%{q}%"))
    cities = [row[0] for row in query.limit(10).all()]
    return cities

@api_router.get("/autocomplete/providers")
async def get_providers(
    q: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Node.provider).filter(Node.provider != "").distinct()
    if q:
        query = query.filter(Node.provider.ilike(f"%{q}%"))
    providers = [row[0] for row in query.limit(10).all()]
    return providers

@api_router.post('/progress/cancel-all')
async def cancel_all_progress(current_user: User = Depends(get_current_user)):
    # Cancel and mark as completed
    for sid, tracker in list(progress_store.items()):
        tracker.status = 'cancelled'
        progress_store[sid] = tracker
    return {"success": True, "message": "All test sessions cancelled"}

# Statistics
@api_router.get("/stats")
async def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # OPTIMIZED: Single query with GROUP BY instead of multiple COUNT queries
    from sqlalchemy import func
    
    # Get status counts in one query
    status_counts = db.query(
        Node.status, func.count(Node.id).label('count')
    ).group_by(Node.status).all()
    
    status_dict = {status: count for status, count in status_counts}
    
    # Get protocol counts in one query
    protocol_counts = db.query(
        Node.protocol, func.count(Node.id).label('count')
    ).group_by(Node.protocol).all()
    
    protocol_dict = {protocol: count for protocol, count in protocol_counts}
    
    # Get total
    total_nodes = sum(status_dict.values())
    
    # Get SOCKS online count (online nodes with SOCKS data)
    socks_online = db.query(Node).filter(
        Node.status == "online",
        Node.socks_ip.isnot(None),
        Node.socks_port.isnot(None)
    ).count()
    
    return {
        "total": total_nodes,
        "not_tested": status_dict.get("not_tested", 0),
        "ping_light": status_dict.get("ping_light", 0),
        "ping_failed": status_dict.get("ping_failed", 0),
        "ping_ok": status_dict.get("ping_ok", 0),
        "speed_ok": status_dict.get("speed_ok", 0),
        "offline": status_dict.get("offline", 0),
        "online": status_dict.get("online", 0),
        "socks_online": socks_online,
        "by_protocol": {
            "pptp": protocol_dict.get("pptp", 0),
            "ssh": protocol_dict.get("ssh", 0),
            "socks": protocol_dict.get("socks", 0),
            "server": protocol_dict.get("server", 0),
            "ovpn": protocol_dict.get("ovpn", 0),
        }
    }

@api_router.get("/progress/{session_id}")
async def get_progress_stream(session_id: str):
    """Server-Sent Events endpoint for real-time progress updates.
    No auth required - session_id serves as access control."""
    
    async def event_generator():
        while True:
            if session_id in progress_store:
                progress = progress_store[session_id]
                data = json.dumps(progress.to_dict())
                yield f"data: {data}\n\n"
                
                # If completed or failed, break the loop
                if progress.status in ["completed", "failed", "cancelled"]:
                    break
            else:
                # Session not found, send empty progress
                yield f"data: {json.dumps({'error': 'Session not found'})}\n\n"
                break
            
            await asyncio.sleep(0.5)  # Update every 500ms
    
    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET",
            "Access-Control-Allow-Headers": "Cache-Control"
        }
    )

@api_router.post("/progress/{session_id}/cancel")
async def cancel_progress(session_id: str, current_user: User = Depends(get_current_user)):
    """Cancel ongoing operation"""
    if session_id in progress_store:
        progress_store[session_id].status = "cancelled"
        return {"success": True, "message": "Operation cancelled"}
    return {"success": False, "message": "Session not found"}

# Service Management Routes
@api_router.post("/services/start")
async def start_services(
    action: ServiceAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start PPTP + SOCKS services for selected nodes"""
    results = []
    
    for node_id in action.node_ids:
        # Get node data
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        try:
            # Start PPTP connection
            pptp_result = await service_manager.start_pptp_connection(
                node_id, node.ip, node.login, node.password
            )
            
            if pptp_result['success']:
                interface = pptp_result['interface']
                
                # Start SOCKS server on the PPTP interface
                socks_result = await service_manager.start_socks_server(
                    node_id, interface
                )
                
                if socks_result['success']:
                    # Update node status to online only if all previous steps passed
                    if node.status in ["ping_ok", "speed_ok"]:
                        node.status = "online"
                        node.last_update = datetime.utcnow()  # Update time when online
                    # Note: Database will auto-commit via get_db() dependency
                    
                    results.append({
                        "node_id": node_id,
                        "success": True,
                        "pptp": pptp_result,
                        "socks": socks_result,
                        "message": f"PPTP + SOCKS started on {interface}:{socks_result['port']}"
                    })
                else:
                    # Service failed to start properly - preserve speed_ok status
                    if node.status == "speed_ok":
                        # Don't downgrade speed_ok nodes - keep for retry
                        logger.info(f"SOCKS failed for speed_ok node {node_id}, preserving status")
                        pass  # Keep current status
                    else:
                        node.status = "offline"
                    logger.info(f"Node {node_id} status after SOCKS failure: {node.status}")
                    node.last_update = datetime.utcnow()  # Update time
                    # Note: Database will auto-commit via get_db() dependency
                    results.append({
                        "node_id": node_id,
                        "success": False,
                        "pptp": pptp_result,
                        "socks": socks_result,
                        "status": node.status,
                        "message": f"PPTP OK, SOCKS failed - status remains {node.status}"
                    })
            else:
                # PPTP connection failed - preserve original status if it was speed_ok
                if node.status == "speed_ok":
                    # Don't downgrade speed_ok nodes - keep for retry
                    logger.info(f"PPTP failed for speed_ok node {node_id}, preserving status")
                    pass  # Keep current status
                else:
                    node.status = "offline"
                logger.info(f"Node {node_id} status after PPTP failure: {node.status}")
                node.last_update = datetime.utcnow()  # Update time
                # Note: get_db() will auto-commit
                results.append({
                    "node_id": node_id,
                    "success": False,
                    "pptp": pptp_result,
                    "status": node.status,
                    "message": f"PPTP connection failed - status remains {node.status}"
                })
                
        except Exception as e:
            # Don't change status on exception - preserve speed_ok if it exists
            results.append({
                "node_id": node_id,
                "success": False,
                "status": node.status,
                "message": f"Service start error: {str(e)} - status remains {node.status}"
            })
    
    return {"results": results}

@api_router.post("/services/stop")
async def stop_services(
    action: ServiceAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stop services for selected nodes"""
    results = []
    
    for node_id in action.node_ids:
        try:
            result = await service_manager.stop_services(node_id)
            
            if result['success']:
                # Update node status
                node = db.query(Node).filter(Node.id == node_id).first()
                if node:
                    node.status = "offline"
                    node.last_update = datetime.utcnow()  # Update time when stopped
                    # Note: get_db() will auto-commit
            
            results.append({
                "node_id": node_id,
                "success": result['success'],
                "message": result['message']
            })
            
        except Exception as e:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Service stop error: {str(e)}"
            })
    
    return {"results": results}

@api_router.get("/services/status/{node_id}")
async def get_service_status(
    node_id: int,
    current_user: User = Depends(get_current_user)
):
    """Get service status for a specific node"""
    try:
        status = await service_manager.get_service_status(node_id)
        return status
    except Exception as e:
        return {"error": str(e)}

# Network Testing Routes  
@api_router.post("/test/ping")
async def test_ping(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test ping for selected nodes - preserves speed_ok status"""
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        # CRITICAL: Save original status BEFORE any changes
        original_status = node.status
        logger.info(f"🔍 Test ping: Node {node_id} original status: {original_status}")
        
        # NEVER test speed_ok nodes
        if original_status == "speed_ok":
            logger.info(f"✅ Test ping: Node {node_id} has speed_ok - SKIPPING to preserve status")
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": True,
                "status": "speed_ok",
                "message": "Node has speed_ok status - test skipped to preserve validation"
            })
            continue
        
        try:
            # Set status to checking
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            ping_result = await network_tester.ping_test(node.ip)
            
            # Update status based on ping result
            if ping_result['reachable']:
                node.status = "ping_ok"
                logger.info(f"✅ Test ping: Node {node_id} SUCCESS - {original_status} -> ping_ok")
            else:
                node.status = "ping_failed"
                logger.info(f"❌ Test ping: Node {node_id} FAILED - {original_status} -> ping_failed")
            
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": ping_result['success'],
                "status": node.status,
                "original_status": original_status,
                "ping": ping_result
            })
            
        except Exception as e:
            # On error, NEVER downgrade speed_ok
            if original_status != "speed_ok":
                node.status = "offline"
                logger.error(f"❌ Test ping: Node {node_id} ERROR - {original_status} -> offline - {str(e)}")
            else:
                node.status = "speed_ok"
                logger.error(f"❌ Test ping: Node {node_id} ERROR but PROTECTED - preserving speed_ok - {str(e)}")
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            results.append({
                "node_id": node_id,
                "success": False,
                "status": node.status,
                "original_status": original_status,
                "message": f"Ping test error: {str(e)}"
            })
    
    return {"results": results}

@api_router.post("/test/speed")
async def test_speed(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test speed for selected nodes (requires active connection)"""
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        try:
            # Check if service is active
            service_status = await service_manager.get_service_status(node_id)
            
            if not service_status['active']:
                results.append({
                    "node_id": node_id,
                    "success": False,
                    "message": "Service not active - start PPTP connection first"
                })
                continue
            
            interface = service_status.get('interface')
            speed_result = await network_tester.speed_test(interface)
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": speed_result['success'],
                "speed": speed_result,
                "interface": interface
            })
            
        except Exception as e:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Speed test error: {str(e)}"
            })
    
    return {"results": results}

@api_router.post("/test/combined") 
async def test_combined(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Combined test (ping + speed) for selected nodes"""
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        try:
            # Set status to checking
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()  # Update time when status changes
            db.commit()
            
            # Get interface if service is active
            service_status = await service_manager.get_service_status(node_id)
            interface = service_status.get('interface') if service_status['active'] else None
            
            # Run combined test
            combined_result = await network_tester.combined_test(
                node.ip, interface, test_request.test_type
            )
            
            # Update node status
            node.status = combined_result['overall']
            node.last_update = datetime.utcnow()  # Update time after test
            db.commit()
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": True,
                "test": combined_result
            })
            
        except Exception as e:
            # Reset status on error
            node.status = "offline"
            node.last_update = datetime.utcnow()  # Update time on error
            db.commit()
            
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Combined test error: {str(e)}"
            })
    
    return {"results": results}

# Auto-test new nodes on creation
@api_router.post("/nodes/auto-test")
async def create_node_with_test(
    node: NodeCreate,
    test_type: str = "ping",  # ping, speed, both
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create node and automatically test it"""
    # Create node first
    db_node = Node(**node.dict())
    db_node.status = "checking"
    db_node.last_update = datetime.utcnow()  # Set time on creation
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    
    try:
        # Run test based on type
        if test_type == "ping":
            ping_result = await network_tester.ping_test(db_node.ip)
            if ping_result['reachable']:
                db_node.status = "ping_ok"
            else:
                db_node.status = "ping_failed"
            test_result = {"ping": ping_result}
            
        elif test_type == "speed":
            # Speed test only if current status allows it
            if db_node.status in ["ping_ok", "speed_ok", "online"]:
                # Skip testing if already speed_ok
                if db_node.status == "speed_ok":
                    speed_result = {"success": True, "download_speed": float(db_node.speed.replace(" Mbps", "")) if db_node.speed else 0, "message": "Already speed_ok"}
                else:
                    speed_result = await network_tester.speed_test()
                    if speed_result['success'] and speed_result.get('download_speed'):
                        if speed_result['download_speed'] > 1.0:
                            db_node.status = "speed_ok"
                        else:
                            # Don't downgrade to ping_failed - keep current status
                            pass  # Keep existing status
                    else:
                        # Keep existing status instead of ping_ok
                        pass  # Don't change status
            else:
                speed_result = {"success": False, "error": "Ping test required first"}
            test_result = {"speed": speed_result}
            
        else:  # both
            combined_result = await network_tester.combined_test(db_node.ip, None, "both")
            db_node.status = combined_result['overall']
            test_result = {"combined": combined_result}
        
        db_node.last_check = datetime.utcnow()
        db_node.last_update = datetime.utcnow()  # Update time after test
        db.commit()
        
        return {
            "node": db_node,
            "test_result": test_result,
            "message": f"Node created and tested ({test_type})"
        }
        
    except Exception as e:
        # Fallback to offline if test fails
        db_node.status = "offline"
        db_node.last_update = datetime.utcnow()  # Update time on error
        db.commit()
        
        return {
            "node": db_node,
            "test_result": {"error": str(e)},
            "message": f"Node created but test failed: {str(e)}"
        }

# Individual Node Actions
@api_router.post("/nodes/{node_id}/test")
async def test_single_node(
    node_id: int,
    test_type: str = "ping",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test a single node"""
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    try:
        # Сохраняем оригинальный статус
        original_status = node.status
        
        # Set status to checking только для ping тестов
        if test_type == "ping":
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
        
        if test_type == "ping":
            result = await network_tester.ping_test(node.ip)
            if result['reachable']:
                node.status = "ping_ok"
            else:
                node.status = "ping_failed"
        elif test_type == "speed":
            # Speed test only if node has passed ping test
            if node.status in ["ping_ok", "speed_ok", "online"]:
                service_status = await service_manager.get_service_status(node_id)
                interface = service_status.get('interface') if service_status['active'] else None
                result = await network_tester.speed_test(interface)
                if result['success'] and result.get('download_speed'):
                    if result['download_speed'] > 1.0:
                        node.status = "speed_ok"
                    else:
                        node.status = "ping_failed"
                else:
                    # Keep current status if speed test fails
                    pass
            else:
                result = {"success": False, "error": "Ping test required first"}
        else:  # both
            service_status = await service_manager.get_service_status(node_id)
            interface = service_status.get('interface') if service_status['active'] else None
            result = await network_tester.combined_test(node.ip, interface, "both")
            node.status = result['overall']
        
        node.last_update = datetime.utcnow()  # Update time after test
        db.commit()
        
        return {
            "success": True,
            "node_id": node_id,
            "test_type": test_type,
            "result": result,
            "status": node.status
        }
        
    except Exception as e:
        node.status = "offline"
        node.last_update = datetime.utcnow()  # Update time on error
        db.commit()
        return {"success": False, "message": str(e)}

@api_router.post("/nodes/{node_id}/services/start")
async def start_single_node_services(
    node_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start services for a single node"""
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    try:
        # Start PPTP connection
        pptp_result = await service_manager.start_pptp_connection(
            node_id, node.ip, node.login, node.password
        )
        
        if pptp_result['success']:
            interface = pptp_result['interface']
            
            # Start SOCKS server
            socks_result = await service_manager.start_socks_server(
                node_id, interface
            )
            
            if socks_result['success']:
                node.status = "online"
                node.last_update = datetime.utcnow()  # Update time when online
                db.commit()
                
                return {
                    "success": True,
                    "node_id": node_id,
                    "pptp": pptp_result,
                    "socks": socks_result,
                    "message": f"Services started on {interface}:{socks_result['port']}"
                }
            else:
                return {
                    "success": False,
                    "message": "PPTP OK, SOCKS failed",
                    "pptp": pptp_result,
                    "socks": socks_result
                }
        else:
            return {
                "success": False,
                "message": "PPTP connection failed",
                "pptp": pptp_result
            }
            
    except Exception as e:
        return {"success": False, "message": str(e)}

@api_router.post("/nodes/{node_id}/services/stop")
async def stop_single_node_services(
    node_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stop services for a single node"""
    node = db.query(Node).filter(Node.id == node_id).first()
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    
    try:
        result = await service_manager.stop_services(node_id)
        
        if result['success']:
            node.status = "offline"
            node.last_update = datetime.utcnow()  # Update time when stopped
            db.commit()
        
        return {
            "success": result['success'],
            "node_id": node_id,
            "message": result['message']
        }
        
    except Exception as e:
        return {"success": False, "message": str(e)}

# ===== MANUAL TESTING WORKFLOW API ENDPOINTS =====
# These endpoints implement the user's required manual testing workflow:
# not_tested → ping_test → ping_ok/ping_failed  
# ping_ok → speed_test → speed_ok/ping_failed
# speed_ok → launch_services → online

@api_router.post("/manual/ping-light-test")
async def manual_ping_light_test(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manual PING LIGHT testing - быстрая проверка TCP порта без авторизации"""
    node_ids = data.get('node_ids', [])
    
    # Если node_ids пустой - тестируем ВСЕ узлы (Select All режим)
    if not node_ids:
        logger.info("🌐 Select All mode detected - loading all nodes from database")
        all_nodes = db.query(Node).all()
        node_ids = [node.id for node in all_nodes]
        logger.info(f"📊 Will test {len(node_ids)} nodes (all nodes in database)")
    
    results = []
    
    for node_id in node_ids:
        # Проверка дедупликации
        if test_dedupe_should_skip(node_id, "ping_light"):
            results.append({
                "node_id": node_id,
                "status": "skipped",
                "message": "Recently tested, skipping to avoid spam",
                "success": False,
                "avg_time": 0.0,
                "packet_loss": 0.0,
                "original_status": None,
                "new_status": None
            })
            continue

        # Получить узел
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "status": "error",
                "message": "Node not found",
                "success": False,
                "avg_time": 0.0,
                "packet_loss": 0.0,
                "original_status": None,
                "new_status": None
            })
            continue

        test_dedupe_mark_enqueued(node_id, "ping_light")
        
        try:
            original_status = node.status
            node.last_update = datetime.utcnow()
            
            # Выполнить PING LIGHT тест
            from ping_speed_test import test_node_ping_light
            ping_result = await test_node_ping_light(node.ip)
            
            # Обновить статус на основе результата (С ЗАЩИТОЙ для ping_light)
            if ping_result['success']:
                node.status = "ping_light"
                logger.info(f"✅ Node {node_id} PING LIGHT SUCCESS - status: {original_status} -> ping_light")
            else:
                # ЗАЩИТА: если уже был ping_light (порт работал хотя бы раз), сохраняем статус
                if original_status in ("ping_light", "ping_ok", "speed_ok", "online"):
                    node.status = original_status  # Сохраняем! Не откатываем до ping_failed
                    logger.info(f"🛡️ Node {node_id} PING LIGHT FAILED but preserving status {original_status} (port was working before)")
                else:
                    node.status = "ping_failed"
                    logger.info(f"❌ Node {node_id} PING LIGHT FAILED - status: {original_status} -> ping_failed")
            
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            
            results.append({
                "node_id": node_id,
                "status": "completed",
                "message": ping_result.get('message', ''),
                "success": ping_result.get('success', False),
                "avg_time": ping_result.get('avg_time', 0.0),
                "packet_loss": ping_result.get('packet_loss', 0.0),
                "original_status": original_status,
                "new_status": node.status
            })
            
        except Exception as e:
            logger.error(f"Error in PING LIGHT test for node {node_id}: {str(e)}")
            results.append({
                "node_id": node_id,
                "status": "error",
                "message": f"PING LIGHT test error: {str(e)}",
                "success": False,
                "avg_time": 0.0,
                "packet_loss": 0.0,
                "original_status": original_status if 'original_status' in locals() else None,
                "new_status": None
            })
        finally:
            test_dedupe_mark_finished(node_id)
    
    return {"results": results}
@api_router.post("/manual/ping-test")
async def manual_ping_test(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manual ping test - works for any node status but preserves speed_ok"""
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        # Store original status BEFORE any changes - CRITICAL for speed_ok preservation
        original_status = node.status
        logger.info(f"🔍 Node {node_id} ping test - original status: {original_status}")
        
        # CRITICAL PROTECTION: Never test speed_ok nodes - they already passed all tests
        if original_status == "speed_ok":
            logger.info(f"✅ Node {node_id} has speed_ok status - SKIPPING ping test to preserve status")
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": True,
                "status": "speed_ok",
                "original_status": original_status,
                "message": "Node already has speed_ok status - test skipped to preserve validation"
            })
            continue
        
        try:
            # Set status to checking during test (only for non-speed_ok nodes)
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            # Perform full PING OK test with authentication
            from ping_speed_test import test_node_ping
            ping_result = await test_node_ping(node.ip, node.login or 'admin', node.password or 'admin')
            # Add packet_loss for UI compatibility (100 - success_rate)
            try:
                ping_result["packet_loss"] = round(100.0 - float(ping_result.get("success_rate", 0.0)), 1)
            except Exception:
                ping_result["packet_loss"] = 100.0 if not ping_result.get("success") else 0.0

            # Update status based on AUTHENTIC PPTP result (ИСПРАВЛЕНО)
            if ping_result['success']:
                node.status = "ping_ok"
                logger.info(f"✅ Node {node_id} AUTHENTIC PPTP SUCCESS - status: {original_status} -> ping_ok")
            else:
                # ИСПРАВЛЕНО: При провале PING OK теста статус должен быть ping_failed
                # Исключение: только для speed_ok и online делаем откат до ping_ok (они уже прошли валидацию)
                if original_status in ("speed_ok", "online"):
                    node.status = "ping_ok"  # откат до baseline для высоких статусов
                    logger.info(f"🔄 Node {node_id} AUTHENTIC PPTP FAILED - rolling back from {original_status} to ping_ok (baseline preserved)")
                else:
                    # Для ping_ok и других статусов - четко ping_failed при провале авторизации
                    node.status = "ping_failed"
                    logger.info(f"❌ Node {node_id} AUTHENTIC PPTP FAILED - status: {original_status} -> ping_failed (invalid credentials)")
            
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": bool(ping_result.get("success", False)),
                "status": node.status,
                "original_status": original_status,
                "ping_result": ping_result,
                "message": f"Ping test completed: {original_status} -> {node.status}"
            })
            
        except Exception as e:
            # On error, set to ping_failed ONLY if original status wasn't speed_ok
            if original_status != "speed_ok":
                node.status = "ping_failed"
                logger.error(f"❌ Node {node_id} ping ERROR - status: {original_status} -> ping_failed - Error: {str(e)}")
            else:
                node.status = "speed_ok"
                logger.error(f"❌ Node {node_id} ping ERROR but PRESERVING speed_ok - Error: {str(e)}")
            
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            # Note: get_db() will auto-commit
            
            results.append({
                "node_id": node_id,
                "success": False,
                "status": node.status,
                "original_status": original_status,
                "message": f"Ping test error: {str(e)} - Status: {original_status} -> {node.status}"
            })
    
    return {"results": results}

@api_router.post("/manual/ping-test-batch")
async def manual_ping_test_batch(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Optimized batch ping test with real-time progress tracking"""
    
    # Generate session ID for progress tracking
    session_id = str(uuid.uuid4())
    
    # Get all nodes first
    nodes = []
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    
    if not nodes:
        return {"results": [], "session_id": session_id}
    
    # Initialize progress tracker
    progress = ProgressTracker(session_id, len(nodes))
    progress.update(0, f"Начинаем ping тестирование {len(nodes)} узлов...")
    
    # Start background batch testing
    asyncio.create_task(process_testing_batches(
        session_id, [n.id for n in nodes], "ping_only", db,
        ping_concurrency=test_request.ping_concurrency or 15,  # АГРЕССИВНО увеличено
        speed_concurrency=test_request.speed_concurrency or 8,   # АГРЕССИВНО увеличено
        ping_timeouts=test_request.ping_timeouts or [0.8,1.2,1.6],
        speed_sample_kb=test_request.speed_sample_kb or 512,
        speed_timeout=test_request.speed_timeout or 15
    ))
    
    return {"results": [], "session_id": session_id, "message": f"Запущено тестирование {len(nodes)} узлов"}

# Removed incomplete process_ping_testing_batches function - using process_testing_batches instead

@api_router.post("/manual/ping-light-test-batch-progress")
async def manual_ping_light_test_batch_progress(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Batch PING LIGHT test with real-time progress tracking - быстрая проверка TCP порта без авторизации"""
    
    # ЗАЩИТА ОТ ПЕРЕГРУЗКИ: проверяем лимит сессий
    if not can_start_new_session():
        raise HTTPException(
            status_code=503, 
            detail=f"Сервер перегружен. Максимум {MAX_CONCURRENT_SESSIONS} тестовых сессий. Попробуйте позже."
        )
    
    # Generate session ID for progress tracking
    session_id = str(uuid.uuid4())
    active_sessions.add(session_id)
    
    # Если node_ids пустой - тестируем узлы по фильтрам (Select All режим)
    node_ids_to_test = test_request.node_ids
    if not node_ids_to_test:
        logger.info("🌐 PING LIGHT BATCH: Select All mode detected - loading nodes with filters")
        query = db.query(Node)
        # Применяем фильтры если есть
        if test_request.filters:
            query = apply_node_filters(query, test_request.filters)
            logger.info(f"🔍 PING LIGHT BATCH: Applying filters: {test_request.filters}")
        all_nodes = query.all()
        node_ids_to_test = [node.id for node in all_nodes]
        logger.info(f"📊 PING LIGHT BATCH: Will test {len(node_ids_to_test)} nodes (with filters)")
    
    # Get all valid nodes
    nodes = []
    for node_id in node_ids_to_test:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    
    if not nodes:
        return {"session_id": session_id, "message": "Нет узлов для тестирования", "started": False}
    
    # Initialize progress tracker
    progress = ProgressTracker(session_id, len(nodes))
    progress.update(0, f"Начинаем PING LIGHT тестирование {len(nodes)} узлов...")
    
    # Start background batch testing with ping_light mode
    # Получаем timeout из ping_timeouts (первое значение)
    ping_light_timeout = 2.0  # default
    if test_request.ping_timeouts and len(test_request.ping_timeouts) > 0:
        ping_light_timeout = test_request.ping_timeouts[0]
    
    asyncio.create_task(process_ping_light_batches(
        session_id, [n.id for n in nodes], db,
        ping_concurrency=test_request.ping_concurrency or 20,  # Еще выше для PING LIGHT
        timeout=ping_light_timeout
    ))
    
    return {"session_id": session_id, "message": f"Запущено PING LIGHT тестирование {len(nodes)} узлов", "started": True}


@api_router.post("/manual/geo-test-batch")
async def manual_geo_test_batch(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """GEO Test - проверка и обновление геолокации и провайдера С ПРОГРЕССОМ"""
    
    node_ids = test_request.node_ids or []
    
    if not node_ids:
        raise HTTPException(status_code=400, detail="No nodes selected")
    
    # Создаем session для прогресса
    session_id = str(uuid.uuid4())
    
    # Создаем progress tracker
    tracker = ProgressTracker(session_id, len(node_ids))
    progress_store[session_id] = tracker
    
    # Запускаем в background
    asyncio.create_task(process_geo_test_background(session_id, node_ids, db))
    
    return {
        "session_id": session_id,
        "message": f"Запущен GEO тест для {len(node_ids)} узлов",
        "started": True
    }

async def process_geo_test_background(session_id: str, node_ids: list, db_session):
    """Background обработка GEO теста с прогрессом"""
    local_db = SessionLocal()
    
    try:
        from service_manager_geo import service_manager
        
        for i, node_id in enumerate(node_ids, 1):
            try:
                node = local_db.query(Node).filter(Node.id == node_id).first()
                if not node:
                    continue
                
                # Обновляем прогресс
                if session_id in progress_store:
                    progress_store[session_id].update(i, f"GEO проверка {node.ip} ({i}/{len(node_ids)})")
                
                # Выполняем проверку
                success = await service_manager.enrich_node_geolocation(node, local_db, force=True)
                
                if success:
                    local_db.commit()
                
            except Exception as e:
                logger.error(f"GEO test error for node {node_id}: {e}")
        
        # Завершаем
        if session_id in progress_store:
            progress_store[session_id].complete("completed")
        
    except Exception as e:
        logger.error(f"GEO background task error: {e}")
        if session_id in progress_store:
            progress_store[session_id].complete("failed")
    finally:
        local_db.close()

@api_router.post("/manual/fraud-test-batch")
async def manual_fraud_test_batch(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fraud Test - проверка Fraud Score и Risk Level С ПРОГРЕССОМ"""
    
    node_ids = test_request.node_ids or []
    
    if not node_ids:
        raise HTTPException(status_code=400, detail="No nodes selected")
    
    # Создаем session для прогресса
    session_id = str(uuid.uuid4())
    
    # Создаем progress tracker
    tracker = ProgressTracker(session_id, len(node_ids))
    progress_store[session_id] = tracker
    
    # Запускаем в background
    asyncio.create_task(process_fraud_test_background(session_id, node_ids, db))
    
    return {
        "session_id": session_id,
        "message": f"Запущен Fraud тест для {len(node_ids)} узлов",
        "started": True
    }

async def process_fraud_test_background(session_id: str, node_ids: list, db_session):
    """Background обработка Fraud теста с прогрессом"""
    local_db = SessionLocal()
    
    try:
        from service_manager_geo import service_manager
        
        for i, node_id in enumerate(node_ids, 1):
            try:
                node = local_db.query(Node).filter(Node.id == node_id).first()
                if not node:
                    continue
                
                # Обновляем прогресс
                if session_id in progress_store:
                    progress_store[session_id].update(i, f"Fraud проверка {node.ip} ({i}/{len(node_ids)})")
                
                # Выполняем проверку
                success = await service_manager.enrich_node_fraud(node, local_db, force=True)
                
                if success:
                    local_db.commit()
                
            except Exception as e:
                logger.error(f"Fraud test error for node {node_id}: {e}")
        
        # Завершаем
        if session_id in progress_store:
            progress_store[session_id].complete("completed")
        
    except Exception as e:
        logger.error(f"Fraud background task error: {e}")
        if session_id in progress_store:
            progress_store[session_id].complete("failed")
    finally:
        local_db.close()

@api_router.post("/manual/geo-fraud-test-batch")
async def manual_geo_fraud_test_batch(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """GEO + Fraud Test - полная проверка С ПРОГРЕССОМ"""
    
    node_ids = test_request.node_ids or []
    
    if not node_ids:
        raise HTTPException(status_code=400, detail="No nodes selected")
    
    # Создаем session для прогресса
    session_id = str(uuid.uuid4())
    
    # Создаем progress tracker
    tracker = ProgressTracker(session_id, len(node_ids))
    progress_store[session_id] = tracker
    
    # Запускаем в background
    asyncio.create_task(process_geo_fraud_test_background(session_id, node_ids, db))
    
    return {
        "session_id": session_id,
        "message": f"Запущен GEO + Fraud тест для {len(node_ids)} узлов",
        "started": True
    }

async def process_geo_fraud_test_background(session_id: str, node_ids: list, db_session):
    """Background обработка GEO + Fraud теста с прогрессом"""
    local_db = SessionLocal()
    
    try:
        from service_manager_geo import service_manager
        
        for i, node_id in enumerate(node_ids, 1):
            try:
                node = local_db.query(Node).filter(Node.id == node_id).first()
                if not node:
                    continue
                
                # Обновляем прогресс
                if session_id in progress_store:
                    progress_store[session_id].update(i, f"Полная проверка {node.ip} ({i}/{len(node_ids)})")
                
                # Выполняем полную проверку
                success = await service_manager.enrich_node_complete(node, local_db)
                
                if success:
                    local_db.commit()
                
            except Exception as e:
                logger.error(f"GEO+Fraud test error for node {node_id}: {e}")
        
        # Завершаем
        if session_id in progress_store:
            progress_store[session_id].complete("completed")
        
    except Exception as e:
        logger.error(f"GEO+Fraud background task error: {e}")
        if session_id in progress_store:
            progress_store[session_id].complete("failed")
    finally:
        local_db.close()

@api_router.post("/manual/ping-test-batch-progress")
async def manual_ping_test_batch_progress(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Batch ping test with real-time progress tracking"""
    
    # ЗАЩИТА ОТ ПЕРЕГРУЗКИ: проверяем лимит сессий
    if not can_start_new_session():
        raise HTTPException(
            status_code=503, 
            detail=f"Сервер перегружен. Максимум {MAX_CONCURRENT_SESSIONS} тестовых сессий. Попробуйте позже."
        )
    
    # Generate session ID for progress tracking
    session_id = str(uuid.uuid4())
    active_sessions.add(session_id)
    
    # Если node_ids пустой - тестируем узлы по фильтрам (Select All режим)
    node_ids_to_test = test_request.node_ids or []
    if not node_ids_to_test:
        logger.info("🌐 PING OK BATCH: Select All mode detected - loading nodes with filters")
        query = db.query(Node)
        # Применяем фильтры если есть
        if test_request.filters:
            query = apply_node_filters(query, test_request.filters)
            logger.info(f"🔍 PING OK BATCH: Applying filters: {test_request.filters}")
        all_nodes = query.all()
        node_ids_to_test = [node.id for node in all_nodes]
        logger.info(f"📊 PING OK BATCH: Will test {len(node_ids_to_test)} nodes (with filters)")
    
    # Get all valid nodes
    nodes = []
    for node_id in node_ids_to_test:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    
    if not nodes:
        return {"session_id": session_id, "message": "Нет узлов для тестирования", "started": False}
    
    # Initialize progress tracker
    progress = ProgressTracker(session_id, len(nodes))
    progress.update(0, f"Начинаем ping тестирование {len(nodes)} узлов...")
    
    # Start background batch testing
    asyncio.create_task(process_testing_batches(
        session_id, [n.id for n in nodes], "ping_only", db,
        ping_concurrency=test_request.ping_concurrency or 15,  # АГРЕССИВНО увеличено
        speed_concurrency=test_request.speed_concurrency or 8,   # АГРЕССИВНО увеличено
        ping_timeouts=test_request.ping_timeouts or [0.8,1.2,1.6],
        speed_sample_kb=test_request.speed_sample_kb or 512,
        speed_timeout=test_request.speed_timeout or 15
    ))
    
    return {"session_id": session_id, "message": f"Запущено тестирование {len(nodes)} узлов", "started": True}

@api_router.post("/manual/speed-test-batch-progress")
async def manual_speed_test_batch_progress(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Batch speed test with real-time progress tracking"""
    
    # ЗАЩИТА ОТ ПЕРЕГРУЗКИ: проверяем лимит сессий
    if not can_start_new_session():
        raise HTTPException(
            status_code=503, 
            detail=f"Сервер перегружен. Максимум {MAX_CONCURRENT_SESSIONS} тестовых сессий. Попробуйте позже."
        )
    
    # Generate session ID for progress tracking
    session_id = str(uuid.uuid4())
    active_sessions.add(session_id)
    
    # Если node_ids пустой - тестируем узлы по фильтрам (Select All режим)
    node_ids_to_test = test_request.node_ids or []
    if not node_ids_to_test:
        logger.info("🌐 SPEED TEST BATCH: Select All mode detected - loading nodes with filters")
        query = db.query(Node)
        # Применяем фильтры если есть
        if test_request.filters:
            query = apply_node_filters(query, test_request.filters)
            logger.info(f"🔍 SPEED TEST BATCH: Applying filters: {test_request.filters}")
        all_nodes = query.all()
        node_ids_to_test = [node.id for node in all_nodes]
        logger.info(f"📊 SPEED TEST BATCH: Will test {len(node_ids_to_test)} nodes (with filters)")
    
    # Get all valid nodes
    nodes = []
    for node_id in node_ids_to_test:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    
    if not nodes:
        return {"session_id": session_id, "message": "Нет узлов для тестирования", "started": False}
    
    # Initialize progress tracker
    progress = ProgressTracker(session_id, len(nodes))
    progress.update(0, f"Начинаем speed тестирование {len(nodes)} узлов...")
    
    # Start background batch testing
    asyncio.create_task(process_testing_batches(
        session_id, [n.id for n in nodes], "speed_only", db,
        ping_concurrency=test_request.ping_concurrency or 15,  # АГРЕССИВНО увеличено
        speed_concurrency=test_request.speed_concurrency or 8,   # АГРЕССИВНО увеличено
        ping_timeouts=test_request.ping_timeouts or [0.8,1.2,1.6],
        speed_sample_kb=test_request.speed_sample_kb or 512,
        speed_timeout=test_request.speed_timeout or 15
    ))
    
    return {"session_id": session_id, "message": f"Запущено тестирование {len(nodes)} узлов", "started": True}

@api_router.post("/manual/ping-speed-test-batch-progress")
async def manual_ping_speed_test_batch_progress(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """DEPRECATED: Combined ping+speed removed. This maps to speed-only for compatibility."""
    session_id = str(uuid.uuid4())
    # Gather nodes
    nodes = []
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    if not nodes:
        return {"session_id": session_id, "message": "Нет узлов для тестирования", "started": False}
    progress = ProgressTracker(session_id, len(nodes))
    progress.update(0, f"Запуск speed-тестирования {len(nodes)} узлов (замена ping+speed)")
    asyncio.create_task(process_testing_batches(
        session_id, [n.id for n in nodes], "speed_only", db,
        ping_concurrency=test_request.ping_concurrency or 15,  # АГРЕССИВНО увеличено
        speed_concurrency=test_request.speed_concurrency or 8,   # АГРЕССИВНО увеличено
        ping_timeouts=test_request.ping_timeouts or [0.8,1.2,1.6],
        speed_sample_kb=test_request.speed_sample_kb or 512,
        speed_timeout=test_request.speed_timeout or 15
    ))
    return {"session_id": session_id, "message": f"Запущено тестирование {len(nodes)} узлов (speed)", "started": True}

async def process_testing_batches(session_id: str, node_ids: list, testing_mode: str, db_session, *,
                                  ping_concurrency: int = 15,   # АГРЕССИВНО увеличено для скорости
                                  speed_concurrency: int = 8,   # АГРЕССИВНО увеличено для скорости  
                                  ping_timeouts: list[float] | None = None,
                                  speed_sample_kb: int = 32,    # МИНИМИЗИРОВАНО для максимальной скорости
                                  speed_timeout: int = 2):      # ЭКСТРЕМАЛЬНО быстро
    """Process testing in batches for any test type with concurrency controls"""
    
    total_nodes = len(node_ids)
    # АГРЕССИВНЫЕ большие батчи для максимальной скорости
    if total_nodes < 100:
        BATCH_SIZE = 50   # Большие батчи даже для малых объемов
    elif total_nodes < 500:
        BATCH_SIZE = 100  # Большие батчи
    elif total_nodes < 1000:
        BATCH_SIZE = 200  # Очень большие батчи
    else:
        BATCH_SIZE = 300  # МАКСИМАЛЬНЫЕ батчи для скорости
    processed_nodes = 0
    failed_tests = 0

    if ping_timeouts is None:
        ping_timeouts = [0.5]  # СВЕРХ-БЫСТРЫЙ единственный таймаут
    
    try:
        # Get fresh database session for background processing
        db = SessionLocal()
        
        logger.info(f"🚀 Testing Batch: Starting {total_nodes} nodes in batches of {BATCH_SIZE}, mode: {testing_mode}")
        
        # Import testing functions
        from ping_speed_test import test_node_ping, test_node_speed
        
        # Process nodes in batches
        for batch_start in range(0, total_nodes, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_nodes)
            current_batch = node_ids[batch_start:batch_end]
            
            logger.info(f"📦 Testing batch {batch_start//BATCH_SIZE + 1}: nodes {batch_start+1}-{batch_end}")
            
            # Check if operation was cancelled
            if session_id in progress_store and progress_store[session_id].status == "cancelled":
                logger.info(f"🚫 Testing cancelled by user for session {session_id}")
                break
            
            # Process current batch with concurrency
            # Choose global semaphore by mode
            global_sem = global_ping_sem if testing_mode == "ping_only" else global_speed_sem
            
            # Combine global limiter + session limiter
            session_sem = asyncio.Semaphore(ping_concurrency if testing_mode == "ping_only" else speed_concurrency)
            sem = session_sem
            tasks = []

            async def process_one(node_id: int, global_index: int):
                async with global_sem:
                    async with sem:
                        local_db = SessionLocal()
                        try:
                            node = local_db.query(Node).filter(Node.id == node_id).first()
                            if not node:
                                logger.warning(f"❌ Testing batch: Node {node_id} not found in database")
                                return False

                            # Dedupe check is done before scheduling; optional extra safety
                            mode_key = "ping" if testing_mode in ["ping_only", "ping_speed"] else ("speed" if testing_mode in ["speed_only"] else testing_mode)

                            # Update progress: starting this node
                            if session_id in progress_store:
                                progress_store[session_id].update(global_index, f"Тестирование {node.ip} ({global_index+1}/{total_nodes})")

                            original_status = node.status
                            logger.info(f"🔍 Testing batch: Node {node.id} ({node.ip}) original status: {original_status}")

                            # Decide actions
                            do_ping = False
                            do_speed = False
                            if testing_mode == "ping_only":
                                do_ping = not has_ping_baseline(original_status)
                            elif testing_mode == "speed_only":
                                do_speed = (original_status != "ping_failed")
                            else:
                                # Treat any other as skip
                                return True

                            # Skip if no action
                            if not (do_ping or do_speed):
                                progress_increment(session_id, f"⏭️ {node.ip} - skipped ({original_status})", {"node_id": node.id, "ip": node.ip, "status": original_status, "success": True})
                                return True

                            # Do ping
                            if do_ping:
                                try:
                                    from ping_speed_test import multiport_tcp_ping
                                    ports = get_ping_ports_for_node(node)
                                    logger.info(f"🔍 Ping testing {node.ip} on ports {ports}")
                                    
                                    ping_result = await multiport_tcp_ping(node.ip, ports=ports, timeouts=ping_timeouts)
                                    logger.info(f"🏓 Ping result for {node.ip}: {ping_result}")
                                    
                                    if ping_result.get('success'):
                                        node.status = "ping_ok"
                                        logger.info(f"✅ {node.ip} ping success: {ping_result.get('avg_time', 0)}ms")
                                        
                                        # УМНАЯ ЛОГИКА: Один запрос для гео + fraud если IPQualityScore
                                        try:
                                            from service_manager_geo import service_manager
                                            complete_success = await service_manager.enrich_node_complete(node, local_db)
                                            if complete_success:
                                                logger.info(f"✅ Node enriched: {node.ip}")
                                                local_db.commit()
                                        except Exception as enrich_error:
                                            logger.warning(f"Enrichment error for {node.ip}: {enrich_error}")
                                    else:
                                        node.status = original_status if has_ping_baseline(original_status) else "ping_failed"
                                        logger.info(f"❌ {node.ip} ping failed: {ping_result.get('message', 'timeout')}")
                                    
                                    node.last_update = datetime.now(timezone.utc)
                                    local_db.commit()
                                except Exception as ping_error:
                                    logger.error(f"❌ Ping test error for {node.ip}: {ping_error}")
                                    node.status = original_status if has_ping_baseline(original_status) else "ping_failed"
                                    node.last_update = datetime.now(timezone.utc)
                                    local_db.commit()

                            # Do speed
                            if do_speed:
                                try:
                                    from ping_speed_test import test_node_speed
                                    logger.info(f"🚀 Speed testing {node.ip}")
                                    
                                    speed_result = await test_node_speed(node.ip, sample_kb=speed_sample_kb, timeout_total=speed_timeout)
                                    logger.info(f"📊 Speed result for {node.ip}: {speed_result}")
                                    
                                    # ИСПРАВЛЕНО: Проверка download_mbps (НЕ download)
                                    if speed_result.get('success') and speed_result.get('download_mbps'):
                                        download_speed = speed_result['download_mbps']
                                        node.speed = f"{download_speed:.1f} Mbps"
                                        node.status = "speed_ok" if download_speed > 1.0 else "ping_ok"
                                        logger.info(f"✅ {node.ip} speed success: {download_speed:.1f} Mbps")
                                    else:
                                        node.status = "ping_ok" if has_ping_baseline(original_status) else "ping_failed"
                                        node.speed = None
                                        logger.info(f"❌ {node.ip} speed failed - result: {speed_result}")
                                    
                                    node.last_update = datetime.now(timezone.utc)
                                    local_db.commit()
                                except Exception as speed_error:
                                    logger.error(f"❌ Speed test error for {node.ip}: {speed_error}")
                                    node.status = "ping_ok" if has_ping_baseline(original_status) else "ping_failed"
                                    node.speed = None
                                    node.last_update = datetime.now(timezone.utc)
                                    local_db.commit()

                            node.last_check = datetime.now(timezone.utc)
                            local_db.commit()

                            # Progress
                            progress_increment(session_id, f"✅ {node.ip} - {node.status}", {"node_id": node.id, "ip": node.ip, "status": node.status, "success": True})
                            return True
                        except Exception as e:
                            logger.error(f"❌ Testing: Node {node_id} error: {e}")
                            return False
                        finally:
                            try:
                                test_dedupe_mark_finished(node_id)
                                local_db.close()
                            except Exception:
                                pass

            for i, node_id in enumerate(current_batch):
                global_index = batch_start + i
                # cancellation
                if session_id in progress_store and progress_store[session_id].status == "cancelled":
                    break
                
                # Определить какие типы тестов будут выполняться
                mode_keys = []
                if testing_mode in ["ping_only", "ping_speed"]:
                    mode_keys.append("ping")
                if testing_mode in ["speed_only", "ping_speed"]:
                    mode_keys.append("speed")
                if not mode_keys:  # Для остальных режимов (no_test и т.д.)
                    mode_keys.append(testing_mode)
                
                # Проверить дедупликацию для ВСЕХ типов тестов
                should_skip = False
                skip_reason = ""
                remaining_time = 0
                for mode_key in mode_keys:
                    if test_dedupe_should_skip(node_id, mode_key):
                        skip_reason = mode_key
                        remaining_time = test_dedupe_get_remaining_time(node_id, mode_key)
                        should_skip = True
                        break
                
                if should_skip:
                    logger.info(f"⏭️ Testing: Skipping node {node_id} (dedupe {skip_reason}, wait {remaining_time}s)")
                    progress_increment(session_id, f"⏭️ Узел {node_id} недавно тестировался ({skip_reason}), подождите {remaining_time}с")
                    # Очистить из inflight и _test_recent если время истекло (wait 0s)
                    if remaining_time == 0:
                        _test_inflight.discard(node_id)
                        # Удалить из _test_recent для всех mode
                        for mk in mode_keys:
                            _test_recent.pop((node_id, mk), None)
                    continue
                
                # Отметить все типы тестов в dedupe
                for mode_key in mode_keys:
                    test_dedupe_mark_enqueued(node_id, mode_key)
                
                tasks.append(asyncio.create_task(process_one(node_id, global_index)))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                # Update counters
                processed_nodes += sum(1 for r in results if r is True)
                failed_tests += sum(1 for r in results if r is False)
            
            # Small delay between batches to prevent system overload
            await asyncio.sleep(0.5)
            
            logger.info(f"✅ Testing batch {batch_start//BATCH_SIZE + 1} completed: {len(current_batch)} nodes scheduled")
            
            # Cleanup dedupe registry periodically (outside inner loops)
            try:
                test_dedupe_cleanup()
            except Exception:
                pass
            
            # Force commit after each batch and clear session cache
            try:
                db.commit()
                db.expunge_all()  # Clear session cache to free memory
            except Exception as commit_error:
                logger.error(f"❌ Testing batch commit error: {commit_error}")
                db.rollback()
            
            # БЕЗ задержек для максимальной скорости
            # await asyncio.sleep(0)  # Убрано для скорости
            
            logger.info(f"✅ Testing batch {batch_start//BATCH_SIZE + 1} completed: {len(current_batch)} nodes processed")
    
    except Exception as e:
        logger.error(f"❌ Testing batch processing error: {str(e)}", exc_info=True)
        if session_id in progress_store:
            progress_store[session_id].complete("failed")
    
    finally:
        # Complete progress tracking
        if session_id in progress_store:
            progress_store[session_id].complete("completed")
            progress_store[session_id].update(
                total_nodes, 
                f"Тестирование завершено: {processed_nodes} успешно, {failed_tests} ошибок"
            )
        
        # Cleanup any remaining nodes stuck in "checking" status
        try:
            stuck_nodes = db.query(Node).filter(Node.status == "checking").all()
            if stuck_nodes:
                logger.warning(f"🧹 Testing: Cleaning up {len(stuck_nodes)} nodes stuck in 'checking' status")
                for stuck_node in stuck_nodes:
                    stuck_node.status = "not_tested"
                    stuck_node.last_update = datetime.utcnow()
                db.commit()
        except Exception as cleanup_error:
            logger.error(f"❌ Testing cleanup error: {cleanup_error}")
        
        db.close()
        
        # КРИТИЧНО: Очистка активной сессии для предотвращения блокировок
        active_sessions.discard(session_id)
        
        logger.info(f"📊 Testing batch processing completed: {processed_nodes} processed, {failed_tests} failed")

async def process_ping_light_batches(session_id: str, node_ids: list, db_session, *,
                                      ping_concurrency: int = 100, timeout: float = 2.0):
    """Process PING LIGHT testing in batches - быстрая проверка TCP порта без авторизации с повышенным параллелизмом"""
    
    total_nodes = len(node_ids)
    # АГРЕССИВНЫЕ большие батчи для максимальной скорости PING LIGHT
    if total_nodes < 100:
        BATCH_SIZE = 100   # Большие батчи даже для малых объемов
    elif total_nodes < 1000:
        BATCH_SIZE = 300   # Очень большие батчи
    else:
        BATCH_SIZE = 500   # МАКСИМАЛЬНЫЕ батчи для PING LIGHT
    
    processed_nodes = 0
    failed_tests = 0
    
    try:
        # Get fresh database session for background processing
        db = SessionLocal()
        
        logger.info(f"🚀 PING LIGHT Batch: Starting {total_nodes} nodes in batches of {BATCH_SIZE}")
        
        # Import testing functions
        from ping_speed_test import test_node_ping_light
        
        # Process nodes in batches
        for batch_start in range(0, total_nodes, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_nodes)
            current_batch = node_ids[batch_start:batch_end]
            
            logger.info(f"📦 PING LIGHT batch {batch_start//BATCH_SIZE + 1}: nodes {batch_start+1}-{batch_end}")
            
            # Check if operation was cancelled
            if session_id in progress_store and progress_store[session_id].status == "cancelled":
                logger.info(f"🚫 PING LIGHT testing cancelled by user for session {session_id}")
                break
            
            # Process current batch with concurrency (используем специальный семафор для PING LIGHT)
            session_sem = asyncio.Semaphore(min(ping_concurrency, MAX_PING_LIGHT_GLOBAL))
            tasks = []

            async def process_one(node_id: int, global_index: int):
                async with session_sem:
                    local_db = SessionLocal()
                    try:
                        node = local_db.query(Node).filter(Node.id == node_id).first()
                        if not node:
                            logger.warning(f"❌ PING LIGHT batch: Node {node_id} not found in database")
                            return False

                        # Update progress: starting this node
                        if session_id in progress_store:
                            progress_store[session_id].update(global_index, f"PING LIGHT тест {node.ip} ({global_index+1}/{total_nodes})")

                        original_status = node.status
                        logger.info(f"🔍 PING LIGHT batch: Node {node.id} ({node.ip}) original status: {original_status}")

                        # Выполнить PING LIGHT тест с заданным timeout
                        ping_result = await test_node_ping_light(node.ip, timeout=timeout)
                        
                        # Обновить статус на основе результата (С ЗАЩИТОЙ для ping_light)
                        if ping_result['success']:
                            node.status = "ping_light"
                            logger.info(f"✅ PING LIGHT batch: Node {node_id} SUCCESS - status: {original_status} -> ping_light")
                            success = True
                            
                            # IP Геолокация (если поля пустые) - через service manager
                            try:
                                from service_manager_geo import service_manager
                                geo_success = await service_manager.enrich_node_geolocation(node, local_db)
                                if geo_success:
                                    logger.info(f"🌍 Geolocation enriched for {node.ip}")
                                    local_db.commit()
                            except Exception as geo_error:
                                logger.warning(f"Geolocation error for {node.ip}: {geo_error}")
                        else:
                            # ЗАЩИТА: если уже был ping_light (порт работал хотя бы раз), сохраняем статус
                            if original_status in ("ping_light", "ping_ok", "speed_ok", "online"):
                                node.status = original_status  # Сохраняем! Не откатываем до ping_failed
                                logger.info(f"🛡️ PING LIGHT batch: Node {node_id} FAILED but preserving status {original_status}")
                            else:
                                node.status = "ping_failed"
                                logger.info(f"❌ PING LIGHT batch: Node {node_id} FAILED - status: {original_status} -> ping_failed")
                            success = False
                        
                        node.last_check = datetime.utcnow()
                        node.last_update = datetime.utcnow()
                        
                        local_db.commit()
                        
                        # Add result to progress
                        result_data = {
                            "node_id": node.id,
                            "ip": node.ip,
                            "status": node.status,
                            "success": success,
                            "original_status": original_status
                        }
                        progress_increment(session_id, f"✅ PING LIGHT {node.ip} - {node.status}", result_data)
                        
                        return success
                        
                    except Exception as e:
                        logger.error(f"❌ PING LIGHT batch: Error testing node {node_id}: {str(e)}")
                        return False
                    finally:
                        local_db.close()

            # Create tasks for this batch
            for i, node_id in enumerate(current_batch):
                global_index = batch_start + i
                tasks.append(process_one(node_id, global_index))

            # Execute batch
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count results
            for result in batch_results:
                if isinstance(result, Exception):
                    failed_tests += 1
                elif result is True:
                    processed_nodes += 1
                else:
                    failed_tests += 1
            
            # Commit batch changes
            try:
                db.commit()
            except Exception as commit_error:
                logger.error(f"❌ PING LIGHT batch commit error: {commit_error}")
                db.rollback()
            
            logger.info(f"✅ PING LIGHT batch {batch_start//BATCH_SIZE + 1} completed: {len(current_batch)} nodes processed")
    
    except Exception as e:
        logger.error(f"❌ PING LIGHT batch processing error: {str(e)}", exc_info=True)
        if session_id in progress_store:
            progress_store[session_id].complete("failed")
    
    finally:
        # Complete progress tracking
        if session_id in progress_store:
            progress_store[session_id].complete("completed")
            progress_store[session_id].update(
                total_nodes, 
                f"PING LIGHT тестирование завершено: {processed_nodes} успешно, {failed_tests} ошибок"
            )
        
        db.close()
        
        # КРИТИЧНО: Очистка активной сессии для предотвращения блокировок
        active_sessions.discard(session_id)
        
        logger.info(f"📊 PING LIGHT batch processing completed: {processed_nodes} processed, {failed_tests} failed")

@api_router.post("/manual/ping-speed-test-batch")
async def manual_ping_speed_test_batch(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Optimized batch ping + speed test with sequential execution"""
    import asyncio
    from ping_speed_test import test_node_ping, test_node_speed
    
    # Get all nodes first
    nodes = []
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if node:
            nodes.append(node)
    
    if not nodes:
        return {"results": []}
    
    # Sequential execution: ping first, then speed only for successful pings
    async def test_single_node_combined(node):
        original_status = getattr(node, 'original_status', 'not_tested')
        
        try:
            # Step 1: Ping test
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
            
            # New single-port multi-timeout TCP ping
            from ping_speed_test import multiport_tcp_ping
            ports = get_ping_ports_for_node(node)
            ping_result = await multiport_tcp_ping(node.ip, ports=ports, timeouts=[0.8, 1.2, 1.6])
            
            if not ping_result or not ping_result.get('success', False):
                # Ping failed - never drop below PING OK baseline
                if has_ping_baseline(original_status):
                    node.status = original_status
                else:
                    node.status = "ping_failed"
                node.last_check = datetime.utcnow()
                node.last_update = datetime.utcnow()
                db.commit()
                
                return {
                    "node_id": node.id,
                    "ip": node.ip,
                    "success": False,
                    "status": node.status,
                    "original_status": original_status,
                    "ping_result": ping_result,
                    "message": f"Ping failed: {original_status} -> {node.status}"
                }
            
            # Step 2: Ping successful, now test speed
            node.status = "ping_ok"
            node.last_update = datetime.utcnow()
            
            # УМНАЯ ЛОГИКА: Один запрос для гео + fraud если используется IPQualityScore
            try:
                from service_manager_geo import service_manager
                complete_success = await service_manager.enrich_node_complete(node, db)
                if complete_success:
                    logger.info(f"✅ Node enriched: {node.ip}")
                    db.commit()
            except Exception as enrich_error:
                logger.warning(f"Enrichment error for {node.ip}: {enrich_error}")
            
            # Note: Database will auto-commit via get_db() dependency
            
            # Small delay before speed test
            await asyncio.sleep(0.5)
            
            speed_result = await asyncio.wait_for(
                test_node_speed(node.ip),
                timeout=15.0
            )
            
            # Update final status based on speed result
            if speed_result and speed_result.get('success', False):
                # On successful speed test, ensure baseline PING OK and set SPEED OK
                node.status = "speed_ok"
                node.speed = f"{speed_result.get('download', 0)} Mbps"
            else:
                # Speed failed: downgrade from SPEED OK only to PING OK; never to PING FAILED
                if has_ping_baseline(original_status):
                    node.status = "ping_ok"
                else:
                    node.status = "ping_failed"
            
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            
            # Note: Database will auto-commit via get_db() dependency
            
            return {
                "node_id": node.id,
                "ip": node.ip,
                "success": True,
                "status": node.status,
                "original_status": original_status,
                "ping_result": ping_result,
                "speed_result": speed_result,
                "message": f"Combined test: {original_status} -> {node.status}"
            }
            
        except asyncio.TimeoutError:
            # Preserve speed_ok status on timeout
            if node.status != "speed_ok":
                node.status = "ping_failed"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
            
            return {
                "node_id": node.id,
                "ip": node.ip,
                "success": False,
                "status": node.status,
                "original_status": original_status,
                "message": f"Combined test timeout: {original_status} -> {node.status}"
            }
            
        except Exception as e:
            # Preserve speed_ok status on exception
            if node.status != "speed_ok":
                node.status = "ping_failed"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
            
            return {
                "node_id": node.id,
                "ip": node.ip,
                "success": False,
                "status": node.status,
                "original_status": original_status,
                "message": f"Combined test error: {str(e)}"
            }
    
    # Run tests with limited concurrency for stability
    semaphore = asyncio.Semaphore(4)  # Only 4 concurrent combined tests
    
    async def limited_combined_test(node):
        async with semaphore:
            return await test_single_node_combined(node)
    
    try:
        # Execute all tests with dynamic timeout
        batch_timeout = max(120.0, len(nodes) * 5.0)  # 120s minimum or 5s per node for combined tests
        results = await asyncio.wait_for(
            asyncio.gather(*[limited_combined_test(node) for node in nodes]),
            timeout=batch_timeout
        )
        
    except asyncio.TimeoutError:
        # If entire batch times out, ensure no nodes remain in 'checking' status
        results = []
        for node in nodes:
            # Don't downgrade from any successful status to ping_failed
            if node.status not in ["speed_ok", "ping_ok", "online"]:
                node.status = "ping_failed"
                node.last_check = datetime.utcnow()
                node.last_update = datetime.utcnow()
                
            results.append({
                "node_id": node.id,
                "ip": node.ip,
                "success": False,
                "status": node.status,
                "message": "Batch operation timed out"
            })
    
    # Ensure all database changes are committed
    try:
        db.commit()
    except Exception as e:
        print(f"Database commit error in combined test: {e}")
        db.rollback()
    
    return {"results": results}

@api_router.post("/manual/speed-test")
async def manual_speed_test(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manual speed test - allowed for all except ping_failed.
    - not_tested: allow speed; success -> speed_ok (baseline PING OK), fail -> ping_failed
    - ping_ok: allow speed; success -> speed_ok, fail -> keep ping_ok
    - speed_ok/online: allow re-test; success -> speed_ok, fail -> keep ping_ok
    - ping_failed: skip
    """
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        original_status = node.status
        
        # Skip ping_failed per requirements
        if original_status == "ping_failed":
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": False,
                "status": original_status,
                "message": "Speed test skipped for ping_failed"
            })
            continue
        
        try:
            # Set status to checking during test
            node.status = "checking"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
            
            # Perform real speed test
            from ping_speed_test import test_node_speed
            speed_result = await test_node_speed(node.ip)
            
            if speed_result.get('success') and speed_result.get('download'):
                node.speed = f"{speed_result['download']:.1f}"
                node.status = "speed_ok"
            else:
                # Failure: keep baseline if it existed; otherwise mark ping_failed
                if has_ping_baseline(original_status):
                    node.status = "ping_ok"
                else:
                    node.status = "ping_failed"
                node.speed = None
            
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            
            try:
                db.commit()
            except Exception as commit_error:
                print(f"Speed test commit error for node {node_id}: {commit_error}")
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": True,
                "status": node.status,
                "speed": node.speed,
                "speed_result": speed_result,
                "message": f"Speed test completed: {node.status}"
            })
            
        except Exception as e:
            # On error, revert to baseline if existed; else ping_failed
            if has_ping_baseline(original_status):
                node.status = "ping_ok"
            else:
                node.status = "ping_failed"
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()
            db.commit()
            
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Speed test error: {str(e)}"
            })
    
    return {"results": results}

@api_router.post("/manual/launch-services")
async def manual_launch_services(
    test_request: TestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manual service launch - allowed for baseline nodes (PING OK / SPEED OK / ONLINE)"""
    results = []
    
    for node_id in test_request.node_ids:
        node = db.query(Node).filter(Node.id == node_id).first()
        if not node:
            results.append({
                "node_id": node_id,
                "success": False,
                "message": "Node not found"
            })
            continue
        
        # Allow launch if node has baseline connectivity (PING OK/SPEED OK/ONLINE)
        if not has_ping_baseline(node.status):
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Node status is '{node.status}', requires at least 'ping_ok' baseline"
            })
            continue
        
        try:
            # Set status to checking during service launch
            node.status = "checking" 
            node.last_update = datetime.utcnow()  # Update time when status changes
            # Note: Database will auto-commit via get_db() dependency
            
            # Launch SOCKS + OVPN services simultaneously
            from ovpn_generator import ovpn_generator
            from ping_speed_test import test_pptp_connection
            
            # Test PPTP connection - skip ping check since node already passed speed_ok
            pptp_result = await test_pptp_connection(node.ip, node.login, node.password, skip_ping_check=True)
            
            if pptp_result['success']:
                # Generate SOCKS credentials
                socks_data = ovpn_generator.generate_socks_credentials(node.ip, node.login)
                
                # Generate OVPN configuration
                client_name = f"{node.login}_{node.ip.replace('.', '_')}"
                ovpn_config = ovpn_generator.generate_ovpn_config(node.ip, client_name, node.login)
                
                # Save SOCKS and OVPN data to database
                node.socks_ip = socks_data['ip']
                node.socks_port = socks_data['port']
                node.socks_login = socks_data['login'] 
                node.socks_password = socks_data['password']
                node.ovpn_config = ovpn_config
                
                # Service launch successful - set to online
                node.status = "online"
                node.last_check = datetime.utcnow()
                node.last_update = datetime.utcnow()  # Update time when online
                # Note: Database will auto-commit via get_db() dependency
                
                results.append({
                    "node_id": node_id,
                    "ip": node.ip,
                    "success": True,
                    "status": "online",
                    "pptp": pptp_result,
                    "socks": socks_data,
                    "ovpn_ready": True,
                    "message": f"Services launched successfully - SOCKS: {socks_data['ip']}:{socks_data['port']}"
                })
            else:
                # CRITICAL FIX: Don't downgrade speed_ok nodes to ping_failed
                # If service launch fails, keep them in speed_ok status for retry
                logger.info(f"PPTP failed for node {node_id}, preserving speed_ok status")
                node.status = "speed_ok"  # Maintain speed_ok status instead of ping_failed
                node.last_check = datetime.utcnow()
                node.last_update = datetime.utcnow()  # Update time
                logger.info(f"Node {node_id} status set to: {node.status}")
                # Note: Database will auto-commit via get_db() dependency
                
                results.append({
                    "node_id": node_id,
                    "ip": node.ip,
                    "success": False,
                    "status": "speed_ok",  # Keep status as speed_ok for retry
                    "message": f"Service launch failed but node remains speed_ok: {pptp_result.get('message', 'Unknown error')}"
                })
        
        except Exception as e:
            # CRITICAL FIX: On error, keep speed_ok status for nodes that passed tests
            logger.info(f"Exception in service launch for node {node_id}, preserving speed_ok status: {str(e)}")
            node.status = "speed_ok"  # Maintain speed_ok instead of ping_failed
            node.last_check = datetime.utcnow()
            node.last_update = datetime.utcnow()  # Update time on error
            logger.info(f"Node {node_id} status set to: {node.status}")
            # Note: Database will auto-commit via get_db() dependency
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": False,
                "status": "speed_ok",  # Keep status for retry
                "message": f"Service launch error but node remains speed_ok: {str(e)}"
            })
    
    return {"results": results}

# ===== SOCKS SERVICE LAUNCH SYSTEM =====
# API endpoints for SOCKS service management

@api_router.get("/socks/stats")
async def get_socks_stats_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get SOCKS statistics and active connections"""
    try:
        # Get real-time statistics from SOCKS server
        socks_server_stats = get_socks_stats()
        
        # Count nodes with SOCKS enabled in database
        socks_enabled_nodes = db.query(Node).filter(
            Node.socks_ip.isnot(None),
            Node.socks_port.isnot(None)
        ).count()
        
        # Count online SOCKS services in database  
        online_socks_db = db.query(Node).filter(
            Node.status == "online",
            Node.socks_ip.isnot(None),
            Node.socks_port.isnot(None)
        ).count()
        
        # Combine database and real-time server statistics
        return {
            "online_socks": socks_server_stats.get('online_socks', 0),
            "total_tunnels": socks_server_stats.get('total_tunnels', 0), 
            "active_connections": socks_server_stats.get('active_connections', 0),
            "total_connections": socks_server_stats.get('total_connections', 0),
            "bytes_transferred": socks_server_stats.get('bytes_transferred', 0),
            "socks_enabled_nodes": socks_enabled_nodes,
            "db_online_socks": online_socks_db  # For verification
        }
    except Exception as e:
        logger.error(f"Error getting SOCKS stats: {e}")
        return {
            "online_socks": 0,
            "total_tunnels": 0,
            "active_connections": 0,
            "total_connections": 0,
            "bytes_transferred": 0,
            "socks_enabled_nodes": 0,
            "db_online_socks": 0
        }

@api_router.get("/socks/config")
async def get_socks_config(
    current_user: User = Depends(get_current_user)
):
    """Get SOCKS configuration settings"""
    # For now, return default configuration
    # This will be enhanced with persistent config storage
    return {
        "masking": {
            "obfuscation": True,
            "http_imitation": True,
            "timing_randomization": True,
            "tunnel_encryption": True
        },
        "performance": {
            "tunnel_limit": 100,
            "auto_scaling": True,
            "cpu_threshold": 80,
            "ram_threshold": 80
        },
        "security": {
            "whitelist_enabled": False,
            "allowed_ips": []
        }
    }

@api_router.post("/socks/config")
async def save_socks_config(
    config_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Save SOCKS configuration settings"""
    # For now, just validate and return success
    # This will be enhanced with persistent config storage
    logger.info(f"SOCKS config saved: {config_data}")
    return {"success": True, "message": "SOCKS конфигурация сохранена"}

@api_router.get("/socks/active")
async def get_active_socks_proxies(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get list of active SOCKS proxies"""
    try:
        active_proxies = db.query(Node).filter(
            Node.status == "online",
            Node.socks_ip.isnot(None),
            Node.socks_port.isnot(None),
            Node.socks_login.isnot(None),
            Node.socks_password.isnot(None)
        ).all()
        
        proxy_list = []
        for node in active_proxies:
            proxy_list.append({
                "node_id": node.id,
                "ip": node.socks_ip,
                "port": node.socks_port,
                "login": node.socks_login,
                "password": node.socks_password,
                "original_ip": node.ip
            })
        
        return {"proxies": proxy_list}
    except Exception as e:
        logger.error(f"Error getting active SOCKS proxies: {e}")
        return {"proxies": []}

@api_router.get("/socks/proxy-file")
async def get_socks_proxy_file(
    current_user: User = Depends(get_current_user)
):
    """Get SOCKS proxy file content (auto-managed by monitoring system)"""
    try:
        # Get proxy file content from monitoring system
        content = get_proxy_file_content()
        return {"content": content}
    except Exception as e:
        logger.error(f"Error getting SOCKS proxy file: {e}")
        return {"content": "# Ошибка получения файла SOCKS прокси"}

@api_router.post("/socks/start")
async def start_socks_services(
    request_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start SOCKS services for selected nodes or filtered nodes"""
    node_ids = request_data.get("node_ids", [])
    filters = request_data.get("filters", {})
    masking_settings = request_data.get("masking_settings", {})
    performance_settings = request_data.get("performance_settings", {})
    security_settings = request_data.get("security_settings", {})
    
    # Если node_ids пустой - используем фильтры для Select All режима
    if not node_ids:
        if filters:
            logger.info(f"🌐 SOCKS START: Select All mode with filters: {filters}")
            query = db.query(Node)
            query = apply_node_filters(query, filters)
            nodes = query.all()
            node_ids = [node.id for node in nodes]
            logger.info(f"📊 SOCKS START: Will start SOCKS for {len(node_ids)} filtered nodes")
        else:
            raise HTTPException(status_code=400, detail="No node IDs or filters provided")
    
    results = []
    
    for node_id in node_ids:
        try:
            node = db.query(Node).filter(Node.id == node_id).first()
            if not node:
                results.append({
                    "node_id": node_id,
                    "success": False,
                    "message": "Node not found"
                })
                continue
            
            # Check if node has ping_ok or speed_ok status
            if node.status not in ["ping_ok", "speed_ok"]:
                results.append({
                    "node_id": node_id,
                    "ip": node.ip,
                    "success": False,
                    "message": f"Node must have ping_ok or speed_ok status (current: {node.status})"
                })
                continue
            
            # Generate SOCKS credentials
            import secrets
            import string
            
            # Generate unique port (1081-9999 range, avoiding 1080)
            socks_port = 1081 + (node_id % 8918)  # Distribute across range based on node ID
            
            # Generate unique login and password
            login_prefix = f"socks_{node_id}"
            password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
            
            # Save previous status for proper restoration later
            node.previous_status = node.status  # Save current status (ping_ok or speed_ok)
            
            # КРИТИЧНО: Создать PPTP туннель ПЕРЕД запуском SOCKS
            logger.info(f"🔧 Creating PPTP tunnel to {node.ip} for node {node_id}")
            from pptp_tunnel_manager import pptp_tunnel_manager
            tunnel_info = pptp_tunnel_manager.create_tunnel(node_id, node.ip, node.login, node.password)
            
            if not tunnel_info:
                results.append({
                    "node_id": node_id,
                    "ip": node.ip,
                    "success": False,
                    "message": "Не удалось создать PPTP туннель"
                })
                continue
            
            # Сохранить ppp_interface
            node.ppp_interface = tunnel_info['interface']
            logger.info(f"✅ PPTP tunnel created: {tunnel_info['interface']}")
            
            # Start actual SOCKS5 server
            socks_success = start_socks_service(
                node_id=node_id,
                node_ip=node.ip,  # Target node IP for routing
                port=socks_port,
                username=login_prefix,
                password=password,
                masking_config=masking_settings
            )
            
            if not socks_success:
                results.append({
                    "node_id": node_id,
                    "ip": node.ip,
                    "success": False,
                    "message": f"Не удалось запустить SOCKS5 сервер на порту {socks_port}"
                })
                continue
            
            # Update node with SOCKS data
            admin_server_ip = os.environ.get('ADMIN_SERVER_IP', '127.0.0.1')  # External IP of admin server
            node.socks_ip = admin_server_ip
            node.socks_port = socks_port
            node.socks_login = login_prefix
            node.socks_password = password
            node.status = "online"  # Transition ping_ok/speed_ok -> online
            node.last_update = datetime.utcnow()
            
            # Log the SOCKS service creation
            logger.info(f"✅ SOCKS5 server started for node {node_id}: {admin_server_ip}:{socks_port} → {node.ip} ({login_prefix})")
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,  # Original node IP (for reference)
                "success": True,
                "status": "online",
                "socks_data": {
                    "ip": admin_server_ip,  # SOCKS server IP (admin server)
                    "port": socks_port,
                    "login": login_prefix,
                    "password": password,
                    "target_node_ip": node.ip  # Target node IP for routing
                },
                "message": f"SOCKS сервис запущен: {admin_server_ip}:{socks_port} → {node.ip}"
            })
            
        except Exception as e:
            logger.error(f"Error starting SOCKS for node {node_id}: {e}")
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Ошибка запуска SOCKS: {str(e)}"
            })
    
    # Commit changes to database
    db.commit()
    return {"results": results}

@api_router.post("/socks/stop")
async def stop_socks_services(
    request_data: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stop SOCKS services for selected nodes or filtered nodes"""
    node_ids = request_data.get("node_ids", [])
    filters = request_data.get("filters", {})
    
    # Если node_ids пустой - используем фильтры для Select All режима
    if not node_ids:
        if filters:
            logger.info(f"🌐 SOCKS STOP: Select All mode with filters: {filters}")
            query = db.query(Node)
            query = apply_node_filters(query, filters)
            nodes = query.all()
            node_ids = [node.id for node in nodes]
            logger.info(f"📊 SOCKS STOP: Will stop SOCKS for {len(node_ids)} filtered nodes")
        else:
            raise HTTPException(status_code=400, detail="No node IDs or filters provided")
    
    results = []
    
    for node_id in node_ids:
        try:
            node = db.query(Node).filter(Node.id == node_id).first()
            if not node:
                results.append({
                    "node_id": node_id,
                    "success": False,
                    "message": "Node not found"
                })
                continue
            
            # Stop actual SOCKS5 server
            socks_success = stop_socks_service(node_id)
            
            if not socks_success:
                logger.warning(f"⚠️ Failed to stop SOCKS5 server for node {node_id}, continuing with database cleanup")
            
            # Clear SOCKS data and revert to previous status
            node.socks_ip = None
            node.socks_port = None
            node.socks_login = None
            node.socks_password = None
            
            # SMART STATUS RESTORATION: 
            # Manual stop -> node remains speed_ok (live and validated)
            # Logic: if SOCKS was successfully running, node is proven to be working -> speed_ok
            if node.status == "online":
                node.status = "speed_ok"  # Node is live and validated if SOCKS was running
                logger.info(f"🔄 SOCKS manual stop: node {node_id} validated as speed_ok (live and working)")
            
            # Clear previous status after restoration
            node.previous_status = None
            
            node.last_update = datetime.utcnow()
            
            logger.info(f"🛑 SOCKS service stopped for node {node_id}")
            
            results.append({
                "node_id": node_id,
                "ip": node.ip,
                "success": True,
                "status": node.status,
                "message": "SOCKS сервис остановлен"
            })
            
        except Exception as e:
            logger.error(f"Error stopping SOCKS for node {node_id}: {e}")
            results.append({
                "node_id": node_id,
                "success": False,
                "message": f"Ошибка остановки SOCKS: {str(e)}"
            })
    
    # Commit changes to database
    db.commit()
    return {"results": results}

@api_router.get("/socks/database-report")
async def get_socks_database_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate SOCKS database report"""
    try:
        # Get all nodes with SOCKS data
        socks_nodes = db.query(Node).filter(
            or_(
                Node.socks_ip.isnot(None),
                Node.socks_port.isnot(None)
            )
        ).all()
        
        # Get monitoring stats
        monitoring_stats = get_monitoring_stats()
        
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_socks_nodes": len(socks_nodes),
            "online_socks": len([n for n in socks_nodes if n.status == "online"]),
            "monitoring": monitoring_stats,
            "nodes": []
        }
        
        for node in socks_nodes:
            report["nodes"].append({
                "id": node.id,
                "ip": node.ip,
                "city": node.city,
                "country": node.country,
                "status": node.status,
                "previous_status": node.previous_status,
                "socks_ip": node.socks_ip,
                "socks_port": node.socks_port,
                "socks_login": node.socks_login,
                "last_update": node.last_update.isoformat() if node.last_update else None
            })
        
        return report
    except Exception as e:
        logger.error(f"Error generating SOCKS database report: {e}")
        raise HTTPException(status_code=500, detail="Error generating SOCKS database report")

@api_router.get("/socks/monitoring")
async def get_socks_monitoring_info(
    current_user: User = Depends(get_current_user)
):
    """Get SOCKS monitoring system information"""
    try:
        monitoring_stats = get_monitoring_stats()
        socks_server_stats = get_socks_stats()
        
        return {
            "monitoring": monitoring_stats,
            "server_stats": socks_server_stats,
            "system_status": "operational" if monitoring_stats.get("monitoring_active") else "inactive"
        }
    except Exception as e:
        logger.error(f"Error getting SOCKS monitoring info: {e}")
        return {
            "monitoring": {},
            "server_stats": {},
            "system_status": "error",
            "error": str(e)
        }

# Include API router

# Settings API endpoints
@api_router.get("/settings")
async def get_settings(
    current_user: User = Depends(get_current_user)
):
    """Get application settings"""
    return {
        # Геолокация
        "geo_service": os.getenv('GEO_SERVICE', 'ip-api'),
        "ipinfo_token": os.getenv('IPINFO_TOKEN', ''),
        "maxmind_key": os.getenv('MAXMIND_KEY', ''),
        
        # Fraud detection
        "fraud_service": os.getenv('FRAUD_SERVICE', 'ipqs'),
        "ipqs_api_key": os.getenv('IPQS_API_KEY', ''),
        "scamalytics_key": os.getenv('SCAMALYTICS_KEY', ''),
        "abuseipdb_key": os.getenv('ABUSEIPDB_KEY', '')
    }

@api_router.post("/settings")
async def save_settings(
    settings_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Save application settings"""
    env_path = Path(__file__).parent / '.env'
    
    # Читаем существующий .env
    env_lines = []
    if env_path.exists():
        with open(env_path, 'r') as f:
            env_lines = f.readlines()
    
    # Функция для обновления/добавления ключа
    def update_env_key(lines, key, value):
        key_found = False
        for i, line in enumerate(lines):
            if line.startswith(f'{key}='):
                lines[i] = f'{key}={value}\n'
                key_found = True
                break
        if not key_found:
            lines.append(f'{key}={value}\n')
        return lines
    
    # Обновить все ключи
    if 'geo_service' in settings_data:
        env_lines = update_env_key(env_lines, 'GEO_SERVICE', settings_data['geo_service'])
    if 'ipinfo_token' in settings_data:
        env_lines = update_env_key(env_lines, 'IPINFO_TOKEN', settings_data['ipinfo_token'])
    if 'maxmind_key' in settings_data:
        env_lines = update_env_key(env_lines, 'MAXMIND_KEY', settings_data['maxmind_key'])
    if 'fraud_service' in settings_data:
        env_lines = update_env_key(env_lines, 'FRAUD_SERVICE', settings_data['fraud_service'])
    if 'ipqs_api_key' in settings_data:
        env_lines = update_env_key(env_lines, 'IPQS_API_KEY', settings_data['ipqs_api_key'])
    if 'scamalytics_key' in settings_data:
        env_lines = update_env_key(env_lines, 'SCAMALYTICS_KEY', settings_data['scamalytics_key'])
    if 'abuseipdb_key' in settings_data:
        env_lines = update_env_key(env_lines, 'ABUSEIPDB_KEY', settings_data['abuseipdb_key'])
    
    # Сохранить
    with open(env_path, 'w') as f:
        f.writelines(env_lines)
    
    # Обновить в памяти
    for key, value in settings_data.items():
        if key == 'geo_service':
            os.environ['GEO_SERVICE'] = value
        elif key == 'fraud_service':
            os.environ['FRAUD_SERVICE'] = value
        else:
            env_key = key.upper()
            os.environ[env_key] = value
    
    logger.info(f"✅ Settings saved: {list(settings_data.keys())}")
    
    return {"success": True, "message": "Настройки сохранены"}


app.include_router(api_router)

# Health check
@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
