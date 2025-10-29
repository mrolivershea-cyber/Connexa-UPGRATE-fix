import subprocess
import asyncio
import os
import time
import json
from typing import Dict, Optional, Tuple
import re
from pathlib import Path

# Directories for service configurations
PPTP_CONFIG_DIR = Path("/etc/ppp/peers")
SOCKS_CONFIG_DIR = Path("/etc/dante")
CONNEXA_RUN_DIR = Path("/var/run/connexa")

# Ensure directories exist
for directory in [PPTP_CONFIG_DIR, SOCKS_CONFIG_DIR, CONNEXA_RUN_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

class ServiceManager:
    """Manages PPTP and SOCKS services"""
    
    def __init__(self):
        self.active_connections = {}
    
    async def start_pptp_connection(self, node_id: int, ip: str, login: str, password: str) -> Dict:
        """Start PPTP connection for a node"""
        try:
            # Create PPTP config
            config_file = PPTP_CONFIG_DIR / f"connexa-{node_id}"
            config_content = f"""pty "pptp {ip} --nolaunchpppd"
name {login}
password {password}
remoteip {ip}
require-mppe-128
file /etc/ppp/options.pptp
ipparam connexa-{node_id}
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            # Start PPTP connection
            cmd = ["pppd", "call", f"connexa-{node_id}"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait a bit for connection to establish
            await asyncio.sleep(3)
            
            # Check if connection is active
            if_name = await self._get_ppp_interface(node_id)
            if if_name:
                self.active_connections[node_id] = {
                    'type': 'pptp',
                    'interface': if_name,
                    'process': process,
                    'started_at': time.time()
                }
                return {'success': True, 'interface': if_name, 'message': 'PPTP connection established'}
            else:
                return {'success': False, 'message': 'PPTP connection failed to establish'}
                
        except Exception as e:
            return {'success': False, 'message': f'PPTP start error: {str(e)}'}
    
    async def start_socks_server(self, node_id: int, interface: str, port: int = None) -> Dict:
        """Start SOCKS server bound to PPTP interface"""
        try:
            if port is None:
                port = 1080 + node_id  # Dynamic port assignment
            
            # Get interface IP
            interface_ip = await self._get_interface_ip(interface)
            if not interface_ip:
                return {'success': False, 'message': f'Cannot get IP for interface {interface}'}
            
            # Create SOCKS config for dante
            config_file = SOCKS_CONFIG_DIR / f"connexa-{node_id}.conf"
            config_content = f"""logoutput: /var/log/connexa/socks-{node_id}.log
internal: {interface_ip} port = {port}
external: {interface}
clientmethod: none
socksmethod: none
user.privileged: proxy
user.unprivileged: nobody

client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}}

socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: error connect disconnect
}}
"""
            
            with open(config_file, 'w') as f:
                f.write(config_content)
            
            # Start SOCKS server
            cmd = ["danted", "-f", str(config_file)]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for server to start
            await asyncio.sleep(2)
            
            # Test if SOCKS server is listening
            listening = await self._check_port_listening(port)
            if listening:
                if node_id in self.active_connections:
                    self.active_connections[node_id]['socks'] = {
                        'port': port,
                        'process': process,
                        'ip': interface_ip
                    }
                return {'success': True, 'port': port, 'ip': interface_ip, 'message': 'SOCKS server started'}
            else:
                return {'success': False, 'message': 'SOCKS server failed to start'}
                
        except Exception as e:
            return {'success': False, 'message': f'SOCKS start error: {str(e)}'}
    
    async def stop_services(self, node_id: int) -> Dict:
        """Stop all services for a node"""
        try:
            results = {'pptp': False, 'socks': False}
            
            if node_id in self.active_connections:
                conn = self.active_connections[node_id]
                
                # Stop SOCKS if running
                if 'socks' in conn:
                    try:
                        conn['socks']['process'].terminate()
                        await conn['socks']['process'].wait()
                        results['socks'] = True
                    except:
                        pass
                
                # Stop PPTP
                try:
                    conn['process'].terminate()
                    await conn['process'].wait()
                    
                    # Kill pppd if still running
                    await asyncio.create_subprocess_exec(
                        "pkill", "-f", f"connexa-{node_id}"
                    )
                    results['pptp'] = True
                except:
                    pass
                
                # Clean up
                del self.active_connections[node_id]
            
            # Remove config files
            try:
                (PPTP_CONFIG_DIR / f"connexa-{node_id}").unlink(missing_ok=True)
                (SOCKS_CONFIG_DIR / f"connexa-{node_id}.conf").unlink(missing_ok=True)
            except:
                pass
            
            return {
                'success': True,
                'stopped': results,
                'message': f'Services stopped for node {node_id}'
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Stop error: {str(e)}'}
    
    async def get_service_status(self, node_id: int) -> Dict:
        """Get status of services for a node"""
        if node_id not in self.active_connections:
            return {'active': False, 'services': []}
        
        conn = self.active_connections[node_id]
        services = ['pptp']
        
        if 'socks' in conn:
            services.append('socks')
        
        return {
            'active': True,
            'services': services,
            'interface': conn.get('interface'),
            'socks_port': conn.get('socks', {}).get('port'),
            'socks_ip': conn.get('socks', {}).get('ip'),
            'uptime': time.time() - conn.get('started_at', 0)
        }
    
    async def _get_ppp_interface(self, node_id: int) -> Optional[str]:
        """Find PPP interface for connection"""
        try:
            # Check for ppp interfaces
            result = await asyncio.create_subprocess_exec(
                "ip", "link", "show", "type", "ppp",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Parse output to find our interface
            for line in stdout.decode().split('\n'):
                if f"connexa-{node_id}" in line or "ppp" in line:
                    match = re.search(r'(ppp\d+):', line)
                    if match:
                        return match.group(1)
            
            return None
        except:
            return None
    
    async def _get_interface_ip(self, interface: str) -> Optional[str]:
        """Get IP address of interface"""
        try:
            result = await asyncio.create_subprocess_exec(
                "ip", "addr", "show", interface,
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            # Parse IP from output
            for line in stdout.decode().split('\n'):
                if 'inet ' in line and not '127.0.0.1' in line:
                    match = re.search(r'inet ([\d.]+)', line)
                    if match:
                        return match.group(1)
            
            return None
        except:
            return None
    
    async def _check_port_listening(self, port: int) -> bool:
        """Check if port is listening"""
        try:
            result = await asyncio.create_subprocess_exec(
                "netstat", "-tlnp",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            
            return f":{port} " in stdout.decode()
        except:
            return False

class NetworkTester:
    """Network testing utilities"""
    
    @staticmethod
    async def ping_test(ip: str, count: int = 4) -> Dict:
        """Ping test with latency measurement"""
        try:
            result = await asyncio.create_subprocess_exec(
                "ping", "-c", str(count), "-W", "3", ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                output = stdout.decode()
                
                # Parse ping results
                packet_loss = 100
                avg_latency = 0
                
                # Extract packet loss
                loss_match = re.search(r'(\d+)% packet loss', output)
                if loss_match:
                    packet_loss = int(loss_match.group(1))
                
                # Extract average latency
                latency_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+', output)
                if latency_match:
                    avg_latency = float(latency_match.group(1))
                
                return {
                    'success': True,
                    'reachable': packet_loss < 100,
                    'packet_loss': packet_loss,
                    'avg_latency': avg_latency,
                    'details': output
                }
            else:
                return {
                    'success': False,
                    'reachable': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'success': False,
                'reachable': False,
                'error': str(e)
            }
    
    @staticmethod
    async def speed_test(interface: str = None) -> Dict:
        """Speed test using speedtest-cli"""
        try:
            cmd = ["speedtest-cli", "--json"]
            if interface:
                # Bind to specific interface if provided
                cmd.extend(["--source", interface])
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0:
                data = json.loads(stdout.decode())
                
                return {
                    'success': True,
                    'download': round(data['download'] / 1000000, 2),  # Mbps
                    'upload': round(data['upload'] / 1000000, 2),      # Mbps
                    'ping': data['ping'],
                    'server': data['server']['name'],
                    'details': data
                }
            else:
                return {
                    'success': False,
                    'error': stderr.decode()
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    @staticmethod
    async def combined_test(ip: str, interface: str = None, test_type: str = "both") -> Dict:
        """Combined network test"""
        results = {'ip': ip, 'test_type': test_type}
        
        if test_type in ['ping', 'both']:
            ping_result = await NetworkTester.ping_test(ip)
            results['ping'] = ping_result
        
        if test_type in ['speed', 'both'] and interface:
            speed_result = await NetworkTester.speed_test(interface)
            results['speed'] = speed_result
        
        # Overall assessment
        if test_type == 'ping':
            results['overall'] = 'online' if results['ping']['reachable'] else 'offline'
        elif test_type == 'speed':
            results['overall'] = 'online' if results['speed']['success'] else 'offline'
        else:  # both
            ping_ok = results.get('ping', {}).get('reachable', False)
            speed_ok = results.get('speed', {}).get('success', False)
            
            if ping_ok and speed_ok:
                results['overall'] = 'online'
            elif ping_ok:
                results['overall'] = 'degraded'
            else:
                results['overall'] = 'offline'
        
        return results
    
    async def enrich_node_complete(self, node, db_session):
        """Обогатить узел fraud и geo данными"""
        try:
            from service_manager_geo import service_manager as geo_manager
            return await geo_manager.enrich_node_complete(node, db_session)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"enrich_node_complete error: {e}")
            return False

# Global instances
service_manager = ServiceManager()
network_tester = NetworkTester()
