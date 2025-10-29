#!/bin/bash

# Фикс 1: load_dotenv в server.py
cd backend
if ! grep -q "load_dotenv()" server.py; then
    sed -i '17a from dotenv import load_dotenv\nload_dotenv()' server.py
    echo "✅ load_dotenv добавлен"
fi

# Фикс 2: AuthContext двойной /api
cd ../frontend/src/contexts
if ! grep -q "endsWith" AuthContext.js; then
    sed -i "s|const API = \`\${BACKEND_URL}/api\`;|const API = BACKEND_URL.endsWith('/api') ? BACKEND_URL : \`\${BACKEND_URL}/api\`;|" AuthContext.js
    echo "✅ AuthContext исправлен"
fi

# Фикс 3: Добавить enrich_node_complete в services.py
cd /tmp/upgrate_final/backend
if ! grep -q "enrich_node_complete" services.py; then
    cat >> services.py << 'SERVICEFIX'

    async def enrich_node_complete(self, node, db_session):
        """Обогатить узел fraud и geo данными"""
        try:
            from service_manager_geo import service_manager as geo_manager
            return await geo_manager.enrich_node_complete(node, db_session)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"enrich_node_complete error: {e}")
            return False
SERVICEFIX
    echo "✅ enrich_node_complete добавлен в services.py"
fi

echo "✅ Все фиксы применены"
