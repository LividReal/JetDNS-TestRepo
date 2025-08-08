"""
JetDNS REST API Server
Umfassende REST API für externe Integration und Management
"""

import asyncio
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from functools import wraps

from aiohttp import web, WSMsgType
from aiohttp.web_middlewares import cors_handler
from aiohttp_cors import setup as cors_setup, ResourceOptions
import aiohttp_swagger

logger = logging.getLogger(__name__)

class APIServer:
    """REST API Server für JetDNS"""

    def __init__(self, config_manager, dns_server, client_manager=None, 
                 analytics_manager=None, dhcp_server=None):
        self.config_manager = config_manager
        self.dns_server = dns_server
        self.client_manager = client_manager
        self.analytics_manager = analytics_manager
        self.dhcp_server = dhcp_server

        self.config = {}
        self.app = None
        self.site = None

        # API Keys Management
        self.api_keys: Dict[str, Dict] = {}

        # WebSocket connections
        self.websocket_connections: List[web.WebSocketResponse] = []

        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}

    async def initialize(self):
        """Initialisiert API Server"""
        await self._load_config()

        if not self.config.get('enabled', True):
            logger.info("API Server deaktiviert")
            return

        await self._setup_app()
        await self._load_api_keys()

        logger.info("🔧 API Server initialisiert")

    async def _load_config(self):
        """Lädt API Konfiguration"""
        self.config = self.config_manager.get_config('api')

    async def _setup_app(self):
        """Richtet aiohttp App ein"""
        self.app = web.Application(middlewares=[
            self._auth_middleware,
            self._rate_limit_middleware,
            self._logging_middleware
        ])

        # CORS Setup
        cors_config = self.config.get('cors', {})
        if cors_config.get('enabled', True):
            cors = cors_setup(self.app, defaults={
                "*": ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                    allow_methods=cors_config.get('methods', ['GET', 'POST', 'PUT', 'DELETE'])
                )
            })

            # Add CORS to all routes
            for route in self.app.router.routes():
                cors.add(route)

        # Routes Setup
        await self._setup_routes()

        # Swagger Documentation
        if self.config.get('documentation', {}).get('enabled', True):
            aiohttp_swagger.setup_swagger(
                self.app,
                swagger_url="/api/docs",
                ui_version=3
            )

    async def _setup_routes(self):
        """Richtet API Routes ein"""

        # System Routes
        self.app.router.add_get('/api/status', self.get_system_status)
        self.app.router.add_get('/api/health', self.health_check)
        self.app.router.add_post('/api/restart', self.restart_service)

        # Configuration Routes
        self.app.router.add_get('/api/config', self.get_config)
        self.app.router.add_put('/api/config', self.update_config)
        self.app.router.add_post('/api/config/reset', self.reset_config)
        self.app.router.add_post('/api/config/backup', self.create_backup)

        # DNS Routes
        self.app.router.add_get('/api/dns/queries', self.get_recent_queries)
        self.app.router.add_get('/api/dns/stats', self.get_dns_stats)
        self.app.router.add_post('/api/dns/query', self.manual_dns_query)
        self.app.router.add_get('/api/dns/cache', self.get_cache_stats)
        self.app.router.add_delete('/api/dns/cache', self.clear_cache)

        # Client Management Routes
        if self.client_manager:
            self.app.router.add_get('/api/clients', self.get_clients)
            self.app.router.add_get('/api/clients/{ip}', self.get_client)
            self.app.router.add_put('/api/clients/{ip}', self.update_client)
            self.app.router.add_delete('/api/clients/{ip}', self.delete_client)
            self.app.router.add_get('/api/groups', self.get_groups)
            self.app.router.add_post('/api/groups', self.create_group)
            self.app.router.add_put('/api/groups/{group_id}', self.update_group)
            self.app.router.add_delete('/api/groups/{group_id}', self.delete_group)

        # Analytics Routes
        if self.analytics_manager:
            self.app.router.add_get('/api/analytics/dashboard', self.get_dashboard_analytics)
            self.app.router.add_get('/api/analytics/timeseries', self.get_timeseries_data)
            self.app.router.add_get('/api/analytics/clients/{ip}/report', self.get_client_report)
            self.app.router.add_get('/api/analytics/export', self.export_analytics_data)

        # DHCP Routes
        if self.dhcp_server:
            self.app.router.add_get('/api/dhcp/leases', self.get_dhcp_leases)
            self.app.router.add_get('/api/dhcp/stats', self.get_dhcp_stats)
            self.app.router.add_post('/api/dhcp/reservation', self.create_dhcp_reservation)

        # Blocklist Routes
        self.app.router.add_get('/api/blocklists', self.get_blocklists)
        self.app.router.add_post('/api/blocklists', self.add_blocklist)
        self.app.router.add_delete('/api/blocklists/{list_id}', self.remove_blocklist)
        self.app.router.add_post('/api/blocklists/update', self.update_blocklists)

        # DNS Rewrite Routes
        self.app.router.add_get('/api/rewrites', self.get_dns_rewrites)
        self.app.router.add_post('/api/rewrites', self.add_dns_rewrite)
        self.app.router.add_put('/api/rewrites/{rule_id}', self.update_dns_rewrite)
        self.app.router.add_delete('/api/rewrites/{rule_id}', self.delete_dns_rewrite)

        # WebSocket for real-time updates
        self.app.router.add_get('/api/ws', self.websocket_handler)

    async def _load_api_keys(self):
        """Lädt API Keys"""
        api_keys_config = self.config.get('authentication', {}).get('api_keys', {})

        for key_name, key_data in api_keys_config.items():
            self.api_keys[key_data] = {
                'name': key_name,
                'permissions': ['*'],  # Default: alle Permissions
                'created_at': datetime.now().isoformat()
            }

        # Erstelle Master-Key falls keiner existiert
        if not self.api_keys:
            master_key = secrets.token_urlsafe(32)
            self.api_keys[master_key] = {
                'name': 'master',
                'permissions': ['*'],
                'created_at': datetime.now().isoformat()
            }

            # Speichere in Konfiguration
            self.config_manager.set_value(
                'api', 'authentication', 
                {'api_keys': {'master': master_key}}
            )

            logger.warning(f"🔑 Master API Key erstellt: {master_key}")

    # Middleware
    async def _auth_middleware(self, request, handler):
        """Authentication Middleware"""

        # Öffentliche Endpoints
        public_endpoints = ['/api/health', '/api/docs']

        if any(request.path.startswith(ep) for ep in public_endpoints):
            return await handler(request)

        # API Key Authentication
        auth_method = self.config.get('authentication', {}).get('method', 'api_key')

        if auth_method == 'api_key':
            api_key = request.headers.get('X-API-Key') or request.query.get('api_key')

            if not api_key or api_key not in self.api_keys:
                return web.json_response(
                    {'error': 'Invalid or missing API key'}, 
                    status=401
                )

            # Füge Key-Info zu Request hinzu
            request['api_key_info'] = self.api_keys[api_key]

        return await handler(request)

    async def _rate_limit_middleware(self, request, handler):
        """Rate Limiting Middleware"""

        if not self.config.get('rate_limiting', {}).get('enabled', True):
            return await handler(request)

        client_ip = request.remote
        now = datetime.now()
        requests_per_minute = self.config.get('rate_limiting', {}).get('requests_per_minute', 60)

        # Bereinige alte Einträge
        if client_ip in self.rate_limits:
            self.rate_limits[client_ip] = [
                req_time for req_time in self.rate_limits[client_ip]
                if now - req_time < timedelta(minutes=1)
            ]
        else:
            self.rate_limits[client_ip] = []

        # Prüfe Limit
        if len(self.rate_limits[client_ip]) >= requests_per_minute:
            return web.json_response(
                {'error': 'Rate limit exceeded'}, 
                status=429
            )

        # Füge Request hinzu
        self.rate_limits[client_ip].append(now)

        return await handler(request)

    async def _logging_middleware(self, request, handler):
        """Request Logging Middleware"""
        start_time = datetime.now()

        try:
            response = await handler(request)

            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"API {request.method} {request.path} - {response.status} - {duration:.3f}s")

            return response

        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"API {request.method} {request.path} - ERROR - {duration:.3f}s: {e}")
            raise

    # API Endpoints
    async def health_check(self, request):
        """Health Check Endpoint"""
        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': self.config_manager.get_value('general', 'version', '1.0.0')
        })

    async def get_system_status(self, request):
        """System Status Endpoint"""
        try:
            # DNS Server Status
            dns_status = {
                'running': self.dns_server.running if self.dns_server else False,
                'queries_total': getattr(self.dns_server, 'stats', {}).get('queries_total', 0),
                'queries_per_second': 0,  # Würde aus Stats berechnet
                'cache_hit_rate': 0,      # Würde aus Cache Manager geholt
                'blocked_queries': getattr(self.dns_server, 'stats', {}).get('queries_blocked', 0)
            }

            # System Resources (vereinfacht)
            system_status = {
                'uptime': '00:00:00',  # Würde berechnet
                'memory_usage': 0,     # Würde aus psutil geholt
                'cpu_usage': 0         # Würde aus psutil geholt
            }

            # Client Manager Status
            client_status = {}
            if self.client_manager:
                all_clients = await self.client_manager.get_all_clients()
                client_status = {
                    'total_clients': len(all_clients),
                    'active_clients': len([c for c in all_clients if c.get('status') == 'active'])
                }

            # DHCP Status
            dhcp_status = {}
            if self.dhcp_server:
                dhcp_status = await self.dhcp_server.get_dhcp_stats()

            return web.json_response({
                'timestamp': datetime.now().isoformat(),
                'dns': dns_status,
                'system': system_status,
                'clients': client_status,
                'dhcp': dhcp_status
            })

        except Exception as e:
            logger.error(f"Fehler bei System Status: {e}")
            return web.json_response(
                {'error': str(e)}, 
                status=500
            )

    async def get_config(self, request):
        """Configuration Endpoint"""
        try:
            section = request.query.get('section')

            if section:
                config = self.config_manager.get_config(section)
            else:
                config = self.config_manager.get_config()

            return web.json_response(config)

        except Exception as e:
            return web.json_response(
                {'error': str(e)}, 
                status=500
            )

    async def update_config(self, request):
        """Configuration Update Endpoint"""
        try:
            data = await request.json()

            self.config_manager.update_config(data)

            return web.json_response({
                'success': True,
                'message': 'Configuration updated successfully'
            })

        except Exception as e:
            return web.json_response(
                {'error': str(e)}, 
                status=400
            )

    async def get_clients(self, request):
        """Clients List Endpoint"""
        if not self.client_manager:
            return web.json_response(
                {'error': 'Client Manager not available'}, 
                status=503
            )

        try:
            clients = await self.client_manager.get_all_clients()
            return web.json_response(clients)

        except Exception as e:
            return web.json_response(
                {'error': str(e)}, 
                status=500
            )

    async def get_client(self, request):
        """Single Client Endpoint"""
        if not self.client_manager:
            return web.json_response(
                {'error': 'Client Manager not available'}, 
                status=503
            )

        try:
            client_ip = request.match_info['ip']
            settings = await self.client_manager.get_client_settings(client_ip)

            return web.json_response(settings)

        except Exception as e:
            return web.json_response(
                {'error': str(e)}, 
                status=500
            )

    async def get_dashboard_analytics(self, request):
        """Dashboard Analytics Endpoint"""
        if not self.analytics_manager:
            return web.json_response(
                {'error': 'Analytics Manager not available'}, 
                status=503
            )

        try:
            stats = await self.analytics_manager.get_dashboard_stats()
            return web.json_response(stats)

        except Exception as e:
            return web.json_response(
                {'error': str(e)}, 
                status=500
            )

    async def websocket_handler(self, request):
        """WebSocket Handler für Real-time Updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self.websocket_connections.append(ws)
        logger.info(f"WebSocket Client verbunden: {request.remote}")

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_websocket_message(ws, data)
                    except json.JSONDecodeError:
                        await ws.send_str(json.dumps({
                            'error': 'Invalid JSON'
                        }))
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f'WebSocket error: {ws.exception()}')

        except Exception as e:
            logger.error(f"WebSocket Fehler: {e}")
        finally:
            if ws in self.websocket_connections:
                self.websocket_connections.remove(ws)
            logger.info(f"WebSocket Client getrennt: {request.remote}")

        return ws

    async def _handle_websocket_message(self, ws, data):
        """Behandelt WebSocket Nachrichten"""
        message_type = data.get('type')

        if message_type == 'subscribe':
            # Subscribe to real-time updates
            await ws.send_str(json.dumps({
                'type': 'subscribed',
                'message': 'Subscribed to real-time updates'
            }))
        elif message_type == 'get_status':
            # Send current status
            status = await self._get_realtime_status()
            await ws.send_str(json.dumps({
                'type': 'status',
                'data': status
            }))

    async def _get_realtime_status(self):
        """Holt aktuellen Status für WebSocket"""
        try:
            status = {}

            if self.analytics_manager:
                status['analytics'] = await self.analytics_manager.get_dashboard_stats()

            if self.dns_server and hasattr(self.dns_server, 'stats'):
                status['dns'] = self.dns_server.stats

            return status

        except Exception as e:
            logger.error(f"Fehler bei Real-time Status: {e}")
            return {'error': str(e)}

    async def broadcast_update(self, update_type: str, data: Dict):
        """Sendet Update an alle WebSocket Clients"""
        if not self.websocket_connections:
            return

        message = {
            'type': 'update',
            'update_type': update_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        }

        disconnected = []

        for ws in self.websocket_connections:
            try:
                await ws.send_str(json.dumps(message))
            except Exception as e:
                logger.debug(f"WebSocket Client disconnected: {e}")
                disconnected.append(ws)

        # Entferne disconnected clients
        for ws in disconnected:
            if ws in self.websocket_connections:
                self.websocket_connections.remove(ws)

    # Placeholder für weitere Endpoints
    async def restart_service(self, request):
        return web.json_response({'error': 'Not implemented'}, status=501)

    async def get_recent_queries(self, request):
        return web.json_response({'error': 'Not implemented'}, status=501)

    async def get_dns_stats(self, request):
        return web.json_response({'error': 'Not implemented'}, status=501)

    # ... weitere Placeholder-Endpoints

    async def start(self):
        """Startet API Server"""
        if not self.config.get('enabled', True):
            return

        try:
            host = self.config.get('host', '0.0.0.0')
            port = self.config.get('port', 8080)

            runner = web.AppRunner(self.app)
            await runner.setup()

            self.site = web.TCPSite(runner, host, port)
            await self.site.start()

            logger.info(f"🌐 API Server gestartet auf {host}:{port}")

        except Exception as e:
            logger.error(f"Fehler beim Starten des API Servers: {e}")
            raise

    async def stop(self):
        """Stoppt API Server"""
        if self.site:
            await self.site.stop()

        # Schließe WebSocket Verbindungen
        for ws in self.websocket_connections:
            try:
                await ws.close()
            except:
                pass

        logger.info("🌐 API Server gestoppt")
