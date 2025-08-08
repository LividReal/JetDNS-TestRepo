"""
Advanced Web Interface - Modern Dashboard like AdGuard Home/OpenDNS
Real-time statistics, threat monitoring, and comprehensive management
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
from pathlib import Path

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import hashlib
import jwt
from functools import wraps


class WebInterfaceManager:
    """Advanced web interface with real-time features"""

    def __init__(self, config: dict, dns_server=None, statistics=None, 
                 ad_blocker=None, threat_intelligence=None, content_filter=None):
        self.config = config
        self.dns_server = dns_server
        self.statistics = statistics
        self.ad_blocker = ad_blocker
        self.threat_intelligence = threat_intelligence
        self.content_filter = content_filter
        self.logger = logging.getLogger(__name__)

        # Web server configuration
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 8080)
        self.secret_key = config.get('secret_key', 'change-this-secret-key')
        self.debug = config.get('debug', False)

        # Authentication
        self.auth_enabled = config.get('auth_enabled', True)
        self.session_timeout = config.get('session_timeout', 3600)

        # Initialize Flask app
        self.app = Flask(__name__, 
                        template_folder='../web/templates',
                        static_folder='../web/static')
        self.app.secret_key = self.secret_key

        # Initialize SocketIO
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')

        # Enable CORS
        CORS(self.app)

        # Connected clients for real-time updates
        self.connected_clients = set()

        # Background tasks
        self.stats_broadcaster = None

        # Initialize database for users and settings
        self.db_path = 'data/web_interface.db'

        self._setup_routes()
        self._setup_socket_events()

    async def initialize(self):
        """Initialize web interface"""
        try:
            # Create database
            await self._initialize_database()

            # Create default admin user if not exists
            await self._create_default_user()

            # Start background tasks
            self.stats_broadcaster = asyncio.create_task(self._broadcast_stats_loop())

            self.logger.info("🖥️  Web Interface initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize web interface: {e}")
            raise

    async def start(self):
        """Start web server"""
        try:
            # Run SocketIO server
            self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=self.debug,
                use_reloader=False,
                allow_unsafe_werkzeug=True
            )

        except Exception as e:
            self.logger.error(f"Failed to start web interface: {e}")
            raise

    def _setup_routes(self):
        """Setup Flask routes"""

        # Authentication decorator
        def login_required(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if self.auth_enabled:
                    if 'user_id' not in session:
                        return redirect(url_for('login'))

                    # Check session timeout
                    if 'login_time' in session:
                        if time.time() - session['login_time'] > self.session_timeout:
                            session.clear()
                            flash('Session expired. Please login again.', 'warning')
                            return redirect(url_for('login'))

                return f(*args, **kwargs)
            return decorated_function

        # API authentication decorator
        def api_auth_required(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if self.auth_enabled:
                    # Check session or API key
                    if 'user_id' not in session:
                        auth_header = request.headers.get('Authorization')
                        if not auth_header or not auth_header.startswith('Bearer '):
                            return jsonify({'error': 'Authentication required'}), 401

                        token = auth_header.split(' ')[1]
                        if not self._verify_api_token(token):
                            return jsonify({'error': 'Invalid token'}), 401

                return f(*args, **kwargs)
            return decorated_function

        # Main routes
        @self.app.route('/')
        @login_required
        def dashboard():
            """Main dashboard"""
            return render_template('dashboard.html', 
                                 config=self.config,
                                 user=session.get('username', 'admin'))

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Login page"""
            if not self.auth_enabled:
                return redirect(url_for('dashboard'))

            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')

                if self._verify_user(username, password):
                    session['user_id'] = username
                    session['username'] = username
                    session['login_time'] = time.time()
                    flash(f'Welcome back, {username}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password', 'error')

            return render_template('login.html')

        @self.app.route('/logout')
        def logout():
            """Logout"""
            session.clear()
            flash('Logged out successfully', 'info')
            return redirect(url_for('login'))

        @self.app.route('/settings')
        @login_required
        def settings():
            """Settings page"""
            return render_template('settings.html', config=self.config)

        @self.app.route('/network')
        @login_required
        def network():
            """Network overview"""
            return render_template('network.html')

        @self.app.route('/security')
        @login_required
        def security():
            """Security overview"""
            return render_template('security.html')

        @self.app.route('/logs')
        @login_required
        def logs():
            """Query logs"""
            return render_template('logs.html')

        @self.app.route('/blocklists')
        @login_required
        def blocklists():
            """Blocklist management"""
            return render_template('blocklists.html')

        # API Routes
        @self.app.route('/api/stats')
        @api_auth_required
        def api_stats():
            """Get current statistics"""
            return jsonify(self._get_current_stats())

        @self.app.route('/api/recent_queries')
        @api_auth_required
        def api_recent_queries():
            """Get recent DNS queries"""
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self._get_recent_queries(limit))

        @self.app.route('/api/top_domains')
        @api_auth_required
        def api_top_domains():
            """Get top queried domains"""
            limit = request.args.get('limit', 20, type=int)
            return jsonify(self._get_top_domains(limit))

        @self.app.route('/api/top_blocked')
        @api_auth_required
        def api_top_blocked():
            """Get top blocked domains"""
            limit = request.args.get('limit', 20, type=int)
            return jsonify(self._get_top_blocked(limit))

        @self.app.route('/api/threat_timeline')
        @api_auth_required
        def api_threat_timeline():
            """Get threat detection timeline"""
            hours = request.args.get('hours', 24, type=int)
            return jsonify(self._get_threat_timeline(hours))

        @self.app.route('/api/network_topology')
        @api_auth_required
        def api_network_topology():
            """Get network topology data"""
            return jsonify(self._get_network_topology())

        @self.app.route('/api/performance_metrics')
        @api_auth_required
        def api_performance_metrics():
            """Get performance metrics"""
            return jsonify(self._get_performance_metrics())

        @self.app.route('/api/security_score')
        @api_auth_required
        def api_security_score():
            """Get overall security score"""
            return jsonify(self._calculate_security_score())

        @self.app.route('/api/settings', methods=['GET', 'POST'])
        @api_auth_required
        def api_settings():
            """Get/Update settings"""
            if request.method == 'GET':
                return jsonify(self._get_settings())
            elif request.method == 'POST':
                settings = request.json
                success = self._update_settings(settings)
                return jsonify({'success': success})

        @self.app.route('/api/blocklist', methods=['POST', 'DELETE'])
        @api_auth_required
        def api_blocklist():
            """Manage blocklist entries"""
            if request.method == 'POST':
                domain = request.json.get('domain')
                success = self._add_to_blocklist(domain)
                return jsonify({'success': success})
            elif request.method == 'DELETE':
                domain = request.json.get('domain')
                success = self._remove_from_blocklist(domain)
                return jsonify({'success': success})

        @self.app.route('/api/whitelist', methods=['POST', 'DELETE'])
        @api_auth_required
        def api_whitelist():
            """Manage whitelist entries"""
            if request.method == 'POST':
                domain = request.json.get('domain')
                success = self._add_to_whitelist(domain)
                return jsonify({'success': success})
            elif request.method == 'DELETE':
                domain = request.json.get('domain')
                success = self._remove_from_whitelist(domain)
                return jsonify({'success': success})

        @self.app.route('/api/flush_cache', methods=['POST'])
        @api_auth_required
        def api_flush_cache():
            """Flush DNS cache"""
            success = self._flush_dns_cache()
            return jsonify({'success': success})

        @self.app.route('/api/test_query', methods=['POST'])
        @api_auth_required
        def api_test_query():
            """Test DNS query"""
            domain = request.json.get('domain')
            result = self._test_dns_query(domain)
            return jsonify(result)

        # Error handlers
        @self.app.errorhandler(404)
        def not_found(error):
            return render_template('error.html', 
                                 error_code=404, 
                                 error_message="Page not found"), 404

        @self.app.errorhandler(500)
        def internal_error(error):
            return render_template('error.html',
                                 error_code=500,
                                 error_message="Internal server error"), 500

    def _setup_socket_events(self):
        """Setup SocketIO events for real-time updates"""

        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            client_id = request.sid
            self.connected_clients.add(client_id)
            self.logger.debug(f"Client connected: {client_id}")

            # Send initial data
            emit('stats_update', self._get_current_stats())

            join_room('stats_room')

        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            client_id = request.sid
            self.connected_clients.discard(client_id)
            self.logger.debug(f"Client disconnected: {client_id}")

            leave_room('stats_room')

        @self.socketio.on('subscribe_logs')
        def handle_subscribe_logs():
            """Subscribe to real-time logs"""
            join_room('logs_room')
            self.logger.debug("Client subscribed to logs")

        @self.socketio.on('unsubscribe_logs')
        def handle_unsubscribe_logs():
            """Unsubscribe from real-time logs"""
            leave_room('logs_room')
            self.logger.debug("Client unsubscribed from logs")

        @self.socketio.on('get_query_details')
        def handle_query_details(data):
            """Get detailed information about a specific query"""
            query_id = data.get('query_id')
            details = self._get_query_details(query_id)
            emit('query_details', details)

    def _get_current_stats(self) -> Dict[str, Any]:
        """Get current DNS server statistics"""
        stats = {
            'queries_total': 0,
            'queries_blocked': 0,
            'queries_cached': 0,
            'queries_forwarded': 0,
            'active_connections': 0,
            'uptime': 0,
            'response_time_avg': 0,
            'cache_hit_rate': 0,
            'block_rate': 0,
            'threats_blocked_today': 0,
            'unique_clients': 0,
            'top_threat_categories': []
        }

        try:
            if self.dns_server:
                dns_stats = self.dns_server.get_stats()
                stats.update(dns_stats)

            if self.statistics:
                analytics = self.statistics.get_analytics()
                stats.update(analytics)

            # Add threat intelligence stats
            if self.threat_intelligence:
                stats['threats_blocked_today'] = self._get_threats_blocked_today()
                stats['top_threat_categories'] = self._get_top_threat_categories()

        except Exception as e:
            self.logger.error(f"Error getting current stats: {e}")

        return stats

    def _get_recent_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent DNS queries"""
        queries = []

        try:
            if self.statistics:
                queries = self.statistics.get_recent_queries(limit)
        except Exception as e:
            self.logger.error(f"Error getting recent queries: {e}")

        return queries

    def _get_top_domains(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top queried domains"""
        domains = []

        try:
            if self.statistics:
                domains = self.statistics.get_top_domains(limit)
        except Exception as e:
            self.logger.error(f"Error getting top domains: {e}")

        return domains

    def _get_top_blocked(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top blocked domains"""
        blocked = []

        try:
            if self.statistics:
                blocked = self.statistics.get_top_blocked(limit)
        except Exception as e:
            self.logger.error(f"Error getting top blocked: {e}")

        return blocked

    def _get_threat_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get threat detection timeline"""
        timeline = []

        try:
            if self.statistics:
                timeline = self.statistics.get_threat_timeline(hours)
        except Exception as e:
            self.logger.error(f"Error getting threat timeline: {e}")

        return timeline

    def _get_network_topology(self) -> Dict[str, Any]:
        """Get network topology data"""
        topology = {
            'nodes': [],
            'links': [],
            'subnets': []
        }

        try:
            if self.statistics:
                topology = self.statistics.get_network_topology()
        except Exception as e:
            self.logger.error(f"Error getting network topology: {e}")

        return topology

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        metrics = {
            'cpu_usage': 0,
            'memory_usage': 0,
            'disk_usage': 0,
            'network_io': {'bytes_sent': 0, 'bytes_recv': 0},
            'response_times': []
        }

        try:
            import psutil

            # CPU usage
            metrics['cpu_usage'] = psutil.cpu_percent()

            # Memory usage
            memory = psutil.virtual_memory()
            metrics['memory_usage'] = memory.percent

            # Disk usage
            disk = psutil.disk_usage('/')
            metrics['disk_usage'] = (disk.used / disk.total) * 100

            # Network I/O
            net_io = psutil.net_io_counters()
            metrics['network_io'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv
            }

            # DNS server specific metrics
            if self.dns_server:
                dns_stats = self.dns_server.get_stats()
                metrics['response_times'] = dns_stats.get('response_times', [])

        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")

        return metrics

    def _calculate_security_score(self) -> Dict[str, Any]:
        """Calculate overall security score"""
        score_data = {
            'overall_score': 85,
            'components': {
                'threat_blocking': 90,
                'content_filtering': 85,
                'dns_security': 80,
                'network_protection': 88
            },
            'recent_threats': 0,
            'security_level': 'Good'
        }

        try:
            # Calculate based on actual metrics
            if self.statistics:
                threats_today = self._get_threats_blocked_today()
                total_queries = self.statistics.get_total_queries_today()

                if total_queries > 0:
                    threat_rate = (threats_today / total_queries) * 100

                    # Adjust score based on threat activity
                    if threat_rate < 1:
                        score_data['components']['threat_blocking'] = 95
                        score_data['security_level'] = 'Excellent'
                    elif threat_rate < 5:
                        score_data['components']['threat_blocking'] = 85
                        score_data['security_level'] = 'Good'
                    else:
                        score_data['components']['threat_blocking'] = 70
                        score_data['security_level'] = 'Fair'

                score_data['recent_threats'] = threats_today

            # Calculate overall score
            components = score_data['components']
            overall = sum(components.values()) / len(components)
            score_data['overall_score'] = int(overall)

        except Exception as e:
            self.logger.error(f"Error calculating security score: {e}")

        return score_data

    def _get_threats_blocked_today(self) -> int:
        """Get number of threats blocked today"""
        try:
            if self.statistics:
                return self.statistics.get_threats_blocked_today()
        except Exception as e:
            self.logger.error(f"Error getting threats blocked today: {e}")
        return 0

    def _get_top_threat_categories(self) -> List[Dict[str, Any]]:
        """Get top threat categories"""
        categories = []

        try:
            if self.statistics:
                categories = self.statistics.get_top_threat_categories()
        except Exception as e:
            self.logger.error(f"Error getting threat categories: {e}")

        return categories

    def _get_settings(self) -> Dict[str, Any]:
        """Get current settings"""
        return self.config

    def _update_settings(self, settings: Dict[str, Any]) -> bool:
        """Update settings"""
        try:
            # Update configuration
            self.config.update(settings)

            # Save to database or file
            # Implementation depends on configuration storage method

            return True
        except Exception as e:
            self.logger.error(f"Error updating settings: {e}")
            return False

    def _add_to_blocklist(self, domain: str) -> bool:
        """Add domain to blocklist"""
        try:
            if self.ad_blocker:
                return self.ad_blocker.add_custom_block(domain)
        except Exception as e:
            self.logger.error(f"Error adding to blocklist: {e}")
        return False

    def _remove_from_blocklist(self, domain: str) -> bool:
        """Remove domain from blocklist"""
        try:
            if self.ad_blocker:
                return self.ad_blocker.remove_custom_block(domain)
        except Exception as e:
            self.logger.error(f"Error removing from blocklist: {e}")
        return False

    def _add_to_whitelist(self, domain: str) -> bool:
        """Add domain to whitelist"""
        try:
            if self.ad_blocker:
                return self.ad_blocker.add_custom_allow(domain)
        except Exception as e:
            self.logger.error(f"Error adding to whitelist: {e}")
        return False

    def _remove_from_whitelist(self, domain: str) -> bool:
        """Remove domain from whitelist"""
        try:
            if self.ad_blocker:
                return self.ad_blocker.remove_custom_allow(domain)
        except Exception as e:
            self.logger.error(f"Error removing from whitelist: {e}")
        return False

    def _flush_dns_cache(self) -> bool:
        """Flush DNS cache"""
        try:
            if self.dns_server and hasattr(self.dns_server, 'cache_manager'):
                return asyncio.run(self.dns_server.cache_manager.clear())
        except Exception as e:
            self.logger.error(f"Error flushing cache: {e}")
        return False

    def _test_dns_query(self, domain: str) -> Dict[str, Any]:
        """Test DNS query"""
        result = {
            'domain': domain,
            'success': False,
            'response_time': 0,
            'answers': [],
            'error': None
        }

        try:
            import dns.resolver
            start_time = time.time()

            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'A')

            result['success'] = True
            result['response_time'] = time.time() - start_time
            result['answers'] = [str(rdata) for rdata in answers]

        except Exception as e:
            result['error'] = str(e)

        return result

    def _get_query_details(self, query_id: str) -> Dict[str, Any]:
        """Get detailed information about a query"""
        details = {
            'query_id': query_id,
            'found': False
        }

        try:
            if self.statistics:
                details = self.statistics.get_query_details(query_id)
        except Exception as e:
            self.logger.error(f"Error getting query details: {e}")

        return details

    # User management
    async def _initialize_database(self):
        """Initialize SQLite database for users and settings"""
        try:
            # Create data directory
            os.makedirs('data', exist_ok=True)

            # Create database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_admin BOOLEAN DEFAULT 1
                )
            ''')

            # Create settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create API keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_hash TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise

    async def _create_default_user(self):
        """Create default admin user"""
        try:
            default_username = self.config.get('default_username', 'admin')
            default_password = self.config.get('default_password', 'admin123')

            # Hash password
            password_hash = hashlib.sha256(default_password.encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (default_username,))
            if not cursor.fetchone():
                # Create default user
                cursor.execute('''
                    INSERT INTO users (username, password_hash, is_admin)
                    VALUES (?, ?, 1)
                ''', (default_username, password_hash))

                conn.commit()
                self.logger.info(f"👤 Created default user: {default_username}")

            conn.close()

        except Exception as e:
            self.logger.error(f"Error creating default user: {e}")

    def _verify_user(self, username: str, password: str) -> bool:
        """Verify user credentials"""
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id FROM users 
                WHERE username = ? AND password_hash = ?
            ''', (username, password_hash))

            user = cursor.fetchone()

            if user:
                # Update last login
                cursor.execute('''
                    UPDATE users SET last_login = CURRENT_TIMESTAMP
                    WHERE username = ?
                ''', (username,))
                conn.commit()

            conn.close()
            return user is not None

        except Exception as e:
            self.logger.error(f"Error verifying user: {e}")
            return False

    def _verify_api_token(self, token: str) -> bool:
        """Verify API token"""
        try:
            # Simple token verification (in production, use JWT or similar)
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id FROM api_keys 
                WHERE key_hash = ? AND is_active = 1
            ''', (token_hash,))

            key = cursor.fetchone()

            if key:
                # Update last used
                cursor.execute('''
                    UPDATE api_keys SET last_used = CURRENT_TIMESTAMP
                    WHERE key_hash = ?
                ''', (token_hash,))
                conn.commit()

            conn.close()
            return key is not None

        except Exception as e:
            self.logger.error(f"Error verifying API token: {e}")
            return False

    # Real-time broadcasting
    async def _broadcast_stats_loop(self):
        """Background task to broadcast real-time statistics"""
        while True:
            try:
                if self.connected_clients:
                    stats = self._get_current_stats()
                    self.socketio.emit('stats_update', stats, room='stats_room')

                await asyncio.sleep(5)  # Broadcast every 5 seconds

            except Exception as e:
                self.logger.error(f"Stats broadcast error: {e}")
                await asyncio.sleep(10)

    def broadcast_query_log(self, query_data: Dict[str, Any]):
        """Broadcast new query log in real-time"""
        try:
            if self.connected_clients:
                self.socketio.emit('new_query', query_data, room='logs_room')
        except Exception as e:
            self.logger.error(f"Query broadcast error: {e}")

    def broadcast_threat_alert(self, threat_data: Dict[str, Any]):
        """Broadcast threat alert in real-time"""
        try:
            if self.connected_clients:
                self.socketio.emit('threat_alert', threat_data, room='stats_room')
        except Exception as e:
            self.logger.error(f"Threat broadcast error: {e}")

    async def stop(self):
        """Stop web interface"""
        try:
            if self.stats_broadcaster:
                self.stats_broadcaster.cancel()

            self.logger.info("🛑 Web Interface stopped")

        except Exception as e:
            self.logger.error(f"Error stopping web interface: {e}")
