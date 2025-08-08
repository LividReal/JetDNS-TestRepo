"""
JetDNS Web Interface
Flask-basierte Web-Anwendung für DNS-Server Management mit Authentifizierung
"""

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import redis
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit
import psutil
import subprocess
import configparser

from .dns_server import AdvancedDNSServer
from ..analytics.query_analyzer import QueryAnalyzer
from ..management.config_manager import ConfigManager

logger = logging.getLogger(__name__)

class UserManager:
    """Benutzer-Management für JetDNS"""

    def __init__(self, db_path='/var/lib/jetdns/users.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialisiert Benutzer-Datenbank"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        role TEXT DEFAULT 'admin',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_login DATETIME,
                        is_active BOOLEAN DEFAULT 1,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until DATETIME NULL
                    )
                ''')

                conn.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                        ip_address TEXT,
                        user_agent TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                conn.execute('''
                    CREATE TABLE IF NOT EXISTS setup_status (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                conn.commit()
                logger.info("Benutzer-Datenbank initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Initialisieren der Benutzer-DB: {e}")

    def _hash_password(self, password, salt=None):
        """Erstellt sicheren Password-Hash"""
        if salt is None:
            salt = secrets.token_hex(32)

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100.000 Iterationen
        ).hex()

        return password_hash, salt

    def create_user(self, username, email, password, role='admin'):
        """Erstellt neuen Benutzer"""
        try:
            password_hash, salt = self._hash_password(password)

            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT INTO users (username, email, password_hash, salt, role)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, salt, role))
                conn.commit()

            logger.info(f"Benutzer erstellt: {username} ({email})")
            return True

        except sqlite3.IntegrityError:
            logger.warning(f"Benutzer bereits vorhanden: {username} oder {email}")
            return False
        except Exception as e:
            logger.error(f"Fehler beim Erstellen des Benutzers: {e}")
            return False

    def verify_user(self, username_or_email, password):
        """Verifiziert Benutzer-Anmeldung"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT id, username, email, password_hash, salt, is_active, 
                           failed_login_attempts, locked_until
                    FROM users 
                    WHERE (username = ? OR email = ?) AND is_active = 1
                ''', (username_or_email, username_or_email))

                user = cursor.fetchone()
                if not user:
                    return None, "Benutzer nicht gefunden"

                user_id, username, email, stored_hash, salt, is_active, failed_attempts, locked_until = user

                # Account-Sperrung prüfen
                if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                    return None, "Account temporär gesperrt"

                # Passwort prüfen
                password_hash, _ = self._hash_password(password, salt)

                if password_hash == stored_hash:
                    # Erfolgreiche Anmeldung
                    conn.execute('''
                        UPDATE users 
                        SET last_login = CURRENT_TIMESTAMP, failed_login_attempts = 0, locked_until = NULL
                        WHERE id = ?
                    ''', (user_id,))
                    conn.commit()

                    return {
                        'id': user_id,
                        'username': username,
                        'email': email,
                        'role': 'admin'
                    }, None
                else:
                    # Fehlgeschlagene Anmeldung
                    failed_attempts += 1
                    locked_until_time = None

                    if failed_attempts >= 5:  # Nach 5 Versuchen sperren
                        locked_until_time = datetime.now() + timedelta(minutes=15)

                    conn.execute('''
                        UPDATE users 
                        SET failed_login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, locked_until_time, user_id))
                    conn.commit()

                    return None, "Ungültige Anmeldedaten"

        except Exception as e:
            logger.error(f"Fehler bei der Benutzer-Verifizierung: {e}")
            return None, "Systemfehler"

    def get_users(self):
        """Gibt alle Benutzer zurück"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT id, username, email, role, created_at, last_login, is_active
                    FROM users
                    ORDER BY created_at DESC
                ''')

                users = []
                for row in cursor.fetchall():
                    users.append({
                        'id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'role': row[3],
                        'created_at': row[4],
                        'last_login': row[5],
                        'is_active': bool(row[6])
                    })

                return users

        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Benutzer: {e}")
            return []

    def is_setup_completed(self):
        """Prüft ob Initial-Setup abgeschlossen ist"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute(
                    'SELECT value FROM setup_status WHERE key = ?',
                    ('setup_completed',)
                )
                result = cursor.fetchone()
                return result and result[0] == 'true'

        except Exception:
            return False

    def mark_setup_completed(self):
        """Markiert Setup als abgeschlossen"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO setup_status (key, value)
                    VALUES ('setup_completed', 'true')
                ''')
                conn.commit()

        except Exception as e:
            logger.error(f"Fehler beim Markieren des Setup-Status: {e}")


class JetDNSWebInterface:
    """Web Interface für JetDNS Management mit Authentifizierung"""

    def __init__(self, config_path='/etc/jetdns/jetdns.conf'):
        self.config_path = config_path
        self.app = Flask(__name__, 
                        template_folder='../../../web/templates',
                        static_folder='../../../web/static')

        # Sichere Session-Konfiguration
        self.app.config['SECRET_KEY'] = self._get_or_create_secret_key()
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
        self.app.config['SESSION_COOKIE_SECURE'] = False  # TODO: True für HTTPS
        self.app.config['SESSION_COOKIE_HTTPONLY'] = True
        self.app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        self.app.config['REALTIME_ENABLED'] = True

        # SocketIO für Real-time Updates
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")

        # Redis für Session Storage und Caching
        try:
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.redis_client.ping()
        except redis.ConnectionError:
            logger.error("Redis nicht verfügbar - Real-time Features deaktiviert")
            self.redis_client = None

        # Komponenten
        self.config_manager = ConfigManager(config_path)
        self.query_analyzer = QueryAnalyzer()
        self.user_manager = UserManager()
        self.dns_server = None

        self._setup_routes()
        self._setup_socketio_events()

        # Background Tasks
        self.stats_thread = None
        self.start_background_tasks()

    def _get_or_create_secret_key(self):
        """Erstellt oder lädt Secret Key für Sessions"""
        key_file = Path('/etc/jetdns/.secret_key')

        try:
            if key_file.exists():
                return key_file.read_text().strip()
            else:
                key = secrets.token_hex(32)
                key_file.parent.mkdir(parents=True, exist_ok=True)
                key_file.write_text(key)
                key_file.chmod(0o600)
                return key
        except Exception as e:
            logger.warning(f"Konnte Secret Key nicht laden/erstellen: {e}")
            return secrets.token_hex(32)

    def require_auth(self, f):
        """Decorator für authentifizierte Routen"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.user_manager.is_setup_completed():
                return redirect(url_for('setup'))

            if 'user_id' not in session:
                return redirect(url_for('login'))

            # Session-Validierung
            user_id = session.get('user_id')
            if not self._validate_session(user_id, session.get('session_token')):
                session.clear()
                return redirect(url_for('login'))

            return f(*args, **kwargs)
        return decorated_function

    def _validate_session(self, user_id, session_token):
        """Validiert aktive Session"""
        if not user_id or not session_token:
            return False

        try:
            with sqlite3.connect(str(self.user_manager.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT s.user_id, s.last_activity, u.is_active
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_id = ? AND s.user_id = ?
                ''', (session_token, user_id))

                result = cursor.fetchone()
                if not result:
                    return False

                _, last_activity, is_active = result

                if not is_active:
                    return False

                # Session-Timeout prüfen (8 Stunden)
                last_activity_dt = datetime.fromisoformat(last_activity)
                if datetime.now() - last_activity_dt > timedelta(hours=8):
                    return False

                # Aktivität aktualisieren
                conn.execute('''
                    UPDATE sessions 
                    SET last_activity = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (session_token,))
                conn.commit()

                return True

        except Exception as e:
            logger.error(f"Session-Validierung fehlgeschlagen: {e}")
            return False

    def _create_session(self, user_id, ip_address, user_agent):
        """Erstellt neue Session"""
        try:
            session_token = secrets.token_urlsafe(32)

            with sqlite3.connect(str(self.user_manager.db_path)) as conn:
                # Alte Sessions bereinigen
                conn.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))

                # Neue Session erstellen
                conn.execute('''
                    INSERT INTO sessions (session_id, user_id, ip_address, user_agent)
                    VALUES (?, ?, ?, ?)
                ''', (session_token, user_id, ip_address, user_agent))
                conn.commit()

            return session_token

        except Exception as e:
            logger.error(f"Session-Erstellung fehlgeschlagen: {e}")
            return None

    def _setup_routes(self):
        """Definiert alle Flask Routes mit Authentifizierung"""

        # ===== SETUP & AUTH ROUTES =====

        @self.app.route('/')
        def index():
            if not self.user_manager.is_setup_completed():
                return redirect(url_for('setup'))
            return redirect(url_for('dashboard'))

        @self.app.route('/setup', methods=['GET', 'POST'])
        def setup():
            if self.user_manager.is_setup_completed():
                return redirect(url_for('login'))

            if request.method == 'POST':
                try:
                    username = request.form.get('username', '').strip()
                    email = request.form.get('email', '').strip()
                    password = request.form.get('password', '')
                    password_confirm = request.form.get('password_confirm', '')

                    # Validierung
                    errors = []
                    if len(username) < 3:
                        errors.append("Benutzername muss mindestens 3 Zeichen lang sein")
                    if '@' not in email or '.' not in email:
                        errors.append("Ungültige E-Mail-Adresse")
                    if len(password) < 8:
                        errors.append("Passwort muss mindestens 8 Zeichen lang sein")
                    if password != password_confirm:
                        errors.append("Passwörter stimmen nicht überein")

                    if errors:
                        for error in errors:
                            flash(error, 'error')
                        return render_template('setup.html')

                    # Admin-Benutzer erstellen
                    if self.user_manager.create_user(username, email, password, 'admin'):
                        self.user_manager.mark_setup_completed()
                        flash('Setup erfolgreich abgeschlossen! Sie können sich jetzt anmelden.', 'success')
                        return redirect(url_for('login'))
                    else:
                        flash('Fehler beim Erstellen des Admin-Benutzers', 'error')

                except Exception as e:
                    logger.error(f"Setup-Fehler: {e}")
                    flash('Ein unerwarteter Fehler ist aufgetreten', 'error')

            return render_template('setup.html')

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if not self.user_manager.is_setup_completed():
                return redirect(url_for('setup'))

            if 'user_id' in session:
                return redirect(url_for('dashboard'))

            if request.method == 'POST':
                username_or_email = request.form.get('username', '').strip()
                password = request.form.get('password', '')

                if not username_or_email or not password:
                    flash('Bitte füllen Sie alle Felder aus', 'error')
                    return render_template('login.html')

                user, error = self.user_manager.verify_user(username_or_email, password)

                if user:
                    # Session erstellen
                    session_token = self._create_session(
                        user['id'],
                        request.remote_addr,
                        request.user_agent.string
                    )

                    if session_token:
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['email'] = user['email']
                        session['role'] = user['role']
                        session['session_token'] = session_token
                        session.permanent = True

                        flash(f'Willkommen zurück, {user["username"]}!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Fehler beim Erstellen der Session', 'error')
                else:
                    flash(error or 'Anmeldung fehlgeschlagen', 'error')

            return render_template('login.html')

        @self.app.route('/logout')
        def logout():
            if 'session_token' in session:
                try:
                    with sqlite3.connect(str(self.user_manager.db_path)) as conn:
                        conn.execute('DELETE FROM sessions WHERE session_id = ?', 
                                   (session['session_token'],))
                        conn.commit()
                except:
                    pass

            session.clear()
            flash('Sie wurden erfolgreich abgemeldet', 'info')
            return redirect(url_for('login'))

        # ===== MAIN APPLICATION ROUTES =====

        @self.app.route('/dashboard')
        @self.require_auth
        def dashboard():
            """Haupt-Dashboard"""
            try:
                # System Status
                system_status = self._get_system_status()

                # DNS Statistiken
                stats = self._get_dns_statistics()

                # Upstream Server Status
                upstream_servers = self._get_upstream_status()

                # Letzte Queries
                recent_queries = self.query_analyzer.get_recent_queries(limit=10)

                # Top Domains
                top_domains = self.query_analyzer.get_top_domains(limit=5)

                # Chart Daten
                chart_data = self._get_chart_data()

    # Security API Endpoints
    @self.app.route('/api/security/stats')
    @self.require_auth
    def api_security_stats():
        """Get security statistics for dashboard"""
        try:
            from src.security.brand_protection import AdvancedBrandProtection
            from src.ml.dga_detector import DGADetector
            from src.ml.zero_day_detector import ZeroDayDetector

            brand_protection = AdvancedBrandProtection()
            stats = brand_protection.get_threat_statistics()

            # Add ML accuracy stats
            try:
                dga_accuracy = self.redis_client.get('ml:dga_accuracy') or '95'
                stats['mlAccuracy'] = float(dga_accuracy)
            except:
                stats['mlAccuracy'] = 95.0

            return jsonify(stats)
        except Exception as e:
            self.logger.error(f"Error getting security stats: {e}")
            return jsonify({'error': str(e)}), 500

    @self.app.route('/api/security/chart-data')
    @self.require_auth
    def api_security_chart_data():
        """Get data for security charts"""
        try:
            # Generate sample data for demo
            import random
            from datetime import datetime, timedelta

            now = datetime.now()
            labels = [(now - timedelta(hours=i)).strftime('%H:%M') for i in range(23, -1, -1)]

            chart_data = {
                'threatTimeline': {
                    'labels': labels,
                    'data': [random.randint(0, 10) for _ in range(24)]
                },
                'threatTypes': [
                    random.randint(5, 25),  # Typosquatting
                    random.randint(3, 15),  # DGA
                    random.randint(2, 12),  # Phishing
                    random.randint(1, 8)    # Malware
                ],
                'analytics': {
                    'labels': labels,
                    'blocked': [random.randint(10, 50) for _ in range(24)],
                    'allowed': [random.randint(100, 500) for _ in range(24)]
                }
            }

            return jsonify(chart_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @self.app.route('/api/security/recent-threats')
    @self.require_auth
    def api_recent_threats():
        """Get recent security threats"""
        try:
            from src.security.brand_protection import AdvancedBrandProtection

            brand_protection = AdvancedBrandProtection()

            # Get recent threats from database
            import sqlite3
            import time

            db_path = brand_protection.db_path
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT threat_id, domain, brand, threat_type, severity, 
                       confidence, first_detected, status
                FROM brand_threats 
                ORDER BY first_detected DESC 
                LIMIT 10
            ''')

            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'threatId': row[0],
                    'domain': row[1],
                    'brand': row[2],
                    'threatType': row[3],
                    'severity': row[4],
                    'confidence': row[5],
                    'firstDetected': row[6],
                    'status': row[7]
                })

            conn.close()
            return jsonify(threats)

        except Exception as e:
            self.logger.error(f"Error getting recent threats: {e}")
            return jsonify([])

    @self.app.route('/api/security/block-threat/<threat_id>', methods=['POST'])
    @self.require_auth
    def api_block_threat(threat_id):
        """Block a specific threat"""
        try:
            from src.security.brand_protection import AdvancedBrandProtection

            brand_protection = AdvancedBrandProtection()

            # Update threat status in database
            import sqlite3

            conn = sqlite3.connect(brand_protection.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE brand_threats 
                SET status = 'blocked' 
                WHERE threat_id = ?
            ''', (threat_id,))

            conn.commit()
            conn.close()

            # Emit socket event
            self.socketio.emit('threat_blocked', {'threatId': threat_id})

            return jsonify({'success': True})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @self.app.route('/api/brand-protection/data')
    @self.require_auth
    def api_brand_protection_data():
        """Get brand protection data"""
        try:
            from src.security.brand_protection import AdvancedBrandProtection

            brand_protection = AdvancedBrandProtection()

            # Get protected brands
            import sqlite3
            conn = sqlite3.connect(brand_protection.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM protected_brands WHERE active = 1')
            brands_data = cursor.fetchall()

            brands = []
            for row in brands_data:
                brands.append({
                    'name': row[1],
                    'primaryDomains': json.loads(row[2]) if row[2] else [],
                    'keywords': json.loads(row[3]) if row[3] else [],
                    'active': bool(row[6])
                })

            # Get typosquatting detections
            cursor.execute('''
                SELECT suspicious_domain, target_brand, similarity_score, 
                       confidence, query_count, blocked
                FROM typosquatting_detections 
                ORDER BY first_seen DESC 
                LIMIT 10
            ''')

            detections = []
            for row in cursor.fetchall():
                detections.append({
                    'suspiciousDomain': row[0],
                    'targetBrand': row[1],
                    'similarityScore': row[2],
                    'confidence': row[3],
                    'queryCount': row[4],
                    'blocked': bool(row[5])
                })

            conn.close()

            return jsonify({
                'brands': brands,
                'detections': detections
            })

        except Exception as e:
            self.logger.error(f"Error getting brand protection data: {e}")
            return jsonify({'brands': [], 'detections': []})

    @self.app.route('/api/traffic-control/rules')
    @self.require_auth
    def api_traffic_control_rules():
        """Get traffic control rules"""
        try:
            # Sample traffic rules data
            rules = [
                {
                    'id': 'rule_1',
                    'name': 'Block Malware Domains',
                    'source': '*',
                    'destination': 'malware-list',
                    'action': 'block',
                    'enabled': True
                },
                {
                    'id': 'rule_2', 
                    'name': 'Allow Corporate DNS',
                    'source': '192.168.1.0/24',
                    'destination': 'corporate.com',
                    'action': 'allow',
                    'enabled': True
                },
                {
                    'id': 'rule_3',
                    'name': 'Rate Limit External',
                    'source': 'external',
                    'destination': '*',
                    'action': 'rate_limit',
                    'enabled': False
                }
            ]

            return jsonify(rules)

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @self.app.route('/api/ml/retrain', methods=['POST'])
    @self.require_auth
    def api_ml_retrain():
        """Retrain ML models"""
        try:
            from src.security.brand_protection import AdvancedBrandProtection

            brand_protection = AdvancedBrandProtection()

            # Start retraining in background thread
            import threading
            def retrain():
                try:
                    brand_protection.retrain_models()
                    self.socketio.emit('model_retrained', {'status': 'success'})
                except Exception as e:
                    self.socketio.emit('model_retrained', {'status': 'error', 'message': str(e)})

            thread = threading.Thread(target=retrain)
            thread.daemon = True
            thread.start()

            return jsonify({'success': True, 'message': 'Retraining started'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @self.app.route('/api/settings', methods=['POST'])
    @self.require_auth
    def api_save_settings():
        """Save security settings"""
        try:
            settings = request.get_json() or {}

            # Save settings to configuration
            config_file = self.config_path
            with open(config_file, 'r') as f:
                config = json.load(f)

            # Update security settings
            if 'security' not in config:
                config['security'] = {}

            config['security'].update(settings)

            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            return jsonify({'success': True})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

                return render_template('dashboard.html',
                                     system=system_status,
                                     stats=stats,
                                     upstream_servers=upstream_servers,
                                     recent_queries=recent_queries,
                                     top_domains=top_domains,
                                     chart_data=chart_data,
                                     chart_labels=self._get_chart_labels(),
                                     config=self.config_manager.get_config(),
                                     version='1.0.0')

            except Exception as e:
                logger.error(f"Dashboard Error: {e}")
                flash(f'Fehler beim Laden des Dashboards: {e}', 'error')
                return render_template('dashboard.html', 
                                     system={}, stats={}, upstream_servers=[],
                                     recent_queries=[], top_domains=[],
                                     chart_data={}, chart_labels=[])

        @self.app.route('/dns-settings')
        def dns_settings():
            """DNS Konfiguration"""
            config = self.config_manager.get_config()
            return render_template('dns_settings.html', config=config)

        @self.app.route('/security')
        def security():
            """Sicherheits-Einstellungen"""
            config = self.config_manager.get_config()
            return render_template('security.html', config=config)

        @self.app.route('/analytics')
        def analytics():
            """Analytics Dashboard"""
            analytics_data = self.query_analyzer.get_analytics_data()
            return render_template('analytics.html', data=analytics_data)

        @self.app.route('/settings')
        def settings():
            """System-Einstellungen"""
            return render_template('settings.html')

        @self.app.route('/logs')
        def logs():
            """Log-Anzeige"""
            try:
                log_entries = self._get_recent_logs()
                return render_template('logs.html', logs=log_entries)
            except Exception as e:
                logger.error(f"Logs Error: {e}")
                flash(f'Fehler beim Laden der Logs: {e}', 'error')
                return render_template('logs.html', logs=[])

        # API Routes
        @self.app.route('/api/status')
        def api_status():
            """API: Aktueller System Status"""
            try:
                status = {
                    'queries_total': self.query_analyzer.get_total_queries(),
                    'queries_per_second': self.query_analyzer.get_queries_per_second(),
                    'cache_hit_rate': self._get_cache_hit_rate(),
                    'blocked_queries': self.query_analyzer.get_blocked_queries(),
                    'system': self._get_system_status()
                }
                return jsonify(status)
            except Exception as e:
                logger.error(f"API Status Error: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/restart', methods=['POST'])
        def api_restart():
            """API: DNS Service neustarten"""
            try:
                result = subprocess.run(['systemctl', 'restart', 'jetdns'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return jsonify({'success': True, 'message': 'Service wird neugestartet'})
                else:
                    return jsonify({'success': False, 'message': result.stderr})
            except Exception as e:
                logger.error(f"API Restart Error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/backup', methods=['POST'])
        def api_backup():
            """API: Backup erstellen"""
            try:
                backup_name = f"web_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                # Hier würde die Backup-Logik implementiert werden
                return jsonify({'success': True, 'backup_name': backup_name})
            except Exception as e:
                logger.error(f"API Backup Error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/api/settings', methods=['POST'])
        def api_save_settings():
            """API: Einstellungen speichern"""
            try:
                settings = request.get_json()
                self.config_manager.update_config(settings)
                return jsonify({'success': True, 'restart_required': True})
            except Exception as e:
                logger.error(f"API Settings Error: {e}")
                return jsonify({'success': False, 'message': str(e)}), 500

        @self.app.route('/logout')
        def logout():
            """Benutzer abmelden"""
            session.clear()
            return redirect(url_for('index'))

        # Error Handlers
        @self.app.errorhandler(404)
        def not_found_error(error):
            return render_template('error.html', 
                                 error_code=404,
                                 error_message='Seite nicht gefunden'), 404

        @self.app.errorhandler(500)
        def internal_error(error):
            return render_template('error.html',
                                 error_code=500,
                                 error_message='Interner Serverfehler'), 500

    def _setup_socketio_events(self):
        """Definiert SocketIO Events für Real-time Updates"""

        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Client verbunden: {request.sid}")
            emit('status', {'message': 'Verbunden mit JetDNS'})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Client getrennt: {request.sid}")

        @self.socketio.on('request_status')
        def handle_status_request():
            """Client fordert Status-Update an"""
            try:
                status = {
                    'queries_total': self.query_analyzer.get_total_queries(),
                    'queries_per_second': self.query_analyzer.get_queries_per_second(),
                    'cache_hit_rate': self._get_cache_hit_rate(),
                    'blocked_queries': self.query_analyzer.get_blocked_queries()
                }
                emit('status_update', status)
            except Exception as e:
                emit('error', {'message': str(e)})

    def _get_system_status(self):
        """Ermittelt den aktuellen Systemstatus"""
        try:
            # DNS Service Status
            dns_result = subprocess.run(['systemctl', 'is-active', 'jetdns'],
                                      capture_output=True, text=True)
            dns_status = dns_result.stdout.strip() == 'active'

            # Web Service Status (immer true wenn diese Methode läuft)
            web_status = True

            # System Resources
            memory_info = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)

            # Uptime
            uptime_seconds = time.time() - psutil.boot_time()
            uptime = str(timedelta(seconds=int(uptime_seconds)))

            return {
                'dns_status': dns_status,
                'web_status': web_status,
                'memory_usage': round(memory_info.used / (1024**2)),  # MB
                'memory_percentage': memory_info.percent,
                'cpu_usage': cpu_percent,
                'uptime': uptime
            }
        except Exception as e:
            logger.error(f"System Status Error: {e}")
            return {
                'dns_status': False,
                'web_status': True,
                'memory_usage': 0,
                'memory_percentage': 0,
                'cpu_usage': 0,
                'uptime': 'Unbekannt'
            }

    def _get_dns_statistics(self):
        """Holt DNS-Statistiken"""
        try:
            if self.redis_client:
                stats = {
                    'queries_total': int(self.redis_client.get('stats:queries_total') or 0),
                    'queries_per_second': int(self.redis_client.get('stats:queries_per_second') or 0),
                    'cache_hit_rate': float(self.redis_client.get('stats:cache_hit_rate') or 0),
                    'blocked_queries': int(self.redis_client.get('stats:blocked_queries') or 0),
                    'cache_entries': int(self.redis_client.get('stats:cache_entries') or 0)
                }
            else:
                # Fallback ohne Redis
                stats = self.query_analyzer.get_basic_stats()

            return stats
        except Exception as e:
            logger.error(f"DNS Statistics Error: {e}")
            return {
                'queries_total': 0,
                'queries_per_second': 0,
                'cache_hit_rate': 0,
                'blocked_queries': 0,
                'cache_entries': 0
            }

    def _get_upstream_status(self):
        """Holt Status der Upstream-Server"""
        try:
            config = self.config_manager.get_config()
            servers = []

            if 'upstream' in config and 'servers' in config['upstream']:
                server_list = config['upstream']['servers'].split(',')
                for server_addr in server_list:
                    server_addr = server_addr.strip()
                    # Health Check Status aus Redis oder Default
                    if self.redis_client:
                        status_key = f'upstream:{server_addr}:status'
                        response_time_key = f'upstream:{server_addr}:response_time'
                        status = self.redis_client.get(status_key) == 'online'
                        response_time = int(self.redis_client.get(response_time_key) or 0)
                    else:
                        status = True  # Default
                        response_time = 10

                    servers.append({
                        'address': server_addr,
                        'status': status,
                        'response_time': response_time
                    })

            return servers
        except Exception as e:
            logger.error(f"Upstream Status Error: {e}")
            return []

    def _get_cache_hit_rate(self):
        """Berechnet Cache Hit Rate"""
        try:
            if self.redis_client:
                total_queries = int(self.redis_client.get('stats:queries_total') or 0)
                cache_hits = int(self.redis_client.get('stats:cache_hits') or 0)

                if total_queries > 0:
                    return round((cache_hits / total_queries) * 100, 1)

            return 0.0
        except Exception as e:
            logger.error(f"Cache Hit Rate Error: {e}")
            return 0.0

    def _get_chart_data(self):
        """Holt Chart-Daten für die letzten 24h"""
        try:
            # 24 Stunden in 1-Stunden-Intervallen
            now = datetime.now()
            hours = []
            queries_data = []
            blocked_data = []

            for i in range(24):
                hour = now - timedelta(hours=23-i)
                hours.append(hour.strftime('%H:00'))

                # Daten aus Redis oder Analytics
                if self.redis_client:
                    hour_key = hour.strftime('%Y%m%d_%H')
                    queries = int(self.redis_client.get(f'hourly:queries:{hour_key}') or 0)
                    blocked = int(self.redis_client.get(f'hourly:blocked:{hour_key}') or 0)
                else:
                    # Fallback: Simuliere Daten
                    queries = max(0, 100 + (i * 10) + (i % 3 * 20))
                    blocked = max(0, queries // 10)

                queries_data.append(queries)
                blocked_data.append(blocked)

            return {
                'queries': queries_data,
                'blocked': blocked_data
            }
        except Exception as e:
            logger.error(f"Chart Data Error: {e}")
            return {'queries': [0] * 24, 'blocked': [0] * 24}

    def _get_chart_labels(self):
        """Erstellt Labels für Chart (letzte 24h)"""
        now = datetime.now()
        labels = []
        for i in range(24):
            hour = now - timedelta(hours=23-i)
            labels.append(hour.strftime('%H:00'))
        return labels

    def _get_recent_logs(self, lines=100):
        """Holt die letzten Log-Einträge"""
        try:
            result = subprocess.run([
                'journalctl', '-u', 'jetdns', '-n', str(lines),
                '--no-pager', '--output=json'
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                logs = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            log_entry = json.loads(line)
                            logs.append({
                                'timestamp': datetime.fromtimestamp(int(log_entry.get('__REALTIME_TIMESTAMP', 0)) / 1000000),
                                'level': log_entry.get('PRIORITY', '6'),
                                'message': log_entry.get('MESSAGE', ''),
                                'unit': log_entry.get('_SYSTEMD_UNIT', '')
                            })
                        except json.JSONDecodeError:
                            continue
                return logs
            else:
                logger.warning(f"journalctl failed: {result.stderr}")
                return []

        except Exception as e:
            logger.error(f"Recent Logs Error: {e}")
            return []

    def start_background_tasks(self):
        """Startet Background Tasks für Statistik-Updates"""
        if self.stats_thread is None or not self.stats_thread.is_alive():
            self.stats_thread = threading.Thread(target=self._stats_collector, daemon=True)
            self.stats_thread.start()

    def _stats_collector(self):
        """Background Task für Statistik-Sammlung"""
        while True:
            try:
                if self.redis_client:
                    # Sammle aktuelle Statistiken
                    stats = self._get_dns_statistics()

                    # Aktualisiere Hourly Stats
                    hour_key = datetime.now().strftime('%Y%m%d_%H')
                    current_queries = int(self.redis_client.get(f'hourly:queries:{hour_key}') or 0)
                    current_blocked = int(self.redis_client.get(f'hourly:blocked:{hour_key}') or 0)

                    # Inkrementiere (simuliert)
                    self.redis_client.set(f'hourly:queries:{hour_key}', current_queries + 1)
                    if current_queries % 10 == 0:  # 10% blocked simulation
                        self.redis_client.set(f'hourly:blocked:{hour_key}', current_blocked + 1)

                    # Expire nach 7 Tagen
                    self.redis_client.expire(f'hourly:queries:{hour_key}', 7 * 24 * 3600)
                    self.redis_client.expire(f'hourly:blocked:{hour_key}', 7 * 24 * 3600)

                    # Emit Real-time Update
                    if hasattr(self, 'socketio'):
                        self.socketio.emit('stats_update', stats)

                time.sleep(10)  # Update alle 10 Sekunden

            except Exception as e:
                logger.error(f"Stats Collector Error: {e}")
                time.sleep(30)  # Längere Pause bei Fehlern

    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Startet die Web-Anwendung"""
        logger.info(f"Starte JetDNS Web Interface auf {host}:{port}")

        if debug:
            self.app.run(host=host, port=port, debug=debug)
        else:
            self.socketio.run(self.app, host=host, port=port, debug=debug)

    def get_app(self):
        """Gibt Flask App zurück für WSGI"""
        return self.app

if __name__ == '__main__':
    # Development Server
    logging.basicConfig(level=logging.INFO)
    web_interface = JetDNSWebInterface()
    web_interface.run(debug=True)
