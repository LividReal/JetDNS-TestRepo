"""
JetDNS DNS Cookies Implementation
RFC 7873 DNS Cookies für verbesserte Sicherheit und DoS-Schutz
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import struct
import time
from typing import Dict, Optional, Tuple
import dns.edns
import dns.message

logger = logging.getLogger(__name__)

class DNSCookieManager:
    """DNS Cookies Manager für Sicherheit und Rate Limiting"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = {}

        # Server Secrets
        self.server_secret = None
        self.previous_secret = None
        self.secret_rotation_time = 0

        # Client Tracking
        self.client_cookies: Dict[str, Dict] = {}  # client_ip -> cookie_info
        self.cookie_cache: Dict[bytes, Dict] = {}  # server_cookie -> validation_info

        # Rate Limiting basierend auf Cookies
        self.rate_limits: Dict[str, Dict] = {}  # client_ip -> rate_info

        # Statistiken
        self.stats = {
            'cookies_issued': 0,
            'cookies_validated': 0,
            'cookie_failures': 0,
            'rate_limited': 0,
            'dos_prevented': 0
        }

    async def initialize(self):
        """Initialisiert DNS Cookies Manager"""
        await self._load_config()

        if not self.config.get('enabled', True):
            logger.info("DNS Cookies deaktiviert")
            return

        await self._setup_server_secrets()

        # Background Tasks
        asyncio.create_task(self._secret_rotation_task())
        asyncio.create_task(self._cleanup_task())

        logger.info("🍪 DNS Cookies Manager initialisiert")

    async def _load_config(self):
        """Lädt DNS Cookies Konfiguration"""
        self.config = self.config_manager.get_config('dns_cookies', {
            'enabled': True,
            'require_cookies': False,  # Wenn True, blockiere Queries ohne gültige Cookies
            'cookie_lifetime': 3600,   # Cookie-Gültigkeit in Sekunden
            'secret_rotation_interval': 3600,  # Secret-Rotation in Sekunden
            'rate_limit_window': 60,   # Rate Limiting Fenster in Sekunden
            'queries_per_window': 100, # Max Queries pro Fenster ohne Cookie
            'queries_per_window_with_cookie': 1000,  # Max Queries mit gültigem Cookie
            'dos_threshold': 1000,     # DoS Detection Threshold
            'grace_period': 30,        # Grace Period für neue Clients
            'server_secret_file': '/var/lib/jetdns/dns_cookie_secret'
        })

    async def _setup_server_secrets(self):
        """Richtet Server Secrets ein"""
        try:
            secret_file = self.config.get('server_secret_file', '/var/lib/jetdns/dns_cookie_secret')

            # Versuche bestehendes Secret zu laden
            try:
                with open(secret_file, 'rb') as f:
                    self.server_secret = f.read()

                if len(self.server_secret) != 32:
                    raise ValueError("Invalid secret length")

                logger.info("DNS Cookie Server Secret geladen")

            except (FileNotFoundError, ValueError):
                # Neues Secret generieren
                self.server_secret = secrets.token_bytes(32)

                # Secret speichern
                import os
                os.makedirs(os.path.dirname(secret_file), exist_ok=True)

                with open(secret_file, 'wb') as f:
                    f.write(self.server_secret)

                # Sichere Dateiberechtigungen
                os.chmod(secret_file, 0o600)

                logger.info("Neues DNS Cookie Server Secret generiert und gespeichert")

            self.secret_rotation_time = time.time()

        except Exception as e:
            logger.error(f"Fehler beim Setup der Server Secrets: {e}")
            # Fallback: In-Memory Secret
            self.server_secret = secrets.token_bytes(32)

    def has_dns_cookie(self, message: dns.message.Message) -> bool:
        """Prüft ob DNS Message Cookie Option hat"""

        if not message.options:
            return False

        for option in message.options:
            if option.otype == dns.edns.COOKIE:
                return True

        return False

    async def validate_dns_cookie(self, message: dns.message.Message, 
                                client_ip: str) -> Tuple[bool, Optional[bytes]]:
        """Validiert DNS Cookie in Message"""

        if not self.config.get('enabled', True):
            return True, None

        # Suche Cookie Option
        cookie_option = None

        if message.options:
            for option in message.options:
                if option.otype == dns.edns.COOKIE:
                    cookie_option = option
                    break

        if not cookie_option:
            # Keine Cookie -> prüfe ob erforderlich
            if self.config.get('require_cookies', False):
                return False, None
            else:
                # Rate Limiting ohne Cookie
                if await self._check_rate_limit_no_cookie(client_ip):
                    return True, None
                else:
                    self.stats['rate_limited'] += 1
                    return False, None

        try:
            cookie_data = cookie_option.data

            if len(cookie_data) < 8:
                self.stats['cookie_failures'] += 1
                return False, None

            # Client Cookie (erste 8 bytes)
            client_cookie = cookie_data[:8]

            if len(cookie_data) == 8:
                # Nur Client Cookie -> neue Session
                return await self._handle_new_cookie_session(client_ip, client_cookie)

            elif len(cookie_data) >= 16:
                # Client + Server Cookie
                server_cookie = cookie_data[8:]
                return await self._validate_server_cookie(client_ip, client_cookie, server_cookie)

        except Exception as e:
            logger.debug(f"DNS Cookie Validation Error: {e}")
            self.stats['cookie_failures'] += 1

        return False, None

    async def _handle_new_cookie_session(self, client_ip: str, 
                                       client_cookie: bytes) -> Tuple[bool, Optional[bytes]]:
        """Behandelt neue Cookie Session"""

        # Generiere Server Cookie
        server_cookie = await self._generate_server_cookie(client_ip, client_cookie)

        # Speichere Client Info
        self.client_cookies[client_ip] = {
            'client_cookie': client_cookie,
            'server_cookie': server_cookie,
            'created_at': time.time(),
            'last_used': time.time(),
            'query_count': 1
        }

        # Cache Server Cookie für Validation
        self.cookie_cache[server_cookie] = {
            'client_ip': client_ip,
            'client_cookie': client_cookie,
            'created_at': time.time()
        }

        self.stats['cookies_issued'] += 1

        # Return Server Cookie für Response
        return True, server_cookie

    async def _validate_server_cookie(self, client_ip: str, client_cookie: bytes, 
                                    server_cookie: bytes) -> Tuple[bool, Optional[bytes]]:
        """Validiert Server Cookie"""

        try:
            # Prüfe Cookie Cache
            if server_cookie in self.cookie_cache:
                cache_info = self.cookie_cache[server_cookie]

                # Prüfe Client IP
                if cache_info['client_ip'] != client_ip:
                    self.stats['cookie_failures'] += 1
                    return False, None

                # Prüfe Client Cookie
                if cache_info['client_cookie'] != client_cookie:
                    self.stats['cookie_failures'] += 1
                    return False, None

                # Prüfe Alter
                cookie_age = time.time() - cache_info['created_at']
                if cookie_age > self.config.get('cookie_lifetime', 3600):
                    # Cookie abgelaufen
                    del self.cookie_cache[server_cookie]
                    if client_ip in self.client_cookies:
                        del self.client_cookies[client_ip]
                    self.stats['cookie_failures'] += 1
                    return False, None

                # Cookie gültig
                if client_ip in self.client_cookies:
                    self.client_cookies[client_ip]['last_used'] = time.time()
                    self.client_cookies[client_ip]['query_count'] += 1

                # Rate Limiting mit Cookie
                if await self._check_rate_limit_with_cookie(client_ip):
                    self.stats['cookies_validated'] += 1
                    return True, server_cookie
                else:
                    self.stats['rate_limited'] += 1
                    return False, None

            else:
                # Server Cookie nicht im Cache -> validiere kryptographisch
                valid = await self._cryptographic_cookie_validation(client_ip, client_cookie, server_cookie)

                if valid:
                    # Re-cache Cookie
                    self.cookie_cache[server_cookie] = {
                        'client_ip': client_ip,
                        'client_cookie': client_cookie,
                        'created_at': time.time()
                    }

                    self.stats['cookies_validated'] += 1
                    return True, server_cookie
                else:
                    self.stats['cookie_failures'] += 1
                    return False, None

        except Exception as e:
            logger.debug(f"Server Cookie Validation Error: {e}")
            self.stats['cookie_failures'] += 1

        return False, None

    async def _generate_server_cookie(self, client_ip: str, client_cookie: bytes) -> bytes:
        """Generiert Server Cookie"""

        # Timestamp (4 bytes)
        timestamp = int(time.time())
        timestamp_bytes = struct.pack('!I', timestamp)

        # HMAC über Client IP + Client Cookie + Timestamp
        mac_input = client_ip.encode() + client_cookie + timestamp_bytes
        mac = hmac.new(self.server_secret, mac_input, hashlib.sha256).digest()[:4]

        # Server Cookie = Timestamp + MAC
        server_cookie = timestamp_bytes + mac

        return server_cookie

    async def _cryptographic_cookie_validation(self, client_ip: str, client_cookie: bytes, 
                                             server_cookie: bytes) -> bool:
        """Kryptographische Validierung des Server Cookies"""

        try:
            if len(server_cookie) < 8:
                return False

            # Timestamp extrahieren
            timestamp = struct.unpack('!I', server_cookie[:4])[0]
            received_mac = server_cookie[4:8]

            # Cookie Alter prüfen
            cookie_age = time.time() - timestamp
            if cookie_age > self.config.get('cookie_lifetime', 3600) or cookie_age < 0:
                return False

            # MAC neu berechnen mit aktuellem und vorherigem Secret
            for secret in [self.server_secret, self.previous_secret]:
                if secret:
                    mac_input = client_ip.encode() + client_cookie + struct.pack('!I', timestamp)
                    expected_mac = hmac.new(secret, mac_input, hashlib.sha256).digest()[:4]

                    if hmac.compare_digest(received_mac, expected_mac):
                        return True

        except Exception as e:
            logger.debug(f"Cryptographic Cookie Validation Error: {e}")

        return False

    async def _check_rate_limit_no_cookie(self, client_ip: str) -> bool:
        """Prüft Rate Limit für Clients ohne Cookie"""

        now = time.time()
        window = self.config.get('rate_limit_window', 60)
        max_queries = self.config.get('queries_per_window', 100)

        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = {
                'queries': [],
                'first_seen': now
            }

        client_rate = self.rate_limits[client_ip]

        # Grace Period für neue Clients
        if now - client_rate['first_seen'] < self.config.get('grace_period', 30):
            client_rate['queries'].append(now)
            return True

        # Bereinige alte Queries
        cutoff = now - window
        client_rate['queries'] = [q for q in client_rate['queries'] if q > cutoff]

        # Rate Check
        if len(client_rate['queries']) >= max_queries:
            # DoS Detection
            if len(client_rate['queries']) > self.config.get('dos_threshold', 1000):
                self.stats['dos_prevented'] += 1
                logger.warning(f"Potentieller DoS von {client_ip}: {len(client_rate['queries'])} Queries")

            return False

        client_rate['queries'].append(now)
        return True

    async def _check_rate_limit_with_cookie(self, client_ip: str) -> bool:
        """Prüft Rate Limit für Clients mit gültigem Cookie"""

        now = time.time()
        window = self.config.get('rate_limit_window', 60)
        max_queries = self.config.get('queries_per_window_with_cookie', 1000)

        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = {
                'queries': [],
                'first_seen': now
            }

        client_rate = self.rate_limits[client_ip]

        # Bereinige alte Queries
        cutoff = now - window
        client_rate['queries'] = [q for q in client_rate['queries'] if q > cutoff]

        # Rate Check (höheres Limit für Cookie-Clients)
        if len(client_rate['queries']) >= max_queries:
            return False

        client_rate['queries'].append(now)
        return True

    async def create_cookie_response(self, query: dns.message.Message, client_ip: str, 
                                   server_cookie: bytes) -> dns.message.Message:
        """Erstellt Response mit DNS Cookie"""

        response = dns.message.make_response(query)

        if not server_cookie:
            return response

        # Extrahiere Client Cookie aus Query
        client_cookie = None

        if query.options:
            for option in query.options:
                if option.otype == dns.edns.COOKIE and len(option.data) >= 8:
                    client_cookie = option.data[:8]
                    break

        if not client_cookie:
            return response

        # Cookie Response = Client Cookie + Server Cookie
        cookie_response = client_cookie + server_cookie

        # EDNS Cookie Option erstellen
        cookie_option = dns.edns.GenericOption(dns.edns.COOKIE, cookie_response)

        # EDNS zu Response hinzufügen
        if not hasattr(response, 'options') or response.options is None:
            response.use_edns(edns=0, payload=4096, options=[cookie_option])
        else:
            response.options.append(cookie_option)

        return response

    async def _secret_rotation_task(self):
        """Background Task für Secret Rotation"""

        while True:
            try:
                rotation_interval = self.config.get('secret_rotation_interval', 3600)
                await asyncio.sleep(rotation_interval)

                # Rotiere Server Secret
                self.previous_secret = self.server_secret
                self.server_secret = secrets.token_bytes(32)
                self.secret_rotation_time = time.time()

                # Speichere neues Secret
                secret_file = self.config.get('server_secret_file', '/var/lib/jetdns/dns_cookie_secret')
                try:
                    with open(secret_file, 'wb') as f:
                        f.write(self.server_secret)
                except Exception as e:
                    logger.error(f"Fehler beim Speichern des rotierten Secrets: {e}")

                # Bereinige Cookie Cache (Cookies mit altem Secret werden ungültig)
                self.cookie_cache.clear()

                logger.info("DNS Cookie Server Secret rotiert")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Secret Rotation: {e}")

    async def _cleanup_task(self):
        """Background Task für Cleanup"""

        while True:
            try:
                await asyncio.sleep(300)  # Alle 5 Minuten

                now = time.time()
                cookie_lifetime = self.config.get('cookie_lifetime', 3600)
                rate_limit_window = self.config.get('rate_limit_window', 60)

                # Client Cookies bereinigen
                expired_clients = []
                for client_ip, cookie_info in self.client_cookies.items():
                    if now - cookie_info['last_used'] > cookie_lifetime:
                        expired_clients.append(client_ip)

                for client_ip in expired_clients:
                    del self.client_cookies[client_ip]

                # Cookie Cache bereinigen
                expired_cookies = []
                for server_cookie, cache_info in self.cookie_cache.items():
                    if now - cache_info['created_at'] > cookie_lifetime:
                        expired_cookies.append(server_cookie)

                for server_cookie in expired_cookies:
                    del self.cookie_cache[server_cookie]

                # Rate Limits bereinigen
                for client_ip, rate_info in list(self.rate_limits.items()):
                    cutoff = now - rate_limit_window * 2  # Behalte etwas länger für Statistiken
                    rate_info['queries'] = [q for q in rate_info['queries'] if q > cutoff]

                    # Entferne komplett inaktive Clients
                    if not rate_info['queries'] and now - rate_info['first_seen'] > 3600:
                        del self.rate_limits[client_ip]

                if expired_clients or expired_cookies:
                    logger.debug(f"DNS Cookie Cleanup: {len(expired_clients)} Clients, {len(expired_cookies)} Cookies bereinigt")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei DNS Cookie Cleanup: {e}")

    async def get_cookie_stats(self) -> Dict:
        """Gibt DNS Cookie Statistiken zurück"""

        now = time.time()

        # Active Clients
        active_clients = len([
            c for c in self.client_cookies.values()
            if now - c['last_used'] < 300  # Aktiv in letzten 5 Minuten
        ])

        # Rate Limited Clients
        rate_limited_clients = len([
            r for r in self.rate_limits.values()
            if len(r['queries']) > self.config.get('queries_per_window', 100)
        ])

        return {
            'enabled': self.config.get('enabled', True),
            'require_cookies': self.config.get('require_cookies', False),
            'cookie_lifetime': self.config.get('cookie_lifetime', 3600),
            'secret_age': int(now - self.secret_rotation_time),
            'active_clients': active_clients,
            'cached_cookies': len(self.cookie_cache),
            'rate_limited_clients': rate_limited_clients,
            'stats': self.stats
        }

    async def blacklist_client(self, client_ip: str, duration: int = 3600):
        """Blacklisted Client (temporär)"""

        # Entferne bestehende Cookies
        if client_ip in self.client_cookies:
            del self.client_cookies[client_ip]

        # Entferne aus Cookie Cache
        expired_cookies = []
        for server_cookie, cache_info in self.cookie_cache.items():
            if cache_info['client_ip'] == client_ip:
                expired_cookies.append(server_cookie)

        for server_cookie in expired_cookies:
            del self.cookie_cache[server_cookie]

        # Setze hohe Rate Limit (praktisch Blacklist)
        self.rate_limits[client_ip] = {
            'queries': [time.time()] * 10000,  # Sehr viele "virtuelle" Queries
            'first_seen': time.time(),
            'blacklisted_until': time.time() + duration
        }

        logger.info(f"Client {client_ip} temporär blacklisted für {duration} Sekunden")

    def is_client_blacklisted(self, client_ip: str) -> bool:
        """Prüft ob Client blacklisted ist"""

        if client_ip not in self.rate_limits:
            return False

        blacklist_until = self.rate_limits[client_ip].get('blacklisted_until', 0)
        return time.time() < blacklist_until

    def requires_cookie(self, client_ip: str) -> bool:
        """Prüft ob Client Cookie benötigt"""

        if not self.config.get('enabled', True):
            return False

        # Blacklisted Clients benötigen immer Cookie
        if self.is_client_blacklisted(client_ip):
            return True

        # Prüfe Rate Limit
        if client_ip in self.rate_limits:
            rate_info = self.rate_limits[client_ip]
            now = time.time()
            window = self.config.get('rate_limit_window', 60)

            # Bereinige alte Queries
            cutoff = now - window
            rate_info['queries'] = [q for q in rate_info['queries'] if q > cutoff]

            # Cookie erforderlich wenn Limit erreicht
            max_queries = self.config.get('queries_per_window', 100)
            return len(rate_info['queries']) >= max_queries

        return self.config.get('require_cookies', False)
