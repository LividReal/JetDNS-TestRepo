"""
JetDNS EDNS0 Support
Extended DNS Support für moderne DNS Features und große Responses
"""

import asyncio
import logging
import struct
from typing import Dict, List, Optional, Tuple
import dns.edns
import dns.flags
import dns.message
import dns.rcode

logger = logging.getLogger(__name__)

class EDNSHandler:
    """EDNS0 Handler für Extended DNS Features"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = {}

        # EDNS Capabilities
        self.max_udp_payload = 4096
        self.version = 0  # EDNS Version
        self.supported_options = {}

        # Statistiken
        self.stats = {
            'edns_queries': 0,
            'edns_responses': 0,
            'large_responses': 0,
            'tcp_fallbacks': 0,
            'option_usage': {}
        }

    async def initialize(self):
        """Initialisiert EDNS Handler"""
        await self._load_config()
        await self._setup_supported_options()

        logger.info(f"🔧 EDNS0 Support initialisiert - Max UDP: {self.max_udp_payload} bytes")

    async def _load_config(self):
        """Lädt EDNS Konfiguration"""
        self.config = self.config_manager.get_config('edns', {
            'enabled': True,
            'max_udp_payload': 4096,
            'version': 0,
            'advertise_options': {
                'nsid': True,           # Name Server Identifier
                'ecs': True,            # EDNS Client Subnet
                'cookie': True,         # DNS Cookies
                'keepalive': True,      # TCP Keep-Alive
                'padding': True,        # Response Padding
                'chain': False,         # Chain Query
                'dau': True,            # DNSSEC Algorithm Understood
                'dhu': True,            # DS Hash Understood
                'n3u': True             # NSEC3 Hash Understood
            },
            'tcp_fallback_threshold': 1472  # Standard Ethernet MTU minus headers
        })

        self.max_udp_payload = min(self.config.get('max_udp_payload', 4096), 65535)
        self.version = self.config.get('version', 0)

    async def _setup_supported_options(self):
        """Richtet unterstützte EDNS Optionen ein"""
        advertise = self.config.get('advertise_options', {})

        self.supported_options = {}

        if advertise.get('nsid', True):
            self.supported_options[dns.edns.NSID] = self._handle_nsid

        if advertise.get('ecs', True):
            self.supported_options[dns.edns.ECS] = self._handle_client_subnet

        if advertise.get('cookie', True):
            self.supported_options[dns.edns.COOKIE] = self._handle_dns_cookie

        if advertise.get('keepalive', True):
            self.supported_options[dns.edns.KEEPALIVE] = self._handle_tcp_keepalive

        if advertise.get('padding', True):
            self.supported_options[dns.edns.PADDING] = self._handle_padding

        # Custom Options
        self.supported_options[65001] = self._handle_jetdns_option  # JetDNS Custom Option

    def has_edns(self, message: dns.message.Message) -> bool:
        """Prüft ob Message EDNS0 unterstützt"""
        return message.edns >= 0

    def get_edns_info(self, message: dns.message.Message) -> Optional[Dict]:
        """Extrahiert EDNS Informationen aus Message"""
        if not self.has_edns(message):
            return None

        return {
            'version': message.ednsversion,
            'udp_payload': message.payload,
            'flags': message.ednsflags,
            'options': {opt.otype: opt.data for opt in message.options} if message.options else {}
        }

    async def process_edns_query(self, query: dns.message.Message, 
                               client_ip: str, protocol: str) -> dns.message.Message:
        """Verarbeitet EDNS Query und erstellt entsprechende Response"""

        if not self.config.get('enabled', True) or not self.has_edns(query):
            return query

        self.stats['edns_queries'] += 1

        # EDNS Informationen extrahieren
        edns_info = self.get_edns_info(query)

        # Client UDP Payload Size
        client_udp_payload = min(edns_info['udp_payload'], self.max_udp_payload)

        # EDNS Optionen verarbeiten
        response_options = []

        if query.options:
            for option in query.options:
                if option.otype in self.supported_options:
                    handler = self.supported_options[option.otype]
                    response_option = await handler(option, client_ip, protocol)

                    if response_option:
                        response_options.append(response_option)

                    # Statistik
                    opt_name = self._get_option_name(option.otype)
                    self.stats['option_usage'][opt_name] = self.stats['option_usage'].get(opt_name, 0) + 1

        # Response EDNS konfigurieren
        response = dns.message.make_response(query)
        response.use_edns(
            edns=self.version,
            ednsflags=0,
            payload=self.max_udp_payload,
            options=response_options
        )

        self.stats['edns_responses'] += 1

        return response

    async def _handle_nsid(self, option: dns.edns.Option, client_ip: str, 
                         protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt NSID (Name Server Identifier) Option"""

        # JetDNS Server Identifier
        server_id = f"JetDNS-{self.config_manager.get_value('general', 'version', '1.0.0')}"
        hostname = self.config_manager.get_value('general', 'hostname', 'jetdns-server')

        nsid_data = f"{hostname}:{server_id}".encode('utf-8')

        return dns.edns.GenericOption(dns.edns.NSID, nsid_data)

    async def _handle_client_subnet(self, option: dns.edns.Option, client_ip: str, 
                                  protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt ECS (EDNS Client Subnet) Option"""

        try:
            # Parse Client Subnet Option
            if len(option.data) < 4:
                return None

            family, source_prefix, scope_prefix = struct.unpack('!HBB', option.data[:4])

            # IPv4
            if family == 1:
                # Berechne Client Subnet basierend auf Source Prefix
                import ipaddress

                client_net = ipaddress.IPv4Network(f"{client_ip}/{source_prefix}", strict=False)

                # Response mit Scope Prefix
                scope_prefix = min(source_prefix, 24)  # Max /24 für IPv4

                # Baue Response
                subnet_bytes = client_net.network_address.packed[:((scope_prefix + 7) // 8)]
                response_data = struct.pack('!HBB', family, source_prefix, scope_prefix) + subnet_bytes

                return dns.edns.GenericOption(dns.edns.ECS, response_data)

        except Exception as e:
            logger.debug(f"ECS Option Parsing fehlgeschlagen: {e}")

        return None

    async def _handle_dns_cookie(self, option: dns.edns.Option, client_ip: str, 
                                protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt DNS Cookie Option"""

        try:
            if len(option.data) < 8:
                return None

            client_cookie = option.data[:8]

            # Generiere Server Cookie
            server_cookie = await self._generate_server_cookie(client_cookie, client_ip)

            # Response Cookie = Client Cookie + Server Cookie
            response_cookie = client_cookie + server_cookie

            return dns.edns.GenericOption(dns.edns.COOKIE, response_cookie)

        except Exception as e:
            logger.debug(f"DNS Cookie Verarbeitung fehlgeschlagen: {e}")

        return None

    async def _generate_server_cookie(self, client_cookie: bytes, client_ip: str) -> bytes:
        """Generiert Server Cookie"""

        import hashlib
        import time

        # Server Secret (sollte persistent und geheim sein)
        server_secret = self.config_manager.get_value('edns', 'cookie_secret', 'jetdns-secret-key')

        # Timestamp (4 bytes)
        timestamp = int(time.time())
        timestamp_bytes = struct.pack('!I', timestamp)

        # Hash(Client IP + Client Cookie + Timestamp + Server Secret)
        hash_input = client_ip.encode() + client_cookie + timestamp_bytes + server_secret.encode()
        hash_digest = hashlib.sha256(hash_input).digest()[:4]  # Erste 4 Bytes

        # Server Cookie = Timestamp + Hash
        return timestamp_bytes + hash_digest

    async def _handle_tcp_keepalive(self, option: dns.edns.Option, client_ip: str, 
                                  protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt TCP Keep-Alive Option"""

        if protocol != 'TCP':
            return None

        # Keep-Alive Timeout in 100ms Units
        keepalive_timeout = self.config.get('tcp_keepalive_timeout', 120)  # 12 Sekunden
        timeout_data = struct.pack('!H', keepalive_timeout)

        return dns.edns.GenericOption(dns.edns.KEEPALIVE, timeout_data)

    async def _handle_padding(self, option: dns.edns.Option, client_ip: str, 
                            protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt Response Padding Option"""

        # Padding für DNS-over-TLS/HTTPS (Privacy)
        if protocol in ['DoT', 'DoH']:
            # Padding zu nächstem 128-Byte Block
            padding_size = 128 - (len(option.data) % 128) if len(option.data) % 128 != 0 else 0
            padding_data = b'\x00' * padding_size

            return dns.edns.GenericOption(dns.edns.PADDING, padding_data)

        return None

    async def _handle_jetdns_option(self, option: dns.edns.Option, client_ip: str, 
                                  protocol: str) -> Optional[dns.edns.Option]:
        """Behandelt JetDNS Custom Option"""

        # JetDNS-spezifische Informationen
        jetdns_info = {
            'version': self.config_manager.get_value('general', 'version', '1.0.0'),
            'features': ['dns64', 'rpz', 'ml_threat_detection', 'analytics'],
            'timestamp': int(asyncio.get_event_loop().time())
        }

        import json
        info_data = json.dumps(jetdns_info).encode('utf-8')

        return dns.edns.GenericOption(65001, info_data)

    def _get_option_name(self, option_type: int) -> str:
        """Gibt Namen für EDNS Option Type zurück"""
        option_names = {
            dns.edns.NSID: 'nsid',
            dns.edns.ECS: 'client_subnet',
            dns.edns.COOKIE: 'cookie',
            dns.edns.KEEPALIVE: 'keepalive',
            dns.edns.PADDING: 'padding',
            dns.edns.CHAIN: 'chain',
            65001: 'jetdns_custom'
        }

        return option_names.get(option_type, f'option_{option_type}')

    async def check_response_size(self, response: dns.message.Message, 
                                client_udp_payload: int, protocol: str) -> Tuple[bool, bool]:
        """Prüft Response-Größe gegen Client UDP Payload"""

        response_size = len(response.to_wire())
        needs_tcp_fallback = False
        is_large_response = False

        if protocol == 'UDP':
            if response_size > client_udp_payload:
                needs_tcp_fallback = True
                self.stats['tcp_fallbacks'] += 1

            threshold = self.config.get('tcp_fallback_threshold', 1472)
            if response_size > threshold:
                is_large_response = True
                self.stats['large_responses'] += 1

        return needs_tcp_fallback, is_large_response

    async def truncate_response(self, response: dns.message.Message) -> dns.message.Message:
        """Truncated Response für UDP Fallback"""

        truncated = dns.message.make_response(response)
        truncated.flags |= dns.flags.TC  # Truncated Flag setzen

        # Entferne Answer Records für minimale Response
        truncated.answer = []
        truncated.authority = []
        truncated.additional = []

        return truncated

    async def add_response_size_hint(self, response: dns.message.Message, 
                                   actual_size: int) -> dns.message.Message:
        """Fügt Response Size Hint als EDNS Option hinzu"""

        if not self.has_edns(response):
            return response

        # Custom Option für Response Size
        size_data = struct.pack('!I', actual_size)
        size_option = dns.edns.GenericOption(65002, size_data)  # JetDNS Response Size

        if response.options:
            response.options.append(size_option)
        else:
            response.options = [size_option]

        return response

    async def optimize_response_for_client(self, response: dns.message.Message, 
                                         client_capabilities: Dict) -> dns.message.Message:
        """Optimiert Response basierend auf Client Capabilities"""

        # Client UDP Payload berücksichtigen
        client_payload = client_capabilities.get('udp_payload', 512)

        # Kompression wenn nötig
        if len(response.to_wire()) > client_payload * 0.8:  # 80% Threshold
            response = await self._compress_response(response)

        return response

    async def _compress_response(self, response: dns.message.Message) -> dns.message.Message:
        """Komprimiert DNS Response"""

        # DNS Name Compression ist bereits im dnspython implementiert
        # Zusätzliche Optimierungen:

        # Entferne redundante Additional Records
        if len(response.additional) > 10:
            response.additional = response.additional[:10]

        # Verkürze TTL Values wenn sehr groß
        for rrset in response.answer + response.authority:
            if rrset.ttl > 86400:  # > 1 Tag
                rrset.ttl = 86400

        return response

    async def get_edns_stats(self) -> Dict:
        """Gibt EDNS Statistiken zurück"""
        return {
            'enabled': self.config.get('enabled', True),
            'max_udp_payload': self.max_udp_payload,
            'version': self.version,
            'supported_options': list(self.supported_options.keys()),
            'stats': self.stats
        }

    def supports_option(self, option_type: int) -> bool:
        """Prüft ob EDNS Option unterstützt wird"""
        return option_type in self.supported_options

    async def validate_edns_query(self, query: dns.message.Message) -> Tuple[bool, Optional[str]]:
        """Validiert EDNS Query"""

        if not self.has_edns(query):
            return True, None

        # Version Check
        if query.ednsversion > self.version:
            return False, f"Unsupported EDNS version: {query.ednsversion}"

        # Payload Size Check
        if query.payload > 65535:
            return False, f"Invalid UDP payload size: {query.payload}"

        # Options Check
        if query.options:
            for option in query.options:
                if option.otype < 0 or option.otype > 65535:
                    return False, f"Invalid EDNS option type: {option.otype}"

        return True, None

    async def create_edns_error_response(self, query: dns.message.Message, 
                                       error_code: int, error_msg: str) -> dns.message.Message:
        """Erstellt EDNS Error Response"""

        response = dns.message.make_response(query)
        response.set_rcode(error_code)

        if self.has_edns(query):
            # Error Info als EDNS Option
            error_data = error_msg.encode('utf-8')
            error_option = dns.edns.GenericOption(65003, error_data)  # JetDNS Error Info

            response.use_edns(
                edns=self.version,
                ednsflags=0,
                payload=self.max_udp_payload,
                options=[error_option]
            )

        return response
