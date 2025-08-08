"""
JetDNS DNS64/NAT64 Support
IPv6-IPv4 Translation für nahtlose Dual-Stack Netzwerke
"""

import asyncio
import ipaddress
import logging
import struct
from typing import Dict, List, Optional, Tuple
import dns.message
import dns.rdata
import dns.rdatatype
import dns.rrset

logger = logging.getLogger(__name__)

class DNS64Handler:
    """DNS64 Handler für IPv6-IPv4 Translation"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = {}

        # DNS64 Prefix (RFC 6052)
        self.dns64_prefix = None  # z.B. 64:ff9b::/96
        self.nat64_enabled = False

        # IPv4 Pool für NAT64
        self.ipv4_pool = []
        self.ipv4_mappings: Dict[str, str] = {}  # IPv6 -> IPv4
        self.ipv6_mappings: Dict[str, str] = {}  # IPv4 -> IPv6

        # Statistiken
        self.stats = {
            'dns64_queries': 0,
            'dns64_syntheses': 0,
            'nat64_translations': 0,
            'ipv6_to_ipv4': 0,
            'ipv4_to_ipv6': 0
        }

    async def initialize(self):
        """Initialisiert DNS64/NAT64 Handler"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("DNS64/NAT64 deaktiviert")
            return

        await self._setup_dns64_prefix()
        await self._setup_ipv4_pool()

        logger.info(f"🔄 DNS64/NAT64 initialisiert - Prefix: {self.dns64_prefix}")

    async def _load_config(self):
        """Lädt DNS64/NAT64 Konfiguration"""
        self.config = self.config_manager.get_config('dns64_nat64', {
            'enabled': False,
            'dns64_prefix': '64:ff9b::/96',  # Well-Known Prefix (RFC 6052)
            'nat64_enabled': True,
            'ipv4_pool': '192.168.100.1-192.168.100.100',
            'allow_rfc1918': True,  # Erlaube private IPv4 Adressen
            'ttl': 300
        })

    async def _setup_dns64_prefix(self):
        """Richtet DNS64 Prefix ein"""
        try:
            prefix_str = self.config.get('dns64_prefix', '64:ff9b::/96')
            self.dns64_prefix = ipaddress.IPv6Network(prefix_str, strict=False)

            logger.info(f"DNS64 Prefix konfiguriert: {self.dns64_prefix}")

        except ValueError as e:
            logger.error(f"Ungültiger DNS64 Prefix: {e}")
            self.dns64_prefix = ipaddress.IPv6Network('64:ff9b::/96')

    async def _setup_ipv4_pool(self):
        """Richtet IPv4 Pool für NAT64 ein"""
        try:
            pool_config = self.config.get('ipv4_pool', '192.168.100.1-192.168.100.100')

            if '-' in pool_config:
                start_str, end_str = pool_config.split('-')
                start_ip = ipaddress.IPv4Address(start_str.strip())
                end_ip = ipaddress.IPv4Address(end_str.strip())

                current_ip = start_ip
                while current_ip <= end_ip:
                    self.ipv4_pool.append(str(current_ip))
                    current_ip += 1

            logger.info(f"NAT64 IPv4 Pool: {len(self.ipv4_pool)} Adressen")

        except Exception as e:
            logger.error(f"Fehler bei IPv4 Pool Setup: {e}")

    async def handle_dns64_query(self, query_message: dns.message.Message, 
                                client_ip: str) -> Optional[dns.message.Message]:
        """Behandelt DNS64 Query (AAAA Request für IPv4-only Domain)"""

        if not self.config.get('enabled', False):
            return None

        # Nur AAAA Queries verarbeiten
        if not query_message.question:
            return None

        question = query_message.question[0]
        if question.rdtype != dns.rdatatype.AAAA:
            return None

        domain = str(question.name).rstrip('.')

        try:
            # Prüfe ob Client IPv6-fähig ist
            if not self._is_ipv6_client(client_ip):
                return None

            # Versuche A Record für Domain zu finden
            a_record = await self._resolve_a_record(domain)

            if a_record:
                # Synthetisiere AAAA Record aus A Record
                synthesized_aaaa = await self._synthesize_aaaa_record(a_record, domain)

                if synthesized_aaaa:
                    response = dns.message.make_response(query_message)
                    response.answer = [synthesized_aaaa]

                    self.stats['dns64_queries'] += 1
                    self.stats['dns64_syntheses'] += 1

                    logger.debug(f"DNS64 Synthesis: {domain} -> {synthesized_aaaa.to_text()}")
                    return response

        except Exception as e:
            logger.error(f"Fehler bei DNS64 Query für {domain}: {e}")

        return None

    def _is_ipv6_client(self, client_ip: str) -> bool:
        """Prüft ob Client IPv6-fähig ist"""
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            return isinstance(ip_obj, ipaddress.IPv6Address)
        except ValueError:
            return False

    async def _resolve_a_record(self, domain: str) -> Optional[str]:
        """Resolved A Record für Domain"""
        try:
            # Hier würde normalerweise der DNS Resolver aufgerufen
            # Für jetzt - Placeholder Implementation
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2

            try:
                answer = resolver.resolve(domain, 'A')
                if answer:
                    return str(answer[0])
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass

        except Exception as e:
            logger.debug(f"A Record Resolution fehgeschlagen für {domain}: {e}")

        return None

    async def _synthesize_aaaa_record(self, ipv4_addr: str, domain: str) -> Optional[dns.rrset.RRset]:
        """Synthetisiert AAAA Record aus IPv4 Adresse"""
        try:
            ipv4 = ipaddress.IPv4Address(ipv4_addr)

            # RFC 1918 Adressen prüfen
            if ipv4.is_private and not self.config.get('allow_rfc1918', True):
                logger.debug(f"RFC 1918 Adresse übersprungen: {ipv4_addr}")
                return None

            # Synthetisiere IPv6 Adresse mit DNS64 Prefix
            # Format: DNS64_PREFIX + IPv4 (embedded)

            # Well-Known Prefix 64:ff9b::/96
            if self.dns64_prefix.prefixlen == 96:
                # IPv4 in die letzten 32 Bits einbetten
                prefix_int = int(self.dns64_prefix.network_address)
                ipv4_int = int(ipv4)

                ipv6_int = prefix_int | ipv4_int
                ipv6_addr = ipaddress.IPv6Address(ipv6_int)

            else:
                # Andere Prefix-Längen (RFC 6052)
                logger.warning(f"Nicht-standard DNS64 Prefix: {self.dns64_prefix}")
                return None

            # Erstelle AAAA RRset
            ttl = self.config.get('ttl', 300)
            rdata = dns.rdata.from_text('IN', 'AAAA', str(ipv6_addr))
            rrset = dns.rrset.from_rdata(domain, ttl, rdata)

            # Speichere Mapping für NAT64
            if self.config.get('nat64_enabled', True):
                self.ipv6_mappings[ipv4_addr] = str(ipv6_addr)
                self.ipv4_mappings[str(ipv6_addr)] = ipv4_addr

            return rrset

        except Exception as e:
            logger.error(f"Fehler bei AAAA Synthesis für {ipv4_addr}: {e}")
            return None

    async def handle_nat64_translation(self, packet_data: bytes, 
                                     direction: str) -> Optional[bytes]:
        """Behandelt NAT64 Packet Translation"""

        if not self.config.get('nat64_enabled', True):
            return None

        try:
            if direction == 'ipv6_to_ipv4':
                return await self._translate_ipv6_to_ipv4(packet_data)
            elif direction == 'ipv4_to_ipv6':
                return await self._translate_ipv4_to_ipv6(packet_data)

        except Exception as e:
            logger.error(f"Fehler bei NAT64 Translation ({direction}): {e}")

        return None

    async def _translate_ipv6_to_ipv4(self, ipv6_packet: bytes) -> Optional[bytes]:
        """Übersetzt IPv6 Packet zu IPv4"""
        try:
            # IPv6 Header parsen (vereinfacht)
            if len(ipv6_packet) < 40:
                return None

            # IPv6 Header: Version(4) + Traffic Class(8) + Flow Label(20) + ...
            version_tc_fl = struct.unpack('!I', ipv6_packet[0:4])[0]
            version = (version_tc_fl >> 28) & 0xF

            if version != 6:
                return None

            # Source und Destination IPv6 Adressen
            src_ipv6 = ipaddress.IPv6Address(ipv6_packet[8:24])
            dst_ipv6 = ipaddress.IPv6Address(ipv6_packet[24:40])

            # Prüfe ob Destination in DNS64 Prefix
            if dst_ipv6 not in self.dns64_prefix:
                return None

            # Extrahiere embedded IPv4 aus IPv6
            dst_ipv4 = self._extract_ipv4_from_dns64(dst_ipv6)
            if not dst_ipv4:
                return None

            # Source IPv6 zu IPv4 mappen (NAT64 Pool)
            src_ipv4 = await self._allocate_nat64_ipv4(str(src_ipv6))
            if not src_ipv4:
                return None

            # IPv4 Packet erstellen (vereinfacht)
            # Hier würde vollständige IP Header Translation stattfinden

            self.stats['nat64_translations'] += 1
            self.stats['ipv6_to_ipv4'] += 1

            logger.debug(f"NAT64 IPv6->IPv4: {src_ipv6} -> {src_ipv4}, {dst_ipv6} -> {dst_ipv4}")

            # Placeholder für vollständiges IPv4 Packet
            return b''  # Würde vollständiges IPv4 Packet zurückgeben

        except Exception as e:
            logger.error(f"Fehler bei IPv6->IPv4 Translation: {e}")
            return None

    def _extract_ipv4_from_dns64(self, ipv6_addr: ipaddress.IPv6Address) -> Optional[str]:
        """Extrahiert embedded IPv4 aus DNS64 IPv6 Adresse"""
        try:
            if self.dns64_prefix.prefixlen == 96:
                # Letzten 32 Bits extrahieren
                ipv6_int = int(ipv6_addr)
                ipv4_int = ipv6_int & 0xFFFFFFFF
                return str(ipaddress.IPv4Address(ipv4_int))

        except Exception as e:
            logger.debug(f"IPv4 Extraktion fehlgeschlagen: {e}")

        return None

    async def _allocate_nat64_ipv4(self, ipv6_addr: str) -> Optional[str]:
        """Alloziert IPv4 Adresse aus NAT64 Pool"""

        # Prüfe existierende Mappings
        if ipv6_addr in self.ipv4_mappings:
            return self.ipv4_mappings[ipv6_addr]

        # Alloziere neue IPv4 aus Pool
        for ipv4 in self.ipv4_pool:
            if ipv4 not in self.ipv6_mappings:
                self.ipv4_mappings[ipv6_addr] = ipv4
                self.ipv6_mappings[ipv4] = ipv6_addr
                return ipv4

        logger.warning("NAT64 IPv4 Pool erschöpft")
        return None

    async def _translate_ipv4_to_ipv6(self, ipv4_packet: bytes) -> Optional[bytes]:
        """Übersetzt IPv4 Packet zu IPv6"""
        try:
            # IPv4 Header parsen
            if len(ipv4_packet) < 20:
                return None

            version_ihl = struct.unpack('!B', ipv4_packet[0:1])[0]
            version = (version_ihl >> 4) & 0xF

            if version != 4:
                return None

            # Source und Destination IPv4 Adressen
            src_ipv4 = ipaddress.IPv4Address(ipv4_packet[12:16])
            dst_ipv4 = ipaddress.IPv4Address(ipv4_packet[16:20])

            # IPv4 zu IPv6 mappen
            src_ipv6 = self.ipv6_mappings.get(str(src_ipv4))
            if not src_ipv6:
                return None

            # Destination IPv4 in DNS64 IPv6 einbetten
            dst_ipv6 = await self._embed_ipv4_in_dns64(str(dst_ipv4))
            if not dst_ipv6:
                return None

            self.stats['nat64_translations'] += 1
            self.stats['ipv4_to_ipv6'] += 1

            logger.debug(f"NAT64 IPv4->IPv6: {src_ipv4} -> {src_ipv6}, {dst_ipv4} -> {dst_ipv6}")

            # Placeholder für vollständiges IPv6 Packet
            return b''  # Würde vollständiges IPv6 Packet zurückgeben

        except Exception as e:
            logger.error(f"Fehler bei IPv4->IPv6 Translation: {e}")
            return None

    async def _embed_ipv4_in_dns64(self, ipv4_addr: str) -> Optional[str]:
        """Bettet IPv4 Adresse in DNS64 IPv6 ein"""
        try:
            ipv4 = ipaddress.IPv4Address(ipv4_addr)

            if self.dns64_prefix.prefixlen == 96:
                prefix_int = int(self.dns64_prefix.network_address)
                ipv4_int = int(ipv4)
                ipv6_int = prefix_int | ipv4_int
                return str(ipaddress.IPv6Address(ipv6_int))

        except Exception as e:
            logger.debug(f"IPv4 Embedding fehlgeschlagen: {e}")

        return None

    async def get_dns64_stats(self) -> Dict:
        """Gibt DNS64/NAT64 Statistiken zurück"""
        return {
            'enabled': self.config.get('enabled', False),
            'dns64_prefix': str(self.dns64_prefix) if self.dns64_prefix else None,
            'nat64_enabled': self.config.get('nat64_enabled', True),
            'ipv4_pool_size': len(self.ipv4_pool),
            'ipv4_pool_used': len(self.ipv6_mappings),
            'active_mappings': len(self.ipv4_mappings),
            'stats': self.stats
        }

    async def cleanup_stale_mappings(self):
        """Bereinigt veraltete NAT64 Mappings"""
        # Hier würde Logic für Cleanup basierend auf Inaktivität implementiert
        pass

    def is_dns64_address(self, ipv6_addr: str) -> bool:
        """Prüft ob IPv6 Adresse DNS64-synthetisiert ist"""
        try:
            ipv6 = ipaddress.IPv6Address(ipv6_addr)
            return ipv6 in self.dns64_prefix if self.dns64_prefix else False
        except ValueError:
            return False

    async def reverse_dns64_lookup(self, ipv6_addr: str) -> Optional[str]:
        """Führt Reverse Lookup für DNS64 Adresse durch"""
        try:
            if not self.is_dns64_address(ipv6_addr):
                return None

            # Extrahiere embedded IPv4
            ipv4 = self._extract_ipv4_from_dns64(ipaddress.IPv6Address(ipv6_addr))
            if ipv4:
                # Führe PTR Query für IPv4 durch
                import dns.resolver

                resolver = dns.resolver.Resolver()
                reversed_addr = dns.reversename.from_address(ipv4)

                try:
                    answer = resolver.resolve(reversed_addr, 'PTR')
                    if answer:
                        return str(answer[0]).rstrip('.')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass

        except Exception as e:
            logger.debug(f"Reverse DNS64 Lookup fehlgeschlagen: {e}")

        return None
