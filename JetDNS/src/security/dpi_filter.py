"""
JetDNS Deep Packet Inspection (DPI) System
Advanced Application Layer Filtering and Content Analysis
"""

import asyncio
import json
import logging
import time
import sqlite3
import threading
import struct
import socket
from typing import Dict, List, Tuple, Optional, Set, Any, Union
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import re
import hashlib
from pathlib import Path
import ipaddress

try:
    import scapy.all as scapy
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy nicht verfügbar - DPI-Features eingeschränkt")

class ProtocolType(Enum):
    """Protokoll-Typen"""
    DNS_UDP = "dns_udp"
    DNS_TCP = "dns_tcp" 
    DNS_OVER_HTTPS = "dns_over_https"
    DNS_OVER_TLS = "dns_over_tls"
    DNS_OVER_QUIC = "dns_over_quic"
    HTTP = "http"
    HTTPS = "https"
    UNKNOWN = "unknown"

class FilterAction(Enum):
    """Filter-Aktionen"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    MODIFY = "modify"
    LOG = "log"

class ThreatLevel(Enum):
    """Bedrohungsstufen"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class PacketInfo:
    """Paket-Informationen"""
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: ProtocolType
    packet_size: int
    flags: Dict[str, bool]
    payload_size: int
    payload_hash: str

@dataclass
class DNSPacketAnalysis:
    """DNS-Paket-Analyse"""
    packet_info: PacketInfo
    query_name: str
    query_type: str
    query_class: str
    response_code: Optional[str]
    answer_count: int
    authority_count: int
    additional_count: int
    flags: Dict[str, bool]
    edns_present: bool
    dnssec_ok: bool
    suspicious_patterns: List[str]
    anomaly_score: float

@dataclass
class ContentFilter:
    """Content-Filter Regel"""
    filter_id: str
    name: str
    description: str
    pattern_type: str  # 'regex', 'string', 'domain', 'ip'
    pattern: str
    action: FilterAction
    threat_level: ThreatLevel
    protocol_scope: List[ProtocolType]
    active: bool = True
    created_at: float = 0.0
    last_triggered: float = 0.0
    trigger_count: int = 0

@dataclass
class DPIAlert:
    """DPI-Alert"""
    alert_id: str
    timestamp: float
    source_ip: str
    threat_level: ThreatLevel
    filter_id: str
    description: str
    packet_info: PacketInfo
    dns_analysis: Optional[DNSPacketAnalysis]
    evidence: Dict
    status: str = "active"

class AdvancedDPIFilter:
    """
    Fortschrittliches Deep Packet Inspection System
    - DNS-Paket-Analyse
    - Protokoll-Erkennung
    - Content-Filtering
    - Anomalie-Erkennung
    - Traffic-Pattern-Analyse
    """

    def __init__(self, config_path: str = "config/dpi_filter.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)

        # Filter und Regeln
        self.content_filters: Dict[str, ContentFilter] = {}
        self.protocol_handlers = {}
        self.dpi_alerts: Dict[str, DPIAlert] = {}

        # Pattern und Signaturen
        self.malware_signatures = {}
        self.suspicious_patterns = []
        self.dns_tunneling_patterns = []
        self.exfiltration_patterns = []

        # Traffic-Analyse
        self.traffic_flows: Dict[str, Dict] = {}  # flow_id -> flow_info
        self.connection_states: Dict[str, Dict] = {}
        self.protocol_stats: Dict[ProtocolType, Dict] = defaultdict(dict)

        # Anomalie-Erkennung
        self.baseline_metrics = {}
        self.anomaly_thresholds = {}
        self.behavioral_profiles: Dict[str, Dict] = {}

        # Caches und Buffer
        self.packet_buffer: deque = deque(maxlen=10000)
        self.analysis_cache: Dict[str, Any] = {}
        self.dns_cache: Dict[str, DNSPacketAnalysis] = {}

        # Statistiken
        self.stats = {
            'packets_analyzed': 0,
            'threats_detected': 0,
            'dns_queries_inspected': 0,
            'suspicious_patterns_found': 0,
            'blocked_connections': 0,
            'data_exfiltration_attempts': 0,
            'malware_signatures_matched': 0,
            'anomalies_detected': 0
        }

        # Konfiguration
        self.config = {}

        # Threading
        self.lock = threading.RLock()

        # Initialisierung
        self._load_configuration()
        self._initialize_database()
        self._load_signatures()
        self._initialize_protocol_handlers()
        self._load_content_filters()
        self._start_background_tasks()

    def _load_configuration(self):
        """Lädt Konfiguration"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                # Standard-Konfiguration
                self.config = {
                    'dpi_analysis': {
                        'enabled': True,
                        'deep_inspection': True,
                        'payload_analysis': True,
                        'protocol_detection': True,
                        'anomaly_detection': True
                    },
                    'dns_inspection': {
                        'tunnel_detection': True,
                        'exfiltration_detection': True,
                        'malformed_packet_detection': True,
                        'suspicious_tld_detection': True,
                        'base64_encoding_detection': True
                    },
                    'content_filtering': {
                        'domain_filtering': True,
                        'ip_filtering': True,
                        'pattern_matching': True,
                        'regex_filtering': True,
                        'case_sensitive': False
                    },
                    'traffic_analysis': {
                        'flow_tracking': True,
                        'connection_profiling': True,
                        'bandwidth_analysis': True,
                        'pattern_recognition': True,
                        'behavioral_analysis': True
                    },
                    'alerting': {
                        'real_time_alerts': True,
                        'severity_filtering': True,
                        'alert_aggregation': True,
                        'false_positive_reduction': True
                    },
                    'thresholds': {
                        'dns_tunnel_threshold': 0.7,
                        'anomaly_threshold': 0.8,
                        'suspicious_pattern_threshold': 3,
                        'data_exfiltration_threshold': 1000000,  # 1MB
                        'query_entropy_threshold': 4.5
                    },
                    'performance': {
                        'max_concurrent_analysis': 100,
                        'packet_buffer_size': 10000,
                        'analysis_timeout': 5.0,
                        'cache_ttl': 300
                    }
                }
                self._save_configuration()
        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Konfiguration: {e}")

    def _save_configuration(self):
        """Speichert Konfiguration"""
        try:
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            self.logger.error(f"Fehler beim Speichern der Konfiguration: {e}")

    def _initialize_database(self):
        """Initialisiert SQLite-Datenbank"""
        try:
            self.db_path = Path("data/dpi_filter.db")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS content_filters (
                    filter_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    pattern_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    protocol_scope TEXT,
                    active INTEGER DEFAULT 1,
                    created_at REAL NOT NULL,
                    last_triggered REAL,
                    trigger_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS dpi_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    filter_id TEXT,
                    description TEXT NOT NULL,
                    packet_info TEXT,
                    dns_analysis TEXT,
                    evidence TEXT,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (filter_id) REFERENCES content_filters (filter_id)
                );

                CREATE TABLE IF NOT EXISTS traffic_flows (
                    flow_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    source_port INTEGER,
                    dest_port INTEGER,
                    protocol TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    packet_count INTEGER DEFAULT 0,
                    byte_count INTEGER DEFAULT 0,
                    flags TEXT,
                    status TEXT DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS packet_analysis (
                    analysis_id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    results TEXT NOT NULL,
                    anomaly_score REAL,
                    threat_detected INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS malware_signatures (
                    signature_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    protocol TEXT,
                    active INTEGER DEFAULT 1,
                    last_updated REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON dpi_alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_source ON dpi_alerts(source_ip);
                CREATE INDEX IF NOT EXISTS idx_flows_source ON traffic_flows(source_ip);
                CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON packet_analysis(timestamp);
            """)

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Fehler beim Initialisieren der Datenbank: {e}")

    def _load_signatures(self):
        """Lädt Malware-Signaturen"""
        try:
            # Standard-Signaturen
            default_signatures = {
                'dns_tunnel_base64': {
                    'pattern': r'[A-Za-z0-9+/]{20,}={0,2}',
                    'type': 'regex',
                    'threat_level': ThreatLevel.HIGH,
                    'description': 'Base64-kodierte DNS-Tunneling-Daten'
                },
                'dns_tunnel_hex': {
                    'pattern': r'[a-fA-F0-9]{32,}',
                    'type': 'regex',
                    'threat_level': ThreatLevel.MEDIUM,
                    'description': 'Hex-kodierte DNS-Tunneling-Daten'
                },
                'suspicious_tld': {
                    'pattern': r'\.(tk|ml|ga|cf|gq)$',
                    'type': 'regex',
                    'threat_level': ThreatLevel.MEDIUM,
                    'description': 'Verdächtige Top-Level-Domain'
                },
                'dga_domain': {
                    'pattern': r'^[a-z]{10,}\.com$',
                    'type': 'regex',
                    'threat_level': ThreatLevel.HIGH,
                    'description': 'Domain Generation Algorithm (DGA) Muster'
                },
                'c2_communication': {
                    'pattern': r'(bot|c2|command|control|cnc)',
                    'type': 'string',
                    'threat_level': ThreatLevel.CRITICAL,
                    'description': 'Command & Control Kommunikation'
                }
            }

            # Signaturen in Datenbank laden
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            current_time = time.time()

            for sig_id, sig_data in default_signatures.items():
                cursor.execute("""
                    INSERT OR REPLACE INTO malware_signatures 
                    (signature_id, name, pattern, pattern_type, threat_level, 
                     protocol, active, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (sig_id, sig_data['description'], sig_data['pattern'], 
                      sig_data['type'], sig_data['threat_level'].value, 
                      'DNS', current_time))

            conn.commit()

            # Signaturen in Memory laden
            cursor.execute("SELECT * FROM malware_signatures WHERE active = 1")
            signatures = cursor.fetchall()

            for sig in signatures:
                sig_id, name, pattern, pattern_type, threat_level, protocol, active, last_updated = sig
                self.malware_signatures[sig_id] = {
                    'name': name,
                    'pattern': pattern,
                    'pattern_type': pattern_type,
                    'threat_level': ThreatLevel(threat_level),
                    'protocol': protocol,
                    'compiled_pattern': re.compile(pattern, re.IGNORECASE) if pattern_type == 'regex' else None
                }

            conn.close()
            self.logger.info(f"Geladen: {len(self.malware_signatures)} Malware-Signaturen")

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Signaturen: {e}")

    def _initialize_protocol_handlers(self):
        """Initialisiert Protokoll-Handler"""
        try:
            self.protocol_handlers = {
                ProtocolType.DNS_UDP: self._analyze_dns_udp,
                ProtocolType.DNS_TCP: self._analyze_dns_tcp,
                ProtocolType.DNS_OVER_HTTPS: self._analyze_doh,
                ProtocolType.DNS_OVER_TLS: self._analyze_dot,
                ProtocolType.HTTP: self._analyze_http,
                ProtocolType.HTTPS: self._analyze_https
            }

            self.logger.info("Protokoll-Handler initialisiert")

        except Exception as e:
            self.logger.error(f"Fehler beim Initialisieren der Protokoll-Handler: {e}")

    def _load_content_filters(self):
        """Lädt Content-Filter aus der Datenbank"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM content_filters WHERE active = 1")
            filters = cursor.fetchall()

            for filter_data in filters:
                (filter_id, name, description, pattern_type, pattern, action,
                 threat_level, protocol_scope_json, active, created_at,
                 last_triggered, trigger_count) = filter_data

                protocol_scope = json.loads(protocol_scope_json) if protocol_scope_json else []
                protocol_scope = [ProtocolType(p) for p in protocol_scope]

                content_filter = ContentFilter(
                    filter_id=filter_id,
                    name=name,
                    description=description,
                    pattern_type=pattern_type,
                    pattern=pattern,
                    action=FilterAction(action),
                    threat_level=ThreatLevel(threat_level),
                    protocol_scope=protocol_scope,
                    active=bool(active),
                    created_at=created_at,
                    last_triggered=last_triggered,
                    trigger_count=trigger_count
                )

                self.content_filters[filter_id] = content_filter

            conn.close()
            self.logger.info(f"Geladen: {len(self.content_filters)} Content-Filter")

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Content-Filter: {e}")

    async def analyze_packet(self, packet_data: bytes, source_ip: str, 
                           dest_ip: str, source_port: int = 0, dest_port: int = 53) -> Dict:
        """Analysiert Paket mit Deep Packet Inspection"""
        try:
            self.stats['packets_analyzed'] += 1

            # Packet-Info erstellen
            packet_info = PacketInfo(
                timestamp=time.time(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=self._detect_protocol(packet_data, dest_port),
                packet_size=len(packet_data),
                flags={},
                payload_size=len(packet_data),
                payload_hash=hashlib.md5(packet_data).hexdigest()
            )

            # Cache-Check
            cache_key = f"{packet_info.payload_hash}_{packet_info.protocol.value}"
            if cache_key in self.analysis_cache:
                cached_result = self.analysis_cache[cache_key]
                if time.time() - cached_result['timestamp'] < self.config['performance']['cache_ttl']:
                    return cached_result['result']

            # DPI-Analyse durchführen
            analysis_result = {
                'packet_info': asdict(packet_info),
                'protocol_analysis': {},
                'content_analysis': {},
                'threat_analysis': {},
                'action': FilterAction.ALLOW,
                'alerts': []
            }

            # Protokoll-spezifische Analyse
            if packet_info.protocol in self.protocol_handlers:
                protocol_result = await self.protocol_handlers[packet_info.protocol](
                    packet_data, packet_info
                )
                analysis_result['protocol_analysis'] = protocol_result

            # Content-Filtering
            content_result = await self._apply_content_filters(packet_data, packet_info)
            analysis_result['content_analysis'] = content_result

            # Malware-Signatur-Matching
            signature_result = await self._check_malware_signatures(packet_data, packet_info)
            analysis_result['threat_analysis'] = signature_result

            # Anomalie-Erkennung
            anomaly_result = await self._detect_anomalies(packet_data, packet_info)
            analysis_result['anomaly_analysis'] = anomaly_result

            # Finale Entscheidung treffen
            final_action = self._determine_final_action(analysis_result)
            analysis_result['action'] = final_action

            # Traffic-Flow aktualisieren
            await self._update_traffic_flow(packet_info, analysis_result)

            # Alerts generieren
            if final_action != FilterAction.ALLOW:
                alerts = await self._generate_alerts(packet_info, analysis_result)
                analysis_result['alerts'] = alerts

            # Cache aktualisieren
            self.analysis_cache[cache_key] = {
                'timestamp': time.time(),
                'result': analysis_result
            }

            return analysis_result

        except Exception as e:
            self.logger.error(f"Fehler bei der Paket-Analyse: {e}")
            return {
                'packet_info': {},
                'action': FilterAction.ALLOW,
                'error': str(e)
            }

    def _detect_protocol(self, packet_data: bytes, dest_port: int) -> ProtocolType:
        """Erkennt Protokoll basierend auf Port und Payload"""
        try:
            # Port-basierte Erkennung
            if dest_port == 53:
                if len(packet_data) > 2:
                    # TCP DNS hat Length-Header
                    if len(packet_data) > 12 and struct.unpack('!H', packet_data[:2])[0] == len(packet_data) - 2:
                        return ProtocolType.DNS_TCP
                    else:
                        return ProtocolType.DNS_UDP
            elif dest_port == 443:
                # HTTPS/DoT/DoH Detection
                if packet_data.startswith(b'\x16\x03'):  # TLS Handshake
                    return ProtocolType.DNS_OVER_TLS
                return ProtocolType.HTTPS
            elif dest_port == 80:
                if b'HTTP' in packet_data[:100]:
                    return ProtocolType.HTTP
            elif dest_port == 853:
                return ProtocolType.DNS_OVER_TLS

            # Payload-basierte Deep Detection
            if SCAPY_AVAILABLE:
                try:
                    # Scapy Packet-Parsing
                    if len(packet_data) >= 12:  # Minimum DNS Header
                        # DNS Header Struktur prüfen
                        header = struct.unpack('!HHHHHH', packet_data[:12])
                        qr, opcode, aa, tc, rd, ra, z, rcode = self._parse_dns_flags(header[1])

                        if opcode == 0 and (qr == 0 or qr == 1):  # Standard Query/Response
                            return ProtocolType.DNS_UDP
                except:
                    pass

            return ProtocolType.UNKNOWN

        except Exception as e:
            self.logger.error(f"Fehler bei Protokoll-Erkennung: {e}")
            return ProtocolType.UNKNOWN

    def _parse_dns_flags(self, flags: int) -> Tuple[int, int, int, int, int, int, int, int]:
        """Parst DNS-Flags"""
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        tc = (flags >> 9) & 1
        rd = (flags >> 8) & 1
        ra = (flags >> 7) & 1
        z = (flags >> 4) & 7
        rcode = flags & 0xF

        return qr, opcode, aa, tc, rd, ra, z, rcode

    async def _analyze_dns_udp(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert DNS-UDP-Paket"""
        try:
            self.stats['dns_queries_inspected'] += 1

            if len(packet_data) < 12:
                return {'error': 'packet_too_short', 'malformed': True}

            # DNS Header parsen
            header = struct.unpack('!HHHHHH', packet_data[:12])
            transaction_id, flags, qdcount, ancount, nscount, arcount = header

            qr, opcode, aa, tc, rd, ra, z, rcode = self._parse_dns_flags(flags)

            analysis = {
                'header': {
                    'transaction_id': transaction_id,
                    'flags': {
                        'qr': bool(qr),
                        'opcode': opcode,
                        'aa': bool(aa),
                        'tc': bool(tc),
                        'rd': bool(rd),
                        'ra': bool(ra),
                        'rcode': rcode
                    },
                    'questions': qdcount,
                    'answers': ancount,
                    'authority': nscount,
                    'additional': arcount
                },
                'queries': [],
                'answers': [],
                'suspicious_indicators': [],
                'anomaly_score': 0.0
            }

            # DNS Queries parsen
            offset = 12
            for i in range(qdcount):
                try:
                    query_name, offset = self._parse_dns_name(packet_data, offset)
                    if offset + 4 <= len(packet_data):
                        qtype, qclass = struct.unpack('!HH', packet_data[offset:offset+4])
                        offset += 4

                        query_info = {
                            'name': query_name,
                            'type': qtype,
                            'class': qclass
                        }
                        analysis['queries'].append(query_info)

                        # DNS-Tunneling-Erkennung
                        tunnel_analysis = await self._detect_dns_tunneling(query_name, packet_data)
                        if tunnel_analysis['tunneling_detected']:
                            analysis['suspicious_indicators'].extend(tunnel_analysis['indicators'])
                            analysis['anomaly_score'] += 0.4

                        # Suspicious Patterns
                        pattern_analysis = self._check_suspicious_patterns(query_name)
                        if pattern_analysis['suspicious']:
                            analysis['suspicious_indicators'].extend(pattern_analysis['patterns'])
                            analysis['anomaly_score'] += 0.2

                except Exception as e:
                    analysis['parsing_errors'] = analysis.get('parsing_errors', [])
                    analysis['parsing_errors'].append(str(e))
                    break

            # DNS Answers parsen (wenn Response)
            if qr == 1 and ancount > 0:
                try:
                    for i in range(ancount):
                        answer_info = self._parse_dns_answer(packet_data, offset)
                        if answer_info:
                            analysis['answers'].append(answer_info)
                            offset = answer_info.get('next_offset', offset)
                except Exception as e:
                    analysis['answer_parsing_error'] = str(e)

            # Malformed Packet Detection
            if self._is_malformed_dns(packet_data, analysis):
                analysis['malformed'] = True
                analysis['anomaly_score'] += 0.3

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei DNS-UDP-Analyse: {e}")
            return {'error': str(e), 'analysis_failed': True}

    def _parse_dns_name(self, packet_data: bytes, offset: int) -> Tuple[str, int]:
        """Parst DNS-Name mit Compression-Support"""
        try:
            name_parts = []
            original_offset = offset
            jumped = False
            max_jumps = 10  # Prevent infinite loops
            jumps = 0

            while offset < len(packet_data) and jumps < max_jumps:
                length = packet_data[offset]

                if length == 0:  # End of name
                    offset += 1
                    break
                elif (length & 0xC0) == 0xC0:  # Compression pointer
                    if not jumped:
                        original_offset = offset + 2
                        jumped = True

                    pointer = struct.unpack('!H', packet_data[offset:offset+2])[0] & 0x3FFF
                    offset = pointer
                    jumps += 1
                else:  # Regular label
                    if offset + length + 1 > len(packet_data):
                        break

                    label = packet_data[offset+1:offset+1+length].decode('utf-8', errors='replace')
                    name_parts.append(label)
                    offset += length + 1

            domain_name = '.'.join(name_parts)
            return domain_name, original_offset if jumped else offset

        except Exception as e:
            self.logger.error(f"Fehler beim DNS-Name-Parsing: {e}")
            return '', offset + 1

    def _parse_dns_answer(self, packet_data: bytes, offset: int) -> Dict:
        """Parst DNS-Answer-Record"""
        try:
            # Name
            name, offset = self._parse_dns_name(packet_data, offset)

            if offset + 10 > len(packet_data):
                return None

            # Type, Class, TTL, RDLength
            type_val, class_val, ttl, rdlength = struct.unpack('!HHIH', packet_data[offset:offset+10])
            offset += 10

            # RData
            if offset + rdlength > len(packet_data):
                return None

            rdata = packet_data[offset:offset+rdlength]
            offset += rdlength

            # RData interpretieren basierend auf Type
            rdata_str = self._interpret_rdata(type_val, rdata)

            return {
                'name': name,
                'type': type_val,
                'class': class_val,
                'ttl': ttl,
                'rdata': rdata_str,
                'next_offset': offset
            }

        except Exception as e:
            self.logger.error(f"Fehler beim DNS-Answer-Parsing: {e}")
            return None

    def _interpret_rdata(self, record_type: int, rdata: bytes) -> str:
        """Interpretiert RData basierend auf Record-Type"""
        try:
            if record_type == 1:  # A Record
                if len(rdata) == 4:
                    return '.'.join(str(b) for b in rdata)
            elif record_type == 28:  # AAAA Record
                if len(rdata) == 16:
                    return str(ipaddress.IPv6Address(rdata))
            elif record_type == 5:  # CNAME
                # Domain Name in RData
                name, _ = self._parse_dns_name(rdata + b'\x00', 0)
                return name
            elif record_type == 16:  # TXT Record
                # TXT Records können mehrere Strings enthalten
                txt_parts = []
                offset = 0
                while offset < len(rdata):
                    length = rdata[offset]
                    if offset + length + 1 > len(rdata):
                        break
                    txt_parts.append(rdata[offset+1:offset+1+length].decode('utf-8', errors='replace'))
                    offset += length + 1
                return ' '.join(txt_parts)

            # Fallback: Hex representation
            return rdata.hex()

        except Exception as e:
            return f"parse_error:{e}"

    async def _detect_dns_tunneling(self, domain: str, packet_data: bytes) -> Dict:
        """Erkennt DNS-Tunneling"""
        try:
            indicators = []
            tunneling_score = 0.0

            # Subdomain-Länge prüfen
            parts = domain.split('.')
            if len(parts) > 0:
                subdomain = parts[0]

                # Ungewöhnlich lange Subdomains
                if len(subdomain) > 50:
                    indicators.append(f"long_subdomain:{len(subdomain)}")
                    tunneling_score += 0.3

                # Base64-ähnliche Patterns
                if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', subdomain):
                    indicators.append("base64_pattern")
                    tunneling_score += 0.4

                # Hex-ähnliche Patterns
                if re.match(r'^[a-fA-F0-9]{32,}$', subdomain):
                    indicators.append("hex_pattern")
                    tunneling_score += 0.3

                # Hohe Entropie
                entropy = self._calculate_entropy(subdomain)
                if entropy > self.config['thresholds']['query_entropy_threshold']:
                    indicators.append(f"high_entropy:{entropy:.2f}")
                    tunneling_score += 0.3

                # Ungewöhnliche Zeichen-Verteilung
                char_dist = self._analyze_character_distribution(subdomain)
                if char_dist['unusual']:
                    indicators.append("unusual_char_distribution")
                    tunneling_score += 0.2

            # Query-Frequenz für diese Domain
            domain_stats = self._get_domain_query_stats(domain)
            if domain_stats['high_frequency']:
                indicators.append(f"high_query_frequency:{domain_stats['queries_per_minute']}")
                tunneling_score += 0.2

            # Packet-Größe Anomalien
            if len(packet_data) > 512:  # Größer als Standard-DNS
                indicators.append(f"large_packet:{len(packet_data)}")
                tunneling_score += 0.1

            return {
                'tunneling_detected': tunneling_score >= self.config['thresholds']['dns_tunnel_threshold'],
                'tunneling_score': tunneling_score,
                'indicators': indicators,
                'domain_analysis': {
                    'entropy': self._calculate_entropy(subdomain) if 'subdomain' in locals() else 0,
                    'length': len(domain),
                    'subdomain_count': len(parts)
                }
            }

        except Exception as e:
            self.logger.error(f"Fehler bei DNS-Tunneling-Erkennung: {e}")
            return {'tunneling_detected': False, 'error': str(e)}

    def _calculate_entropy(self, data: str) -> float:
        """Berechnet Shannon-Entropie"""
        try:
            if not data:
                return 0.0

            char_counts = {}
            for char in data:
                char_counts[char] = char_counts.get(char, 0) + 1

            entropy = 0.0
            data_len = len(data)

            for count in char_counts.values():
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0

            return entropy

        except Exception as e:
            self.logger.error(f"Fehler bei Entropie-Berechnung: {e}")
            return 0.0

    def _analyze_character_distribution(self, text: str) -> Dict:
        """Analysiert Zeichen-Verteilung"""
        try:
            if not text:
                return {'unusual': False}

            char_types = {
                'alpha': sum(1 for c in text if c.isalpha()),
                'digit': sum(1 for c in text if c.isdigit()),
                'special': sum(1 for c in text if not c.isalnum())
            }

            total = len(text)
            ratios = {k: v / total for k, v in char_types.items()}

            # Ungewöhnliche Verteilungen erkennen
            unusual = (
                ratios['digit'] > 0.7 or  # Zu viele Ziffern
                ratios['special'] > 0.3 or  # Zu viele Sonderzeichen
                (ratios['alpha'] < 0.3 and ratios['digit'] > 0.5)  # Unausgewogen
            )

            return {
                'unusual': unusual,
                'ratios': ratios,
                'char_types': char_types
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Zeichen-Analyse: {e}")
            return {'unusual': False, 'error': str(e)}

    def _get_domain_query_stats(self, domain: str) -> Dict:
        """Holt Domain-Query-Statistiken"""
        try:
            current_time = time.time()
            time_window = 60  # 1 Minute

            # Query-Counts für letzte Minute
            recent_queries = 0
            for packet in self.packet_buffer:
                if (current_time - packet.get('timestamp', 0) < time_window and
                    packet.get('domain') == domain):
                    recent_queries += 1

            return {
                'queries_per_minute': recent_queries,
                'high_frequency': recent_queries > 100,  # Threshold
                'domain': domain
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Domain-Stats: {e}")
            return {'queries_per_minute': 0, 'high_frequency': False}

    def _check_suspicious_patterns(self, domain: str) -> Dict:
        """Prüft auf verdächtige Patterns"""
        try:
            patterns_found = []

            # Bekannte Malware-Patterns
            malware_patterns = [
                (r'\.tk$', 'suspicious_tld'),
                (r'^[a-z]{8,12}\.com$', 'dga_pattern'),
                (r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}', 'ip_in_domain'),
                (r'(bot|c2|cmd|exec|shell)', 'malware_keywords'),
                (r'^[a-f0-9]{32}', 'md5_hash_pattern')
            ]

            for pattern, description in malware_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    patterns_found.append(description)

            return {
                'suspicious': len(patterns_found) > 0,
                'patterns': patterns_found,
                'pattern_count': len(patterns_found)
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Pattern-Check: {e}")
            return {'suspicious': False, 'patterns': []}

    def _is_malformed_dns(self, packet_data: bytes, analysis: Dict) -> bool:
        """Prüft auf malformierte DNS-Pakete"""
        try:
            # Grundlegende Größen-Checks
            if len(packet_data) < 12:  # Minimum DNS Header
                return True

            header = analysis.get('header', {})

            # Header-Inkonsistenzen
            if header.get('questions', 0) > 100:  # Ungewöhnlich viele Questions
                return True

            if header.get('answers', 0) > 100:  # Ungewöhnlich viele Answers
                return True

            # Parsing-Fehler
            if 'parsing_errors' in analysis:
                return True

            # Flags-Inkonsistenzen
            flags = header.get('flags', {})
            if flags.get('qr') and flags.get('rcode', 0) > 5:  # Unbekannte RCODEs
                return True

            return False

        except Exception as e:
            self.logger.error(f"Fehler bei Malformed-Check: {e}")
            return False

    async def _analyze_dns_tcp(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert DNS-TCP-Paket"""
        try:
            if len(packet_data) < 2:
                return {'error': 'tcp_packet_too_short'}

            # TCP DNS hat Length-Prefix
            length = struct.unpack('!H', packet_data[:2])[0]
            dns_data = packet_data[2:]

            if len(dns_data) != length:
                return {'error': 'length_mismatch', 'malformed': True}

            # DNS-UDP-Analyse auf TCP-Payload anwenden
            udp_analysis = await self._analyze_dns_udp(dns_data, packet_info)
            udp_analysis['transport'] = 'TCP'
            udp_analysis['length_prefix'] = length

            return udp_analysis

        except Exception as e:
            self.logger.error(f"Fehler bei DNS-TCP-Analyse: {e}")
            return {'error': str(e)}

    async def _analyze_doh(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert DNS-over-HTTPS"""
        try:
            # DoH ist HTTP/2 oder HTTP/3 mit DNS-Payload
            # Vereinfachte Analyse für Demo

            analysis = {
                'protocol': 'DNS-over-HTTPS',
                'encrypted': True,
                'analysis_limited': True,
                'suspicious_indicators': []
            }

            # Frequency-basierte Anomalie-Erkennung
            doh_stats = self._get_protocol_stats(ProtocolType.DNS_OVER_HTTPS, packet_info.source_ip)
            if doh_stats['high_frequency']:
                analysis['suspicious_indicators'].append('high_doh_frequency')

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei DoH-Analyse: {e}")
            return {'error': str(e)}

    async def _analyze_dot(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert DNS-over-TLS"""
        try:
            analysis = {
                'protocol': 'DNS-over-TLS',
                'encrypted': True,
                'analysis_limited': True,
                'suspicious_indicators': []
            }

            # TLS-Header-Analyse (vereinfacht)
            if len(packet_data) >= 5:
                content_type = packet_data[0]
                version = struct.unpack('!H', packet_data[1:3])[0]
                length = struct.unpack('!H', packet_data[3:5])[0]

                analysis['tls_info'] = {
                    'content_type': content_type,
                    'version': hex(version),
                    'length': length
                }

                # Ungewöhnliche TLS-Parameter
                if content_type not in [20, 21, 22, 23]:  # Standard TLS Content Types
                    analysis['suspicious_indicators'].append('unusual_tls_content_type')

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei DoT-Analyse: {e}")
            return {'error': str(e)}

    async def _analyze_http(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert HTTP-Traffic"""
        try:
            http_data = packet_data.decode('utf-8', errors='replace')

            analysis = {
                'protocol': 'HTTP',
                'method': None,
                'uri': None,
                'headers': {},
                'suspicious_indicators': []
            }

            # HTTP-Request/Response parsen
            lines = http_data.split('\n')
            if lines:
                first_line = lines[0].strip()

                # Request-Line parsen
                if ' ' in first_line:
                    parts = first_line.split()
                    if len(parts) >= 2:
                        analysis['method'] = parts[0]
                        analysis['uri'] = parts[1]

                # Headers parsen
                for line in lines[1:]:
                    if ':' in line:
                        header, value = line.split(':', 1)
                        analysis['headers'][header.strip().lower()] = value.strip()

            # Suspicious Pattern Detection
            if analysis['uri'] and len(analysis['uri']) > 500:
                analysis['suspicious_indicators'].append('long_uri')

            user_agent = analysis['headers'].get('user-agent', '')
            if 'bot' in user_agent.lower() or 'crawler' in user_agent.lower():
                analysis['suspicious_indicators'].append('bot_user_agent')

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei HTTP-Analyse: {e}")
            return {'error': str(e)}

    async def _analyze_https(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Analysiert HTTPS-Traffic"""
        try:
            analysis = {
                'protocol': 'HTTPS',
                'encrypted': True,
                'analysis_limited': True,
                'tls_info': {},
                'suspicious_indicators': []
            }

            # TLS-Handshake-Analyse
            if len(packet_data) >= 5 and packet_data[0] == 0x16:  # Handshake
                content_type = packet_data[0]
                version = struct.unpack('!H', packet_data[1:3])[0]
                length = struct.unpack('!H', packet_data[3:5])[0]

                analysis['tls_info'] = {
                    'content_type': content_type,
                    'version': hex(version),
                    'length': length,
                    'handshake_type': packet_data[5] if len(packet_data) > 5 else None
                }

                # SNI-Extraktion (vereinfacht)
                sni = self._extract_sni(packet_data)
                if sni:
                    analysis['sni'] = sni

                    # SNI-basierte Analyse
                    if self._is_suspicious_domain(sni):
                        analysis['suspicious_indicators'].append('suspicious_sni')

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei HTTPS-Analyse: {e}")
            return {'error': str(e)}

    def _extract_sni(self, tls_data: bytes) -> Optional[str]:
        """Extrahiert Server Name Indication aus TLS Handshake"""
        try:
            # Vereinfachte SNI-Extraktion
            # In produktiver Umgebung sollte vollständiger TLS-Parser verwendet werden

            offset = 43  # Typischer Offset für Extensions in ClientHello

            while offset < len(tls_data) - 4:
                if offset + 2 > len(tls_data):
                    break

                ext_type = struct.unpack('!H', tls_data[offset:offset+2])[0]
                ext_length = struct.unpack('!H', tls_data[offset+2:offset+4])[0]

                if ext_type == 0:  # SNI Extension
                    sni_offset = offset + 4
                    if sni_offset + 5 < len(tls_data):
                        sni_list_length = struct.unpack('!H', tls_data[sni_offset:sni_offset+2])[0]
                        sni_type = tls_data[sni_offset+2]
                        sni_length = struct.unpack('!H', tls_data[sni_offset+3:sni_offset+5])[0]

                        if sni_type == 0 and sni_offset + 5 + sni_length <= len(tls_data):
                            sni = tls_data[sni_offset+5:sni_offset+5+sni_length].decode('utf-8', errors='replace')
                            return sni

                offset += 4 + ext_length

            return None

        except Exception as e:
            self.logger.error(f"Fehler bei SNI-Extraktion: {e}")
            return None

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Prüft ob Domain verdächtig ist"""
        try:
            # Bekannte Malware-Domains, DGA-Patterns, etc.
            suspicious_patterns = [
                r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free TLDs
                r'^[a-z]{8,15}\.com$',  # DGA Pattern
                r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',  # IP in Domain
                r'^[a-f0-9]{32}'  # MD5-ähnliche Patterns
            ]

            for pattern in suspicious_patterns:
                if re.search(pattern, domain, re.IGNORECASE):
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Fehler bei Domain-Suspicious-Check: {e}")
            return False

    async def _apply_content_filters(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Wendet Content-Filter an"""
        try:
            filter_results = []
            highest_threat_level = None
            triggered_filters = []

            packet_text = packet_data.decode('utf-8', errors='replace').lower()

            for filter_id, content_filter in self.content_filters.items():
                if not content_filter.active:
                    continue

                # Protokoll-Scope prüfen
                if (content_filter.protocol_scope and 
                    packet_info.protocol not in content_filter.protocol_scope):
                    continue

                # Pattern-Matching
                match_found = False

                if content_filter.pattern_type == 'string':
                    pattern = content_filter.pattern.lower() if not self.config['content_filtering']['case_sensitive'] else content_filter.pattern
                    match_found = pattern in packet_text

                elif content_filter.pattern_type == 'regex':
                    flags = re.IGNORECASE if not self.config['content_filtering']['case_sensitive'] else 0
                    match_found = bool(re.search(content_filter.pattern, packet_text, flags))

                elif content_filter.pattern_type == 'domain':
                    # Domain-Pattern für DNS-Queries
                    if hasattr(packet_info, 'queries'):
                        for query in packet_info.queries:
                            if content_filter.pattern in query.get('name', ''):
                                match_found = True
                                break

                elif content_filter.pattern_type == 'ip':
                    # IP-Pattern Matching
                    if content_filter.pattern in [packet_info.source_ip, packet_info.dest_ip]:
                        match_found = True

                if match_found:
                    triggered_filters.append(filter_id)

                    # Filter-Statistiken aktualisieren
                    with self.lock:
                        content_filter.trigger_count += 1
                        content_filter.last_triggered = time.time()

                    filter_result = {
                        'filter_id': filter_id,
                        'filter_name': content_filter.name,
                        'action': content_filter.action,
                        'threat_level': content_filter.threat_level,
                        'pattern': content_filter.pattern,
                        'pattern_type': content_filter.pattern_type
                    }

                    filter_results.append(filter_result)

                    # Höchste Bedrohungsstufe verfolgen
                    if (highest_threat_level is None or 
                        self._threat_level_priority(content_filter.threat_level) > 
                        self._threat_level_priority(highest_threat_level)):
                        highest_threat_level = content_filter.threat_level

            return {
                'filters_triggered': len(triggered_filters),
                'triggered_filter_ids': triggered_filters,
                'filter_results': filter_results,
                'highest_threat_level': highest_threat_level.value if highest_threat_level else None,
                'action_required': len(filter_results) > 0
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Content-Filtering: {e}")
            return {'error': str(e), 'filters_triggered': 0}

    def _threat_level_priority(self, threat_level: ThreatLevel) -> int:
        """Gibt Prioritätswert für Bedrohungsstufe zurück"""
        priorities = {
            ThreatLevel.INFO: 1,
            ThreatLevel.LOW: 2,
            ThreatLevel.MEDIUM: 3,
            ThreatLevel.HIGH: 4,
            ThreatLevel.CRITICAL: 5
        }
        return priorities.get(threat_level, 0)

    async def _check_malware_signatures(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Prüft Malware-Signaturen"""
        try:
            matched_signatures = []
            highest_threat_level = None

            packet_text = packet_data.decode('utf-8', errors='replace')

            for sig_id, signature in self.malware_signatures.items():
                match_found = False

                if signature['pattern_type'] == 'string':
                    match_found = signature['pattern'].lower() in packet_text.lower()

                elif signature['pattern_type'] == 'regex' and signature['compiled_pattern']:
                    match_found = bool(signature['compiled_pattern'].search(packet_text))

                if match_found:
                    self.stats['malware_signatures_matched'] += 1

                    matched_signatures.append({
                        'signature_id': sig_id,
                        'name': signature['name'],
                        'threat_level': signature['threat_level'],
                        'pattern': signature['pattern']
                    })

                    if (highest_threat_level is None or 
                        self._threat_level_priority(signature['threat_level']) > 
                        self._threat_level_priority(highest_threat_level)):
                        highest_threat_level = signature['threat_level']

            return {
                'signatures_matched': len(matched_signatures),
                'matched_signatures': matched_signatures,
                'highest_threat_level': highest_threat_level.value if highest_threat_level else None,
                'malware_detected': len(matched_signatures) > 0
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Malware-Signatur-Check: {e}")
            return {'signatures_matched': 0, 'error': str(e)}

    async def _detect_anomalies(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Erkennt Anomalien im Traffic"""
        try:
            anomaly_indicators = []
            anomaly_score = 0.0

            # Packet-Größen-Anomalien
            expected_size = self._get_expected_packet_size(packet_info.protocol)
            size_deviation = abs(len(packet_data) - expected_size) / expected_size

            if size_deviation > 2.0:  # Mehr als 200% Abweichung
                anomaly_indicators.append(f"size_anomaly:{size_deviation:.2f}")
                anomaly_score += 0.3

            # Timing-Anomalien
            timing_anomaly = self._detect_timing_anomaly(packet_info)
            if timing_anomaly['anomalous']:
                anomaly_indicators.append(f"timing_anomaly:{timing_anomaly['description']}")
                anomaly_score += 0.2

            # Protocol-Anomalien
            protocol_anomaly = self._detect_protocol_anomaly(packet_data, packet_info)
            if protocol_anomaly['anomalous']:
                anomaly_indicators.extend(protocol_anomaly['indicators'])
                anomaly_score += protocol_anomaly['score']

            # Behavioral-Anomalien
            behavioral_anomaly = self._detect_behavioral_anomaly(packet_info)
            if behavioral_anomaly['anomalous']:
                anomaly_indicators.extend(behavioral_anomaly['indicators'])
                anomaly_score += behavioral_anomaly['score']

            if anomaly_score >= self.config['thresholds']['anomaly_threshold']:
                self.stats['anomalies_detected'] += 1

            return {
                'anomalous': anomaly_score >= self.config['thresholds']['anomaly_threshold'],
                'anomaly_score': anomaly_score,
                'indicators': anomaly_indicators,
                'analysis_details': {
                    'size_deviation': size_deviation,
                    'timing_analysis': timing_anomaly,
                    'protocol_analysis': protocol_anomaly,
                    'behavioral_analysis': behavioral_anomaly
                }
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Anomalie-Erkennung: {e}")
            return {'anomalous': False, 'error': str(e)}

    def _get_expected_packet_size(self, protocol: ProtocolType) -> int:
        """Gibt erwartete Paket-Größe für Protokoll zurück"""
        expected_sizes = {
            ProtocolType.DNS_UDP: 128,
            ProtocolType.DNS_TCP: 256,
            ProtocolType.DNS_OVER_HTTPS: 512,
            ProtocolType.DNS_OVER_TLS: 512,
            ProtocolType.HTTP: 1024,
            ProtocolType.HTTPS: 1024
        }
        return expected_sizes.get(protocol, 256)

    def _detect_timing_anomaly(self, packet_info: PacketInfo) -> Dict:
        """Erkennt Timing-Anomalien"""
        try:
            # Query-Frequenz für Client prüfen
            client_queries = [
                p for p in self.packet_buffer 
                if p.get('source_ip') == packet_info.source_ip and
                   packet_info.timestamp - p.get('timestamp', 0) < 60  # Letzte Minute
            ]

            queries_per_minute = len(client_queries)

            # Ungewöhnlich hohe Frequenz
            if queries_per_minute > 100:
                return {
                    'anomalous': True,
                    'description': f'high_frequency:{queries_per_minute}',
                    'queries_per_minute': queries_per_minute
                }

            # Regelmäßige Intervalle (Bot-Verhalten)
            if len(client_queries) > 10:
                intervals = []
                for i in range(1, len(client_queries)):
                    interval = client_queries[i]['timestamp'] - client_queries[i-1]['timestamp']
                    intervals.append(interval)

                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    interval_variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

                    # Sehr regelmäßige Intervalle deuten auf automatisiertes Verhalten hin
                    if interval_variance < 0.1 and avg_interval < 10:
                        return {
                            'anomalous': True,
                            'description': f'regular_intervals:{avg_interval:.2f}s',
                            'interval_variance': interval_variance
                        }

            return {'anomalous': False}

        except Exception as e:
            self.logger.error(f"Fehler bei Timing-Anomalie-Erkennung: {e}")
            return {'anomalous': False, 'error': str(e)}

    def _detect_protocol_anomaly(self, packet_data: bytes, packet_info: PacketInfo) -> Dict:
        """Erkennt Protokoll-Anomalien"""
        try:
            indicators = []
            score = 0.0

            # Port/Protocol Mismatch
            if packet_info.dest_port == 53 and packet_info.protocol == ProtocolType.UNKNOWN:
                indicators.append("protocol_mismatch")
                score += 0.2

            # Ungewöhnliche Flags oder Header
            if packet_info.protocol in [ProtocolType.DNS_UDP, ProtocolType.DNS_TCP]:
                try:
                    if len(packet_data) >= 2:
                        # DNS Header Flags prüfen
                        flags = struct.unpack('!H', packet_data[:2])[0] if packet_info.protocol == ProtocolType.DNS_UDP else struct.unpack('!H', packet_data[2:4])[0]

                        qr, opcode, aa, tc, rd, ra, z, rcode = self._parse_dns_flags(flags)

                        # Ungewöhnliche OPCODE
                        if opcode > 2:  # Standard: 0=QUERY, 1=IQUERY, 2=STATUS
                            indicators.append(f"unusual_opcode:{opcode}")
                            score += 0.3

                        # Reserved Bits gesetzt
                        if z != 0:
                            indicators.append("reserved_bits_set")
                            score += 0.2
                except:
                    pass

            return {
                'anomalous': score > 0,
                'indicators': indicators,
                'score': score
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Protokoll-Anomalie-Erkennung: {e}")
            return {'anomalous': False, 'indicators': [], 'score': 0.0}

    def _detect_behavioral_anomaly(self, packet_info: PacketInfo) -> Dict:
        """Erkennt verhaltensbasierte Anomalien"""
        try:
            indicators = []
            score = 0.0

            client_ip = packet_info.source_ip

            # Client-Profil abrufen oder erstellen
            if client_ip not in self.behavioral_profiles:
                self.behavioral_profiles[client_ip] = {
                    'first_seen': packet_info.timestamp,
                    'query_patterns': defaultdict(int),
                    'protocol_usage': defaultdict(int),
                    'time_patterns': defaultdict(int),
                    'total_queries': 0
                }

            profile = self.behavioral_profiles[client_ip]
            profile['total_queries'] += 1
            profile['protocol_usage'][packet_info.protocol.value] += 1

            # Ungewöhnliche Protokoll-Nutzung
            if profile['total_queries'] > 100:
                protocol_ratio = profile['protocol_usage'][packet_info.protocol.value] / profile['total_queries']

                # Clients die plötzlich andere Protokolle verwenden
                if packet_info.protocol != ProtocolType.DNS_UDP and protocol_ratio < 0.1:
                    indicators.append(f"unusual_protocol_change:{packet_info.protocol.value}")
                    score += 0.2

            # Geografische Anomalien (vereinfacht)
            geo_anomaly = self._detect_geo_anomaly(client_ip)
            if geo_anomaly['anomalous']:
                indicators.append(geo_anomaly['description'])
                score += geo_anomaly['score']

            return {
                'anomalous': score > 0,
                'indicators': indicators,
                'score': score,
                'profile_age': packet_info.timestamp - profile['first_seen']
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Behavioral-Anomalie-Erkennung: {e}")
            return {'anomalous': False, 'indicators': [], 'score': 0.0}

    def _detect_geo_anomaly(self, client_ip: str) -> Dict:
        """Erkennt geografische Anomalien (vereinfacht)"""
        try:
            # Vereinfachte Geo-IP-Analyse
            # In Produktivumgebung sollte echte GeoIP-Datenbank verwendet werden

            # Private/Interne IPs sind normal
            try:
                ip_obj = ipaddress.ip_address(client_ip)
                if ip_obj.is_private:
                    return {'anomalous': False}
            except:
                pass

            # Bekannte Botnet-IP-Ranges (Beispiel)
            suspicious_ranges = [
                '185.220.100.0/24',  # Tor Exit Nodes (Beispiel)
                '198.98.0.0/16'      # Bekannte Botnet-Range (Beispiel)
            ]

            for suspicious_range in suspicious_ranges:
                try:
                    if ipaddress.ip_address(client_ip) in ipaddress.ip_network(suspicious_range):
                        return {
                            'anomalous': True,
                            'description': f'suspicious_ip_range:{suspicious_range}',
                            'score': 0.4
                        }
                except:
                    continue

            return {'anomalous': False}

        except Exception as e:
            self.logger.error(f"Fehler bei Geo-Anomalie-Erkennung: {e}")
            return {'anomalous': False}

    def _determine_final_action(self, analysis_result: Dict) -> FilterAction:
        """Bestimmt finale Aktion basierend auf allen Analysen"""
        try:
            # Höchste Bedrohungsstufe ermitteln
            threat_levels = []

            content_analysis = analysis_result.get('content_analysis', {})
            if content_analysis.get('highest_threat_level'):
                threat_levels.append(ThreatLevel(content_analysis['highest_threat_level']))

            threat_analysis = analysis_result.get('threat_analysis', {})
            if threat_analysis.get('highest_threat_level'):
                threat_levels.append(ThreatLevel(threat_analysis['highest_threat_level']))

            anomaly_analysis = analysis_result.get('anomaly_analysis', {})
            if anomaly_analysis.get('anomalous'):
                threat_levels.append(ThreatLevel.MEDIUM)

            if not threat_levels:
                return FilterAction.ALLOW

            # Höchste Bedrohung bestimmen
            highest_threat = max(threat_levels, key=lambda t: self._threat_level_priority(t))

            # Aktion basierend auf Bedrohungsstufe
            if highest_threat == ThreatLevel.CRITICAL:
                return FilterAction.BLOCK
            elif highest_threat == ThreatLevel.HIGH:
                return FilterAction.QUARANTINE
            elif highest_threat in [ThreatLevel.MEDIUM, ThreatLevel.LOW]:
                return FilterAction.LOG
            else:
                return FilterAction.ALLOW

        except Exception as e:
            self.logger.error(f"Fehler bei finaler Aktions-Bestimmung: {e}")
            return FilterAction.ALLOW

    async def _update_traffic_flow(self, packet_info: PacketInfo, analysis_result: Dict):
        """Aktualisiert Traffic-Flow-Informationen"""
        try:
            flow_id = f"{packet_info.source_ip}:{packet_info.source_port}-{packet_info.dest_ip}:{packet_info.dest_port}"

            if flow_id not in self.traffic_flows:
                self.traffic_flows[flow_id] = {
                    'source_ip': packet_info.source_ip,
                    'dest_ip': packet_info.dest_ip,
                    'source_port': packet_info.source_port,
                    'dest_port': packet_info.dest_port,
                    'protocol': packet_info.protocol,
                    'start_time': packet_info.timestamp,
                    'last_packet_time': packet_info.timestamp,
                    'packet_count': 0,
                    'byte_count': 0,
                    'threat_indicators': [],
                    'status': 'active'
                }

            flow = self.traffic_flows[flow_id]
            flow['packet_count'] += 1
            flow['byte_count'] += packet_info.packet_size
            flow['last_packet_time'] = packet_info.timestamp

            # Bedrohungsindikatoren hinzufügen
            if analysis_result.get('action') != FilterAction.ALLOW:
                threat_info = {
                    'timestamp': packet_info.timestamp,
                    'action': analysis_result['action'].value,
                    'threat_level': analysis_result.get('threat_analysis', {}).get('highest_threat_level'),
                    'indicators': []
                }

                # Indikatoren sammeln
                content_analysis = analysis_result.get('content_analysis', {})
                if content_analysis.get('triggered_filter_ids'):
                    threat_info['indicators'].extend(content_analysis['triggered_filter_ids'])

                anomaly_analysis = analysis_result.get('anomaly_analysis', {})
                if anomaly_analysis.get('indicators'):
                    threat_info['indicators'].extend(anomaly_analysis['indicators'])

                flow['threat_indicators'].append(threat_info)

            # Protokoll-Statistiken aktualisieren
            protocol_stats = self.protocol_stats[packet_info.protocol]
            protocol_stats['total_packets'] = protocol_stats.get('total_packets', 0) + 1
            protocol_stats['total_bytes'] = protocol_stats.get('total_bytes', 0) + packet_info.packet_size
            protocol_stats['last_update'] = packet_info.timestamp

        except Exception as e:
            self.logger.error(f"Fehler bei Traffic-Flow-Update: {e}")

    async def _generate_alerts(self, packet_info: PacketInfo, analysis_result: Dict) -> List[DPIAlert]:
        """Generiert DPI-Alerts"""
        try:
            alerts = []

            # Alert-ID generieren
            alert_id = f"dpi_{int(packet_info.timestamp)}_{packet_info.source_ip}_{len(self.dpi_alerts)}"

            # Bedrohungsstufe ermitteln
            threat_level = ThreatLevel.MEDIUM
            content_analysis = analysis_result.get('content_analysis', {})
            if content_analysis.get('highest_threat_level'):
                threat_level = ThreatLevel(content_analysis['highest_threat_level'])

            # Filter-ID ermitteln
            filter_id = None
            if content_analysis.get('triggered_filter_ids'):
                filter_id = content_analysis['triggered_filter_ids'][0]

            # Beschreibung erstellen
            description_parts = []

            if content_analysis.get('filters_triggered', 0) > 0:
                description_parts.append(f"Content filters triggered: {content_analysis['filters_triggered']}")

            threat_analysis = analysis_result.get('threat_analysis', {})
            if threat_analysis.get('signatures_matched', 0) > 0:
                description_parts.append(f"Malware signatures matched: {threat_analysis['signatures_matched']}")

            anomaly_analysis = analysis_result.get('anomaly_analysis', {})
            if anomaly_analysis.get('anomalous'):
                description_parts.append(f"Anomaly detected (score: {anomaly_analysis.get('anomaly_score', 0):.2f})")

            description = "; ".join(description_parts) if description_parts else "Threat detected"

            # DNS-Analyse hinzufügen
            dns_analysis = None
            protocol_analysis = analysis_result.get('protocol_analysis', {})
            if protocol_analysis and packet_info.protocol in [ProtocolType.DNS_UDP, ProtocolType.DNS_TCP]:
                dns_analysis = DNSPacketAnalysis(
                    packet_info=packet_info,
                    query_name=protocol_analysis.get('queries', [{}])[0].get('name', '') if protocol_analysis.get('queries') else '',
                    query_type=str(protocol_analysis.get('queries', [{}])[0].get('type', '')) if protocol_analysis.get('queries') else '',
                    query_class=str(protocol_analysis.get('queries', [{}])[0].get('class', '')) if protocol_analysis.get('queries') else '',
                    response_code=str(protocol_analysis.get('header', {}).get('flags', {}).get('rcode', '')),
                    answer_count=protocol_analysis.get('header', {}).get('answers', 0),
                    authority_count=protocol_analysis.get('header', {}).get('authority', 0),
                    additional_count=protocol_analysis.get('header', {}).get('additional', 0),
                    flags=protocol_analysis.get('header', {}).get('flags', {}),
                    edns_present=False,  # Vereinfacht
                    dnssec_ok=False,     # Vereinfacht
                    suspicious_patterns=protocol_analysis.get('suspicious_indicators', []),
                    anomaly_score=protocol_analysis.get('anomaly_score', 0.0)
                )

            # Alert erstellen
            alert = DPIAlert(
                alert_id=alert_id,
                timestamp=packet_info.timestamp,
                source_ip=packet_info.source_ip,
                threat_level=threat_level,
                filter_id=filter_id,
                description=description,
                packet_info=packet_info,
                dns_analysis=dns_analysis,
                evidence=analysis_result,
                status='active'
            )

            alerts.append(alert)

            # Alert in Cache und Datenbank speichern
            with self.lock:
                self.dpi_alerts[alert_id] = alert
                self._persist_alert(alert)

            self.stats['threats_detected'] += 1
            self.logger.warning(f"DPI-Alert generiert: {alert_id} - {description}")

            return alerts

        except Exception as e:
            self.logger.error(f"Fehler bei Alert-Generierung: {e}")
            return []

    def _persist_alert(self, alert: DPIAlert):
        """Speichert Alert in Datenbank"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO dpi_alerts 
                (alert_id, timestamp, source_ip, threat_level, filter_id, 
                 description, packet_info, dns_analysis, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id, alert.timestamp, alert.source_ip,
                alert.threat_level.value, alert.filter_id, alert.description,
                json.dumps(asdict(alert.packet_info), default=str),
                json.dumps(asdict(alert.dns_analysis), default=str) if alert.dns_analysis else None,
                json.dumps(alert.evidence, default=str), alert.status
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Fehler beim Speichern des Alerts: {e}")

    def _get_protocol_stats(self, protocol: ProtocolType, client_ip: str) -> Dict:
        """Holt Protokoll-Statistiken für Client"""
        try:
            current_time = time.time()
            time_window = 300  # 5 Minuten

            recent_packets = [
                p for p in self.packet_buffer
                if (p.get('source_ip') == client_ip and 
                    p.get('protocol') == protocol.value and
                    current_time - p.get('timestamp', 0) < time_window)
            ]

            packets_per_minute = len(recent_packets) / (time_window / 60)

            return {
                'packets_per_minute': packets_per_minute,
                'high_frequency': packets_per_minute > 50,  # Threshold
                'total_recent_packets': len(recent_packets)
            }

        except Exception as e:
            self.logger.error(f"Fehler bei Protokoll-Stats: {e}")
            return {'packets_per_minute': 0, 'high_frequency': False}

    def add_content_filter(self, filter_id: str, name: str, description: str,
                          pattern_type: str, pattern: str, action: FilterAction,
                          threat_level: ThreatLevel, protocol_scope: List[ProtocolType] = None) -> bool:
        """Fügt neuen Content-Filter hinzu"""
        try:
            if protocol_scope is None:
                protocol_scope = []

            current_time = time.time()

            content_filter = ContentFilter(
                filter_id=filter_id,
                name=name,
                description=description,
                pattern_type=pattern_type,
                pattern=pattern,
                action=action,
                threat_level=threat_level,
                protocol_scope=protocol_scope,
                active=True,
                created_at=current_time
            )

            with self.lock:
                # In Datenbank speichern
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT OR REPLACE INTO content_filters 
                    (filter_id, name, description, pattern_type, pattern, action,
                     threat_level, protocol_scope, active, created_at, trigger_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0)
                """, (filter_id, name, description, pattern_type, pattern,
                      action.value, threat_level.value, 
                      json.dumps([p.value for p in protocol_scope]), current_time))

                conn.commit()
                conn.close()

                # In Cache speichern
                self.content_filters[filter_id] = content_filter

            self.logger.info(f"Content-Filter hinzugefügt: {name} ({filter_id})")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen des Filters {filter_id}: {e}")
            return False

    def get_dpi_statistics(self) -> Dict:
        """Gibt DPI-Statistiken zurück"""
        try:
            with self.lock:
                current_time = time.time()
                last_24h = current_time - 86400

                # Recent Alerts
                recent_alerts = [
                    alert for alert in self.dpi_alerts.values()
                    if alert.timestamp >= last_24h
                ]

                # Threat Level Breakdown
                threat_breakdown = defaultdict(int)
                for alert in recent_alerts:
                    threat_breakdown[alert.threat_level.value] += 1

                # Top Source IPs
                source_ip_counts = defaultdict(int)
                for alert in recent_alerts:
                    source_ip_counts[alert.source_ip] += 1

                top_source_ips = sorted(source_ip_counts.items(), 
                                      key=lambda x: x[1], reverse=True)[:10]

                stats = {
                    **self.stats,
                    'recent_alerts': len(recent_alerts),
                    'active_content_filters': len([f for f in self.content_filters.values() if f.active]),
                    'active_signatures': len(self.malware_signatures),
                    'active_flows': len([f for f in self.traffic_flows.values() if f.get('status') == 'active']),
                    'protocol_distribution': {
                        protocol.value: stats_data.get('total_packets', 0)
                        for protocol, stats_data in self.protocol_stats.items()
                    },
                    'threat_level_breakdown': dict(threat_breakdown),
                    'top_source_ips': top_source_ips,
                    'behavioral_profiles': len(self.behavioral_profiles),
                    'cache_hit_rate': len(self.analysis_cache) / max(self.stats['packets_analyzed'], 1),
                    'uptime': current_time - getattr(self, 'start_time', current_time)
                }

                return stats

        except Exception as e:
            self.logger.error(f"Fehler beim Abrufen der DPI-Statistiken: {e}")
            return self.stats

    def _start_background_tasks(self):
        """Startet Hintergrund-Tasks"""
        try:
            # Cleanup Task
            cleanup_task = threading.Thread(
                target=self._cleanup_task_worker,
                daemon=True
            )
            cleanup_task.start()

            # Baseline Update Task
            baseline_task = threading.Thread(
                target=self._baseline_update_worker,
                daemon=True
            )
            baseline_task.start()

            self.start_time = time.time()
            self.logger.info("DPI-Hintergrund-Tasks gestartet")

        except Exception as e:
            self.logger.error(f"Fehler beim Starten der Hintergrund-Tasks: {e}")

    def _cleanup_task_worker(self):
        """Cleanup-Task Worker"""
        while True:
            try:
                time.sleep(3600)  # Jede Stunde
                self._cleanup_old_data()
            except Exception as e:
                self.logger.error(f"Fehler im Cleanup-Task: {e}")

    def _baseline_update_worker(self):
        """Baseline-Update Worker"""
        while True:
            try:
                time.sleep(1800)  # Alle 30 Minuten
                self._update_baselines()
            except Exception as e:
                self.logger.error(f"Fehler im Baseline-Update-Task: {e}")

    def _cleanup_old_data(self):
        """Bereinigt alte Daten"""
        try:
            current_time = time.time()
            cutoff_time = current_time - 86400  # 24 Stunden

            with self.lock:
                # Alte Alerts entfernen
                alerts_to_remove = [
                    alert_id for alert_id, alert in self.dpi_alerts.items()
                    if alert.timestamp < cutoff_time
                ]

                for alert_id in alerts_to_remove:
                    del self.dpi_alerts[alert_id]

                # Alte Traffic-Flows entfernen
                flows_to_remove = [
                    flow_id for flow_id, flow in self.traffic_flows.items()
                    if flow.get('last_packet_time', 0) < cutoff_time
                ]

                for flow_id in flows_to_remove:
                    del self.traffic_flows[flow_id]

                # Cache bereinigen
                cache_keys_to_remove = []
                for cache_key, cache_data in self.analysis_cache.items():
                    if cache_data['timestamp'] < cutoff_time:
                        cache_keys_to_remove.append(cache_key)

                for cache_key in cache_keys_to_remove:
                    del self.analysis_cache[cache_key]

            self.logger.debug("Alte DPI-Daten bereinigt")

        except Exception as e:
            self.logger.error(f"Fehler bei der DPI-Datenbereinigung: {e}")

    def _update_baselines(self):
        """Aktualisiert Baseline-Metriken"""
        try:
            current_time = time.time()

            # Protokoll-Baselines aktualisieren
            for protocol, stats in self.protocol_stats.items():
                if 'baseline_packets_per_hour' not in stats:
                    stats['baseline_packets_per_hour'] = stats.get('total_packets', 0)
                else:
                    # Exponential Moving Average
                    current_pph = stats.get('total_packets', 0)
                    stats['baseline_packets_per_hour'] = (
                        0.9 * stats['baseline_packets_per_hour'] + 
                        0.1 * current_pph
                    )

            # Client-Behavioral-Baselines
            for client_ip, profile in self.behavioral_profiles.items():
                if current_time - profile['first_seen'] > 3600:  # Mindestens 1 Stunde Daten
                    # Baseline Query-Rate
                    age_hours = (current_time - profile['first_seen']) / 3600
                    avg_queries_per_hour = profile['total_queries'] / age_hours
                    profile['baseline_queries_per_hour'] = avg_queries_per_hour

            self.logger.debug("Baseline-Metriken aktualisiert")

        except Exception as e:
            self.logger.error(f"Fehler bei Baseline-Update: {e}")

    def export_dpi_report(self, format: str = 'json') -> str:
        """Exportiert DPI-Bericht"""
        try:
            current_time = time.time()

            report_data = {
                'generated_at': current_time,
                'statistics': self.get_dpi_statistics(),
                'recent_alerts': [
                    asdict(alert) for alert in self.dpi_alerts.values()
                    if current_time - alert.timestamp < 86400
                ],
                'active_filters': [
                    asdict(filter_obj) for filter_obj in self.content_filters.values()
                    if filter_obj.active
                ],
                'traffic_flows': [
                    flow_data for flow_data in self.traffic_flows.values()
                    if flow_data.get('status') == 'active'
                ],
                'protocol_statistics': dict(self.protocol_stats),
                'configuration': self.config
            }

            if format.lower() == 'json':
                return json.dumps(report_data, indent=4, default=str)
            else:
                return str(report_data)

        except Exception as e:
            self.logger.error(f"Fehler beim Exportieren des DPI-Berichts: {e}")
            return "{}"
