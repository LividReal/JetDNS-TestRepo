"""
JetDNS Application Layer Filtering & Deep Packet Inspection (DPI)
Advanced Traffic Analysis & Threat Detection

Features:
- Deep Packet Inspection (DPI)
- Application protocol detection
- Payload analysis & pattern matching
- Behavioral analysis & anomaly detection
- Machine Learning threat classification
- Real-time traffic monitoring
- Custom filtering rules
"""

import asyncio
import logging
import re
import json
import time
import struct
import base64
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import ipaddress

# Network Analysis
try:
    import scapy.all as scapy
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - limited DPI functionality")

# ML & Pattern Recognition
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import nltk
from nltk.corpus import stopwords
try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)


class ThreatLevel(Enum):
    """Bedrohungsebenen für DPI-Findings"""
    INFO = "info"
    LOW = "low" 
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApplicationProtocol(Enum):
    """Erkannte Anwendungsprotokolle"""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    DOH = "doh"  # DNS over HTTPS
    DOT = "dot"  # DNS over TLS
    DOQ = "doq"  # DNS over QUIC
    UNKNOWN = "unknown"


class FilterAction(Enum):
    """Aktionen für DPI-Filter"""
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    MODIFY = "modify"


@dataclass
class PacketAnalysis:
    """Ergebnis der Paket-Analyse"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    application_protocol: ApplicationProtocol
    payload_size: int
    payload_hash: str

    # DNS-specific fields
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    dns_response_code: Optional[int] = None
    dns_flags: Optional[Dict] = None

    # Analysis results
    threat_level: ThreatLevel = ThreatLevel.INFO
    threats_detected: List[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    confidence: float = 0.0

    # Metadata
    geolocation: Optional[Dict] = None
    asn_info: Optional[Dict] = None
    reputation_score: float = 0.5


@dataclass 
class DPIRule:
    """Deep Packet Inspection Regel"""
    name: str
    description: str
    pattern: str  # Regex pattern oder Signature
    pattern_type: str = "regex"  # regex, binary, dns_name, payload
    action: FilterAction = FilterAction.LOG
    threat_level: ThreatLevel = ThreatLevel.MEDIUM
    enabled: bool = True

    # Matching conditions
    protocols: List[str] = field(default_factory=lambda: ["dns"])
    source_ips: List[str] = field(default_factory=list)  # CIDR blocks
    dest_ips: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)

    # Advanced matching
    payload_size_min: Optional[int] = None
    payload_size_max: Optional[int] = None
    time_window: Optional[Dict] = None  # {'start': 'HH:MM', 'end': 'HH:MM'}

    # Actions & responses
    custom_response: Optional[str] = None
    alert_threshold: int = 1
    created_at: datetime = field(default_factory=datetime.now)


class PayloadAnalyzer:
    """Analyzer für DNS Payload Deep Inspection"""

    def __init__(self):
        self.logger = logging.getLogger('jetdns.dpi.payload')

        # DNS-specific patterns
        self.dns_patterns = {
            'dga_domains': [
                r'^[a-z]{8,}\.(?:com|net|org|info|biz)$',  # Long random strings
                r'^[0-9a-f]{16,}\.(?:com|tk|ml)$',         # Hex strings
                r'^[bcdfghjklmnpqrstvwxyz]{10,}\.com$',     # No vowels (common in DGA)
            ],

            'typosquatting': [
                r'g[o0][o0]g[l1][e3]\.com',  # Google variations
                r'm[i1]cr[o0]s[o0]ft\.com',  # Microsoft variations  
                r'[a4]m[a4]z[o0]n\.com',     # Amazon variations
                r'p[a4]yp[a4][l1]\.com',     # PayPal variations
            ],

            'c2_patterns': [
                r'\d+\.\d+\.\d+\.\d+\.xip\.io$',          # IP-based domains
                r'^[a-z0-9]{5,10}-[a-z0-9]{5,10}\..*$',   # Hyphenated random
                r'^update[0-9]+\..*$',                      # Update domains
                r'^[0-9]{6,}\..*$',                         # Numeric prefixes
            ],

            'dns_tunneling': [
                r'^[a-zA-Z0-9+/]{50,}\..*$',               # Base64-like strings
                r'^[a-fA-F0-9]{32,}\..*$',                 # Hex encoded data
                r'\.{2,}',                                  # Multiple consecutive dots
                r'^.{100,}$',                               # Very long queries
            ],

            'phishing': [
                r'bank.*login',
                r'secure.*update',
                r'verify.*account', 
                r'suspended.*account',
                r'click.*here',
                r'urgent.*action',
            ]
        }

        # Binary patterns for payload inspection
        self.binary_signatures = {
            'dns_cache_poisoning': [
                b'\x00\x00\x01\x00\x00\x01',  # Suspicious DNS header
                b'\x81\x80\x00\x01',           # Response with recursion
            ],

            'dns_amplification': [
                b'\x00\x00\xff\x00',           # ANY query type
                b'\x00\x00\x10\x00',           # TXT record query
            ]
        }

        # Entropy-based detection
        self.entropy_thresholds = {
            'high_entropy': 4.5,   # Randomness threshold
            'low_entropy': 1.5,    # Suspiciously ordered
        }

    def analyze_dns_payload(self, packet_data: bytes) -> Dict[str, Any]:
        """Analysiert DNS Payload für verdächtige Patterns"""
        analysis = {
            'patterns_matched': [],
            'entropy_analysis': {},
            'binary_signatures': [],
            'payload_anomalies': [],
            'risk_score': 0.0
        }

        try:
            if SCAPY_AVAILABLE:
                # Parse with Scapy if available
                packet = scapy.DNS(packet_data)
                analysis.update(self._analyze_dns_structure(packet))
            else:
                # Basic binary analysis
                analysis.update(self._analyze_dns_binary(packet_data))

            # Entropy analysis
            analysis['entropy_analysis'] = self._calculate_payload_entropy(packet_data)

            # Pattern matching
            text_data = self._extract_text_from_payload(packet_data)
            analysis['patterns_matched'] = self._match_patterns(text_data)

            # Binary signature detection
            analysis['binary_signatures'] = self._detect_binary_signatures(packet_data)

            # Calculate overall risk score
            analysis['risk_score'] = self._calculate_risk_score(analysis)

        except Exception as e:
            self.logger.error(f"Error analyzing DNS payload: {e}")
            analysis['error'] = str(e)

        return analysis

    def _analyze_dns_structure(self, dns_packet) -> Dict[str, Any]:
        """Analysiert DNS-Paketstruktur mit Scapy"""
        analysis = {
            'header_analysis': {},
            'query_analysis': {},
            'response_analysis': {},
            'anomalies': []
        }

        try:
            # Header analysis
            analysis['header_analysis'] = {
                'id': dns_packet.id,
                'qr': dns_packet.qr,
                'opcode': dns_packet.opcode,
                'aa': dns_packet.aa,
                'tc': dns_packet.tc,
                'rd': dns_packet.rd,
                'ra': dns_packet.ra,
                'rcode': dns_packet.rcode,
                'qdcount': dns_packet.qdcount,
                'ancount': dns_packet.ancount,
                'nscount': dns_packet.nscount,
                'arcount': dns_packet.arcount
            }

            # Detect header anomalies
            if dns_packet.qdcount > 10:  # Too many questions
                analysis['anomalies'].append('excessive_questions')
            if dns_packet.ancount > 100:  # Too many answers
                analysis['anomalies'].append('excessive_answers')
            if dns_packet.opcode not in [0, 1, 2]:  # Unusual opcode
                analysis['anomalies'].append('unusual_opcode')

            # Query analysis
            if dns_packet.qd:
                query = dns_packet.qd
                analysis['query_analysis'] = {
                    'qname': query.qname.decode('utf-8', errors='ignore'),
                    'qtype': query.qtype,
                    'qclass': query.qclass
                }

                # Query anomalies
                qname = query.qname.decode('utf-8', errors='ignore')
                if len(qname) > 253:  # RFC limit exceeded
                    analysis['anomalies'].append('query_too_long')
                if qname.count('.') > 10:  # Too many subdomains
                    analysis['anomalies'].append('excessive_subdomains')

            # Response analysis
            if dns_packet.an:
                answers = []
                for answer in dns_packet.an:
                    answer_data = {
                        'name': answer.rrname.decode('utf-8', errors='ignore'),
                        'type': answer.type,
                        'rdata': str(answer.rdata),
                        'ttl': answer.ttl
                    }
                    answers.append(answer_data)

                    # Response anomalies
                    if answer.ttl < 60:  # Very short TTL
                        analysis['anomalies'].append('short_ttl')
                    if answer.ttl > 86400 * 7:  # Very long TTL (> 1 week)
                        analysis['anomalies'].append('long_ttl')

                analysis['response_analysis']['answers'] = answers

        except Exception as e:
            self.logger.error(f"Error in DNS structure analysis: {e}")
            analysis['error'] = str(e)

        return analysis

    def _analyze_dns_binary(self, payload: bytes) -> Dict[str, Any]:
        """Basic DNS binary analysis ohne Scapy"""
        analysis = {
            'header_analysis': {},
            'payload_structure': {},
            'anomalies': []
        }

        try:
            if len(payload) < 12:  # Minimum DNS header size
                analysis['anomalies'].append('packet_too_small')
                return analysis

            # Parse basic header
            header = struct.unpack('!HHHHHH', payload[:12])
            analysis['header_analysis'] = {
                'id': header[0],
                'flags': header[1],
                'qdcount': header[2],
                'ancount': header[3],
                'nscount': header[4],
                'arcount': header[5]
            }

            # Extract flags
            flags = header[1]
            qr = (flags & 0x8000) >> 15
            opcode = (flags & 0x7800) >> 11
            rcode = flags & 0x000F

            analysis['header_analysis'].update({
                'qr': qr,
                'opcode': opcode, 
                'rcode': rcode
            })

            # Detect anomalies
            if header[2] > 10:  # Too many questions
                analysis['anomalies'].append('excessive_questions')
            if header[3] > 100:  # Too many answers
                analysis['anomalies'].append('excessive_answers')
            if len(payload) > 4096:  # Very large packet
                analysis['anomalies'].append('oversized_packet')

        except Exception as e:
            self.logger.error(f"Error in binary DNS analysis: {e}")
            analysis['error'] = str(e)

        return analysis

    def _calculate_payload_entropy(self, payload: bytes) -> Dict[str, float]:
        """Berechnet Entropie des Payloads"""
        if not payload:
            return {'entropy': 0.0, 'assessment': 'empty'}

        # Calculate Shannon entropy
        byte_counts = defaultdict(int)
        for byte in payload:
            byte_counts[byte] += 1

        entropy = 0.0
        payload_len = len(payload)

        for count in byte_counts.values():
            probability = count / payload_len
            if probability > 0:
                entropy -= probability * np.log2(probability)

        # Assess entropy level
        assessment = 'normal'
        if entropy > self.entropy_thresholds['high_entropy']:
            assessment = 'high_randomness'
        elif entropy < self.entropy_thresholds['low_entropy']:
            assessment = 'low_randomness'

        return {
            'entropy': entropy,
            'assessment': assessment,
            'byte_distribution': dict(byte_counts)
        }

    def _extract_text_from_payload(self, payload: bytes) -> str:
        """Extrahiert lesbaren Text aus Payload"""
        try:
            # Try different encodings
            for encoding in ['utf-8', 'ascii', 'latin-1']:
                try:
                    text = payload.decode(encoding, errors='ignore')
                    # Filter out control characters
                    text = ''.join(char for char in text if char.isprintable() or char.isspace())
                    return text
                except:
                    continue
        except:
            pass

        # Fallback: extract printable ASCII
        return ''.join(chr(byte) for byte in payload if 32 <= byte <= 126)

    def _match_patterns(self, text_data: str) -> List[Dict[str, Any]]:
        """Matched Patterns gegen bekannte Bedrohungen"""
        matches = []

        for category, patterns in self.dns_patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text_data, re.IGNORECASE):
                        matches.append({
                            'category': category,
                            'pattern': pattern,
                            'matched_text': text_data[:200]  # First 200 chars
                        })
                except re.error:
                    continue

        return matches

    def _detect_binary_signatures(self, payload: bytes) -> List[Dict[str, Any]]:
        """Erkennt binäre Signaturen"""
        signatures = []

        for category, sig_list in self.binary_signatures.items():
            for signature in sig_list:
                if signature in payload:
                    offset = payload.find(signature)
                    signatures.append({
                        'category': category,
                        'signature': signature.hex(),
                        'offset': offset
                    })

        return signatures

    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Berechnet Gesamt-Risk-Score"""
        score = 0.0

        # Pattern matches
        high_risk_categories = ['c2_patterns', 'dns_tunneling', 'phishing']
        for match in analysis.get('patterns_matched', []):
            if match['category'] in high_risk_categories:
                score += 0.3
            else:
                score += 0.1

        # Binary signatures
        score += len(analysis.get('binary_signatures', [])) * 0.2

        # Entropy analysis
        entropy_data = analysis.get('entropy_analysis', {})
        if entropy_data.get('assessment') == 'high_randomness':
            score += 0.3
        elif entropy_data.get('assessment') == 'low_randomness':
            score += 0.1

        # Structural anomalies
        score += len(analysis.get('anomalies', [])) * 0.15

        return min(1.0, score)


class BehavioralAnalyzer:
    """Verhaltensanalyse für DPI-basierte Anomalie-Erkennung"""

    def __init__(self):
        self.logger = logging.getLogger('jetdns.dpi.behavioral')

        # Client behavior tracking
        self.client_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'query_patterns': deque(maxlen=1000),
            'timing_patterns': deque(maxlen=1000),
            'domain_patterns': defaultdict(int),
            'payload_sizes': deque(maxlen=500),
            'error_patterns': deque(maxlen=100),
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'anomaly_scores': deque(maxlen=100)
        })

        # ML models for anomaly detection
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()

        # Feature tracking
        self.feature_history = deque(maxlen=10000)
        self.model_trained = False
        self.last_training = None

        # Anomaly thresholds
        self.anomaly_threshold = -0.5  # IsolationForest threshold
        self.pattern_deviation_threshold = 2.0  # Standard deviations

    def analyze_client_behavior(self, client_ip: str, packet_analysis: PacketAnalysis) -> Dict[str, Any]:
        """Analysiert Client-Verhalten für Anomalie-Erkennung"""
        profile = self.client_profiles[client_ip]
        current_time = datetime.now()

        # Update profile
        profile['last_seen'] = current_time

        # Extract features
        features = self._extract_behavioral_features(packet_analysis, profile)

        # Store features for model training
        self.feature_history.append(features)

        # Update profile with new data
        self._update_client_profile(profile, packet_analysis, features)

        # Detect anomalies
        anomaly_analysis = self._detect_behavioral_anomalies(client_ip, features, profile)

        # Train model periodically
        if len(self.feature_history) >= 1000 and (
            not self.model_trained or 
            (self.last_training and (current_time - self.last_training).seconds > 3600)
        ):
            asyncio.create_task(self._retrain_models())

        return anomaly_analysis

    def _extract_behavioral_features(self, analysis: PacketAnalysis, profile: Dict) -> np.ndarray:
        """Extrahiert Features für ML-Analyse"""
        features = []

        # Timing features
        if profile['timing_patterns']:
            last_query_time = profile['timing_patterns'][-1]
            time_delta = (analysis.timestamp - last_query_time).total_seconds()
            features.extend([
                time_delta,
                np.std(profile['timing_patterns']) if len(profile['timing_patterns']) > 1 else 0
            ])
        else:
            features.extend([0, 0])

        # Query pattern features
        features.extend([
            len(analysis.dns_query) if analysis.dns_query else 0,
            analysis.dns_query.count('.') if analysis.dns_query else 0,
            analysis.payload_size,
            analysis.anomaly_score
        ])

        # Domain diversity (entropy of domain queries)
        if profile['domain_patterns']:
            domain_counts = list(profile['domain_patterns'].values())
            total_queries = sum(domain_counts)
            domain_probs = [count/total_queries for count in domain_counts]
            domain_entropy = -sum(p * np.log2(p) for p in domain_probs if p > 0)
            features.append(domain_entropy)
        else:
            features.append(0)

        # Error rate
        if profile['error_patterns']:
            error_rate = sum(1 for error in profile['error_patterns'] if error) / len(profile['error_patterns'])
            features.append(error_rate)
        else:
            features.append(0)

        # Payload size statistics
        if profile['payload_sizes']:
            features.extend([
                np.mean(profile['payload_sizes']),
                np.std(profile['payload_sizes']),
                np.max(profile['payload_sizes']) - np.min(profile['payload_sizes'])
            ])
        else:
            features.extend([0, 0, 0])

        return np.array(features)

    def _update_client_profile(self, profile: Dict, analysis: PacketAnalysis, features: np.ndarray):
        """Aktualisiert Client-Profil"""
        profile['timing_patterns'].append(analysis.timestamp)
        profile['payload_sizes'].append(analysis.payload_size)

        if analysis.dns_query:
            profile['domain_patterns'][analysis.dns_query] += 1

        # Track errors
        error_occurred = analysis.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        profile['error_patterns'].append(error_occurred)

    def _detect_behavioral_anomalies(self, client_ip: str, features: np.ndarray, profile: Dict) -> Dict[str, Any]:
        """Erkennt Verhaltensanomalien"""
        anomalies = {
            'ml_anomaly_score': 0.0,
            'pattern_anomalies': [],
            'temporal_anomalies': [],
            'statistical_anomalies': [],
            'overall_risk_score': 0.0
        }

        try:
            # ML-based anomaly detection
            if self.model_trained and len(features) > 0:
                features_scaled = self.scaler.transform([features])
                anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
                anomalies['ml_anomaly_score'] = float(anomaly_score)

                if anomaly_score < self.anomaly_threshold:
                    anomalies['pattern_anomalies'].append('ml_detected_anomaly')

            # Statistical anomalies
            anomalies['statistical_anomalies'] = self._detect_statistical_anomalies(features, profile)

            # Temporal anomalies
            anomalies['temporal_anomalies'] = self._detect_temporal_anomalies(profile)

            # Calculate overall risk
            risk_factors = (
                len(anomalies['pattern_anomalies']) * 0.3 +
                len(anomalies['temporal_anomalies']) * 0.2 +
                len(anomalies['statistical_anomalies']) * 0.1 +
                abs(anomalies['ml_anomaly_score']) * 0.4
            )

            anomalies['overall_risk_score'] = min(1.0, risk_factors)

        except Exception as e:
            self.logger.error(f"Error detecting behavioral anomalies for {client_ip}: {e}")
            anomalies['error'] = str(e)

        return anomalies

    def _detect_statistical_anomalies(self, features: np.ndarray, profile: Dict) -> List[str]:
        """Erkennt statistische Anomalien"""
        anomalies = []

        # Payload size anomalies
        if len(profile['payload_sizes']) > 10:
            sizes = list(profile['payload_sizes'])
            mean_size = np.mean(sizes)
            std_size = np.std(sizes)
            current_size = features[2]  # payload_size feature

            if abs(current_size - mean_size) > self.pattern_deviation_threshold * std_size:
                anomalies.append('payload_size_anomaly')

        # Query frequency anomalies
        if len(profile['timing_patterns']) > 10:
            intervals = []
            times = list(profile['timing_patterns'])
            for i in range(1, len(times)):
                interval = (times[i] - times[i-1]).total_seconds()
                intervals.append(interval)

            if intervals:
                mean_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                current_interval = features[0]  # time_delta feature

                if current_interval > 0 and abs(current_interval - mean_interval) > self.pattern_deviation_threshold * std_interval:
                    anomalies.append('timing_anomaly')

        return anomalies

    def _detect_temporal_anomalies(self, profile: Dict) -> List[str]:
        """Erkennt zeitliche Anomalien"""
        anomalies = []
        current_time = datetime.now()

        # Unusual activity hours
        hour = current_time.hour
        if 2 <= hour <= 5:  # Very early morning activity
            anomalies.append('unusual_hour_activity')

        # Burst detection
        recent_queries = [t for t in profile['timing_patterns'] 
                         if (current_time - t).total_seconds() < 60]  # Last minute

        if len(recent_queries) > 100:  # More than 100 queries in last minute
            anomalies.append('query_burst')

        return anomalies

    async def _retrain_models(self):
        """Trainiert ML-Modelle neu"""
        try:
            if len(self.feature_history) < 100:
                return

            # Prepare training data
            features_array = np.array(list(self.feature_history))

            # Handle any NaN or infinite values
            features_array = np.nan_to_num(features_array)

            # Fit scaler and model
            features_scaled = self.scaler.fit_transform(features_array)
            self.isolation_forest.fit(features_scaled)

            self.model_trained = True
            self.last_training = datetime.now()

            self.logger.info(f"Retrained behavioral analysis models with {len(features_array)} samples")

        except Exception as e:
            self.logger.error(f"Error retraining behavioral models: {e}")


class ApplicationLayerFilteringEngine:
    """Hauptklasse für Application Layer Filtering & DPI"""

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger('jetdns.application_layer_filtering')
        self.config = config

        # Core analyzers
        self.payload_analyzer = PayloadAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()

        # Rules & policies
        self.dpi_rules: Dict[str, DPIRule] = {}
        self.custom_patterns: Dict[str, Any] = {}

        # Traffic statistics
        self.analysis_stats = defaultdict(int)
        self.threat_detections = defaultdict(lambda: defaultdict(int))
        self.performance_metrics = {
            'total_packets_analyzed': 0,
            'average_analysis_time': 0.0,
            'analysis_times': deque(maxlen=1000)
        }

        # Caching for performance
        self.analysis_cache: Dict[str, Dict] = {}
        self.cache_ttl = config.get('cache_ttl', 300)  # 5 minutes
        self.max_cache_size = config.get('max_cache_size', 10000)

        # Initialize
        asyncio.create_task(self.initialize())

    async def initialize(self):
        """Initialisiert das DPI System"""
        try:
            await self._load_dpi_rules()
            await self._load_custom_patterns()
            self.logger.info("Application Layer Filtering Engine initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize DPI Engine: {e}")

    async def _load_dpi_rules(self):
        """Lädt DPI-Regeln aus der Konfiguration"""
        rules_config = self.config.get('dpi_rules', [])

        for rule_data in rules_config:
            rule = DPIRule(
                name=rule_data['name'],
                description=rule_data.get('description', ''),
                pattern=rule_data['pattern'],
                pattern_type=rule_data.get('pattern_type', 'regex'),
                action=FilterAction(rule_data.get('action', 'log')),
                threat_level=ThreatLevel(rule_data.get('threat_level', 'medium')),
                enabled=rule_data.get('enabled', True),
                protocols=rule_data.get('protocols', ['dns']),
                source_ips=rule_data.get('source_ips', []),
                dest_ips=rule_data.get('dest_ips', []),
                ports=rule_data.get('ports', []),
                payload_size_min=rule_data.get('payload_size_min'),
                payload_size_max=rule_data.get('payload_size_max'),
                custom_response=rule_data.get('custom_response')
            )

            self.dpi_rules[rule.name] = rule

        # Add default rules if none exist
        if not self.dpi_rules:
            await self._create_default_rules()

        self.logger.info(f"Loaded {len(self.dpi_rules)} DPI rules")

    async def _create_default_rules(self):
        """Erstellt Standard-DPI-Regeln"""
        default_rules = [
            {
                'name': 'dns_tunneling_detection',
                'description': 'Detects potential DNS tunneling',
                'pattern': r'^[a-zA-Z0-9+/]{50,}\..*$',
                'action': 'alert',
                'threat_level': 'high'
            },
            {
                'name': 'dga_domains',
                'description': 'Detects Domain Generation Algorithm patterns',
                'pattern': r'^[a-z]{12,}\.(?:com|net|org)$',
                'action': 'log',
                'threat_level': 'medium'
            },
            {
                'name': 'typosquatting_protection',
                'description': 'Detects typosquatting attempts',
                'pattern': r'g[o0][o0]g[l1][e3]\.com|m[i1]cr[o0]s[o0]ft\.com',
                'action': 'block',
                'threat_level': 'high'
            }
        ]

        for rule_data in default_rules:
            rule = DPIRule(**rule_data)
            self.dpi_rules[rule.name] = rule

    async def _load_custom_patterns(self):
        """Lädt benutzerdefinierte Patterns"""
        patterns_config = self.config.get('custom_patterns', {})
        self.custom_patterns = patterns_config

    async def analyze_packet(self, packet_data: bytes, source_ip: str, dest_ip: str, 
                           source_port: int = 0, dest_port: int = 53) -> PacketAnalysis:
        """Hauptfunktion für Paket-Analyse"""
        start_time = time.time()

        try:
            # Create analysis object
            analysis = PacketAnalysis(
                timestamp=datetime.now(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol='UDP' if dest_port == 53 else 'TCP',
                application_protocol=self._detect_application_protocol(packet_data, dest_port),
                payload_size=len(packet_data),
                payload_hash=hashlib.sha256(packet_data).hexdigest()[:16]
            )

            # Check cache first
            cache_key = f"{analysis.payload_hash}:{source_ip}"
            if cache_key in self.analysis_cache:
                cached_result = self.analysis_cache[cache_key]
                if (datetime.now() - cached_result['timestamp']).seconds < self.cache_ttl:
                    return cached_result['analysis']

            # Deep packet inspection
            if analysis.application_protocol == ApplicationProtocol.DNS:
                await self._analyze_dns_packet(analysis, packet_data)

            # Behavioral analysis
            behavioral_analysis = self.behavioral_analyzer.analyze_client_behavior(source_ip, analysis)
            analysis.anomaly_score = behavioral_analysis['overall_risk_score']

            # Rule matching
            await self._apply_dpi_rules(analysis, packet_data)

            # Update statistics
            analysis_time = time.time() - start_time
            self._update_performance_metrics(analysis_time)

            # Cache result
            self.analysis_cache[cache_key] = {
                'analysis': analysis,
                'timestamp': datetime.now()
            }

            # Cleanup cache if needed
            if len(self.analysis_cache) > self.max_cache_size:
                self._cleanup_cache()

            return analysis

        except Exception as e:
            self.logger.error(f"Error analyzing packet from {source_ip}: {e}")
            # Return basic analysis on error
            return PacketAnalysis(
                timestamp=datetime.now(),
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol='Unknown',
                application_protocol=ApplicationProtocol.UNKNOWN,
                payload_size=len(packet_data),
                payload_hash=hashlib.sha256(packet_data).hexdigest()[:16],
                threat_level=ThreatLevel.INFO
            )

    def _detect_application_protocol(self, packet_data: bytes, dest_port: int) -> ApplicationProtocol:
        """Erkennt Anwendungsprotokoll"""
        # Port-based detection first
        if dest_port == 53:
            return ApplicationProtocol.DNS
        elif dest_port == 443:
            # Could be HTTPS or DoH
            if b'dns-query' in packet_data.lower() or b'application/dns-message' in packet_data.lower():
                return ApplicationProtocol.DOH
            return ApplicationProtocol.HTTPS
        elif dest_port == 853:
            return ApplicationProtocol.DOT
        elif dest_port == 80:
            return ApplicationProtocol.HTTP

        # Content-based detection
        if packet_data.startswith(b'\x00\x00') or len(packet_data) >= 12:
            try:
                # Try to parse as DNS
                header = struct.unpack('!HHHHHH', packet_data[:12])
                if 0 <= header[1] & 0x7800 <= 0x2000:  # Valid opcode range
                    return ApplicationProtocol.DNS
            except:
                pass

        return ApplicationProtocol.UNKNOWN

    async def _analyze_dns_packet(self, analysis: PacketAnalysis, packet_data: bytes):
        """Analysiert DNS-spezifische Eigenschaften"""
        try:
            # Payload analysis
            payload_analysis = self.payload_analyzer.analyze_dns_payload(packet_data)

            # Extract DNS information
            if SCAPY_AVAILABLE:
                try:
                    dns_packet = scapy.DNS(packet_data)
                    if dns_packet.qd:
                        analysis.dns_query = dns_packet.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        analysis.dns_qtype = dns_packet.qd.qtype

                    analysis.dns_response_code = dns_packet.rcode
                    analysis.dns_flags = {
                        'qr': dns_packet.qr,
                        'aa': dns_packet.aa,
                        'tc': dns_packet.tc,
                        'rd': dns_packet.rd,
                        'ra': dns_packet.ra
                    }
                except:
                    pass

            # Update threat level based on payload analysis
            risk_score = payload_analysis.get('risk_score', 0.0)
            if risk_score >= 0.8:
                analysis.threat_level = ThreatLevel.CRITICAL
            elif risk_score >= 0.6:
                analysis.threat_level = ThreatLevel.HIGH
            elif risk_score >= 0.4:
                analysis.threat_level = ThreatLevel.MEDIUM
            elif risk_score >= 0.2:
                analysis.threat_level = ThreatLevel.LOW

            # Add detected threats
            for match in payload_analysis.get('patterns_matched', []):
                analysis.threats_detected.append(f"pattern_{match['category']}")

            for sig in payload_analysis.get('binary_signatures', []):
                analysis.threats_detected.append(f"signature_{sig['category']}")

            for anomaly in payload_analysis.get('anomalies', []):
                analysis.threats_detected.append(f"anomaly_{anomaly}")

        except Exception as e:
            self.logger.error(f"Error in DNS packet analysis: {e}")

    async def _apply_dpi_rules(self, analysis: PacketAnalysis, packet_data: bytes):
        """Wendet DPI-Regeln auf das Paket an"""
        try:
            text_payload = self.payload_analyzer._extract_text_from_payload(packet_data)

            for rule_name, rule in self.dpi_rules.items():
                if not rule.enabled:
                    continue

                # Check if rule applies to this packet
                if not self._rule_matches_packet(rule, analysis):
                    continue

                # Apply pattern matching
                matches = False

                if rule.pattern_type == 'regex':
                    try:
                        matches = bool(re.search(rule.pattern, text_payload, re.IGNORECASE))
                    except re.error:
                        self.logger.warning(f"Invalid regex in rule {rule_name}: {rule.pattern}")
                        continue

                elif rule.pattern_type == 'binary':
                    pattern_bytes = bytes.fromhex(rule.pattern)
                    matches = pattern_bytes in packet_data

                elif rule.pattern_type == 'dns_name' and analysis.dns_query:
                    matches = bool(re.search(rule.pattern, analysis.dns_query, re.IGNORECASE))

                elif rule.pattern_type == 'payload':
                    matches = rule.pattern.lower() in text_payload.lower()

                if matches:
                    # Rule matched, apply action
                    await self._execute_rule_action(rule, analysis)

                    # Update threat level if rule is more severe
                    if rule.threat_level.value == 'critical' and analysis.threat_level != ThreatLevel.CRITICAL:
                        analysis.threat_level = ThreatLevel.CRITICAL
                    elif rule.threat_level.value == 'high' and analysis.threat_level not in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                        analysis.threat_level = ThreatLevel.HIGH
                    elif rule.threat_level.value == 'medium' and analysis.threat_level in [ThreatLevel.INFO, ThreatLevel.LOW]:
                        analysis.threat_level = ThreatLevel.MEDIUM

                    # Add threat to list
                    analysis.threats_detected.append(f"rule_{rule_name}")

                    # Update statistics
                    self.threat_detections[rule_name]['total'] += 1
                    self.threat_detections[rule_name][analysis.source_ip] += 1

        except Exception as e:
            self.logger.error(f"Error applying DPI rules: {e}")

    def _rule_matches_packet(self, rule: DPIRule, analysis: PacketAnalysis) -> bool:
        """Prüft, ob eine Regel auf das Paket anwendbar ist"""
        try:
            # Protocol check
            if rule.protocols and analysis.protocol.lower() not in [p.lower() for p in rule.protocols]:
                return False

            # IP range checks
            if rule.source_ips:
                source_matched = False
                for ip_range in rule.source_ips:
                    try:
                        network = ipaddress.ip_network(ip_range, strict=False)
                        if ipaddress.ip_address(analysis.source_ip) in network:
                            source_matched = True
                            break
                    except ValueError:
                        continue
                if not source_matched:
                    return False

            if rule.dest_ips:
                dest_matched = False
                for ip_range in rule.dest_ips:
                    try:
                        network = ipaddress.ip_network(ip_range, strict=False)
                        if ipaddress.ip_address(analysis.dest_ip) in network:
                            dest_matched = True
                            break
                    except ValueError:
                        continue
                if not dest_matched:
                    return False

            # Port checks
            if rule.ports:
                if analysis.dest_port not in rule.ports and analysis.source_port not in rule.ports:
                    return False

            # Payload size checks
            if rule.payload_size_min and analysis.payload_size < rule.payload_size_min:
                return False
            if rule.payload_size_max and analysis.payload_size > rule.payload_size_max:
                return False

            # Time window check
            if rule.time_window:
                current_time = datetime.now().time()
                start_time = datetime.strptime(rule.time_window['start'], '%H:%M').time()
                end_time = datetime.strptime(rule.time_window['end'], '%H:%M').time()

                if start_time <= end_time:
                    if not (start_time <= current_time <= end_time):
                        return False
                else:  # Time window crosses midnight
                    if not (current_time >= start_time or current_time <= end_time):
                        return False

            return True

        except Exception as e:
            self.logger.error(f"Error checking rule match: {e}")
            return False

    async def _execute_rule_action(self, rule: DPIRule, analysis: PacketAnalysis):
        """Führt die Aktion einer DPI-Regel aus"""
        try:
            if rule.action == FilterAction.LOG:
                self.logger.info(f"DPI Rule '{rule.name}' matched: {analysis.source_ip} -> {analysis.dest_ip}")

            elif rule.action == FilterAction.ALERT:
                self.logger.warning(f"DPI ALERT - Rule '{rule.name}': {analysis.source_ip} queried {analysis.dns_query}")

            elif rule.action == FilterAction.BLOCK:
                self.logger.warning(f"DPI BLOCK - Rule '{rule.name}': Blocking {analysis.source_ip}")
                analysis.threat_level = ThreatLevel.CRITICAL

            elif rule.action == FilterAction.QUARANTINE:
                self.logger.warning(f"DPI QUARANTINE - Rule '{rule.name}': Quarantining {analysis.source_ip}")
                # Here you could add the IP to a quarantine list

            elif rule.action == FilterAction.MODIFY:
                if rule.custom_response:
                    self.logger.info(f"DPI MODIFY - Rule '{rule.name}': Custom response for {analysis.source_ip}")

        except Exception as e:
            self.logger.error(f"Error executing rule action for {rule.name}: {e}")

    def _update_performance_metrics(self, analysis_time: float):
        """Aktualisiert Performance-Metriken"""
        self.performance_metrics['total_packets_analyzed'] += 1
        self.performance_metrics['analysis_times'].append(analysis_time)

        if self.performance_metrics['analysis_times']:
            self.performance_metrics['average_analysis_time'] = (
                sum(self.performance_metrics['analysis_times']) / 
                len(self.performance_metrics['analysis_times'])
            )

    def _cleanup_cache(self):
        """Bereinigt den Analysis-Cache"""
        # Remove oldest 20% of entries
        sorted_items = sorted(
            self.analysis_cache.items(),
            key=lambda x: x[1]['timestamp']
        )

        keep_count = int(self.max_cache_size * 0.8)
        new_cache = dict(sorted_items[-keep_count:])
        self.analysis_cache = new_cache

    async def get_dpi_statistics(self) -> Dict[str, Any]:
        """Liefert DPI-Statistiken"""
        stats = {
            'performance': dict(self.performance_metrics),
            'threat_detections': dict(self.threat_detections),
            'analysis_stats': dict(self.analysis_stats),
            'active_rules': len([r for r in self.dpi_rules.values() if r.enabled]),
            'total_rules': len(self.dpi_rules),
            'cache_stats': {
                'cache_size': len(self.analysis_cache),
                'max_cache_size': self.max_cache_size,
                'cache_hit_ratio': 0.0  # Could be calculated if we track hits
            }
        }

        return stats

    async def add_dpi_rule(self, rule: DPIRule) -> bool:
        """Fügt eine neue DPI-Regel hinzu"""
        try:
            self.dpi_rules[rule.name] = rule
            self.logger.info(f"Added DPI rule: {rule.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add DPI rule {rule.name}: {e}")
            return False

    async def update_dpi_rule(self, rule_name: str, updates: Dict) -> bool:
        """Aktualisiert eine DPI-Regel"""
        try:
            if rule_name not in self.dpi_rules:
                return False

            rule = self.dpi_rules[rule_name]

            for field, value in updates.items():
                if hasattr(rule, field):
                    setattr(rule, field, value)

            self.logger.info(f"Updated DPI rule: {rule_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to update DPI rule {rule_name}: {e}")
            return False

    async def delete_dpi_rule(self, rule_name: str) -> bool:
        """Löscht eine DPI-Regel"""
        try:
            if rule_name in self.dpi_rules:
                del self.dpi_rules[rule_name]
                self.logger.info(f"Deleted DPI rule: {rule_name}")
                return True
            return False

        except Exception as e:
            self.logger.error(f"Failed to delete DPI rule {rule_name}: {e}")
            return False


# Export for other modules
__all__ = [
    'ThreatLevel',
    'ApplicationProtocol', 
    'FilterAction',
    'PacketAnalysis',
    'DPIRule',
    'PayloadAnalyzer',
    'BehavioralAnalyzer',
    'ApplicationLayerFilteringEngine'
]
