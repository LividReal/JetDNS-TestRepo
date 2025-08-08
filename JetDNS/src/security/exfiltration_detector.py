"""
JetDNS DNS Exfiltration Detection
Erkennung von DNS-basierter Datenexfiltration mit Machine Learning
"""

import asyncio
import base64
import binascii
import logging
import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import statistics

logger = logging.getLogger(__name__)

@dataclass
class ExfiltrationPattern:
    """DNS Exfiltration Pattern"""
    client_ip: str
    domain_pattern: str
    query_count: int
    data_volume: int
    time_span: float
    entropy_avg: float
    subdomain_lengths: List[int]
    encoding_detected: List[str]
    tunnel_protocol: Optional[str]
    confidence: float
    first_seen: datetime
    last_seen: datetime

@dataclass
class DNSExfiltrationAlert:
    """DNS Exfiltration Alert"""
    alert_id: str
    client_ip: str
    target_domain: str
    pattern: ExfiltrationPattern
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    estimated_data_size: int
    tunnel_type: str
    detection_methods: List[str]
    timestamp: datetime
    is_confirmed: bool = False

class DNSExfiltrationDetector:
    """DNS Exfiltration Detection Engine"""

    def __init__(self, config_manager, analytics_manager=None):
        self.config_manager = config_manager
        self.analytics_manager = analytics_manager
        self.config = {}

        # Tracking Data Structures
        self.client_activity: Dict[str, Dict] = defaultdict(dict)  # IP -> activity data
        self.domain_patterns: Dict[str, Dict] = defaultdict(dict)  # domain -> pattern data
        self.query_sequences: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))  # IP -> queries

        # ML Models
        self.anomaly_detector = None
        self.scaler = None

        # Detection Patterns
        self.encoding_patterns = {
            'base64': re.compile(r'^[A-Za-z0-9+/]+=*$'),
            'base32': re.compile(r'^[A-Z2-7]+=*$'),
            'hex': re.compile(r'^[0-9a-fA-F]+$'),
            'base58': re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$')
        }

        # Known Tunneling Tools Signatures
        self.tunnel_signatures = {
            'dnscat2': {
                'pattern': r'^[0-9a-f]{8}\.[0-9a-f]+\.',
                'characteristics': ['hex_encoding', 'session_id', 'sequence_numbers']
            },
            'iodine': {
                'pattern': r'^[0-9a-zA-Z\-]{4,}\..*',
                'characteristics': ['base32_encoding', 'fragmentation', 'high_entropy']
            },
            'dns2tcp': {
                'pattern': r'^[0-9a-f]{2}[0-9a-f]*\.',
                'characteristics': ['hex_encoding', 'tcp_over_dns', 'session_management']
            },
            'ozymandns': {
                'pattern': r'^[a-zA-Z0-9]{8,16}\.',
                'characteristics': ['custom_encoding', 'compression', 'steganography']
            }
        }

        # Statistics
        self.stats = {
            'queries_analyzed': 0,
            'exfiltration_detected': 0,
            'false_positives': 0,
            'data_volume_detected': 0,
            'active_tunnels': 0
        }

    async def initialize(self):
        """Initialize DNS Exfiltration Detector"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("DNS Exfiltration Detection deaktiviert")
            return

        await self._initialize_ml_models()

        # Background tasks
        asyncio.create_task(self._analysis_task())
        asyncio.create_task(self._cleanup_task())
        asyncio.create_task(self._pattern_correlation_task())

        logger.info("🕵️ DNS Exfiltration Detector initialisiert")

    async def _load_config(self):
        """Load exfiltration detection configuration"""
        self.config = self.config_manager.get_config('dns_exfiltration', {
            'enabled': True,
            'detection_threshold': 0.7,
            'analysis_window': 300,  # 5 minutes
            'min_query_count': 10,
            'max_subdomain_length': 63,
            'entropy_threshold': 3.5,
            'data_volume_threshold': 1024,  # bytes
            'whitelist_domains': [
                'update.microsoft.com',
                'clients.google.com',
                'ocsp.apple.com'
            ],
            'alert_severities': {
                'low_threshold': 0.5,
                'medium_threshold': 0.7,
                'high_threshold': 0.85,
                'critical_threshold': 0.95
            },
            'ml_detection': {
                'enabled': True,
                'contamination_rate': 0.1,
                'feature_window': 100
            }
        })

    async def _initialize_ml_models(self):
        """Initialize ML models for anomaly detection"""
        try:
            if not self.config.get('ml_detection', {}).get('enabled', True):
                return

            # Isolation Forest for anomaly detection
            contamination = self.config.get('ml_detection', {}).get('contamination_rate', 0.1)
            self.anomaly_detector = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )

            # Feature scaler
            self.scaler = StandardScaler()

            logger.info("🕵️ ML models for exfiltration detection initialized")

        except Exception as e:
            logger.error(f"Error initializing exfiltration detection ML models: {e}")

    async def analyze_query(self, query_data: Dict) -> Optional[DNSExfiltrationAlert]:
        """Analyze single DNS query for exfiltration patterns"""
        try:
            self.stats['queries_analyzed'] += 1

            client_ip = query_data.get('client_ip')
            domain = query_data.get('domain', '').lower()
            query_time = query_data.get('timestamp', time.time())

            if not client_ip or not domain:
                return None

            # Check whitelist
            if any(domain.endswith(whitelist) for whitelist in self.config.get('whitelist_domains', [])):
                return None

            # Update client activity
            await self._update_client_activity(client_ip, domain, query_time)

            # Add to query sequence
            self.query_sequences[client_ip].append({
                'domain': domain,
                'timestamp': query_time,
                'query_type': query_data.get('qtype', 'A'),
                'response_code': query_data.get('response_code', 'NOERROR')
            })

            # Analyze for exfiltration patterns
            alert = await self._detect_exfiltration_pattern(client_ip, domain, query_time)

            if alert:
                self.stats['exfiltration_detected'] += 1
                logger.warning(f"🕵️ DNS Exfiltration detected: {client_ip} -> {domain}")

            return alert

        except Exception as e:
            logger.error(f"Error analyzing query for exfiltration: {e}")
            return None

    async def _update_client_activity(self, client_ip: str, domain: str, query_time: float):
        """Update client activity tracking"""
        try:
            if client_ip not in self.client_activity:
                self.client_activity[client_ip] = {
                    'first_seen': query_time,
                    'last_seen': query_time,
                    'query_count': 0,
                    'unique_domains': set(),
                    'domain_patterns': defaultdict(int),
                    'total_data_volume': 0,
                    'entropy_values': [],
                    'subdomain_lengths': [],
                    'time_intervals': deque(maxlen=100)
                }

            activity = self.client_activity[client_ip]

            # Update basic stats
            activity['last_seen'] = query_time
            activity['query_count'] += 1
            activity['unique_domains'].add(domain)

            # Track time intervals
            if activity.get('prev_query_time'):
                interval = query_time - activity['prev_query_time']
                activity['time_intervals'].append(interval)

            activity['prev_query_time'] = query_time

            # Analyze domain structure
            await self._analyze_domain_structure(activity, domain)

        except Exception as e:
            logger.error(f"Error updating client activity: {e}")

    async def _analyze_domain_structure(self, activity: Dict, domain: str):
        """Analyze domain structure for exfiltration indicators"""
        try:
            parts = domain.split('.')

            for part in parts[:-2]:  # Exclude TLD and main domain
                # Track subdomain length
                activity['subdomain_lengths'].append(len(part))

                # Calculate entropy
                entropy = await self._calculate_entropy(part)
                activity['entropy_values'].append(entropy)

                # Estimate data volume (rough approximation)
                if await self._is_encoded_data(part):
                    estimated_bytes = await self._estimate_data_size(part)
                    activity['total_data_volume'] += estimated_bytes

                # Track patterns
                pattern = await self._extract_pattern(part)
                activity['domain_patterns'][pattern] += 1

        except Exception as e:
            logger.error(f"Error analyzing domain structure: {e}")

    async def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        try:
            if not text:
                return 0.0

            from collections import Counter
            import math

            char_counts = Counter(text.lower())
            text_length = len(text)

            entropy = 0.0
            for count in char_counts.values():
                probability = count / text_length
                entropy -= probability * math.log2(probability)

            return entropy

        except Exception:
            return 0.0

    async def _is_encoded_data(self, text: str) -> bool:
        """Check if text appears to be encoded data"""
        try:
            # Check against encoding patterns
            for encoding_name, pattern in self.encoding_patterns.items():
                if pattern.match(text) and len(text) > 8:
                    return True

            # High entropy indicator
            entropy = await self._calculate_entropy(text)
            if entropy > self.config.get('entropy_threshold', 3.5):
                return True

            return False

        except Exception:
            return False

    async def _estimate_data_size(self, encoded_text: str) -> int:
        """Estimate decoded data size"""
        try:
            # Base64: 4 chars = 3 bytes
            if self.encoding_patterns['base64'].match(encoded_text):
                return (len(encoded_text) * 3) // 4

            # Base32: 8 chars = 5 bytes
            if self.encoding_patterns['base32'].match(encoded_text):
                return (len(encoded_text) * 5) // 8

            # Hex: 2 chars = 1 byte
            if self.encoding_patterns['hex'].match(encoded_text):
                return len(encoded_text) // 2

            # Default estimation
            return len(encoded_text) // 2

        except Exception:
            return 0

    async def _extract_pattern(self, text: str) -> str:
        """Extract pattern from domain part"""
        try:
            # Replace digits with 'N', letters with 'A'
            pattern = ''
            for char in text:
                if char.isdigit():
                    pattern += 'N'
                elif char.isalpha():
                    pattern += 'A'
                else:
                    pattern += char

            # Compress consecutive same characters
            compressed = ''
            prev_char = ''
            count = 0

            for char in pattern:
                if char == prev_char:
                    count += 1
                else:
                    if prev_char and count > 0:
                        compressed += f"{prev_char}{count}" if count > 1 else prev_char
                    prev_char = char
                    count = 1

            if prev_char and count > 0:
                compressed += f"{prev_char}{count}" if count > 1 else prev_char

            return compressed

        except Exception:
            return 'UNKNOWN'

    async def _detect_exfiltration_pattern(self, client_ip: str, domain: str, 
                                         query_time: float) -> Optional[DNSExfiltrationAlert]:
        """Detect exfiltration patterns"""
        try:
            activity = self.client_activity.get(client_ip)
            if not activity:
                return None

            # Time window analysis
            window_size = self.config.get('analysis_window', 300)
            recent_queries = [
                q for q in self.query_sequences[client_ip]
                if query_time - q['timestamp'] <= window_size
            ]

            if len(recent_queries) < self.config.get('min_query_count', 10):
                return None

            # Feature extraction
            features = await self._extract_features(activity, recent_queries)

            # Rule-based detection
            rule_result = await self._rule_based_detection(features)

            # ML-based detection
            ml_result = await self._ml_based_detection(features)

            # Signature-based detection
            signature_result = await self._signature_based_detection(recent_queries)

            # Combine results
            max_confidence = max(
                rule_result.get('confidence', 0),
                ml_result.get('confidence', 0),
                signature_result.get('confidence', 0)
            )

            detection_threshold = self.config.get('detection_threshold', 0.7)

            if max_confidence >= detection_threshold:
                # Create alert
                alert = await self._create_exfiltration_alert(
                    client_ip, domain, features, max_confidence,
                    [rule_result, ml_result, signature_result]
                )

                return alert

            return None

        except Exception as e:
            logger.error(f"Error detecting exfiltration pattern: {e}")
            return None

    async def _extract_features(self, activity: Dict, recent_queries: List[Dict]) -> Dict:
        """Extract features for exfiltration detection"""
        try:
            features = {}

            # Query frequency features
            features['query_count'] = len(recent_queries)
            features['unique_domains'] = len(set(q['domain'] for q in recent_queries))
            features['query_rate'] = len(recent_queries) / self.config.get('analysis_window', 300)

            # Time-based features
            if activity.get('time_intervals'):
                intervals = list(activity['time_intervals'])
                features['avg_interval'] = statistics.mean(intervals)
                features['interval_variance'] = statistics.variance(intervals) if len(intervals) > 1 else 0
                features['regular_timing'] = features['interval_variance'] < 1.0  # Regular intervals
            else:
                features['avg_interval'] = 0
                features['interval_variance'] = 0
                features['regular_timing'] = False

            # Domain structure features
            if activity.get('subdomain_lengths'):
                lengths = activity['subdomain_lengths'][-100:]  # Recent lengths
                features['avg_subdomain_length'] = statistics.mean(lengths)
                features['max_subdomain_length'] = max(lengths)
                features['length_variance'] = statistics.variance(lengths) if len(lengths) > 1 else 0
            else:
                features['avg_subdomain_length'] = 0
                features['max_subdomain_length'] = 0
                features['length_variance'] = 0

            # Entropy features
            if activity.get('entropy_values'):
                entropies = activity['entropy_values'][-100:]  # Recent entropies
                features['avg_entropy'] = statistics.mean(entropies)
                features['max_entropy'] = max(entropies)
                features['high_entropy_ratio'] = sum(1 for e in entropies if e > 3.5) / len(entropies)
            else:
                features['avg_entropy'] = 0
                features['max_entropy'] = 0
                features['high_entropy_ratio'] = 0

            # Data volume features
            features['total_data_volume'] = activity.get('total_data_volume', 0)
            features['data_rate'] = features['total_data_volume'] / self.config.get('analysis_window', 300)

            # Pattern diversity
            patterns = activity.get('domain_patterns', {})
            features['pattern_diversity'] = len(patterns)
            features['most_common_pattern_ratio'] = max(patterns.values()) / sum(patterns.values()) if patterns else 0

            return features

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {}

    async def _rule_based_detection(self, features: Dict) -> Dict:
        """Rule-based exfiltration detection"""
        try:
            score = 0.0
            reasons = []

            # High query frequency
            if features.get('query_rate', 0) > 10:  # > 10 queries per minute
                score += 0.2
                reasons.append('high_query_rate')

            # Large subdomains
            if features.get('avg_subdomain_length', 0) > 30:
                score += 0.3
                reasons.append('large_subdomains')

            # High entropy
            if features.get('avg_entropy', 0) > 3.5:
                score += 0.3
                reasons.append('high_entropy')

            # Regular timing (automated)
            if features.get('regular_timing', False) and features.get('interval_variance', 0) < 0.5:
                score += 0.2
                reasons.append('regular_timing')

            # High data volume
            if features.get('total_data_volume', 0) > self.config.get('data_volume_threshold', 1024):
                score += 0.3
                reasons.append('high_data_volume')

            # Pattern repetition
            if features.get('most_common_pattern_ratio', 0) > 0.8:
                score += 0.2
                reasons.append('pattern_repetition')

            return {
                'method': 'rule_based',
                'confidence': min(score, 1.0),
                'reasons': reasons
            }

        except Exception as e:
            logger.error(f"Rule-based detection error: {e}")
            return {'method': 'rule_based', 'confidence': 0.0, 'reasons': []}

    async def _ml_based_detection(self, features: Dict) -> Dict:
        """ML-based anomaly detection"""
        try:
            if not self.anomaly_detector or not self.scaler:
                return {'method': 'ml_based', 'confidence': 0.0, 'reasons': []}

            # Feature vector
            feature_vector = np.array([[
                features.get('query_count', 0),
                features.get('query_rate', 0),
                features.get('avg_subdomain_length', 0),
                features.get('avg_entropy', 0),
                features.get('total_data_volume', 0),
                features.get('pattern_diversity', 0),
                features.get('interval_variance', 0)
            ]])

            # Normalize features
            if hasattr(self.scaler, 'transform'):
                feature_vector = self.scaler.transform(feature_vector)

            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
            is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1

            # Convert anomaly score to confidence
            confidence = 0.0
            if is_anomaly:
                # Normalize anomaly score to 0-1 range
                confidence = min(abs(anomaly_score) / 2.0, 1.0)

            return {
                'method': 'ml_based',
                'confidence': confidence,
                'anomaly_score': anomaly_score,
                'is_anomaly': is_anomaly
            }

        except Exception as e:
            logger.error(f"ML-based detection error: {e}")
            return {'method': 'ml_based', 'confidence': 0.0, 'reasons': []}

    async def _signature_based_detection(self, recent_queries: List[Dict]) -> Dict:
        """Signature-based detection for known tools"""
        try:
            max_confidence = 0.0
            detected_tool = None

            # Check against known tunneling tool signatures
            for query in recent_queries:
                domain = query['domain']

                for tool_name, signature_data in self.tunnel_signatures.items():
                    pattern = signature_data['pattern']

                    if re.search(pattern, domain):
                        confidence = 0.8  # High confidence for signature match

                        # Additional characteristic checks
                        characteristics = signature_data.get('characteristics', [])
                        char_score = 0.0

                        for characteristic in characteristics:
                            if await self._check_characteristic(domain, characteristic):
                                char_score += 0.1

                        total_confidence = min(confidence + char_score, 1.0)

                        if total_confidence > max_confidence:
                            max_confidence = total_confidence
                            detected_tool = tool_name

            return {
                'method': 'signature_based',
                'confidence': max_confidence,
                'detected_tool': detected_tool
            }

        except Exception as e:
            logger.error(f"Signature-based detection error: {e}")
            return {'method': 'signature_based', 'confidence': 0.0}

    async def _check_characteristic(self, domain: str, characteristic: str) -> bool:
        """Check for specific tunneling tool characteristics"""
        try:
            if characteristic == 'hex_encoding':
                parts = domain.split('.')
                return any(self.encoding_patterns['hex'].match(part) for part in parts[:-2])

            elif characteristic == 'base32_encoding':
                parts = domain.split('.')
                return any(self.encoding_patterns['base32'].match(part) for part in parts[:-2])

            elif characteristic == 'high_entropy':
                parts = domain.split('.')
                for part in parts[:-2]:
                    entropy = await self._calculate_entropy(part)
                    if entropy > 4.0:
                        return True
                return False

            elif characteristic == 'session_id':
                # Look for session ID patterns
                return bool(re.search(r'[0-9a-f]{8,16}', domain))

            elif characteristic == 'fragmentation':
                # Look for fragmentation indicators
                return bool(re.search(r'[0-9]+\.[0-9]+\.', domain))

            return False

        except Exception:
            return False

    async def _create_exfiltration_alert(self, client_ip: str, domain: str, features: Dict,
                                       confidence: float, detection_results: List[Dict]) -> DNSExfiltrationAlert:
        """Create exfiltration alert"""
        try:
            # Determine severity
            severities = self.config.get('alert_severities', {})

            if confidence >= severities.get('critical_threshold', 0.95):
                severity = 'CRITICAL'
            elif confidence >= severities.get('high_threshold', 0.85):
                severity = 'HIGH'
            elif confidence >= severities.get('medium_threshold', 0.7):
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

            # Identify tunnel type
            tunnel_type = 'unknown'
            for result in detection_results:
                if result.get('detected_tool'):
                    tunnel_type = result['detected_tool']
                    break

            # Create pattern
            activity = self.client_activity[client_ip]
            pattern = ExfiltrationPattern(
                client_ip=client_ip,
                domain_pattern=domain,
                query_count=features.get('query_count', 0),
                data_volume=features.get('total_data_volume', 0),
                time_span=self.config.get('analysis_window', 300),
                entropy_avg=features.get('avg_entropy', 0),
                subdomain_lengths=activity.get('subdomain_lengths', [])[-10:],
                encoding_detected=[],
                tunnel_protocol=tunnel_type,
                confidence=confidence,
                first_seen=datetime.fromtimestamp(activity.get('first_seen', time.time())),
                last_seen=datetime.fromtimestamp(activity.get('last_seen', time.time()))
            )

            # Detection methods
            detection_methods = [r['method'] for r in detection_results if r.get('confidence', 0) > 0.5]

            alert = DNSExfiltrationAlert(
                alert_id=f"exfil_{client_ip}_{int(time.time())}",
                client_ip=client_ip,
                target_domain=domain,
                pattern=pattern,
                severity=severity,
                estimated_data_size=features.get('total_data_volume', 0),
                tunnel_type=tunnel_type,
                detection_methods=detection_methods,
                timestamp=datetime.now()
            )

            # Update stats
            self.stats['data_volume_detected'] += features.get('total_data_volume', 0)

            return alert

        except Exception as e:
            logger.error(f"Error creating exfiltration alert: {e}")
            return None

    async def _analysis_task(self):
        """Background task for continuous analysis"""
        while True:
            try:
                await asyncio.sleep(60)  # Every minute

                # Update ML model with recent data
                await self._update_ml_model()

                # Check for long-term patterns
                await self._analyze_long_term_patterns()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Analysis task error: {e}")

    async def _cleanup_task(self):
        """Background task for data cleanup"""
        while True:
            try:
                await asyncio.sleep(3600)  # Every hour

                current_time = time.time()
                cleanup_age = 3600 * 24  # 24 hours

                # Clean old client activity
                expired_clients = [
                    ip for ip, activity in self.client_activity.items()
                    if current_time - activity.get('last_seen', 0) > cleanup_age
                ]

                for ip in expired_clients:
                    del self.client_activity[ip]
                    if ip in self.query_sequences:
                        del self.query_sequences[ip]

                if expired_clients:
                    logger.debug(f"🕵️ Cleaned {len(expired_clients)} expired client activities")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    async def _pattern_correlation_task(self):
        """Background task for pattern correlation"""
        while True:
            try:
                await asyncio.sleep(1800)  # Every 30 minutes

                # Correlate patterns across clients
                await self._correlate_patterns()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Pattern correlation task error: {e}")

    async def _update_ml_model(self):
        """Update ML model with recent data"""
        try:
            if not self.anomaly_detector or len(self.client_activity) < 10:
                return

            # Extract features from all clients
            feature_vectors = []

            for client_ip, activity in self.client_activity.items():
                if activity.get('query_count', 0) > 0:
                    recent_queries = list(self.query_sequences[client_ip])[-100:]  # Recent queries

                    if recent_queries:
                        features = await self._extract_features(activity, recent_queries)

                        feature_vector = [
                            features.get('query_count', 0),
                            features.get('query_rate', 0),
                            features.get('avg_subdomain_length', 0),
                            features.get('avg_entropy', 0),
                            features.get('total_data_volume', 0),
                            features.get('pattern_diversity', 0),
                            features.get('interval_variance', 0)
                        ]

                        feature_vectors.append(feature_vector)

            if len(feature_vectors) >= 10:
                # Retrain anomaly detector
                X = np.array(feature_vectors)

                # Fit scaler
                self.scaler.fit(X)
                X_scaled = self.scaler.transform(X)

                # Retrain anomaly detector
                self.anomaly_detector.fit(X_scaled)

                logger.debug(f"🕵️ ML model updated with {len(feature_vectors)} samples")

        except Exception as e:
            logger.error(f"ML model update error: {e}")

    async def _analyze_long_term_patterns(self):
        """Analyze long-term exfiltration patterns"""
        try:
            # This would implement long-term trend analysis
            # For now, just update statistics

            self.stats['active_tunnels'] = len([
                activity for activity in self.client_activity.values()
                if time.time() - activity.get('last_seen', 0) < 3600  # Active in last hour
            ])

        except Exception as e:
            logger.error(f"Long-term analysis error: {e}")

    async def _correlate_patterns(self):
        """Correlate patterns across different clients"""
        try:
            # Group clients by similar patterns
            pattern_groups = defaultdict(list)

            for client_ip, activity in self.client_activity.items():
                # Create a signature for the client's behavior
                signature = self._create_behavior_signature(activity)
                pattern_groups[signature].append(client_ip)

            # Identify coordinated exfiltration
            for signature, clients in pattern_groups.items():
                if len(clients) > 1:
                    logger.info(f"🕵️ Potential coordinated exfiltration detected: {len(clients)} clients with similar patterns")

        except Exception as e:
            logger.error(f"Pattern correlation error: {e}")

    def _create_behavior_signature(self, activity: Dict) -> str:
        """Create behavior signature for pattern correlation"""
        try:
            # Create a simple signature based on activity patterns
            query_rate = activity.get('query_count', 0) / max(time.time() - activity.get('first_seen', time.time()), 1)
            avg_entropy = statistics.mean(activity.get('entropy_values', [0])[-10:])
            avg_length = statistics.mean(activity.get('subdomain_lengths', [0])[-10:])

            # Quantize values for grouping
            rate_bucket = int(query_rate * 10) // 10
            entropy_bucket = int(avg_entropy * 10) // 10
            length_bucket = int(avg_length) // 5

            return f"{rate_bucket}_{entropy_bucket}_{length_bucket}"

        except Exception:
            return "unknown"

    async def get_exfiltration_stats(self) -> Dict:
        """Get DNS exfiltration detection statistics"""
        active_clients = len([
            activity for activity in self.client_activity.values()
            if time.time() - activity.get('last_seen', 0) < 3600
        ])

        return {
            'enabled': self.config.get('enabled', False),
            'detection_threshold': self.config.get('detection_threshold', 0.7),
            'analysis_window': self.config.get('analysis_window', 300),
            'active_clients': active_clients,
            'total_tracked_clients': len(self.client_activity),
            'ml_detection_enabled': self.config.get('ml_detection', {}).get('enabled', True),
            'known_tunnel_signatures': len(self.tunnel_signatures),
            'stats': self.stats
        }

    async def get_client_activity(self, client_ip: str) -> Optional[Dict]:
        """Get detailed activity for specific client"""
        activity = self.client_activity.get(client_ip)

        if not activity:
            return None

        # Convert to serializable format
        serializable_activity = {
            'client_ip': client_ip,
            'first_seen': datetime.fromtimestamp(activity.get('first_seen', 0)).isoformat(),
            'last_seen': datetime.fromtimestamp(activity.get('last_seen', 0)).isoformat(),
            'query_count': activity.get('query_count', 0),
            'unique_domains': len(activity.get('unique_domains', set())),
            'total_data_volume': activity.get('total_data_volume', 0),
            'avg_entropy': statistics.mean(activity.get('entropy_values', [0])) if activity.get('entropy_values') else 0,
            'avg_subdomain_length': statistics.mean(activity.get('subdomain_lengths', [0])) if activity.get('subdomain_lengths') else 0,
            'pattern_diversity': len(activity.get('domain_patterns', {})),
            'recent_queries': list(self.query_sequences[client_ip])[-10:]  # Last 10 queries
        }

        return serializable_activity

    def reload_config(self):
        """Reload exfiltration detection configuration"""
        asyncio.create_task(self._load_config())
        logger.info("🕵️ DNS Exfiltration Detector Konfiguration neu geladen")
