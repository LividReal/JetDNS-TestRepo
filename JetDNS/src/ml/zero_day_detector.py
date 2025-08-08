"""
JetDNS Zero-Day Domain Detection
Machine Learning-basierte Erkennung von neu registrierten und verdächtigen Domains
"""

import asyncio
import hashlib
import logging
import math
import re
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import whois
import requests

logger = logging.getLogger(__name__)

@dataclass
class DomainFeatures:
    """Features for zero-day domain analysis"""
    domain: str
    length: int
    entropy: float
    vowel_consonant_ratio: float
    digit_ratio: float
    special_char_ratio: float
    subdomain_count: int
    tld_category: str
    registrar_reputation: float
    age_in_days: int
    certificate_info: Dict
    dns_records_count: int
    mx_records_exist: bool
    suspicious_keywords: List[str]
    similarity_to_popular: float
    linguistic_features: Dict
    network_features: Dict
    first_seen_timestamp: float

@dataclass
class ZeroDayAlert:
    """Zero-day domain detection alert"""
    alert_id: str
    domain: str
    confidence: float
    risk_category: str  # SUSPICIOUS, MALICIOUS, PHISHING, DGA
    detection_methods: List[str]
    features: DomainFeatures
    similar_domains: List[str]
    threat_indicators: List[str]
    recommended_action: str
    timestamp: datetime

class ZeroDayDetector:
    """Zero-Day Domain Detection Engine"""

    def __init__(self, config_manager, threat_intelligence=None):
        self.config_manager = config_manager
        self.threat_intelligence = threat_intelligence
        self.config = {}

        # ML Models
        self.classifier = None
        self.clustering_model = None
        self.scaler = None
        self.vectorizer = None

        # Domain Intelligence
        self.domain_database: Dict[str, Dict] = {}  # domain -> metadata
        self.popular_domains: Set[str] = set()
        self.tld_categories: Dict[str, str] = {}
        self.registrar_reputation: Dict[str, float] = {}

        # Suspicious patterns
        self.suspicious_keywords = {
            'phishing': [
                'login', 'secure', 'account', 'verify', 'update', 'confirm',
                'bank', 'paypal', 'amazon', 'microsoft', 'google', 'apple',
                'facebook', 'twitter', 'instagram', 'linkedin'
            ],
            'malware': [
                'download', 'free', 'crack', 'keygen', 'patch', 'serial',
                'activation', 'license', 'premium', 'full', 'version'
            ],
            'spam': [
                'casino', 'pharmacy', 'viagra', 'pills', 'loan', 'credit',
                'money', 'earn', 'profit', 'investment', 'bitcoin'
            ],
            'typosquatting': [
                'goog1e', 'arnazon', 'microsft', 'facebbok', 'twiter'
            ]
        }

        # Statistics
        self.stats = {
            'domains_analyzed': 0,
            'zero_days_detected': 0,
            'phishing_detected': 0,
            'malware_detected': 0,
            'false_positives': 0,
            'model_accuracy': 0.0
        }

    async def initialize(self):
        """Initialize Zero-Day Detector"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("Zero-Day Domain Detection deaktiviert")
            return

        await self._load_domain_intelligence()
        await self._load_models()

        # Background tasks
        asyncio.create_task(self._domain_intelligence_update_task())
        asyncio.create_task(self._model_training_task())
        asyncio.create_task(self._threat_feed_integration_task())

        logger.info("🎯 Zero-Day Detector initialisiert")

    async def _load_config(self):
        """Load zero-day detection configuration"""
        self.config = self.config_manager.get_config('zero_day_detection', {
            'enabled': True,
            'detection_threshold': 0.75,
            'real_time_analysis': True,
            'domain_age_threshold': 30,  # days
            'entropy_threshold': 3.0,
            'similarity_threshold': 0.8,
            'whois_lookup': True,
            'certificate_analysis': True,
            'dns_analysis': True,
            'clustering_enabled': True,
            'threat_feed_integration': True,
            'whitelist_tlds': [
                'edu', 'gov', 'mil', 'org'
            ],
            'suspicious_tlds': [
                'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'work'
            ],
            'model_update_interval': 86400,  # 24 hours
            'max_domain_age': 365  # days
        })

    async def _load_domain_intelligence(self):
        """Load domain intelligence data"""
        try:
            # Load popular domains (Alexa Top 1M equivalent)
            popular_domains_list = [
                'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
                'instagram.com', 'linkedin.com', 'wikipedia.org', 'amazon.com',
                'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com',
                'yahoo.com', 'ebay.com', 'pinterest.com', 'tumblr.com'
            ]
            self.popular_domains = set(popular_domains_list)

            # TLD categories
            self.tld_categories = {
                'com': 'commercial',
                'org': 'organization',
                'net': 'network',
                'edu': 'education',
                'gov': 'government',
                'mil': 'military',
                'int': 'international',
                'tk': 'suspicious',
                'ml': 'suspicious',
                'ga': 'suspicious',
                'cf': 'suspicious',
                'gq': 'suspicious'
            }

            # Registrar reputation scores (simplified)
            self.registrar_reputation = {
                'GoDaddy': 0.8,
                'Namecheap': 0.8,
                'CloudFlare': 0.9,
                'Amazon': 0.9,
                'Google': 0.9,
                'Unknown': 0.3,
                'Freenom': 0.2  # Often used for malicious domains
            }

            logger.info(f"🎯 Domain intelligence loaded: {len(self.popular_domains)} popular domains")

        except Exception as e:
            logger.error(f"Error loading domain intelligence: {e}")

    async def _load_models(self):
        """Load or train ML models"""
        try:
            # Try to load existing models
            model_path = '/var/lib/jetdns/ml_models/'

            try:
                import joblib
                self.classifier = joblib.load(f'{model_path}/zero_day_classifier.pkl')
                self.scaler = joblib.load(f'{model_path}/zero_day_scaler.pkl')
                self.vectorizer = joblib.load(f'{model_path}/zero_day_vectorizer.pkl')

                logger.info("🎯 Pre-trained zero-day models loaded")

            except FileNotFoundError:
                # Train new models
                await self._train_models()

        except Exception as e:
            logger.error(f"Error loading zero-day models: {e}")
            await self._train_models()

    async def _train_models(self):
        """Train zero-day detection models"""
        try:
            logger.info("🎯 Training zero-day detection models...")

            # Generate training data
            training_data = await self._generate_training_data()

            if len(training_data) < 1000:
                logger.warning("Insufficient training data for zero-day detection")
                return

            # Extract features and labels
            X_features = []
            X_text = []
            y = []

            for domain_data in training_data:
                features = await self._extract_features(domain_data['domain'])

                # Numerical features
                feature_vector = [
                    features.length,
                    features.entropy,
                    features.vowel_consonant_ratio,
                    features.digit_ratio,
                    features.subdomain_count,
                    features.registrar_reputation,
                    features.age_in_days,
                    features.dns_records_count,
                    features.similarity_to_popular,
                    len(features.suspicious_keywords)
                ]

                X_features.append(feature_vector)
                X_text.append(domain_data['domain'])
                y.append(domain_data['is_malicious'])

            X_features = np.array(X_features)
            y = np.array(y)

            # Train feature scaler
            self.scaler = StandardScaler()
            X_features_scaled = self.scaler.fit_transform(X_features)

            # Train text vectorizer
            self.vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 4),
                max_features=1000
            )
            X_text_features = self.vectorizer.fit_transform(X_text)

            # Combine features
            from scipy.sparse import hstack
            X_combined = hstack([X_features_scaled, X_text_features])

            # Train classifier
            self.classifier = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42
            )
            self.classifier.fit(X_combined, y)

            # Evaluate model
            from sklearn.model_selection import cross_val_score
            scores = cross_val_score(self.classifier, X_combined, y, cv=5)
            self.stats['model_accuracy'] = np.mean(scores)

            # Train clustering model for similar domain detection
            if self.config.get('clustering_enabled', True):
                self.clustering_model = DBSCAN(eps=0.3, min_samples=5)
                self.clustering_model.fit(X_text_features.toarray())

            # Save models
            await self._save_models()

            logger.info(f"🎯 Zero-day models trained successfully (Accuracy: {self.stats['model_accuracy']:.3f})")

        except Exception as e:
            logger.error(f"Error training zero-day models: {e}")

    async def _generate_training_data(self) -> List[Dict]:
        """Generate training data for zero-day detection"""
        training_data = []

        try:
            # Legitimate domains
            legitimate_domains = list(self.popular_domains)

            for domain in legitimate_domains:
                training_data.append({
                    'domain': domain,
                    'is_malicious': False,
                    'category': 'legitimate'
                })

            # Generate suspicious domains
            suspicious_domains = await self._generate_suspicious_domains()

            for domain in suspicious_domains:
                training_data.append({
                    'domain': domain,
                    'is_malicious': True,
                    'category': 'suspicious'
                })

            # Load from threat intelligence
            if self.threat_intelligence:
                ti_domains = await self.threat_intelligence.get_malicious_domains()
                for domain_info in ti_domains:
                    training_data.append({
                        'domain': domain_info['domain'],
                        'is_malicious': True,
                        'category': 'threat_intel'
                    })

            logger.info(f"🎯 Generated {len(training_data)} training samples")
            return training_data

        except Exception as e:
            logger.error(f"Error generating training data: {e}")
            return []

    async def _generate_suspicious_domains(self) -> List[str]:
        """Generate synthetic suspicious domains"""
        suspicious_domains = []

        try:
            import random
            import string

            # Typosquatting domains
            for popular_domain in list(self.popular_domains)[:50]:
                base_name = popular_domain.split('.')[0]

                # Character substitution
                substitutions = {'o': '0', 'i': '1', 'e': '3', 'a': '@', 's': '$'}
                for char, sub in substitutions.items():
                    if char in base_name:
                        typo_domain = base_name.replace(char, sub) + '.com'
                        suspicious_domains.append(typo_domain)

                # Character insertion
                pos = random.randint(1, len(base_name) - 1)
                char = random.choice('abcdefghijklmnopqrstuvwxyz')
                typo_domain = base_name[:pos] + char + base_name[pos:] + '.com'
                suspicious_domains.append(typo_domain)

                # Character deletion
                if len(base_name) > 4:
                    pos = random.randint(1, len(base_name) - 2)
                    typo_domain = base_name[:pos] + base_name[pos+1:] + '.com'
                    suspicious_domains.append(typo_domain)

            # Random high-entropy domains
            for _ in range(200):
                length = random.randint(8, 20)
                domain = ''.join(random.choices(string.ascii_lowercase, k=length))
                tld = random.choice(['com', 'net', 'org', 'tk', 'ml'])
                suspicious_domains.append(f"{domain}.{tld}")

            # Suspicious keyword combinations
            for category, keywords in self.suspicious_keywords.items():
                for _ in range(50):
                    keyword = random.choice(keywords)
                    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
                    domain = f"{keyword}{suffix}.com"
                    suspicious_domains.append(domain)

            return suspicious_domains

        except Exception as e:
            logger.error(f"Error generating suspicious domains: {e}")
            return []

    async def analyze_domain(self, domain: str, context: Optional[Dict] = None) -> Optional[ZeroDayAlert]:
        """Analyze domain for zero-day characteristics"""
        try:
            self.stats['domains_analyzed'] += 1

            # Check if domain is whitelisted
            if await self._is_whitelisted(domain):
                return None

            # Extract comprehensive features
            features = await self._extract_features(domain, context)

            # ML-based classification
            ml_result = await self._classify_with_ml(features)

            # Rule-based analysis
            rule_result = await self._rule_based_analysis(features)

            # Threat intelligence lookup
            ti_result = await self._threat_intelligence_lookup(domain)

            # Combine results
            max_confidence = max(
                ml_result.get('confidence', 0),
                rule_result.get('confidence', 0),
                ti_result.get('confidence', 0)
            )

            detection_threshold = self.config.get('detection_threshold', 0.75)

            if max_confidence >= detection_threshold:
                alert = await self._create_zero_day_alert(
                    domain, features, max_confidence,
                    [ml_result, rule_result, ti_result]
                )

                if alert:
                    self._update_detection_stats(alert)

                return alert

            return None

        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")
            return None

    async def _extract_features(self, domain: str, context: Optional[Dict] = None) -> DomainFeatures:
        """Extract comprehensive features from domain"""
        try:
            # Basic string features
            domain_part = domain.split('.')[0] if '.' in domain else domain
            length = len(domain_part)

            # Character analysis
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            digits = '0123456789'

            vowel_count = sum(1 for c in domain_part.lower() if c in vowels)
            consonant_count = sum(1 for c in domain_part.lower() if c in consonants)
            digit_count = sum(1 for c in domain_part if c in digits)
            special_count = length - vowel_count - consonant_count - digit_count

            vowel_consonant_ratio = vowel_count / max(consonant_count, 1)
            digit_ratio = digit_count / length if length > 0 else 0
            special_char_ratio = special_count / length if length > 0 else 0

            # Entropy calculation
            entropy = await self._calculate_entropy(domain_part)

            # Subdomain analysis
            subdomain_count = len(domain.split('.')) - 2  # Exclude domain and TLD

            # TLD analysis
            tld = domain.split('.')[-1] if '.' in domain else ''
            tld_category = self.tld_categories.get(tld.lower(), 'unknown')

            # Domain age (simplified - would use WHOIS in production)
            age_in_days = await self._get_domain_age(domain)

            # Registrar reputation (simplified)
            registrar_reputation = await self._get_registrar_reputation(domain)

            # Certificate info (simplified)
            certificate_info = await self._get_certificate_info(domain)

            # DNS records analysis
            dns_records_count = await self._get_dns_records_count(domain)
            mx_records_exist = await self._check_mx_records(domain)

            # Suspicious keywords
            suspicious_keywords = await self._find_suspicious_keywords(domain)

            # Similarity to popular domains
            similarity_to_popular = await self._calculate_similarity_to_popular(domain)

            # Linguistic features
            linguistic_features = await self._extract_linguistic_features(domain_part)

            # Network features
            network_features = await self._extract_network_features(domain, context)

            return DomainFeatures(
                domain=domain,
                length=length,
                entropy=entropy,
                vowel_consonant_ratio=vowel_consonant_ratio,
                digit_ratio=digit_ratio,
                special_char_ratio=special_char_ratio,
                subdomain_count=subdomain_count,
                tld_category=tld_category,
                registrar_reputation=registrar_reputation,
                age_in_days=age_in_days,
                certificate_info=certificate_info,
                dns_records_count=dns_records_count,
                mx_records_exist=mx_records_exist,
                suspicious_keywords=suspicious_keywords,
                similarity_to_popular=similarity_to_popular,
                linguistic_features=linguistic_features,
                network_features=network_features,
                first_seen_timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Error extracting features from {domain}: {e}")
            return DomainFeatures(
                domain=domain,
                length=len(domain),
                entropy=0,
                vowel_consonant_ratio=0,
                digit_ratio=0,
                special_char_ratio=0,
                subdomain_count=0,
                tld_category='unknown',
                registrar_reputation=0.5,
                age_in_days=0,
                certificate_info={},
                dns_records_count=0,
                mx_records_exist=False,
                suspicious_keywords=[],
                similarity_to_popular=0,
                linguistic_features={},
                network_features={},
                first_seen_timestamp=time.time()
            )

    async def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        try:
            if not text:
                return 0.0

            char_counts = Counter(text.lower())
            text_length = len(text)

            entropy = 0.0
            for count in char_counts.values():
                probability = count / text_length
                entropy -= probability * math.log2(probability)

            return entropy

        except Exception:
            return 0.0

    async def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days (simplified implementation)"""
        try:
            if self.config.get('whois_lookup', False):
                # In production, would use WHOIS lookup
                # For now, simulate based on domain characteristics

                # Suspicious TLDs are often newer
                tld = domain.split('.')[-1].lower()
                if tld in self.config.get('suspicious_tlds', []):
                    return 10  # Assume recent registration

                # Popular domains are older
                if domain in self.popular_domains:
                    return 3000  # Assume old domain

                # Random age for others
                import random
                return random.randint(1, 365)

            return 0  # Unknown age

        except Exception:
            return 0

    async def _get_registrar_reputation(self, domain: str) -> float:
        """Get registrar reputation score"""
        try:
            # Simplified implementation
            tld = domain.split('.')[-1].lower()

            if tld in ['tk', 'ml', 'ga', 'cf', 'gq']:
                return 0.2  # Free TLD services often used maliciously
            elif tld in ['com', 'net', 'org']:
                return 0.7  # Reputable TLDs
            elif tld in ['edu', 'gov', 'mil']:
                return 0.9  # Highly reputable

            return 0.5  # Default

        except Exception:
            return 0.5

    async def _get_certificate_info(self, domain: str) -> Dict:
        """Get SSL certificate information"""
        try:
            if not self.config.get('certificate_analysis', True):
                return {}

            # Simplified implementation
            # In production, would check SSL certificate details
            return {
                'has_certificate': True,
                'issuer': 'Unknown',
                'valid_days_remaining': 90
            }

        except Exception:
            return {}

    async def _get_dns_records_count(self, domain: str) -> int:
        """Count DNS records for domain"""
        try:
            if not self.config.get('dns_analysis', True):
                return 0

            # Simplified implementation
            # In production, would query DNS records
            import random
            return random.randint(1, 10)

        except Exception:
            return 0

    async def _check_mx_records(self, domain: str) -> bool:
        """Check if domain has MX records"""
        try:
            # Simplified implementation
            # In production, would check MX records
            return True  # Assume has MX records

        except Exception:
            return False

    async def _find_suspicious_keywords(self, domain: str) -> List[str]:
        """Find suspicious keywords in domain"""
        found_keywords = []

        domain_lower = domain.lower()

        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword in domain_lower:
                    found_keywords.append(keyword)

        return found_keywords

    async def _calculate_similarity_to_popular(self, domain: str) -> float:
        """Calculate similarity to popular domains"""
        try:
            max_similarity = 0.0
            domain_lower = domain.lower().replace('.', '')

            for popular_domain in list(self.popular_domains)[:100]:  # Check top 100
                popular_lower = popular_domain.lower().replace('.', '')

                # Simple Levenshtein-like similarity
                similarity = await self._calculate_string_similarity(domain_lower, popular_lower)
                max_similarity = max(max_similarity, similarity)

            return max_similarity

        except Exception:
            return 0.0

    async def _calculate_string_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity (simplified Levenshtein)"""
        try:
            if not s1 or not s2:
                return 0.0

            # Simple similarity based on common characters
            s1_set = set(s1)
            s2_set = set(s2)

            intersection = len(s1_set.intersection(s2_set))
            union = len(s1_set.union(s2_set))

            return intersection / union if union > 0 else 0.0

        except Exception:
            return 0.0

    async def _extract_linguistic_features(self, domain_part: str) -> Dict:
        """Extract linguistic features"""
        try:
            # Pronounceability score
            vowels = 'aeiou'
            pronounceable_score = 0.0

            for i, char in enumerate(domain_part.lower()):
                if i == 0:
                    continue

                prev_char = domain_part[i-1].lower()

                if char in vowels and prev_char not in vowels:
                    pronounceable_score += 1
                elif char not in vowels and prev_char in vowels:
                    pronounceable_score += 1

            pronounceable_score /= max(len(domain_part) - 1, 1)

            # Character distribution
            char_distribution = Counter(domain_part.lower())
            distribution_entropy = await self._calculate_entropy(domain_part)

            return {
                'pronounceable_score': pronounceable_score,
                'distribution_entropy': distribution_entropy,
                'unique_chars': len(char_distribution),
                'most_common_char_freq': max(char_distribution.values()) / len(domain_part) if domain_part else 0
            }

        except Exception as e:
            logger.error(f"Error extracting linguistic features: {e}")
            return {}

    async def _extract_network_features(self, domain: str, context: Optional[Dict]) -> Dict:
        """Extract network-based features"""
        try:
            features = {}

            if context:
                features['query_count'] = context.get('query_count', 0)
                features['client_count'] = context.get('client_count', 0)
                features['first_query_time'] = context.get('first_query_time', time.time())
                features['query_types'] = context.get('query_types', [])

            return features

        except Exception:
            return {}

    async def _classify_with_ml(self, features: DomainFeatures) -> Dict:
        """Classify domain using ML models"""
        try:
            if not self.classifier or not self.scaler or not self.vectorizer:
                return {'method': 'ml', 'confidence': 0.0}

            # Numerical features
            feature_vector = np.array([[
                features.length,
                features.entropy,
                features.vowel_consonant_ratio,
                features.digit_ratio,
                features.subdomain_count,
                features.registrar_reputation,
                features.age_in_days,
                features.dns_records_count,
                features.similarity_to_popular,
                len(features.suspicious_keywords)
            ]])

            # Scale features
            feature_vector_scaled = self.scaler.transform(feature_vector)

            # Text features
            text_features = self.vectorizer.transform([features.domain])

            # Combine features
            from scipy.sparse import hstack
            combined_features = hstack([feature_vector_scaled, text_features])

            # Predict
            prediction = self.classifier.predict(combined_features)[0]
            confidence = max(self.classifier.predict_proba(combined_features)[0])

            return {
                'method': 'ml',
                'confidence': confidence if prediction else 0.0,
                'prediction': bool(prediction)
            }

        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return {'method': 'ml', 'confidence': 0.0}

    async def _rule_based_analysis(self, features: DomainFeatures) -> Dict:
        """Rule-based zero-day analysis"""
        try:
            score = 0.0
            reasons = []

            # High entropy domains
            if features.entropy > 4.0:
                score += 0.3
                reasons.append('high_entropy')

            # Recently registered domains
            if features.age_in_days < self.config.get('domain_age_threshold', 30):
                score += 0.2
                reasons.append('recently_registered')

            # Suspicious TLD
            if features.tld_category == 'suspicious':
                score += 0.2
                reasons.append('suspicious_tld')

            # Low registrar reputation
            if features.registrar_reputation < 0.5:
                score += 0.2
                reasons.append('low_registrar_reputation')

            # Suspicious keywords
            if features.suspicious_keywords:
                score += len(features.suspicious_keywords) * 0.1
                reasons.append('suspicious_keywords')

            # High similarity to popular domains (typosquatting)
            if features.similarity_to_popular > self.config.get('similarity_threshold', 0.8):
                score += 0.4
                reasons.append('typosquatting')

            # Unusual character patterns
            if features.digit_ratio > 0.3:
                score += 0.1
                reasons.append('high_digit_ratio')

            # Long subdomains
            if features.subdomain_count > 3:
                score += 0.1
                reasons.append('multiple_subdomains')

            return {
                'method': 'rule_based',
                'confidence': min(score, 1.0),
                'reasons': reasons
            }

        except Exception as e:
            logger.error(f"Rule-based analysis error: {e}")
            return {'method': 'rule_based', 'confidence': 0.0, 'reasons': []}

    async def _threat_intelligence_lookup(self, domain: str) -> Dict:
        """Lookup domain in threat intelligence sources"""
        try:
            if not self.threat_intelligence:
                return {'method': 'threat_intel', 'confidence': 0.0}

            # Check threat intelligence
            threat_info = await self.threat_intelligence.lookup_domain(domain)

            if threat_info and threat_info.get('is_malicious'):
                confidence = threat_info.get('confidence', 0.9)
                return {
                    'method': 'threat_intel',
                    'confidence': confidence,
                    'threat_type': threat_info.get('category', 'unknown'),
                    'source': threat_info.get('source', 'unknown')
                }

            return {'method': 'threat_intel', 'confidence': 0.0}

        except Exception as e:
            logger.error(f"Threat intelligence lookup error: {e}")
            return {'method': 'threat_intel', 'confidence': 0.0}

    async def _create_zero_day_alert(self, domain: str, features: DomainFeatures, 
                                   confidence: float, detection_results: List[Dict]) -> ZeroDayAlert:
        """Create zero-day detection alert"""
        try:
            # Determine risk category
            if features.suspicious_keywords:
                if any(kw in self.suspicious_keywords['phishing'] for kw in features.suspicious_keywords):
                    risk_category = 'PHISHING'
                elif any(kw in self.suspicious_keywords['malware'] for kw in features.suspicious_keywords):
                    risk_category = 'MALICIOUS'
                else:
                    risk_category = 'SUSPICIOUS'
            elif features.similarity_to_popular > 0.8:
                risk_category = 'PHISHING'
            elif features.entropy > 4.0:
                risk_category = 'DGA'
            else:
                risk_category = 'SUSPICIOUS'

            # Detection methods
            detection_methods = [
                result['method'] for result in detection_results 
                if result.get('confidence', 0) > 0.5
            ]

            # Find similar domains
            similar_domains = await self._find_similar_domains(domain)

            # Threat indicators
            threat_indicators = []
            for result in detection_results:
                if result.get('reasons'):
                    threat_indicators.extend(result['reasons'])
                if result.get('threat_type'):
                    threat_indicators.append(result['threat_type'])

            # Recommended action
            if confidence >= 0.9:
                recommended_action = 'BLOCK'
            elif confidence >= 0.7:
                recommended_action = 'MONITOR'
            else:
                recommended_action = 'ALERT'

            alert = ZeroDayAlert(
                alert_id=f"zero_day_{hash(domain)}_{int(time.time())}",
                domain=domain,
                confidence=confidence,
                risk_category=risk_category,
                detection_methods=detection_methods,
                features=features,
                similar_domains=similar_domains,
                threat_indicators=threat_indicators,
                recommended_action=recommended_action,
                timestamp=datetime.now()
            )

            return alert

        except Exception as e:
            logger.error(f"Error creating zero-day alert: {e}")
            return None

    async def _find_similar_domains(self, domain: str) -> List[str]:
        """Find similar domains using clustering"""
        try:
            if not self.clustering_model or not self.vectorizer:
                return []

            # This would implement similarity search using the clustering model
            # For now, return empty list
            return []

        except Exception as e:
            logger.error(f"Error finding similar domains: {e}")
            return []

    async def _is_whitelisted(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        try:
            # Check popular domains
            if domain in self.popular_domains:
                return True

            # Check TLD whitelist
            tld = domain.split('.')[-1].lower()
            if tld in self.config.get('whitelist_tlds', []):
                return True

            return False

        except Exception:
            return False

    def _update_detection_stats(self, alert: ZeroDayAlert):
        """Update detection statistics"""
        try:
            self.stats['zero_days_detected'] += 1

            if alert.risk_category == 'PHISHING':
                self.stats['phishing_detected'] += 1
            elif alert.risk_category == 'MALICIOUS':
                self.stats['malware_detected'] += 1

        except Exception as e:
            logger.error(f"Error updating detection stats: {e}")

    async def _save_models(self):
        """Save trained models to disk"""
        try:
            import os
            import joblib

            model_path = '/var/lib/jetdns/ml_models/'
            os.makedirs(model_path, exist_ok=True)

            if self.classifier:
                joblib.dump(self.classifier, f'{model_path}/zero_day_classifier.pkl')

            if self.scaler:
                joblib.dump(self.scaler, f'{model_path}/zero_day_scaler.pkl')

            if self.vectorizer:
                joblib.dump(self.vectorizer, f'{model_path}/zero_day_vectorizer.pkl')

            logger.info("🎯 Zero-day models saved successfully")

        except Exception as e:
            logger.error(f"Error saving zero-day models: {e}")

    # Background Tasks
    async def _domain_intelligence_update_task(self):
        """Background task for domain intelligence updates"""
        while True:
            try:
                await asyncio.sleep(86400)  # Daily

                # Update popular domains list
                await self._update_popular_domains()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Domain intelligence update error: {e}")

    async def _model_training_task(self):
        """Background task for model retraining"""
        while True:
            try:
                interval = self.config.get('model_update_interval', 86400)
                await asyncio.sleep(interval)

                # Retrain models with new data
                await self._train_models()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Model training task error: {e}")

    async def _threat_feed_integration_task(self):
        """Background task for threat feed integration"""
        while True:
            try:
                await asyncio.sleep(3600)  # Hourly

                if self.config.get('threat_feed_integration', True) and self.threat_intelligence:
                    # Update threat intelligence data
                    await self.threat_intelligence.update_feeds()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Threat feed integration error: {e}")

    async def _update_popular_domains(self):
        """Update popular domains list"""
        try:
            # This would fetch updated popular domains
            # For now, keep existing list
            pass

        except Exception as e:
            logger.error(f"Error updating popular domains: {e}")

    async def get_zero_day_stats(self) -> Dict:
        """Get zero-day detection statistics"""
        return {
            'enabled': self.config.get('enabled', False),
            'detection_threshold': self.config.get('detection_threshold', 0.75),
            'domain_age_threshold': self.config.get('domain_age_threshold', 30),
            'popular_domains_count': len(self.popular_domains),
            'suspicious_keywords_count': sum(len(keywords) for keywords in self.suspicious_keywords.values()),
            'model_accuracy': self.stats['model_accuracy'],
            'clustering_enabled': self.config.get('clustering_enabled', True),
            'stats': self.stats
        }

    def reload_config(self):
        """Reload zero-day detection configuration"""
        asyncio.create_task(self._load_config())
        logger.info("🎯 Zero-Day Detector Konfiguration neu geladen")
