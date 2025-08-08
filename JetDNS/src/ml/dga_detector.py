"""
JetDNS DGA (Domain Generation Algorithm) Detection
Machine Learning-basierte Erkennung von algorithmisch generierten Domains
"""

import asyncio
import logging
import pickle
import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import joblib
from collections import Counter
import math

logger = logging.getLogger(__name__)

@dataclass
class DGAFeatures:
    """DGA Features für ML-Modell"""
    domain: str
    length: int
    entropy: float
    vowel_ratio: float
    consonant_ratio: float
    digit_ratio: float
    special_char_ratio: float
    pronounceable_score: float
    n_gram_score: float
    dictionary_score: float
    tld_score: float
    repetition_score: float
    char_distribution_score: float
    bigram_frequency: float
    trigram_frequency: float
    keyboard_pattern_score: float
    is_dga: bool = False

@dataclass
class DGADetection:
    """DGA Detection Result"""
    domain: str
    is_dga: bool
    confidence: float
    dga_family: Optional[str]
    risk_level: str
    features: DGAFeatures
    timestamp: datetime

class DGADetector:
    """Machine Learning-basierte DGA Detection"""

    def __init__(self, config_manager, threat_intelligence=None):
        self.config_manager = config_manager
        self.threat_intelligence = threat_intelligence
        self.config = {}

        # ML Models
        self.classifier = None
        self.anomaly_detector = None
        self.vectorizer = None

        # Training Data
        self.training_data = []
        self.feature_cache = {}

        # Dictionary Data
        self.common_words = set()
        self.common_tlds = set()
        self.common_bigrams = {}
        self.common_trigrams = {}

        # Known DGA Families
        self.dga_families = {
            'conficker': {'min_length': 8, 'max_length': 11, 'pattern': r'^[a-z]+\.(com|net|org|info|biz)$'},
            'cryptolocker': {'min_length': 12, 'max_length': 16, 'pattern': r'^[a-z]+\.com$'},
            'zeus': {'min_length': 8, 'max_length': 20, 'pattern': r'^[a-z0-9]+\.(com|net|org)$'},
            'torpig': {'min_length': 6, 'max_length': 12, 'pattern': r'^[a-z]+\.(com|net)$'},
            'tinba': {'min_length': 12, 'max_length': 16, 'pattern': r'^[a-z]+\.(tk|ml|ga|cf)$'}
        }

        # Statistics
        self.stats = {
            'domains_analyzed': 0,
            'dga_detected': 0,
            'false_positives': 0,
            'model_accuracy': 0.0,
            'last_training': None
        }

    async def initialize(self):
        """Initialize DGA Detector"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("DGA Detection deaktiviert")
            return

        await self._load_dictionaries()
        await self._load_models()

        # Background tasks
        asyncio.create_task(self._model_update_task())
        asyncio.create_task(self._feature_cache_cleanup_task())

        logger.info("🤖 DGA Detector initialisiert")

    async def _load_config(self):
        """Load DGA detection configuration"""
        self.config = self.config_manager.get_config('dga_detection', {
            'enabled': True,
            'confidence_threshold': 0.7,
            'model_update_interval': 86400,  # 24 hours
            'cache_size': 10000,
            'training_data_size': 50000,
            'feature_weights': {
                'entropy': 1.5,
                'pronounceable': 1.2,
                'n_gram': 1.3,
                'dictionary': 1.4,
                'length': 1.0
            },
            'whitelist_domains': [
                'google.com', 'facebook.com', 'amazon.com', 'microsoft.com'
            ],
            'auto_learning': True,
            'feedback_integration': True
        })

    async def _load_dictionaries(self):
        """Load language dictionaries and n-grams"""
        try:
            # Common English words (top 10000)
            english_words = [
                'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
                'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
                'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
                'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
                'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go',
                'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
                'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them',
                'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over',
                'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
                'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day'
            ]
            self.common_words = set(english_words)

            # Common TLDs
            self.common_tlds = {
                'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'eu', 'uk', 'de',
                'fr', 'it', 'es', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk', 'fi',
                'ru', 'ua', 'pl', 'cz', 'hu', 'ro', 'bg', 'hr', 'rs', 'si', 'sk',
                'jp', 'cn', 'kr', 'in', 'au', 'nz', 'ca', 'mx', 'br', 'ar'
            }

            # Common bigrams and trigrams (simplified)
            await self._build_ngram_frequencies()

            logger.info(f"🤖 Dictionaries loaded: {len(self.common_words)} words, {len(self.common_tlds)} TLDs")

        except Exception as e:
            logger.error(f"Error loading dictionaries: {e}")

    async def _build_ngram_frequencies(self):
        """Build n-gram frequency tables"""
        try:
            # Common English bigrams
            english_text = " ".join(self.common_words)

            # Bigrams
            bigrams = []
            for i in range(len(english_text) - 1):
                if english_text[i] != ' ' and english_text[i+1] != ' ':
                    bigrams.append(english_text[i:i+2])

            self.common_bigrams = Counter(bigrams)

            # Trigrams
            trigrams = []
            for i in range(len(english_text) - 2):
                if ' ' not in english_text[i:i+3]:
                    trigrams.append(english_text[i:i+3])

            self.common_trigrams = Counter(trigrams)

        except Exception as e:
            logger.error(f"Error building n-gram frequencies: {e}")

    async def _load_models(self):
        """Load or train ML models"""
        try:
            # Try to load existing models
            model_path = '/var/lib/jetdns/ml_models/'

            try:
                self.classifier = joblib.load(f'{model_path}/dga_classifier.pkl')
                self.anomaly_detector = joblib.load(f'{model_path}/dga_anomaly_detector.pkl')
                self.vectorizer = joblib.load(f'{model_path}/dga_vectorizer.pkl')

                logger.info("🤖 Pre-trained DGA models loaded")

            except FileNotFoundError:
                # Train new models
                await self._train_models()

        except Exception as e:
            logger.error(f"Error loading DGA models: {e}")
            # Fallback: Train new models
            await self._train_models()

    async def _train_models(self):
        """Train DGA detection models"""
        try:
            logger.info("🤖 Training DGA detection models...")

            # Generate training data
            training_data = await self._generate_training_data()

            if len(training_data) < 1000:
                logger.warning("Insufficient training data for DGA detection")
                return

            # Extract features
            X = []
            y = []

            for domain_data in training_data:
                features = await self._extract_features(domain_data['domain'])
                feature_vector = [
                    features.length,
                    features.entropy,
                    features.vowel_ratio,
                    features.consonant_ratio,
                    features.digit_ratio,
                    features.pronounceable_score,
                    features.n_gram_score,
                    features.dictionary_score,
                    features.repetition_score,
                    features.char_distribution_score
                ]

                X.append(feature_vector)
                y.append(domain_data['is_dga'])

            X = np.array(X)
            y = np.array(y)

            # Train classifier
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            self.classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.classifier.fit(X_train, y_train)

            # Evaluate model
            accuracy = self.classifier.score(X_test, y_test)
            self.stats['model_accuracy'] = accuracy

            # Train anomaly detector
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            self.anomaly_detector.fit(X_train[y_train == 0])  # Train on legitimate domains

            # Train text vectorizer for domain names
            domain_names = [data['domain'] for data in training_data]
            self.vectorizer = TfidfVectorizer(
                analyzer='char',
                ngram_range=(2, 4),
                max_features=1000
            )
            self.vectorizer.fit(domain_names)

            # Save models
            await self._save_models()

            self.stats['last_training'] = datetime.now()

            logger.info(f"🤖 DGA models trained successfully (Accuracy: {accuracy:.3f})")

        except Exception as e:
            logger.error(f"Error training DGA models: {e}")

    async def _generate_training_data(self) -> List[Dict]:
        """Generate training data for DGA detection"""
        training_data = []

        try:
            # Legitimate domains (from Alexa Top 1M, DNS logs, etc.)
            legitimate_domains = [
                'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
                'linkedin.com', 'wikipedia.org', 'apple.com', 'amazon.com', 'microsoft.com',
                'reddit.com', 'netflix.com', 'yahoo.com', 'whatsapp.com', 'zoom.us',
                'tiktok.com', 'discord.com', 'spotify.com', 'twitch.tv', 'pinterest.com'
            ]

            # Add legitimate domains
            for domain in legitimate_domains:
                training_data.append({
                    'domain': domain,
                    'is_dga': False,
                    'source': 'whitelist'
                })

            # Generate DGA-like domains
            dga_domains = await self._generate_dga_samples()

            for domain in dga_domains:
                training_data.append({
                    'domain': domain,
                    'is_dga': True,
                    'source': 'synthetic'
                })

            # Load from threat intelligence if available
            if self.threat_intelligence:
                ti_domains = await self.threat_intelligence.get_known_dga_domains()
                for domain_info in ti_domains:
                    training_data.append({
                        'domain': domain_info['domain'],
                        'is_dga': True,
                        'source': 'threat_intel'
                    })

            logger.info(f"🤖 Generated {len(training_data)} training samples")
            return training_data

        except Exception as e:
            logger.error(f"Error generating training data: {e}")
            return []

    async def _generate_dga_samples(self) -> List[str]:
        """Generate synthetic DGA-like domains"""
        dga_samples = []

        try:
            import random
            import string

            # Conficker-like domains
            for _ in range(100):
                length = random.randint(8, 11)
                domain = ''.join(random.choices(string.ascii_lowercase, k=length))
                tld = random.choice(['com', 'net', 'org'])
                dga_samples.append(f"{domain}.{tld}")

            # CryptoLocker-like domains
            for _ in range(100):
                length = random.randint(12, 16)
                domain = ''.join(random.choices(string.ascii_lowercase, k=length))
                dga_samples.append(f"{domain}.com")

            # High-entropy random domains
            for _ in range(100):
                length = random.randint(6, 20)
                # Mix of consonants for high entropy
                consonants = 'bcdfghjklmnpqrstvwxyz'
                domain = ''.join(random.choices(consonants, k=length))
                tld = random.choice(['com', 'net', 'org', 'tk', 'ml'])
                dga_samples.append(f"{domain}.{tld}")

            return dga_samples

        except Exception as e:
            logger.error(f"Error generating DGA samples: {e}")
            return []

    async def analyze_domain(self, domain: str, client_ip: Optional[str] = None) -> DGADetection:
        """Analyze domain for DGA characteristics"""
        try:
            self.stats['domains_analyzed'] += 1

            # Check cache
            if domain in self.feature_cache:
                cached_result, timestamp = self.feature_cache[domain]
                if time.time() - timestamp < 3600:  # Cache for 1 hour
                    return cached_result

            # Check whitelist
            if domain in self.config.get('whitelist_domains', []):
                result = DGADetection(
                    domain=domain,
                    is_dga=False,
                    confidence=0.0,
                    dga_family=None,
                    risk_level='LOW',
                    features=await self._extract_features(domain),
                    timestamp=datetime.now()
                )

                self.feature_cache[domain] = (result, time.time())
                return result

            # Extract features
            features = await self._extract_features(domain)

            # ML-based classification
            ml_result = await self._classify_with_ml(features)

            # Rule-based detection
            rule_result = await self._classify_with_rules(features)

            # Combine results
            is_dga = ml_result['is_dga'] or rule_result['is_dga']
            confidence = max(ml_result['confidence'], rule_result['confidence'])

            # Determine DGA family
            dga_family = await self._identify_dga_family(features)

            # Risk level
            if confidence >= 0.9:
                risk_level = 'CRITICAL'
            elif confidence >= 0.7:
                risk_level = 'HIGH'
            elif confidence >= 0.5:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'

            result = DGADetection(
                domain=domain,
                is_dga=is_dga,
                confidence=confidence,
                dga_family=dga_family,
                risk_level=risk_level,
                features=features,
                timestamp=datetime.now()
            )

            # Cache result
            self.feature_cache[domain] = (result, time.time())

            if is_dga:
                self.stats['dga_detected'] += 1
                logger.warning(f"🤖 DGA detected: {domain} (confidence: {confidence:.3f}, family: {dga_family})")

            return result

        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")

            # Fallback result
            return DGADetection(
                domain=domain,
                is_dga=False,
                confidence=0.0,
                dga_family=None,
                risk_level='LOW',
                features=DGAFeatures(domain=domain, length=len(domain), entropy=0, vowel_ratio=0, consonant_ratio=0, digit_ratio=0, special_char_ratio=0, pronounceable_score=0, n_gram_score=0, dictionary_score=0, tld_score=0, repetition_score=0, char_distribution_score=0, bigram_frequency=0, trigram_frequency=0, keyboard_pattern_score=0),
                timestamp=datetime.now()
            )

    async def _extract_features(self, domain: str) -> DGAFeatures:
        """Extract features from domain for ML analysis"""
        try:
            # Remove TLD for analysis
            if '.' in domain:
                domain_part, tld = domain.rsplit('.', 1)
            else:
                domain_part = domain
                tld = ''

            # Basic features
            length = len(domain_part)

            # Character analysis
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            digits = '0123456789'

            vowel_count = sum(1 for c in domain_part.lower() if c in vowels)
            consonant_count = sum(1 for c in domain_part.lower() if c in consonants)
            digit_count = sum(1 for c in domain_part if c in digits)
            special_count = length - vowel_count - consonant_count - digit_count

            vowel_ratio = vowel_count / length if length > 0 else 0
            consonant_ratio = consonant_count / length if length > 0 else 0
            digit_ratio = digit_count / length if length > 0 else 0
            special_char_ratio = special_count / length if length > 0 else 0

            # Entropy calculation
            entropy = await self._calculate_entropy(domain_part)

            # Pronounceability score
            pronounceable_score = await self._calculate_pronounceability(domain_part)

            # N-gram analysis
            n_gram_score = await self._calculate_ngram_score(domain_part)

            # Dictionary word presence
            dictionary_score = await self._calculate_dictionary_score(domain_part)

            # TLD analysis
            tld_score = 1.0 if tld.lower() in self.common_tlds else 0.0

            # Repetition patterns
            repetition_score = await self._calculate_repetition_score(domain_part)

            # Character distribution
            char_distribution_score = await self._calculate_char_distribution_score(domain_part)

            # Bigram/Trigram frequency
            bigram_frequency = await self._calculate_bigram_frequency(domain_part)
            trigram_frequency = await self._calculate_trigram_frequency(domain_part)

            # Keyboard pattern detection
            keyboard_pattern_score = await self._calculate_keyboard_pattern_score(domain_part)

            return DGAFeatures(
                domain=domain,
                length=length,
                entropy=entropy,
                vowel_ratio=vowel_ratio,
                consonant_ratio=consonant_ratio,
                digit_ratio=digit_ratio,
                special_char_ratio=special_char_ratio,
                pronounceable_score=pronounceable_score,
                n_gram_score=n_gram_score,
                dictionary_score=dictionary_score,
                tld_score=tld_score,
                repetition_score=repetition_score,
                char_distribution_score=char_distribution_score,
                bigram_frequency=bigram_frequency,
                trigram_frequency=trigram_frequency,
                keyboard_pattern_score=keyboard_pattern_score
            )

        except Exception as e:
            logger.error(f"Error extracting features from {domain}: {e}")
            return DGAFeatures(domain=domain, length=len(domain), entropy=0, vowel_ratio=0, consonant_ratio=0, digit_ratio=0, special_char_ratio=0, pronounceable_score=0, n_gram_score=0, dictionary_score=0, tld_score=0, repetition_score=0, char_distribution_score=0, bigram_frequency=0, trigram_frequency=0, keyboard_pattern_score=0)

    async def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        try:
            if not text:
                return 0.0

            # Count character frequencies
            char_counts = Counter(text.lower())
            text_length = len(text)

            # Calculate entropy
            entropy = 0.0
            for count in char_counts.values():
                probability = count / text_length
                entropy -= probability * math.log2(probability)

            return entropy

        except Exception:
            return 0.0

    async def _calculate_pronounceability(self, domain: str) -> float:
        """Calculate how pronounceable the domain is"""
        try:
            # Simple pronounceability heuristic
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'

            score = 0.0
            prev_was_vowel = False

            for char in domain.lower():
                if char in vowels:
                    if not prev_was_vowel:
                        score += 1
                    prev_was_vowel = True
                elif char in consonants:
                    if prev_was_vowel:
                        score += 1
                    prev_was_vowel = False

            return score / len(domain) if len(domain) > 0 else 0.0

        except Exception:
            return 0.0

    async def _calculate_ngram_score(self, domain: str) -> float:
        """Calculate n-gram naturalness score"""
        try:
            if len(domain) < 2:
                return 0.0

            # Bigram score
            bigram_score = 0.0
            for i in range(len(domain) - 1):
                bigram = domain[i:i+2].lower()
                if bigram in self.common_bigrams:
                    bigram_score += math.log(self.common_bigrams[bigram] + 1)

            return bigram_score / (len(domain) - 1) if len(domain) > 1 else 0.0

        except Exception:
            return 0.0

    async def _calculate_dictionary_score(self, domain: str) -> float:
        """Calculate dictionary word presence score"""
        try:
            # Check for dictionary words within domain
            domain_lower = domain.lower()
            max_word_length = 0

            for word in self.common_words:
                if len(word) > 2 and word in domain_lower:
                    max_word_length = max(max_word_length, len(word))

            return max_word_length / len(domain) if len(domain) > 0 else 0.0

        except Exception:
            return 0.0

    async def _calculate_repetition_score(self, domain: str) -> float:
        """Calculate repetition pattern score"""
        try:
            if len(domain) < 2:
                return 0.0

            # Look for repeating patterns
            repetitions = 0
            for i in range(len(domain) - 1):
                if domain[i] == domain[i + 1]:
                    repetitions += 1

            return repetitions / len(domain)

        except Exception:
            return 0.0

    async def _calculate_char_distribution_score(self, domain: str) -> float:
        """Calculate character distribution uniformity"""
        try:
            if not domain:
                return 0.0

            char_counts = Counter(domain.lower())
            total_chars = len(domain)

            # Calculate chi-square statistic for uniformity
            expected = total_chars / len(char_counts)
            chi_square = sum((count - expected) ** 2 / expected for count in char_counts.values())

            # Normalize to 0-1 range
            return min(chi_square / total_chars, 1.0)

        except Exception:
            return 0.0

    async def _calculate_bigram_frequency(self, domain: str) -> float:
        """Calculate average bigram frequency"""
        try:
            if len(domain) < 2:
                return 0.0

            total_frequency = 0
            bigram_count = 0

            for i in range(len(domain) - 1):
                bigram = domain[i:i+2].lower()
                if bigram in self.common_bigrams:
                    total_frequency += self.common_bigrams[bigram]
                    bigram_count += 1

            return total_frequency / bigram_count if bigram_count > 0 else 0.0

        except Exception:
            return 0.0

    async def _calculate_trigram_frequency(self, domain: str) -> float:
        """Calculate average trigram frequency"""
        try:
            if len(domain) < 3:
                return 0.0

            total_frequency = 0
            trigram_count = 0

            for i in range(len(domain) - 2):
                trigram = domain[i:i+3].lower()
                if trigram in self.common_trigrams:
                    total_frequency += self.common_trigrams[trigram]
                    trigram_count += 1

            return total_frequency / trigram_count if trigram_count > 0 else 0.0

        except Exception:
            return 0.0

    async def _calculate_keyboard_pattern_score(self, domain: str) -> float:
        """Detect keyboard walking patterns"""
        try:
            # QWERTY keyboard layout
            keyboard_rows = [
                'qwertyuiop',
                'asdfghjkl',
                'zxcvbnm'
            ]

            pattern_score = 0.0

            for row in keyboard_rows:
                for i in range(len(row) - 2):
                    pattern = row[i:i+3]
                    if pattern in domain.lower():
                        pattern_score += len(pattern) / len(domain)

            return min(pattern_score, 1.0)

        except Exception:
            return 0.0

    async def _classify_with_ml(self, features: DGAFeatures) -> Dict:
        """Classify using ML models"""
        try:
            if not self.classifier:
                return {'is_dga': False, 'confidence': 0.0}

            # Feature vector
            feature_vector = np.array([[
                features.length,
                features.entropy,
                features.vowel_ratio,
                features.consonant_ratio,
                features.digit_ratio,
                features.pronounceable_score,
                features.n_gram_score,
                features.dictionary_score,
                features.repetition_score,
                features.char_distribution_score
            ]])

            # Predict with classifier
            prediction = self.classifier.predict(feature_vector)[0]
            confidence = max(self.classifier.predict_proba(feature_vector)[0])

            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
            is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1

            # Combine results
            final_confidence = confidence
            if is_anomaly and anomaly_score < -0.5:
                final_confidence = max(final_confidence, 0.8)
                prediction = True

            return {
                'is_dga': bool(prediction),
                'confidence': final_confidence
            }

        except Exception as e:
            logger.error(f"ML classification error: {e}")
            return {'is_dga': False, 'confidence': 0.0}

    async def _classify_with_rules(self, features: DGAFeatures) -> Dict:
        """Classify using rule-based heuristics"""
        try:
            dga_score = 0.0

            # High entropy indicates randomness
            if features.entropy > 3.5:
                dga_score += 0.3

            # Low pronounceability
            if features.pronounceable_score < 0.3:
                dga_score += 0.2

            # Low dictionary score
            if features.dictionary_score < 0.2:
                dga_score += 0.2

            # Poor n-gram score
            if features.n_gram_score < 1.0:
                dga_score += 0.2

            # High character distribution uniformity
            if features.char_distribution_score > 0.5:
                dga_score += 0.1

            # Length-based heuristics
            if features.length > 15 or features.length < 6:
                dga_score += 0.1

            # High repetition
            if features.repetition_score > 0.3:
                dga_score += 0.1

            # Keyboard patterns
            if features.keyboard_pattern_score > 0.2:
                dga_score += 0.1

            is_dga = dga_score >= self.config.get('confidence_threshold', 0.7)

            return {
                'is_dga': is_dga,
                'confidence': min(dga_score, 1.0)
            }

        except Exception as e:
            logger.error(f"Rule-based classification error: {e}")
            return {'is_dga': False, 'confidence': 0.0}

    async def _identify_dga_family(self, features: DGAFeatures) -> Optional[str]:
        """Identify specific DGA family"""
        try:
            domain = features.domain

            for family_name, family_config in self.dga_families.items():
                # Check length constraints
                if family_config['min_length'] <= features.length <= family_config['max_length']:
                    # Check pattern
                    pattern = family_config.get('pattern')
                    if pattern and re.match(pattern, domain):
                        return family_name

            return None

        except Exception as e:
            logger.error(f"DGA family identification error: {e}")
            return None

    async def _save_models(self):
        """Save trained models to disk"""
        try:
            import os
            model_path = '/var/lib/jetdns/ml_models/'
            os.makedirs(model_path, exist_ok=True)

            if self.classifier:
                joblib.dump(self.classifier, f'{model_path}/dga_classifier.pkl')

            if self.anomaly_detector:
                joblib.dump(self.anomaly_detector, f'{model_path}/dga_anomaly_detector.pkl')

            if self.vectorizer:
                joblib.dump(self.vectorizer, f'{model_path}/dga_vectorizer.pkl')

            logger.info("🤖 DGA models saved successfully")

        except Exception as e:
            logger.error(f"Error saving DGA models: {e}")

    async def _model_update_task(self):
        """Background task for model updates"""
        while True:
            try:
                update_interval = self.config.get('model_update_interval', 86400)
                await asyncio.sleep(update_interval)

                if self.config.get('auto_learning', True):
                    await self._retrain_models()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Model update task error: {e}")

    async def _feature_cache_cleanup_task(self):
        """Background task for feature cache cleanup"""
        while True:
            try:
                await asyncio.sleep(1800)  # Every 30 minutes

                current_time = time.time()
                cache_size = self.config.get('cache_size', 10000)

                # Remove expired entries
                expired_keys = [
                    key for key, (_, timestamp) in self.feature_cache.items()
                    if current_time - timestamp > 3600
                ]

                for key in expired_keys:
                    del self.feature_cache[key]

                # Limit cache size
                if len(self.feature_cache) > cache_size:
                    # Remove oldest entries
                    sorted_items = sorted(
                        self.feature_cache.items(),
                        key=lambda x: x[1][1]
                    )

                    for key, _ in sorted_items[:-cache_size]:
                        del self.feature_cache[key]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Feature cache cleanup error: {e}")

    async def _retrain_models(self):
        """Retrain models with new data"""
        try:
            # Collect new training data from recent detections
            # This would include user feedback, threat intelligence updates, etc.
            await self._train_models()

            logger.info("🤖 DGA models retrained successfully")

        except Exception as e:
            logger.error(f"Model retraining error: {e}")

    async def get_dga_stats(self) -> Dict:
        """Get DGA detection statistics"""
        cache_hit_rate = 1.0 - (self.stats['domains_analyzed'] / max(len(self.feature_cache), 1))

        return {
            'enabled': self.config.get('enabled', False),
            'model_accuracy': self.stats['model_accuracy'],
            'confidence_threshold': self.config.get('confidence_threshold', 0.7),
            'cache_size': len(self.feature_cache),
            'cache_hit_rate': cache_hit_rate,
            'dga_families': list(self.dga_families.keys()),
            'last_training': self.stats['last_training'].isoformat() if self.stats['last_training'] else None,
            'stats': self.stats
        }

    async def add_feedback(self, domain: str, is_dga: bool, confidence: float):
        """Add user feedback for model improvement"""
        try:
            if self.config.get('feedback_integration', True):
                # Store feedback for future model training
                feedback_data = {
                    'domain': domain,
                    'is_dga': is_dga,
                    'confidence': confidence,
                    'timestamp': datetime.now(),
                    'source': 'user_feedback'
                }

                # Add to training data
                self.training_data.append(feedback_data)

                # Limit training data size
                max_size = self.config.get('training_data_size', 50000)
                if len(self.training_data) > max_size:
                    self.training_data = self.training_data[-max_size:]

                logger.info(f"🤖 DGA feedback added: {domain} ({'DGA' if is_dga else 'Legitimate'})")

        except Exception as e:
            logger.error(f"Error adding DGA feedback: {e}")

    def reload_config(self):
        """Reload DGA detection configuration"""
        asyncio.create_task(self._load_config())
        logger.info("🤖 DGA Detector Konfiguration neu geladen")
