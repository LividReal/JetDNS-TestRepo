"""
JetDNS Brand Protection System
Advanced Typosquatting Detection with Machine Learning
"""

import asyncio
import json
import logging
import re
import time
import sqlite3
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from collections import defaultdict, deque
import threading
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib

@dataclass
class BrandDomain:
    """Geschützte Marken-Domain"""
    domain: str
    brand_name: str
    protection_level: str  # 'strict', 'moderate', 'basic'
    keywords: List[str]
    created_at: float
    last_updated: float
    active: bool = True

@dataclass
class TyposquattingDetection:
    """Erkannte Typosquatting-Domain"""
    suspicious_domain: str
    target_brand: str
    similarity_score: float
    detection_method: str
    confidence: float
    first_seen: float
    query_count: int
    client_ips: Set[str]
    blocked: bool = False

@dataclass
class BrandThreat:
    """Brand-Bedrohung"""
    threat_id: str
    domain: str
    brand: str
    threat_type: str  # 'typosquatting', 'phishing', 'trademark_infringement'
    severity: str  # 'critical', 'high', 'medium', 'low'
    confidence: float
    evidence: Dict
    first_detected: float
    last_seen: float
    status: str = 'active'

class AdvancedBrandProtection:
    """
    Fortschrittliches Brand Protection System
    - Typosquatting-Erkennung mit ML
    - Marken-Monitoring
    - Phishing-Schutz
    - Domain-Ähnlichkeitsanalyse
    """

    def __init__(self, config_path: str = "config/brand_protection.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)

        # Geschützte Marken und Domains
        self.protected_brands: Dict[str, BrandDomain] = {}
        self.typosquatting_cache: Dict[str, TyposquattingDetection] = {}
        self.threat_database: Dict[str, BrandThreat] = {}

        # Machine Learning Modelle
        self.tfidf_vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(2, 4),
            max_features=10000
        )
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.domain_clusterer = DBSCAN(eps=0.3, min_samples=2)
        self.scaler = StandardScaler()

        # Statistiken und Metriken
        self.stats = {
            'total_queries_analyzed': 0,
            'typosquatting_detected': 0,
            'brands_protected': 0,
            'threats_blocked': 0,
            'false_positives': 0,
            'model_accuracy': 0.0,
            'last_model_update': 0.0
        }

        # Konfiguration und Caches
        self.config = {}
        self.domain_features_cache = {}
        self.similarity_cache = {}
        self.query_patterns = defaultdict(lambda: deque(maxlen=1000))

        # Threading
        self.lock = threading.RLock()

        # Initialisierung
        self._load_configuration()
        self._initialize_database()
        self._load_protected_brands()
        self._train_initial_models()

    def _load_configuration(self):
        """Lädt Konfiguration"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                # Standard-Konfiguration
                self.config = {
                    'detection': {
                        'similarity_threshold': 0.8,
                        'confidence_threshold': 0.7,
                        'max_edit_distance': 3,
                        'enable_ml_detection': True,
                        'enable_phonetic_analysis': True
                    },
                    'blocking': {
                        'auto_block_threshold': 0.9,
                        'quarantine_threshold': 0.7,
                        'whitelist_similar_domains': True
                    },
                    'monitoring': {
                        'alert_on_detection': True,
                        'log_all_queries': False,
                        'track_client_patterns': True
                    },
                    'models': {
                        'retrain_interval': 86400,  # 24 Stunden
                        'min_samples_for_training': 1000,
                        'feature_update_interval': 3600
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
            self.db_path = Path("data/brand_protection.db")
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Tabellen erstellen
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS protected_brands (
                    domain TEXT PRIMARY KEY,
                    brand_name TEXT NOT NULL,
                    protection_level TEXT NOT NULL,
                    keywords TEXT,
                    created_at REAL NOT NULL,
                    last_updated REAL NOT NULL,
                    active INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS typosquatting_detections (
                    suspicious_domain TEXT PRIMARY KEY,
                    target_brand TEXT NOT NULL,
                    similarity_score REAL NOT NULL,
                    detection_method TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    first_seen REAL NOT NULL,
                    query_count INTEGER DEFAULT 1,
                    client_ips TEXT,
                    blocked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS brand_threats (
                    threat_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    brand TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evidence TEXT,
                    first_detected REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    status TEXT DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS query_patterns (
                    domain TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    features TEXT,
                    PRIMARY KEY (domain, client_ip, timestamp)
                );

                CREATE INDEX IF NOT EXISTS idx_threats_domain ON brand_threats(domain);
                CREATE INDEX IF NOT EXISTS idx_threats_brand ON brand_threats(brand);
                CREATE INDEX IF NOT EXISTS idx_detections_brand ON typosquatting_detections(target_brand);
                CREATE INDEX IF NOT EXISTS idx_patterns_timestamp ON query_patterns(timestamp);
            """)

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Fehler beim Initialisieren der Datenbank: {e}")

    def _load_protected_brands(self):
        """Lädt geschützte Marken aus der Datenbank"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM protected_brands WHERE active = 1")
            brands = cursor.fetchall()

            for brand_data in brands:
                domain, brand_name, protection_level, keywords_json, created_at, last_updated, active = brand_data
                keywords = json.loads(keywords_json) if keywords_json else []

                brand = BrandDomain(
                    domain=domain,
                    brand_name=brand_name,
                    protection_level=protection_level,
                    keywords=keywords,
                    created_at=created_at,
                    last_updated=last_updated,
                    active=bool(active)
                )

                self.protected_brands[domain] = brand

            self.stats['brands_protected'] = len(self.protected_brands)
            conn.close()

            self.logger.info(f"Geladen: {len(self.protected_brands)} geschützte Marken")

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Marken: {e}")

    def add_protected_brand(self, domain: str, brand_name: str, 
                          protection_level: str = 'moderate', 
                          keywords: List[str] = None) -> bool:
        """Fügt neue geschützte Marke hinzu"""
        try:
            if keywords is None:
                keywords = []

            # Domain normalisieren
            domain = domain.lower().strip()
            if not domain:
                return False

            current_time = time.time()

            brand = BrandDomain(
                domain=domain,
                brand_name=brand_name,
                protection_level=protection_level,
                keywords=keywords,
                created_at=current_time,
                last_updated=current_time
            )

            with self.lock:
                # In Datenbank speichern
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT OR REPLACE INTO protected_brands 
                    (domain, brand_name, protection_level, keywords, created_at, last_updated, active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (domain, brand_name, protection_level, json.dumps(keywords), 
                      current_time, current_time))

                conn.commit()
                conn.close()

                # In Cache speichern
                self.protected_brands[domain] = brand
                self.stats['brands_protected'] = len(self.protected_brands)

            self.logger.info(f"Marke hinzugefügt: {brand_name} ({domain})")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen der Marke {domain}: {e}")
            return False

    def remove_protected_brand(self, domain: str) -> bool:
        """Entfernt geschützte Marke"""
        try:
            domain = domain.lower().strip()

            with self.lock:
                if domain in self.protected_brands:
                    # In Datenbank deaktivieren
                    conn = sqlite3.connect(str(self.db_path))
                    cursor = conn.cursor()

                    cursor.execute("""
                        UPDATE protected_brands 
                        SET active = 0, last_updated = ?
                        WHERE domain = ?
                    """, (time.time(), domain))

                    conn.commit()
                    conn.close()

                    # Aus Cache entfernen
                    del self.protected_brands[domain]
                    self.stats['brands_protected'] = len(self.protected_brands)

                    self.logger.info(f"Marke entfernt: {domain}")
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Fehler beim Entfernen der Marke {domain}: {e}")
            return False

    async def analyze_domain_query(self, domain: str, client_ip: str) -> Dict:
        """Analysiert Domain-Query auf Brand-Bedrohungen"""
        try:
            self.stats['total_queries_analyzed'] += 1

            domain = domain.lower().strip()
            if not domain:
                return {'action': 'allow', 'reason': 'empty_domain'}

            # Whitelist-Check
            if self._is_whitelisted(domain):
                return {'action': 'allow', 'reason': 'whitelisted'}

            # Typosquatting-Erkennung
            typosquatting_result = await self._detect_typosquatting(domain, client_ip)
            if typosquatting_result['detected']:
                detection = typosquatting_result['detection']

                # Auto-Block bei hoher Konfidenz
                auto_block_threshold = self.config['blocking']['auto_block_threshold']
                if detection.confidence >= auto_block_threshold:
                    self._record_threat(domain, detection.target_brand, 'typosquatting', 
                                      'high', detection.confidence, typosquatting_result)
                    self.stats['threats_blocked'] += 1

                    return {
                        'action': 'block',
                        'reason': 'typosquatting_detected',
                        'details': {
                            'target_brand': detection.target_brand,
                            'confidence': detection.confidence,
                            'similarity': detection.similarity_score,
                            'method': detection.detection_method
                        }
                    }

                # Quarantäne bei mittlerer Konfidenz
                quarantine_threshold = self.config['blocking']['quarantine_threshold']
                if detection.confidence >= quarantine_threshold:
                    return {
                        'action': 'quarantine',
                        'reason': 'suspicious_domain',
                        'details': {
                            'target_brand': detection.target_brand,
                            'confidence': detection.confidence
                        }
                    }

            # Machine Learning Anomalie-Erkennung
            if self.config['detection']['enable_ml_detection']:
                ml_result = await self._ml_anomaly_detection(domain, client_ip)
                if ml_result['anomaly_detected']:
                    return {
                        'action': 'monitor',
                        'reason': 'ml_anomaly_detected',
                        'details': ml_result
                    }

            return {'action': 'allow', 'reason': 'no_threat_detected'}

        except Exception as e:
            self.logger.error(f"Fehler bei der Domain-Analyse für {domain}: {e}")
            return {'action': 'allow', 'reason': 'analysis_error'}

    async def _detect_typosquatting(self, domain: str, client_ip: str) -> Dict:
        """Erkennt Typosquatting-Versuche"""
        try:
            best_match = None
            highest_score = 0

            for protected_domain, brand in self.protected_brands.items():
                # Ähnlichkeitsscore berechnen
                similarity = self._calculate_domain_similarity(domain, protected_domain)

                if similarity > self.config['detection']['similarity_threshold']:
                    if similarity > highest_score:
                        highest_score = similarity
                        best_match = brand

            if best_match and highest_score > self.config['detection']['similarity_threshold']:
                # Konfidenz berechnen
                confidence = self._calculate_confidence(domain, best_match, highest_score)

                if confidence >= self.config['detection']['confidence_threshold']:
                    # Erkennung erstellen
                    detection = TyposquattingDetection(
                        suspicious_domain=domain,
                        target_brand=best_match.brand_name,
                        similarity_score=highest_score,
                        detection_method='similarity_analysis',
                        confidence=confidence,
                        first_seen=time.time(),
                        query_count=1,
                        client_ips={client_ip}
                    )

                    # Cache und Datenbank aktualisieren
                    await self._update_detection_cache(detection)

                    self.stats['typosquatting_detected'] += 1

                    return {
                        'detected': True,
                        'detection': detection
                    }

            return {'detected': False}

        except Exception as e:
            self.logger.error(f"Fehler bei Typosquatting-Erkennung für {domain}: {e}")
            return {'detected': False}

    def _calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Berechnet Ähnlichkeit zwischen zwei Domains"""
        try:
            # Cache-Check
            cache_key = f"{domain1}:{domain2}"
            if cache_key in self.similarity_cache:
                return self.similarity_cache[cache_key]

            # Basis-Ähnlichkeit mit SequenceMatcher
            base_similarity = SequenceMatcher(None, domain1, domain2).ratio()

            # Levenshtein-Distanz normalisiert
            max_len = max(len(domain1), len(domain2))
            levenshtein_distance = self._levenshtein_distance(domain1, domain2)
            levenshtein_similarity = 1 - (levenshtein_distance / max_len)

            # Phonetische Ähnlichkeit (vereinfacht)
            phonetic_similarity = 0
            if self.config['detection']['enable_phonetic_analysis']:
                phonetic_similarity = self._phonetic_similarity(domain1, domain2)

            # Gewichtete Kombinierung
            final_similarity = (
                base_similarity * 0.4 +
                levenshtein_similarity * 0.4 +
                phonetic_similarity * 0.2
            )

            # Cache speichern
            self.similarity_cache[cache_key] = final_similarity

            return final_similarity

        except Exception as e:
            self.logger.error(f"Fehler bei Ähnlichkeitsberechnung: {e}")
            return 0.0

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Berechnet Levenshtein-Distanz"""
        if len(s1) > len(s2):
            s1, s2 = s2, s1

        distances = range(len(s1) + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2 + 1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
        return distances[-1]

    def _phonetic_similarity(self, domain1: str, domain2: str) -> float:
        """Berechnet phonetische Ähnlichkeit (vereinfacht)"""
        # Phonetische Ähnlichkeitsmuster
        similar_chars = {
            'c': 'k', 'k': 'c',
            'f': 'ph', 'ph': 'f',
            'i': 'y', 'y': 'i',
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1',
            '5': 's', 's': '5'
        }

        # Vereinfachte phonetische Transformation
        def normalize_phonetic(text):
            text = text.lower()
            for char, replacement in similar_chars.items():
                text = text.replace(char, replacement)
            return text

        norm1 = normalize_phonetic(domain1)
        norm2 = normalize_phonetic(domain2)

        return SequenceMatcher(None, norm1, norm2).ratio()

    def _calculate_confidence(self, domain: str, brand: BrandDomain, similarity: float) -> float:
        """Berechnet Konfidenz der Typosquatting-Erkennung"""
        try:
            confidence_factors = []

            # Basis-Ähnlichkeit
            confidence_factors.append(similarity)

            # Keyword-Matching
            keyword_match = 0
            for keyword in brand.keywords:
                if keyword.lower() in domain.lower():
                    keyword_match += 0.2
            confidence_factors.append(min(keyword_match, 1.0))

            # Domain-Längen-Ähnlichkeit
            len_similarity = 1 - abs(len(domain) - len(brand.domain)) / max(len(domain), len(brand.domain))
            confidence_factors.append(len_similarity)

            # TLD-Analyse
            tld_confidence = self._analyze_tld_suspicion(domain, brand.domain)
            confidence_factors.append(tld_confidence)

            # Protection Level berücksichtigen
            level_multiplier = {
                'strict': 1.2,
                'moderate': 1.0,
                'basic': 0.8
            }.get(brand.protection_level, 1.0)

            # Gewichtete Konfidenz berechnen
            weighted_confidence = np.mean(confidence_factors) * level_multiplier

            return min(weighted_confidence, 1.0)

        except Exception as e:
            self.logger.error(f"Fehler bei Konfidenzberechnung: {e}")
            return 0.0

    def _analyze_tld_suspicion(self, domain: str, original_domain: str) -> float:
        """Analysiert TLD-Verdächtigkeit"""
        try:
            # TLD extrahieren
            domain_parts = domain.split('.')
            original_parts = original_domain.split('.')

            if len(domain_parts) < 2 or len(original_parts) < 2:
                return 0.5

            domain_tld = domain_parts[-1]
            original_tld = original_parts[-1]

            # Gleiche TLD = höhere Konfidenz
            if domain_tld == original_tld:
                return 0.8

            # Verdächtige TLD-Kombinationen
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'pw']
            if domain_tld in suspicious_tlds:
                return 0.9

            # Ähnliche TLDs
            similar_tlds = {
                'com': ['co', 'cm', 'om'],
                'org': ['ogr', 'orq'],
                'net': ['net', 'nit'],
                'de': ['de', 'dd']
            }

            for main_tld, similar in similar_tlds.items():
                if original_tld == main_tld and domain_tld in similar:
                    return 0.7

            return 0.5

        except Exception as e:
            self.logger.error(f"Fehler bei TLD-Analyse: {e}")
            return 0.5

    async def _ml_anomaly_detection(self, domain: str, client_ip: str) -> Dict:
        """Machine Learning Anomalie-Erkennung"""
        try:
            if not hasattr(self, 'anomaly_detector_trained'):
                return {'anomaly_detected': False, 'reason': 'model_not_trained'}

            # Domain-Features extrahieren
            features = self._extract_domain_features(domain)

            # Anomalie-Score berechnen
            feature_vector = np.array(features).reshape(1, -1)
            anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
            is_outlier = self.anomaly_detector.predict(feature_vector)[0] == -1

            if is_outlier:
                # Client-Pattern analysieren
                pattern_analysis = self._analyze_client_patterns(client_ip, domain)

                return {
                    'anomaly_detected': True,
                    'anomaly_score': float(anomaly_score),
                    'features': features,
                    'pattern_analysis': pattern_analysis
                }

            return {'anomaly_detected': False, 'anomaly_score': float(anomaly_score)}

        except Exception as e:
            self.logger.error(f"Fehler bei ML-Anomalie-Erkennung für {domain}: {e}")
            return {'anomaly_detected': False, 'error': str(e)}

    def _extract_domain_features(self, domain: str) -> List[float]:
        """Extrahiert ML-Features aus Domain"""
        try:
            if domain in self.domain_features_cache:
                return self.domain_features_cache[domain]

            features = []

            # Basis-Features
            features.append(len(domain))  # Domain-Länge
            features.append(domain.count('.'))  # Anzahl Subdomains
            features.append(len(domain.replace('.', '')))  # Länge ohne Punkte

            # Zeichen-Analyse
            features.append(sum(c.isdigit() for c in domain) / len(domain))  # Digit-Ratio
            features.append(sum(c.isalpha() for c in domain) / len(domain))  # Alpha-Ratio
            features.append(sum(c == '-' for c in domain) / len(domain))  # Dash-Ratio

            # Entropie
            char_counts = defaultdict(int)
            for char in domain:
                char_counts[char] += 1

            entropy = 0
            for count in char_counts.values():
                p = count / len(domain)
                if p > 0:
                    entropy -= p * np.log2(p)
            features.append(entropy)

            # TLD-Features
            parts = domain.split('.')
            if len(parts) > 1:
                tld = parts[-1]
                features.append(len(tld))
                features.append(1 if tld in ['com', 'org', 'net', 'de'] else 0)  # Common TLD
            else:
                features.extend([0, 0])

            # Verdächtige Muster
            suspicious_patterns = [
                r'\d{2,}',  # Mehrere Ziffern hintereinander
                r'(.)\1{2,}',  # Wiederholende Zeichen
                r'[0-9][a-z]{1,2}[0-9]',  # Digit-Letter-Digit Pattern
                r'[a-z]-[a-z]'  # Letter-Dash-Letter Pattern
            ]

            for pattern in suspicious_patterns:
                features.append(len(re.findall(pattern, domain)) / max(len(domain), 1))

            # N-Gram Features (vereinfacht)
            bigrams = [domain[i:i+2] for i in range(len(domain)-1)]
            common_bigrams = ['th', 'er', 'on', 'an', 'in', 'ed', 're', 'nd']
            common_bigram_ratio = sum(1 for bg in bigrams if bg in common_bigrams) / len(bigrams)
            features.append(common_bigram_ratio)

            # Cache speichern
            self.domain_features_cache[domain] = features

            return features

        except Exception as e:
            self.logger.error(f"Fehler bei Feature-Extraktion für {domain}: {e}")
            return [0.0] * 15  # Default-Features

    def _analyze_client_patterns(self, client_ip: str, domain: str) -> Dict:
        """Analysiert Client-Query-Muster"""
        try:
            current_time = time.time()

            # Pattern-History abrufen
            patterns = self.query_patterns.get(client_ip, deque())

            # Aktuelle Query hinzufügen
            patterns.append({
                'domain': domain,
                'timestamp': current_time,
                'features': self._extract_domain_features(domain)
            })

            self.query_patterns[client_ip] = patterns

            if len(patterns) < 5:
                return {'insufficient_data': True, 'query_count': len(patterns)}

            # Muster analysieren
            recent_queries = [p for p in patterns if current_time - p['timestamp'] < 3600]  # Letzte Stunde

            analysis = {
                'total_queries': len(patterns),
                'recent_queries': len(recent_queries),
                'unique_domains': len(set(p['domain'] for p in recent_queries)),
                'query_frequency': len(recent_queries) / 60,  # Queries pro Minute
                'pattern_score': 0.0
            }

            # Anomalie-Score für Pattern
            if len(recent_queries) > 10:  # Hohe Frequenz
                analysis['pattern_score'] += 0.3

            if analysis['unique_domains'] / max(len(recent_queries), 1) < 0.5:  # Wenig einzigartige Domains
                analysis['pattern_score'] += 0.2

            # Ähnliche Domains in kurzer Zeit
            domain_similarities = []
            for i, query in enumerate(recent_queries[-10:]):  # Letzte 10 Queries
                for j, other_query in enumerate(recent_queries[-10:]):
                    if i != j:
                        similarity = self._calculate_domain_similarity(query['domain'], other_query['domain'])
                        domain_similarities.append(similarity)

            if domain_similarities:
                avg_similarity = np.mean(domain_similarities)
                if avg_similarity > 0.7:  # Sehr ähnliche Domains
                    analysis['pattern_score'] += 0.4

            analysis['pattern_score'] = min(analysis['pattern_score'], 1.0)

            return analysis

        except Exception as e:
            self.logger.error(f"Fehler bei Client-Pattern-Analyse für {client_ip}: {e}")
            return {'error': str(e)}

    async def _update_detection_cache(self, detection: TyposquattingDetection):
        """Aktualisiert Detection-Cache und Datenbank"""
        try:
            domain = detection.suspicious_domain

            with self.lock:
                if domain in self.typosquatting_cache:
                    # Existierende Erkennung aktualisieren
                    existing = self.typosquatting_cache[domain]
                    existing.query_count += 1
                    existing.client_ips.add(list(detection.client_ips)[0])
                    existing.confidence = max(existing.confidence, detection.confidence)
                else:
                    # Neue Erkennung
                    self.typosquatting_cache[domain] = detection

                # Datenbank aktualisieren
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                current_detection = self.typosquatting_cache[domain]
                cursor.execute("""
                    INSERT OR REPLACE INTO typosquatting_detections 
                    (suspicious_domain, target_brand, similarity_score, detection_method, 
                     confidence, first_seen, query_count, client_ips, blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    domain, current_detection.target_brand, current_detection.similarity_score,
                    current_detection.detection_method, current_detection.confidence,
                    current_detection.first_seen, current_detection.query_count,
                    json.dumps(list(current_detection.client_ips)), 
                    int(current_detection.blocked)
                ))

                conn.commit()
                conn.close()

        except Exception as e:
            self.logger.error(f"Fehler beim Aktualisieren der Detection-Cache: {e}")

    def _record_threat(self, domain: str, brand: str, threat_type: str, 
                      severity: str, confidence: float, evidence: Dict):
        """Zeichnet Brand-Bedrohung auf"""
        try:
            threat_id = f"{domain}_{brand}_{int(time.time())}"
            current_time = time.time()

            threat = BrandThreat(
                threat_id=threat_id,
                domain=domain,
                brand=brand,
                threat_type=threat_type,
                severity=severity,
                confidence=confidence,
                evidence=evidence,
                first_detected=current_time,
                last_seen=current_time
            )

            with self.lock:
                self.threat_database[threat_id] = threat

                # Datenbank aktualisieren
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO brand_threats 
                    (threat_id, domain, brand, threat_type, severity, confidence, 
                     evidence, first_detected, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat_id, domain, brand, threat_type, severity, confidence,
                    json.dumps(evidence), current_time, current_time, 'active'
                ))

                conn.commit()
                conn.close()

            self.logger.warning(f"Brand-Bedrohung erkannt: {threat_type} für {brand} - {domain}")

        except Exception as e:
            self.logger.error(f"Fehler beim Aufzeichnen der Bedrohung: {e}")

    def _is_whitelisted(self, domain: str) -> bool:
        """Prüft ob Domain auf der Whitelist steht"""
        try:
            # Whitelist aus Konfiguration
            whitelist = self.config.get('whitelist', [])

            for whitelisted in whitelist:
                if domain.endswith(whitelisted.lower()):
                    return True

            # Geschützte Domains sind automatisch gewhitelisted
            if domain in self.protected_brands:
                return True

            return False

        except Exception as e:
            self.logger.error(f"Fehler bei Whitelist-Check für {domain}: {e}")
            return False

    def _train_initial_models(self):
        """Trainiert initiale ML-Modelle"""
        try:
            # Beispiel-Domains für Training generieren
            legitimate_domains = [
                "google.com", "facebook.com", "amazon.com", "microsoft.com",
                "apple.com", "twitter.com", "instagram.com", "linkedin.com",
                "wikipedia.org", "reddit.com", "youtube.com", "github.com"
            ]

            suspicious_domains = [
                "g00gle.com", "faceb00k.com", "amaz0n.com", "micr0soft.com",
                "apple-security.com", "twiter.com", "instgram.com", "linkedln.com",
                "wikipedla.org", "reddt.com", "youtub.com", "githup.com"
            ]

            # Features extrahieren
            all_domains = legitimate_domains + suspicious_domains
            all_features = [self._extract_domain_features(domain) for domain in all_domains]

            if len(all_features) > 0:
                # Anomalie-Detektor trainieren
                self.anomaly_detector.fit(all_features)
                self.anomaly_detector_trained = True

                self.logger.info("Initiale ML-Modelle trainiert")

        except Exception as e:
            self.logger.error(f"Fehler beim Trainieren der Modelle: {e}")

    def get_threat_statistics(self) -> Dict:
        """Gibt Bedrohungsstatistiken zurück"""
        try:
            with self.lock:
                current_time = time.time()
                last_24h = current_time - 86400

                # Recent threats
                recent_threats = [
                    t for t in self.threat_database.values()
                    if t.last_seen >= last_24h
                ]

                # Typosquatting detections
                recent_detections = [
                    d for d in self.typosquatting_cache.values()
                    if d.first_seen >= last_24h
                ]

                stats = {
                    **self.stats,
                    'recent_threats': len(recent_threats),
                    'recent_detections': len(recent_detections),
                    'threat_severity_breakdown': {
                        'critical': len([t for t in recent_threats if t.severity == 'critical']),
                        'high': len([t for t in recent_threats if t.severity == 'high']),
                        'medium': len([t for t in recent_threats if t.severity == 'medium']),
                        'low': len([t for t in recent_threats if t.severity == 'low'])
                    },
                    'top_targeted_brands': self._get_top_targeted_brands(),
                    'detection_accuracy': self._calculate_detection_accuracy()
                }

                return stats

        except Exception as e:
            self.logger.error(f"Fehler beim Abrufen der Statistiken: {e}")
            return self.stats

    def _get_top_targeted_brands(self) -> List[Tuple[str, int]]:
        """Gibt am häufigsten angegriffene Marken zurück"""
        try:
            brand_counts = defaultdict(int)

            for detection in self.typosquatting_cache.values():
                brand_counts[detection.target_brand] += detection.query_count

            for threat in self.threat_database.values():
                brand_counts[threat.brand] += 1

            # Top 5 Marken
            top_brands = sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            return top_brands

        except Exception as e:
            self.logger.error(f"Fehler beim Abrufen der Top-Marken: {e}")
            return []

    def _calculate_detection_accuracy(self) -> float:
        """Berechnet Erkennungsgenauigkeit"""
        try:
            total_detections = len(self.typosquatting_cache)
            if total_detections == 0:
                return 1.0

            # Vereinfachte Genauigkeitsberechnung basierend auf Konfidenz
            total_confidence = sum(d.confidence for d in self.typosquatting_cache.values())
            false_positives = self.stats['false_positives']

            accuracy = (total_confidence / total_detections) - (false_positives / max(total_detections, 1) * 0.1)
            return max(0.0, min(1.0, accuracy))

        except Exception as e:
            self.logger.error(f"Fehler bei Genauigkeitsberechnung: {e}")
            return 0.0

    async def retrain_models(self) -> bool:
        """Trainiert ML-Modelle neu"""
        try:
            # Aktuelle Daten aus Datenbank laden
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                SELECT suspicious_domain, confidence, blocked 
                FROM typosquatting_detections 
                ORDER BY first_seen DESC 
                LIMIT 10000
            """)
            detections = cursor.fetchall()
            conn.close()

            if len(detections) < self.config['models']['min_samples_for_training']:
                self.logger.info("Nicht genügend Daten für Model-Retraining")
                return False

            # Features und Labels vorbereiten
            features = []
            for domain, confidence, blocked in detections:
                domain_features = self._extract_domain_features(domain)
                features.append(domain_features)

            if features:
                # Modell neu trainieren
                self.anomaly_detector.fit(features)
                self.stats['last_model_update'] = time.time()

                self.logger.info(f"ML-Modelle mit {len(features)} Samples neu trainiert")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Fehler beim Retraining der Modelle: {e}")
            return False

    def export_threat_report(self, format: str = 'json') -> str:
        """Exportiert Bedrohungsbericht"""
        try:
            current_time = time.time()
"""
JetDNS Brand Protection System
Advanced Typosquatting Detection & Brand Monitoring

Features:
- AI-powered domain similarity detection
- Brand keyword monitoring
- Homograph attack detection
- Real-time typosquatting alerts
- Custom brand protection rules
"""

import asyncio
import logging
import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from difflib import SequenceMatcher
import unicodedata
import hashlib

# ML & Analytics imports
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
import nltk
from nltk.corpus import words
from nltk.distance import edit_distance


@dataclass
class BrandProfile:
    """Definiert ein zu schützendes Brand-Profil"""
    name: str
    primary_domains: List[str]
    keywords: List[str]
    tlds: List[str] = field(default_factory=lambda: ['.com', '.net', '.org'])
    protection_level: str = 'high'  # low, medium, high, critical
    whitelist_domains: List[str] = field(default_factory=list)
    custom_rules: List[Dict] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class TyposquattingThreat:
    """Repräsentiert eine potenzielle Typosquatting-Bedrohung"""
    suspicious_domain: str
    target_brand: str
    threat_type: str  # typosquatting, homograph, combosquatting, bitsquatting
    similarity_score: float
    detection_algorithm: str
    risk_level: str  # low, medium, high, critical
    evidence: Dict[str, Any]
    first_seen: datetime
    last_seen: datetime
    query_count: int = 0
    source_ips: Set[str] = field(default_factory=set)


class TyposquattingDetector:
    """Erweiterte Typosquatting-Erkennung mit ML-Algorithmen"""

    def __init__(self):
        self.logger = logging.getLogger('jetdns.brand_protection')

        # Character substitution maps für verschiedene Angriffstechniken
        self.keyboard_adjacent = {
            'a': ['q', 'w', 's', 'z'],
            'b': ['v', 'g', 'h', 'n'],
            'c': ['x', 'd', 'f', 'v'],
            'd': ['s', 'e', 'r', 'f', 'c', 'x'],
            'e': ['w', 's', 'd', 'r'],
            'f': ['d', 'r', 't', 'g', 'v', 'c'],
            'g': ['f', 't', 'y', 'h', 'b', 'v'],
            'h': ['g', 'y', 'u', 'j', 'n', 'b'],
            'i': ['u', 'j', 'k', 'o'],
            'j': ['h', 'u', 'i', 'k', 'm', 'n'],
            'k': ['j', 'i', 'o', 'l', 'm'],
            'l': ['k', 'o', 'p'],
            'm': ['n', 'j', 'k'],
            'n': ['b', 'h', 'j', 'm'],
            'o': ['i', 'k', 'l', 'p'],
            'p': ['o', 'l'],
            'q': ['w', 'a', 's'],
            'r': ['e', 'd', 'f', 't'],
            's': ['a', 'w', 'e', 'd', 'x', 'z'],
            't': ['r', 'f', 'g', 'y'],
            'u': ['y', 'h', 'j', 'i'],
            'v': ['c', 'f', 'g', 'b'],
            'w': ['q', 'a', 's', 'e'],
            'x': ['z', 's', 'd', 'c'],
            'y': ['t', 'g', 'h', 'u'],
            'z': ['a', 's', 'x']
        }

        # Homograph substitutions (visuell ähnliche Zeichen)
        self.homograph_map = {
            'a': ['а', 'ɑ', 'α', '@'],
            'e': ['е', 'ε', '3'],
            'o': ['о', 'ο', '0'],
            'p': ['р', 'ρ'],
            'c': ['с', 'ϲ'],
            'x': ['х', 'χ'],
            'y': ['у', 'γ'],
            'h': ['һ', 'η'],
            'i': ['і', 'ι', '1', 'l'],
            'n': ['η', 'ñ'],
            'u': ['υ', 'μ'],
            'v': ['ѵ', 'ν'],
            'w': ['ω', 'ш'],
            'b': ['Ь', 'β'],
            'd': ['ď', 'δ'],
            'g': ['ğ', 'γ'],
            'l': ['ł', 'ι', '1', 'I'],
            'm': ['м', 'μ'],
            'r': ['г', 'ρ'],
            's': ['ѕ', 'σ'],
            't': ['т', 'τ']
        }

        # TLD variations für combosquatting
        self.common_tlds = [
            '.com', '.net', '.org', '.info', '.biz', '.co', '.io',
            '.de', '.uk', '.fr', '.ru', '.cn', '.jp', '.br',
            '.tk', '.ml', '.ga', '.cf', '.eu', '.us', '.ca'
        ]

        # ML-Modelle initialisieren
        self.tfidf_vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 4),
            max_features=10000
        )

        # Domain-Corpus für Training laden
        try:
            nltk.download('words', quiet=True)
            self.english_words = set(words.words())
        except:
            self.english_words = set()

    def generate_typosquatting_variants(self, domain: str) -> Set[str]:
        """Generiert alle möglichen Typosquatting-Varianten einer Domain"""
        variants = set()
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return variants

        base_domain = domain_parts[0]
        tld = '.'.join(domain_parts[1:])

        # 1. Character omission (Zeichen weglassen)
        for i in range(len(base_domain)):
            variant = base_domain[:i] + base_domain[i+1:]
            if variant and len(variant) > 1:
                variants.add(f"{variant}.{tld}")

        # 2. Character insertion (Zeichen einfügen)
        for i in range(len(base_domain) + 1):
            for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
                variant = base_domain[:i] + char + base_domain[i:]
                variants.add(f"{variant}.{tld}")

        # 3. Character substitution (Zeichen ersetzen)
        for i, char in enumerate(base_domain):
            # Keyboard-based substitution
            if char in self.keyboard_adjacent:
                for sub_char in self.keyboard_adjacent[char]:
                    variant = base_domain[:i] + sub_char + base_domain[i+1:]
                    variants.add(f"{variant}.{tld}")

            # Homograph substitution
            if char in self.homograph_map:
                for homo_char in self.homograph_map[char]:
                    variant = base_domain[:i] + homo_char + base_domain[i+1:]
                    variants.add(f"{variant}.{tld}")

        # 4. Character transposition (Zeichen vertauschen)
        for i in range(len(base_domain) - 1):
            variant = (base_domain[:i] + 
                      base_domain[i+1] + 
                      base_domain[i] + 
                      base_domain[i+2:])
            variants.add(f"{variant}.{tld}")

        # 5. Bitsquatting (einzelne Bits flippen)
        for i, char in enumerate(base_domain):
            char_code = ord(char)
            for bit in range(8):
                flipped_code = char_code ^ (1 << bit)
                if 32 <= flipped_code <= 126:  # Printable ASCII
                    flipped_char = chr(flipped_code)
                    if flipped_char.isalnum():
                        variant = base_domain[:i] + flipped_char + base_domain[i+1:]
                        variants.add(f"{variant}.{tld}")

        # 6. TLD variations (combosquatting)
        for alt_tld in self.common_tlds:
            if alt_tld != f".{tld}":
                variants.add(f"{base_domain}{alt_tld}")

        # 7. Hyphen insertion/removal
        if '-' in base_domain:
            # Remove hyphens
            variant = base_domain.replace('-', '')
            variants.add(f"{variant}.{tld}")
        else:
            # Insert hyphens
            for i in range(1, len(base_domain)):
                variant = base_domain[:i] + '-' + base_domain[i:]
                variants.add(f"{variant}.{tld}")

        return variants

    def calculate_domain_similarity(self, domain1: str, domain2: str) -> float:
        """Berechnet die Ähnlichkeit zwischen zwei Domains (0.0 - 1.0)"""
        # Verschiedene Ähnlichkeitsmetriken kombinieren

        # 1. Edit Distance (Levenshtein)
        edit_sim = 1.0 - (edit_distance(domain1, domain2) / max(len(domain1), len(domain2)))

        # 2. Sequence Matcher
        seq_sim = SequenceMatcher(None, domain1, domain2).ratio()

        # 3. Jaro-Winkler Similarity (approximiert)
        def jaro_similarity(s1, s2):
            if len(s1) == 0 or len(s2) == 0:
                return 0.0
            match_distance = max(len(s1), len(s2)) // 2 - 1
            if match_distance < 0:
                match_distance = 0

            s1_matches = [False] * len(s1)
            s2_matches = [False] * len(s2)
            matches = 0
            transpositions = 0

            # Find matches
            for i in range(len(s1)):
                start = max(0, i - match_distance)
                end = min(i + match_distance + 1, len(s2))
                for j in range(start, end):
                    if s2_matches[j] or s1[i] != s2[j]:
                        continue
                    s1_matches[i] = True
                    s2_matches[j] = True
                    matches += 1
                    break

            if matches == 0:
                return 0.0

            # Count transpositions
            k = 0
            for i in range(len(s1)):
                if not s1_matches[i]:
                    continue
                while not s2_matches[k]:
                    k += 1
                if s1[i] != s2[k]:
                    transpositions += 1
                k += 1

            jaro = (matches / len(s1) + matches / len(s2) + 
                   (matches - transpositions/2) / matches) / 3.0
            return jaro

        jaro_sim = jaro_similarity(domain1, domain2)

        # 4. N-gram similarity
        def ngram_similarity(s1, s2, n=2):
            if len(s1) < n or len(s2) < n:
                return 0.0
            ngrams1 = set(s1[i:i+n] for i in range(len(s1)-n+1))
            ngrams2 = set(s2[i:i+n] for i in range(len(s2)-n+1))
            intersection = len(ngrams1 & ngrams2)
            union = len(ngrams1 | ngrams2)
            return intersection / union if union > 0 else 0.0

        bigram_sim = ngram_similarity(domain1, domain2, 2)
        trigram_sim = ngram_similarity(domain1, domain2, 3)

        # Gewichtete Kombination der Ähnlichkeitsmaße
        final_similarity = (
            edit_sim * 0.25 +
            seq_sim * 0.25 +
            jaro_sim * 0.25 +
            bigram_sim * 0.15 +
            trigram_sim * 0.10
        )

        return min(1.0, max(0.0, final_similarity))

    def detect_homograph_attack(self, domain: str, target_domains: List[str]) -> List[Tuple[str, float, str]]:
        """Erkennt Homograph-Angriffe (visuell ähnliche Zeichen)"""
        threats = []

        for target in target_domains:
            # Prüfe auf verdächtige Unicode-Zeichen
            suspicious_chars = []
            normalized_domain = ""

            for char in domain:
                if ord(char) > 127:  # Non-ASCII
                    # Normalisiere zu ASCII wenn möglich
                    try:
                        normalized = unicodedata.normalize('NFKD', char)
                        ascii_char = normalized.encode('ascii', 'ignore').decode('ascii')
                        if ascii_char:
                            normalized_domain += ascii_char
                            suspicious_chars.append((char, ascii_char))
                        else:
                            normalized_domain += char
                            suspicious_chars.append((char, '?'))
                    except:
                        normalized_domain += char
                        suspicious_chars.append((char, '?'))
                else:
                    normalized_domain += char

            # Berechne Ähnlichkeit nach Normalisierung
            similarity = self.calculate_domain_similarity(normalized_domain, target)

            if similarity > 0.8 and suspicious_chars:
                evidence = {
                    'suspicious_characters': suspicious_chars,
                    'normalized_domain': normalized_domain,
                    'original_domain': domain
                }
                threats.append((target, similarity, json.dumps(evidence)))

        return threats

    def detect_combosquatting(self, domain: str, brand_keywords: List[str]) -> List[Tuple[str, float, str]]:
        """Erkennt Combosquatting (Brand + zusätzliche Wörter)"""
        threats = []
        domain_lower = domain.lower()

        for keyword in brand_keywords:
            keyword_lower = keyword.lower()

            if keyword_lower in domain_lower and keyword_lower != domain_lower:
                # Analysiere die Kombination
                parts = domain_lower.split(keyword_lower)
                additional_parts = [part for part in parts if part.strip('-_.')]

                if additional_parts:
                    risk_score = 0.7  # Base score für Combosquatting

                    # Erhöhe Score für verdächtige Zusätze
                    suspicious_additions = [
                        'login', 'secure', 'bank', 'pay', 'account', 'verify',
                        'update', 'confirm', 'support', 'help', 'official',
                        'new', 'mobile', 'app', 'mail', 'store', 'shop'
                    ]

                    for part in additional_parts:
                        clean_part = part.strip('-_.')
                        if clean_part in suspicious_additions:
                            risk_score = min(0.95, risk_score + 0.15)
                        elif clean_part.isdigit():
                            risk_score = min(0.9, risk_score + 0.1)

                    evidence = {
                        'brand_keyword': keyword,
                        'additional_parts': additional_parts,
                        'domain_structure': domain_lower
                    }

                    threats.append((keyword, risk_score, json.dumps(evidence)))

        return threats


class BrandProtectionEngine:
    """Hauptklasse für Brand Protection & Typosquatting Detection"""

    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger('jetdns.brand_protection')
        self.config = config

        # Core components
        self.detector = TyposquattingDetector()
        self.brand_profiles: Dict[str, BrandProfile] = {}
        self.threat_cache: Dict[str, TyposquattingThreat] = {}
        self.query_stats = defaultdict(lambda: defaultdict(int))

        # Performance optimization
        self.domain_whitelist: Set[str] = set()
        self.threat_blacklist: Set[str] = set()
        self.similarity_cache: Dict[str, float] = {}

        # Alerting & reporting
        self.alert_thresholds = {
            'critical': 0.95,
            'high': 0.85,
            'medium': 0.70,
            'low': 0.50
        }

        self.max_cache_size = config.get('max_cache_size', 100000)
        self.cache_ttl = config.get('cache_ttl', 3600)  # 1 hour

        # Load initial data
        asyncio.create_task(self.initialize())

    async def initialize(self):
        """Initialisiert das Brand Protection System"""
        try:
            await self._load_brand_profiles()
            await self._load_threat_intelligence()
            self.logger.info("Brand Protection Engine initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Brand Protection Engine: {e}")

    async def _load_brand_profiles(self):
        """Lädt Brand-Profile aus der Konfiguration"""
        brand_config = self.config.get('brand_profiles', [])

        for profile_data in brand_config:
            profile = BrandProfile(
                name=profile_data['name'],
                primary_domains=profile_data['domains'],
                keywords=profile_data.get('keywords', [profile_data['name'].lower()]),
                tlds=profile_data.get('tlds', ['.com', '.net', '.org']),
                protection_level=profile_data.get('protection_level', 'high'),
                whitelist_domains=profile_data.get('whitelist', []),
                custom_rules=profile_data.get('custom_rules', [])
            )

            self.brand_profiles[profile.name] = profile

            # Add primary domains to whitelist
            for domain in profile.primary_domains:
                self.domain_whitelist.add(domain.lower())

            # Add whitelist domains
            for domain in profile.whitelist_domains:
                self.domain_whitelist.add(domain.lower())

        self.logger.info(f"Loaded {len(self.brand_profiles)} brand profiles")

    async def _load_threat_intelligence(self):
        """Lädt bekannte Threats aus externen Quellen"""
        # Hier könnten externe Threat-Intelligence-Feeds eingebunden werden
        # z.B. URLVoid, VirusTotal, etc.
        pass

    async def analyze_domain_query(self, domain: str, client_ip: str) -> Optional[TyposquattingThreat]:
        """Analysiert eine Domain-Anfrage auf Typosquatting"""
        domain_lower = domain.lower()

        # Skip whitelisted domains
        if domain_lower in self.domain_whitelist:
            return None

        # Check cache first
        cache_key = f"threat:{domain_lower}"
        if cache_key in self.threat_cache:
            threat = self.threat_cache[cache_key]
            threat.last_seen = datetime.now()
            threat.query_count += 1
            threat.source_ips.add(client_ip)
            return threat

        # Analyze against all brand profiles
        max_threat = None
        max_risk = 0.0

        for brand_name, profile in self.brand_profiles.items():
            threat = await self._analyze_against_brand(domain_lower, profile, client_ip)
            if threat and threat.similarity_score > max_risk:
                max_threat = threat
                max_risk = threat.similarity_score

        # Cache result
        if max_threat:
            self.threat_cache[cache_key] = max_threat
            self._cleanup_cache()

        return max_threat

    async def _analyze_against_brand(self, domain: str, profile: BrandProfile, client_ip: str) -> Optional[TyposquattingThreat]:
        """Analysiert eine Domain gegen ein spezifisches Brand-Profil"""
        max_similarity = 0.0
        threat_type = ""
        detection_algorithm = ""
        evidence = {}
        target_domain = ""

        # 1. Direct similarity check gegen primary domains
        for primary_domain in profile.primary_domains:
            similarity = self.detector.calculate_domain_similarity(domain, primary_domain)
            if similarity > max_similarity:
                max_similarity = similarity
                target_domain = primary_domain
                threat_type = "typosquatting"
                detection_algorithm = "similarity_analysis"
                evidence = {
                    'target_domain': primary_domain,
                    'similarity_score': similarity,
                    'algorithm': 'multi_metric_similarity'
                }

        # 2. Homograph attack detection
        homograph_threats = self.detector.detect_homograph_attack(domain, profile.primary_domains)
        for target, similarity, homograph_evidence in homograph_threats:
            if similarity > max_similarity:
                max_similarity = similarity
                target_domain = target
                threat_type = "homograph_attack"
                detection_algorithm = "homograph_detection"
                evidence = json.loads(homograph_evidence)

        # 3. Combosquatting detection
        combo_threats = self.detector.detect_combosquatting(domain, profile.keywords)
        for keyword, risk_score, combo_evidence in combo_threats:
            if risk_score > max_similarity:
                max_similarity = risk_score
                target_domain = f"{profile.name} (keyword: {keyword})"
                threat_type = "combosquatting"
                detection_algorithm = "combosquatting_detection"
                evidence = json.loads(combo_evidence)

        # 4. Custom rules check
        for rule in profile.custom_rules:
            if await self._evaluate_custom_rule(domain, rule):
                rule_score = rule.get('risk_score', 0.8)
                if rule_score > max_similarity:
                    max_similarity = rule_score
                    target_domain = rule.get('target', profile.name)
                    threat_type = rule.get('threat_type', 'custom_rule')
                    detection_algorithm = "custom_rule"
                    evidence = {'rule': rule}

        # Determine risk level
        risk_level = "low"
        for level, threshold in self.alert_thresholds.items():
            if max_similarity >= threshold:
                risk_level = level
                break

        # Only create threat if above minimum threshold
        min_threshold = self.alert_thresholds['low']
        if max_similarity >= min_threshold:
            return TyposquattingThreat(
                suspicious_domain=domain,
                target_brand=profile.name,
                threat_type=threat_type,
                similarity_score=max_similarity,
                detection_algorithm=detection_algorithm,
                risk_level=risk_level,
                evidence=evidence,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                query_count=1,
                source_ips={client_ip}
            )

        return None

    async def _evaluate_custom_rule(self, domain: str, rule: Dict) -> bool:
        """Evaluiert eine custom Brand-Protection-Regel"""
        rule_type = rule.get('type', 'regex')
        pattern = rule.get('pattern', '')

        if rule_type == 'regex':
            try:
                return bool(re.search(pattern, domain, re.IGNORECASE))
            except re.error:
                self.logger.warning(f"Invalid regex pattern: {pattern}")
                return False

        elif rule_type == 'contains':
            return pattern.lower() in domain.lower()

        elif rule_type == 'starts_with':
            return domain.lower().startswith(pattern.lower())

        elif rule_type == 'ends_with':
            return domain.lower().endswith(pattern.lower())

        elif rule_type == 'length':
            min_len = rule.get('min_length', 0)
            max_len = rule.get('max_length', 1000)
            return min_len <= len(domain) <= max_len

        return False

    def _cleanup_cache(self):
        """Bereinigt den Threat-Cache"""
        if len(self.threat_cache) > self.max_cache_size:
            # Remove oldest entries
            sorted_items = sorted(
                self.threat_cache.items(),
                key=lambda x: x[1].last_seen
            )

            # Keep only the newest 80% of entries
            keep_count = int(self.max_cache_size * 0.8)
            new_cache = dict(sorted_items[-keep_count:])
            self.threat_cache = new_cache

    async def get_threat_statistics(self) -> Dict[str, Any]:
        """Liefert Statistiken über erkannte Threats"""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        stats = {
            'total_threats': len(self.threat_cache),
            'threat_levels': defaultdict(int),
            'threat_types': defaultdict(int),
            'brands_targeted': defaultdict(int),
            'recent_threats': {
                '24h': 0,
                '7d': 0
            },
            'top_threats': [],
            'unique_source_ips': set()
        }

        threats_by_score = []

        for threat in self.threat_cache.values():
            # Count by risk level
            stats['threat_levels'][threat.risk_level] += 1

            # Count by threat type
            stats['threat_types'][threat.threat_type] += 1

            # Count by target brand
            stats['brands_targeted'][threat.target_brand] += 1

            # Recent threats
            if threat.first_seen >= last_24h:
                stats['recent_threats']['24h'] += 1
            if threat.first_seen >= last_7d:
                stats['recent_threats']['7d'] += 1

            # Collect all source IPs
            stats['unique_source_ips'].update(threat.source_ips)

            # For top threats ranking
            threats_by_score.append({
                'domain': threat.suspicious_domain,
                'target_brand': threat.target_brand,
                'risk_level': threat.risk_level,
                'similarity_score': threat.similarity_score,
                'query_count': threat.query_count,
                'threat_type': threat.threat_type,
                'first_seen': threat.first_seen.isoformat(),
                'source_ip_count': len(threat.source_ips)
            })

        # Sort threats by risk and query count
        threats_by_score.sort(
            key=lambda x: (x['similarity_score'], x['query_count']),
            reverse=True
        )

        stats['top_threats'] = threats_by_score[:20]  # Top 20 threats
        stats['unique_source_ips'] = len(stats['unique_source_ips'])

        # Convert defaultdicts to regular dicts
        stats['threat_levels'] = dict(stats['threat_levels'])
        stats['threat_types'] = dict(stats['threat_types'])
        stats['brands_targeted'] = dict(stats['brands_targeted'])

        return stats

    async def add_brand_profile(self, profile: BrandProfile) -> bool:
        """Fügt ein neues Brand-Profil hinzu"""
        try:
            self.brand_profiles[profile.name] = profile

            # Update whitelist
            for domain in profile.primary_domains + profile.whitelist_domains:
                self.domain_whitelist.add(domain.lower())

            self.logger.info(f"Added brand profile: {profile.name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add brand profile {profile.name}: {e}")
            return False

    async def remove_brand_profile(self, brand_name: str) -> bool:
        """Entfernt ein Brand-Profil"""
        try:
            if brand_name in self.brand_profiles:
                del self.brand_profiles[brand_name]

                # Clean up related threats
                to_remove = []
                for key, threat in self.threat_cache.items():
                    if threat.target_brand == brand_name:
                        to_remove.append(key)

                for key in to_remove:
                    del self.threat_cache[key]

                self.logger.info(f"Removed brand profile: {brand_name}")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to remove brand profile {brand_name}: {e}")
            return False

    async def update_brand_profile(self, brand_name: str, updates: Dict) -> bool:
        """Aktualisiert ein Brand-Profil"""
        try:
            if brand_name not in self.brand_profiles:
                return False

            profile = self.brand_profiles[brand_name]

            # Update fields
            for field, value in updates.items():
                if hasattr(profile, field):
                    setattr(profile, field, value)

            # Update whitelist if domains changed
            if 'primary_domains' in updates or 'whitelist_domains' in updates:
                # Rebuild whitelist for this brand
                self.domain_whitelist.discard(profile.name.lower())
                for domain in profile.primary_domains + profile.whitelist_domains:
                    self.domain_whitelist.add(domain.lower())

            self.logger.info(f"Updated brand profile: {brand_name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to update brand profile {brand_name}: {e}")
            return False


# Export for other modules
__all__ = [
    'BrandProfile',
    'TyposquattingThreat', 
    'TyposquattingDetector',
    'BrandProtectionEngine'
]
            report_data = {
                'generated_at': current_time,
                'statistics': self.get_threat_statistics(),
                'protected_brands': [asdict(brand) for brand in self.protected_brands.values()],
                'recent_threats': [
                    asdict(threat) for threat in self.threat_database.values()
                    if current_time - threat.last_seen < 86400
                ],
                'typosquatting_detections': [
                    asdict(detection) for detection in self.typosquatting_cache.values()
                    if current_time - detection.first_seen < 86400
                ]
            }

            if format.lower() == 'json':
                return json.dumps(report_data, indent=4, default=str)
            else:
                return str(report_data)

        except Exception as e:
            self.logger.error(f"Fehler beim Exportieren des Berichts: {e}")
            return "{}"

    async def cleanup_old_data(self, days_to_keep: int = 30):
        """Bereinigt alte Daten"""
        try:
            cutoff_time = time.time() - (days_to_keep * 86400)

            # Cache bereinigen
            with self.lock:
                domains_to_remove = [
                    domain for domain, detection in self.typosquatting_cache.items()
                    if detection.first_seen < cutoff_time
                ]

                for domain in domains_to_remove:
                    del self.typosquatting_cache[domain]

                # Datenbank bereinigen
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("DELETE FROM typosquatting_detections WHERE first_seen < ?", (cutoff_time,))
                cursor.execute("DELETE FROM brand_threats WHERE first_detected < ?", (cutoff_time,))
                cursor.execute("DELETE FROM query_patterns WHERE timestamp < ?", (cutoff_time,))

                conn.commit()
                conn.close()

            self.logger.info(f"Alte Daten bereinigt (älter als {days_to_keep} Tage)")

        except Exception as e:
            self.logger.error(f"Fehler bei der Datenbereinigung: {e}")
