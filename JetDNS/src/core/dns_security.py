"""
JetDNS Security Manager
Zentrale Sicherheitsschicht für DNS-Anfragen
"""

import time
import logging
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from threading import Lock
import json

from src.security.brand_protection import AdvancedBrandProtection, BrandProtectionEngine
from src.security.threat_intelligence import get_threat_intelligence, ThreatIndicator
from src.ml.dga_detector import DGADetector
from src.ml.zero_day_detector import ZeroDayDetector

@dataclass
class SecurityResult:
    """Ergebnis einer Sicherheitsprüfung"""
    blocked: bool
    reason: str
    confidence: float
    category: str
    threat_type: str
    source: str
    metadata: Dict = None

class DNSSecurityManager:
    """
    Zentraler DNS Security Manager
    Koordiniert alle Sicherheitsmodule und trifft Entscheidungen
    """

    def __init__(self, config_path: str = "/etc/jetdns/security.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)

        # Sicherheitsmodule
        self.brand_protection = None
        self.threat_intelligence = None
        self.dga_detector = None
        self.zero_day_detector = None

        # Konfiguration
        self.config = {}
        self.enabled_modules = set()

        # Performance Tracking
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'allowed_queries': 0,
            'brand_protection_blocks': 0,
            'threat_intel_blocks': 0,
            'ml_blocks': 0,
            'false_positives': 0,
            'processing_time_ms': 0
        }

        # Cache für Entscheidungen
        self.decision_cache: Dict[str, SecurityResult] = {}
        self.cache_lock = Lock()
        self.cache_ttl = 300  # 5 Minuten

        # Whitelist/Blacklist
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()

        self._load_configuration()
        self._initialize_modules()

    def _load_configuration(self):
        """Lädt Sicherheitskonfiguration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)

            # Module aktivieren basierend auf Konfiguration
            security_config = self.config.get('security', {})

            if security_config.get('enable_brand_protection', True):
                self.enabled_modules.add('brand_protection')

            if security_config.get('enable_threat_intelligence', True):
                self.enabled_modules.add('threat_intelligence')

            if security_config.get('enable_ml_detection', True):
                self.enabled_modules.add('ml_detection')

            # Whitelists/Blacklists laden
            self.whitelist = set(security_config.get('whitelist', []))
            self.blacklist = set(security_config.get('blacklist', []))

            # Cache TTL
            self.cache_ttl = security_config.get('cache_ttl', 300)

            self.logger.info(f"Security Manager konfiguriert: {len(self.enabled_modules)} Module aktiv")

        except FileNotFoundError:
            self.logger.warning("Keine Security-Konfiguration gefunden, verwende Defaults")
            self._create_default_config()
        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Security-Konfiguration: {e}")

    def _create_default_config(self):
        """Erstellt Standard-Sicherheitskonfiguration"""
        default_config = {
            'security': {
                'enable_brand_protection': True,
                'enable_threat_intelligence': True,
                'enable_ml_detection': True,
                'confidence_threshold': 0.7,
                'cache_ttl': 300,
                'whitelist': [],
                'blacklist': [],
                'alert_thresholds': {
                    'high_threat_count': 10,
                    'ml_accuracy_drop': 0.85
                }
            }
        }

        try:
            import os
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)

            self.config = default_config

        except Exception as e:
            self.logger.error(f"Fehler beim Erstellen der Default-Konfiguration: {e}")

    def _initialize_modules(self):
        """Initialisiert Sicherheitsmodule"""
        try:
            if 'brand_protection' in self.enabled_modules:
                self.brand_protection = AdvancedBrandProtection()
                self.logger.info("Brand Protection Modul initialisiert")

            if 'threat_intelligence' in self.enabled_modules:
                self.threat_intelligence = get_threat_intelligence()
                self.logger.info("Threat Intelligence Modul initialisiert")

            if 'ml_detection' in self.enabled_modules:
                try:
                    self.dga_detector = DGADetector()
                    self.zero_day_detector = ZeroDayDetector()
                    self.logger.info("ML Detection Module initialisiert")
                except Exception as e:
                    self.logger.warning(f"ML Module konnten nicht initialisiert werden: {e}")
                    self.enabled_modules.discard('ml_detection')

        except Exception as e:
            self.logger.error(f"Fehler beim Initialisieren der Security Module: {e}")

    def analyze_query(self, domain: str, client_ip: str, query_type: str = 'A') -> SecurityResult:
        """
        Analysiert DNS-Anfrage auf Sicherheitsbedrohungen

        Args:
            domain: Angefragte Domain
            client_ip: IP des anfragenden Clients
            query_type: DNS-Abfragetyp

        Returns:
            SecurityResult mit Entscheidung und Details
        """
        start_time = time.time()
        self.stats['total_queries'] += 1

        try:
            # Cache prüfen
            cache_key = hashlib.md5(f"{domain}:{client_ip}:{query_type}".encode()).hexdigest()
            cached_result = self._get_cached_decision(cache_key)
            if cached_result:
                return cached_result

            # Whitelist prüfen (höchste Priorität)
            if domain in self.whitelist:
                result = SecurityResult(
                    blocked=False,
                    reason="Domain in Whitelist",
                    confidence=1.0,
                    category="whitelist",
                    threat_type="none",
                    source="whitelist"
                )
                self._cache_decision(cache_key, result)
                self.stats['allowed_queries'] += 1
                return result

            # Blacklist prüfen
            if domain in self.blacklist:
                result = SecurityResult(
                    blocked=True,
                    reason="Domain in Blacklist",
                    confidence=1.0,
                    category="blacklist",
                    threat_type="manual_block",
                    source="blacklist"
                )
                self._cache_decision(cache_key, result)
                self.stats['blocked_queries'] += 1
                return result

            # Threat Intelligence prüfen
            if self.threat_intelligence and 'threat_intelligence' in self.enabled_modules:
                threat_result = self._check_threat_intelligence(domain, client_ip)
                if threat_result and threat_result.blocked:
                    self._cache_decision(cache_key, threat_result)
                    self.stats['blocked_queries'] += 1
                    self.stats['threat_intel_blocks'] += 1
                    return threat_result

            # Brand Protection prüfen
            if self.brand_protection and 'brand_protection' in self.enabled_modules:
                brand_result = self._check_brand_protection(domain, client_ip)
                if brand_result and brand_result.blocked:
                    self._cache_decision(cache_key, brand_result)
                    self.stats['blocked_queries'] += 1
                    self.stats['brand_protection_blocks'] += 1
                    return brand_result

            # ML-basierte Erkennung
            if 'ml_detection' in self.enabled_modules:
                ml_result = self._check_ml_detection(domain, client_ip)
                if ml_result and ml_result.blocked:
                    self._cache_decision(cache_key, ml_result)
                    self.stats['blocked_queries'] += 1
                    self.stats['ml_blocks'] += 1
                    return ml_result

            # Keine Bedrohung erkannt
            result = SecurityResult(
                blocked=False,
                reason="Keine Bedrohung erkannt",
                confidence=0.0,
                category="safe",
                threat_type="none",
                source="security_analysis"
            )

            self._cache_decision(cache_key, result)
            self.stats['allowed_queries'] += 1
            return result

        except Exception as e:
            self.logger.error(f"Fehler bei Security-Analyse für {domain}: {e}")

            # Im Fehlerfall: Durchlassen mit Warnung
            return SecurityResult(
                blocked=False,
                reason=f"Security-Analyse fehlgeschlagen: {str(e)}",
                confidence=0.0,
                category="error",
                threat_type="analysis_error",
                source="error_handler"
            )

        finally:
            # Performance Tracking
            processing_time = (time.time() - start_time) * 1000
            self.stats['processing_time_ms'] = (
                (self.stats['processing_time_ms'] * (self.stats['total_queries'] - 1) + processing_time) 
                / self.stats['total_queries']
            )

    def _check_threat_intelligence(self, domain: str, client_ip: str) -> Optional[SecurityResult]:
        """Prüft Domain gegen Threat Intelligence Feeds"""
        try:
            threat_indicator = self.threat_intelligence.check_domain(domain, client_ip)
            if threat_indicator:
                confidence_threshold = self.config.get('security', {}).get('confidence_threshold', 0.7)

                if threat_indicator.confidence >= confidence_threshold:
                    return SecurityResult(
                        blocked=True,
                        reason=f"Domain in Threat Intelligence: {threat_indicator.category}",
                        confidence=threat_indicator.confidence,
                        category=threat_indicator.category,
                        threat_type="threat_intel",
                        source=threat_indicator.source,
                        metadata={
                            'indicator': threat_indicator.indicator,
                            'tags': list(threat_indicator.tags),
                            'first_seen': threat_indicator.first_seen
                        }
                    )

        except Exception as e:
            self.logger.error(f"Fehler bei Threat Intelligence Check: {e}")

        return None

    def _check_brand_protection(self, domain: str, client_ip: str) -> Optional[SecurityResult]:
        """Prüft Domain auf Brand Protection Verstöße"""
        try:
            detection = self.brand_protection.analyze_domain_query(domain, client_ip)

            if detection and detection.blocked:
                return SecurityResult(
                    blocked=True,
                    reason=f"Brand Protection: {detection.detection_method}",
                    confidence=detection.confidence,
                    category="brand_protection",
                    threat_type=detection.detection_method,
                    source="brand_protection",
                    metadata={
                        'target_brand': detection.target_brand,
                        'similarity_score': detection.similarity_score,
                        'query_count': detection.query_count
                    }
                )

        except Exception as e:
            self.logger.error(f"Fehler bei Brand Protection Check: {e}")

        return None

    def _check_ml_detection(self, domain: str, client_ip: str) -> Optional[SecurityResult]:
        """Führt ML-basierte Bedrohungserkennung durch"""
        try:
            confidence_threshold = self.config.get('security', {}).get('confidence_threshold', 0.7)

            # DGA Detection
            if self.dga_detector:
                dga_result = self.dga_detector.predict(domain)
                if dga_result['is_dga'] and dga_result['confidence'] >= confidence_threshold:
                    return SecurityResult(
                        blocked=True,
                        reason="DGA (Domain Generation Algorithm) erkannt",
                        confidence=dga_result['confidence'],
                        category="dga",
                        threat_type="ml_dga",
                        source="dga_detector",
                        metadata=dga_result.get('features', {})
                    )

            # Zero-Day Detection
            if self.zero_day_detector:
                zeroday_result = self.zero_day_detector.analyze_domain(domain)
                if zeroday_result['is_malicious'] and zeroday_result['confidence'] >= confidence_threshold:
                    return SecurityResult(
                        blocked=True,
                        reason="Zero-Day Bedrohung erkannt",
                        confidence=zeroday_result['confidence'],
                        category="zero_day",
                        threat_type="ml_zeroday",
                        source="zero_day_detector",
                        metadata=zeroday_result.get('indicators', {})
                    )

        except Exception as e:
            self.logger.error(f"Fehler bei ML Detection: {e}")

        return None

    def _get_cached_decision(self, cache_key: str) -> Optional[SecurityResult]:
        """Holt Entscheidung aus Cache"""
        try:
            with self.cache_lock:
                if cache_key in self.decision_cache:
                    cached_data = self.decision_cache[cache_key]

                    # TTL prüfen
                    if time.time() - cached_data['timestamp'] < self.cache_ttl:
                        return cached_data['result']
                    else:
                        # Veralteten Eintrag entfernen
                        del self.decision_cache[cache_key]
        except Exception as e:
            self.logger.error(f"Fehler beim Cache-Zugriff: {e}")

        return None

    def _cache_decision(self, cache_key: str, result: SecurityResult):
        """Speichert Entscheidung im Cache"""
        try:
            with self.cache_lock:
                # Cache-Größe begrenzen
                if len(self.decision_cache) >= 10000:
                    # Älteste 20% entfernen
                    old_keys = list(self.decision_cache.keys())[:2000]
                    for key in old_keys:
                        del self.decision_cache[key]

                self.decision_cache[cache_key] = {
                    'result': result,
                    'timestamp': time.time()
                }

        except Exception as e:
            self.logger.error(f"Fehler beim Caching: {e}")

    def add_to_whitelist(self, domain: str) -> bool:
        """Fügt Domain zur Whitelist hinzu"""
        try:
            self.whitelist.add(domain)

            # Konfiguration aktualisieren
            if 'security' not in self.config:
                self.config['security'] = {}

            self.config['security']['whitelist'] = list(self.whitelist)

            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            self.logger.info(f"Domain {domain} zur Whitelist hinzugefügt")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen zur Whitelist: {e}")
            return False

    def add_to_blacklist(self, domain: str) -> bool:
        """Fügt Domain zur Blacklist hinzu"""
        try:
            self.blacklist.add(domain)

            # Konfiguration aktualisieren
            if 'security' not in self.config:
                self.config['security'] = {}

            self.config['security']['blacklist'] = list(self.blacklist)

            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            self.logger.info(f"Domain {domain} zur Blacklist hinzugefügt")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen zur Blacklist: {e}")
            return False

    def remove_from_whitelist(self, domain: str) -> bool:
        """Entfernt Domain aus Whitelist"""
        try:
            if domain in self.whitelist:
                self.whitelist.remove(domain)

                self.config['security']['whitelist'] = list(self.whitelist)
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)

                return True
            return False

        except Exception as e:
            self.logger.error(f"Fehler beim Entfernen aus Whitelist: {e}")
            return False

    def remove_from_blacklist(self, domain: str) -> bool:
        """Entfernt Domain aus Blacklist"""
        try:
            if domain in self.blacklist:
                self.blacklist.remove(domain)

                self.config['security']['blacklist'] = list(self.blacklist)
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)

                return True
            return False

        except Exception as e:
            self.logger.error(f"Fehler beim Entfernen aus Blacklist: {e}")
            return False

    def report_false_positive(self, domain: str, reason: str = "") -> bool:
        """Meldet False Positive für ML-Training"""
        try:
            self.stats['false_positives'] += 1

            # Domain zur Whitelist hinzufügen
            self.add_to_whitelist(domain)

            # False Positive für ML-Training protokollieren
            false_positive_data = {
                'domain': domain,
                'timestamp': time.time(),
                'reason': reason,
                'client_feedback': True
            }

            # TODO: An ML-Training System weiterleiten

            self.logger.info(f"False Positive gemeldet für {domain}: {reason}")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Melden des False Positive: {e}")
            return False

    def get_security_statistics(self) -> Dict:
        """Gibt detaillierte Sicherheitsstatistiken zurück"""
        try:
            stats = dict(self.stats)

            # Zusätzliche Statistiken
            if self.stats['total_queries'] > 0:
                stats['block_rate'] = (self.stats['blocked_queries'] / self.stats['total_queries']) * 100
                stats['false_positive_rate'] = (self.stats['false_positives'] / self.stats['total_queries']) * 100
            else:
                stats['block_rate'] = 0.0
                stats['false_positive_rate'] = 0.0

            # Module-spezifische Statistiken
            if self.threat_intelligence:
                ti_stats = self.threat_intelligence.get_statistics()
                stats['threat_intelligence'] = ti_stats

            if self.brand_protection:
                bp_stats = self.brand_protection.get_threat_statistics()
                stats['brand_protection'] = bp_stats

            # Cache Statistiken
            stats['cache_size'] = len(self.decision_cache)
            stats['whitelist_size'] = len(self.whitelist)
            stats['blacklist_size'] = len(self.blacklist)

            return stats

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Statistiken: {e}")
            return self.stats

    def enable_module(self, module_name: str) -> bool:
        """Aktiviert Sicherheitsmodul"""
        try:
            if module_name not in ['brand_protection', 'threat_intelligence', 'ml_detection']:
                return False

            self.enabled_modules.add(module_name)

            # Modul initialisieren falls noch nicht geschehen
            if module_name == 'brand_protection' and not self.brand_protection:
                self.brand_protection = AdvancedBrandProtection()
            elif module_name == 'threat_intelligence' and not self.threat_intelligence:
                self.threat_intelligence = get_threat_intelligence()
            elif module_name == 'ml_detection' and not self.dga_detector:
                self.dga_detector = DGADetector()
                self.zero_day_detector = ZeroDayDetector()

            # Konfiguration aktualisieren
            self.config['security'][f'enable_{module_name}'] = True
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            self.logger.info(f"Security Modul {module_name} aktiviert")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Aktivieren des Moduls {module_name}: {e}")
            return False

    def disable_module(self, module_name: str) -> bool:
        """Deaktiviert Sicherheitsmodul"""
        try:
            self.enabled_modules.discard(module_name)

            # Konfiguration aktualisieren
            self.config['security'][f'enable_{module_name}'] = False
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            self.logger.info(f"Security Modul {module_name} deaktiviert")
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Deaktivieren des Moduls {module_name}: {e}")
            return False

    def cleanup_cache(self):
        """Bereinigt veraltete Cache-Einträge"""
        try:
            current_time = time.time()
            with self.cache_lock:
                expired_keys = []
                for key, data in self.decision_cache.items():
                    if current_time - data['timestamp'] >= self.cache_ttl:
                        expired_keys.append(key)

                for key in expired_keys:
                    del self.decision_cache[key]

                self.logger.debug(f"Cache bereinigt: {len(expired_keys)} veraltete Einträge entfernt")

        except Exception as e:
            self.logger.error(f"Fehler beim Cache-Cleanup: {e}")

# Global Instance
security_manager = None

def get_security_manager() -> DNSSecurityManager:
    """Gibt globale DNSSecurityManager Instanz zurück"""
    global security_manager
    if security_manager is None:
        security_manager = DNSSecurityManager()
    return security_manager
