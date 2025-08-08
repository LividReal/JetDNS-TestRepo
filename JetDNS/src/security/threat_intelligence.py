"""
JetDNS Threat Intelligence Integration
Zentrale Verwaltung von Bedrohungsdaten und Threat Feeds
"""

import json
import os
import time
import asyncio
import logging
import hashlib
import requests
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from threading import Lock, Thread
from datetime import datetime, timedelta
import sqlite3

@dataclass
class ThreatFeed:
    """Threat Feed Konfiguration"""
    name: str
    url: str
    format: str  # 'json', 'csv', 'xml', 'dns'
    update_interval: int  # Sekunden
    enabled: bool = True
    last_update: float = 0
    auth_token: Optional[str] = None
    categories: List[str] = field(default_factory=list)

@dataclass
class ThreatIndicator:
    """Bedrohungsindikator"""
    indicator: str
    type: str  # 'domain', 'ip', 'hash', 'url'
    category: str  # 'malware', 'phishing', 'c2', 'exploit'
    confidence: float
    source: str
    first_seen: float
    last_seen: float
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

class ThreatIntelligenceEngine:
    """
    Zentrale Threat Intelligence Engine
    Verwaltet Feeds, Indikatoren und Threat Matching
    """

    def __init__(self, config_path: str = "/etc/jetdns/threat_intelligence.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.db_path = "/var/lib/jetdns/threat_intelligence.db"

        # Thread-sichere Datenstrukturen
        self.lock = Lock()
        self.feeds: Dict[str, ThreatFeed] = {}
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.domain_cache: Dict[str, bool] = {}
        self.ip_cache: Dict[str, bool] = {}

        # Performance Metriken
        self.stats = {
            'total_indicators': 0,
            'active_feeds': 0,
            'last_update': 0,
            'matches_today': 0,
            'false_positives': 0
        }

        self._initialize_database()
        self._load_configuration()
        self._load_threat_data()

        # Update Thread starten
        self.update_thread = Thread(target=self._update_worker, daemon=True)
        self.update_thread.start()

    def _initialize_database(self):
        """Initialisiert die SQLite-Datenbank"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Threat Feeds Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    name TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    format TEXT NOT NULL,
                    update_interval INTEGER NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    last_update REAL DEFAULT 0,
                    auth_token TEXT,
                    categories TEXT
                )
            ''')

            # Threat Indicators Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    tags TEXT,
                    metadata TEXT
                )
            ''')

            # Performance Index
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_indicator_type 
                ON threat_indicators(type, category)
            ''')

            # Match History Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    query_domain TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    confidence REAL NOT NULL
                )
            ''')

            conn.commit()
            conn.close()

            self.logger.info("Threat Intelligence Datenbank initialisiert")

        except Exception as e:
            self.logger.error(f"Fehler beim Initialisieren der Datenbank: {e}")

    def _load_configuration(self):
        """Lädt Konfiguration aus JSON-Datei"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)

            # Standard Threat Feeds konfigurieren
            default_feeds = {
                'malware_domains': ThreatFeed(
                    name='malware_domains',
                    url='https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt',
                    format='dns',
                    update_interval=3600,
                    categories=['malware']
                ),
                'phishing_domains': ThreatFeed(
                    name='phishing_domains', 
                    url='https://openphish.com/feed.txt',
                    format='dns',
                    update_interval=1800,
                    categories=['phishing']
                ),
                'botnet_c2': ThreatFeed(
                    name='botnet_c2',
                    url='https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                    format='dns',
                    update_interval=3600,
                    categories=['c2', 'botnet']
                ),
                'custom_threats': ThreatFeed(
                    name='custom_threats',
                    url='file:///etc/jetdns/custom_threats.json',
                    format='json',
                    update_interval=300,
                    categories=['custom']
                )
            }

            # Feeds aus Konfiguration laden
            for feed_config in config.get('threat_feeds', []):
                feed = ThreatFeed(**feed_config)
                self.feeds[feed.name] = feed

            # Default Feeds hinzufügen falls nicht konfiguriert
            for name, feed in default_feeds.items():
                if name not in self.feeds:
                    self.feeds[name] = feed

            self.logger.info(f"Threat Intelligence Konfiguration geladen: {len(self.feeds)} Feeds")

        except FileNotFoundError:
            self.logger.warning("Keine Threat Intelligence Konfiguration gefunden, verwende Defaults")
            self._create_default_config()
        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Konfiguration: {e}")

    def _create_default_config(self):
        """Erstellt Standard-Konfigurationsdatei"""
        default_config = {
            'threat_feeds': [
                {
                    'name': 'malware_domains',
                    'url': 'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt',
                    'format': 'dns',
                    'update_interval': 3600,
                    'categories': ['malware']
                }
            ],
            'settings': {
                'cache_ttl': 3600,
                'max_indicators': 1000000,
                'confidence_threshold': 0.7
            }
        }

        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Fehler beim Erstellen der Standard-Konfiguration: {e}")

    def _load_threat_data(self):
        """Lädt Threat-Daten aus der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM threat_indicators')
            count = cursor.fetchone()[0]
            self.stats['total_indicators'] = count

            # Aktive Feeds zählen
            cursor.execute('SELECT COUNT(*) FROM threat_feeds WHERE enabled = 1')
            active_feeds = cursor.fetchone()[0]
            self.stats['active_feeds'] = active_feeds

            conn.close()

            self.logger.info(f"Threat Intelligence geladen: {count} Indikatoren, {active_feeds} aktive Feeds")

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Threat-Daten: {e}")

    def _update_worker(self):
        """Background Worker für Feed-Updates"""
        while True:
            try:
                current_time = time.time()

                for feed_name, feed in self.feeds.items():
                    if not feed.enabled:
                        continue

                    if current_time - feed.last_update >= feed.update_interval:
                        self._update_feed(feed)
                        feed.last_update = current_time

                # Cache aufräumen
                self._cleanup_cache()

                # 60 Sekunden warten bis zum nächsten Update-Zyklus
                time.sleep(60)

            except Exception as e:
                self.logger.error(f"Fehler im Update-Worker: {e}")
                time.sleep(60)

    def _update_feed(self, feed: ThreatFeed):
        """Aktualisiert einen einzelnen Threat Feed"""
        try:
            self.logger.info(f"Aktualisiere Threat Feed: {feed.name}")

            if feed.url.startswith('file://'):
                # Lokale Datei laden
                file_path = feed.url[7:]  # Remove 'file://'
                with open(file_path, 'r') as f:
                    data = f.read()
            else:
                # HTTP Request
                headers = {}
                if feed.auth_token:
                    headers['Authorization'] = f'Bearer {feed.auth_token}'

                response = requests.get(feed.url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.text

            # Daten parsen basierend auf Format
            indicators = self._parse_feed_data(data, feed)

            # Indikatoren in Datenbank speichern
            self._store_indicators(indicators, feed.name)

            self.logger.info(f"Feed {feed.name} aktualisiert: {len(indicators)} Indikatoren")

        except Exception as e:
            self.logger.error(f"Fehler beim Aktualisieren von Feed {feed.name}: {e}")

    def _parse_feed_data(self, data: str, feed: ThreatFeed) -> List[ThreatIndicator]:
        """Parst Feed-Daten basierend auf Format"""
        indicators = []
        current_time = time.time()

        try:
            if feed.format == 'dns':
                # Einfache Domain/IP Liste
                lines = data.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Domain oder IP erkennen
                    if '.' in line:
                        indicator_type = 'ip' if line.replace('.', '').isdigit() else 'domain'

                        indicator = ThreatIndicator(
                            indicator=line,
                            type=indicator_type,
                            category=feed.categories[0] if feed.categories else 'unknown',
                            confidence=0.8,
                            source=feed.name,
                            first_seen=current_time,
                            last_seen=current_time,
                            tags=set(feed.categories)
                        )
                        indicators.append(indicator)

            elif feed.format == 'json':
                # JSON Format
                json_data = json.loads(data)
                if isinstance(json_data, list):
                    for item in json_data:
                        indicator = ThreatIndicator(
                            indicator=item.get('indicator', ''),
                            type=item.get('type', 'domain'),
                            category=item.get('category', 'unknown'),
                            confidence=float(item.get('confidence', 0.8)),
                            source=feed.name,
                            first_seen=current_time,
                            last_seen=current_time,
                            tags=set(item.get('tags', [])),
                            metadata=item.get('metadata', {})
                        )
                        indicators.append(indicator)

            elif feed.format == 'csv':
                # CSV Format
                lines = data.strip().split('\n')
                headers = lines[0].split(',') if lines else []

                for line in lines[1:]:
                    values = line.split(',')
                    if len(values) >= len(headers):
                        row_data = dict(zip(headers, values))

                        indicator = ThreatIndicator(
                            indicator=row_data.get('indicator', ''),
                            type=row_data.get('type', 'domain'),
                            category=row_data.get('category', 'unknown'),
                            confidence=float(row_data.get('confidence', 0.8)),
                            source=feed.name,
                            first_seen=current_time,
                            last_seen=current_time
                        )
                        indicators.append(indicator)

        except Exception as e:
            self.logger.error(f"Fehler beim Parsen von Feed-Daten {feed.name}: {e}")

        return indicators

    def _store_indicators(self, indicators: List[ThreatIndicator], source: str):
        """Speichert Indikatoren in der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            for indicator in indicators:
                # Upsert Operation
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_indicators 
                    (indicator, type, category, confidence, source, first_seen, last_seen, tags, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator.indicator,
                    indicator.type,
                    indicator.category,
                    indicator.confidence,
                    indicator.source,
                    indicator.first_seen,
                    indicator.last_seen,
                    json.dumps(list(indicator.tags)),
                    json.dumps(indicator.metadata)
                ))

            conn.commit()
            conn.close()

            # Cache aktualisieren
            with self.lock:
                for indicator in indicators:
                    if indicator.type == 'domain':
                        self.domain_cache[indicator.indicator] = True
                    elif indicator.type == 'ip':
                        self.ip_cache[indicator.indicator] = True

            # Statistiken aktualisieren
            self.stats['total_indicators'] += len(indicators)
            self.stats['last_update'] = time.time()

        except Exception as e:
            self.logger.error(f"Fehler beim Speichern der Indikatoren: {e}")

    def check_domain(self, domain: str, client_ip: str = "") -> Optional[ThreatIndicator]:
        """
        Prüft ob Domain eine bekannte Bedrohung ist
        Returns: ThreatIndicator wenn Bedrohung erkannt, None sonst
        """
        try:
            # Cache prüfen
            with self.lock:
                if domain in self.domain_cache:
                    if self.domain_cache[domain]:
                        # Aus Datenbank laden für Details
                        return self._get_indicator_from_db(domain)
                    else:
                        return None

            # Datenbank prüfen
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM threat_indicators 
                WHERE indicator = ? AND type = 'domain'
                ORDER BY confidence DESC LIMIT 1
            ''', (domain,))

            row = cursor.fetchone()
            conn.close()

            if row:
                indicator = self._row_to_indicator(row)

                # Cache aktualisieren
                with self.lock:
                    self.domain_cache[domain] = True

                # Match protokollieren
                self._log_match(indicator, domain, client_ip)

                return indicator
            else:
                # Negative Cache
                with self.lock:
                    self.domain_cache[domain] = False

                return None

        except Exception as e:
            self.logger.error(f"Fehler beim Prüfen der Domain {domain}: {e}")
            return None

    def check_ip(self, ip: str, client_ip: str = "") -> Optional[ThreatIndicator]:
        """Prüft ob IP eine bekannte Bedrohung ist"""
        try:
            # Cache prüfen
            with self.lock:
                if ip in self.ip_cache:
                    if self.ip_cache[ip]:
                        return self._get_indicator_from_db(ip)
                    else:
                        return None

            # Datenbank prüfen
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM threat_indicators 
                WHERE indicator = ? AND type = 'ip'
                ORDER BY confidence DESC LIMIT 1
            ''', (ip,))

            row = cursor.fetchone()
            conn.close()

            if row:
                indicator = self._row_to_indicator(row)

                # Cache aktualisieren
                with self.lock:
                    self.ip_cache[ip] = True

                # Match protokollieren
                self._log_match(indicator, ip, client_ip)

                return indicator
            else:
                with self.lock:
                    self.ip_cache[ip] = False
                return None

        except Exception as e:
            self.logger.error(f"Fehler beim Prüfen der IP {ip}: {e}")
            return None

    def _get_indicator_from_db(self, indicator_value: str) -> Optional[ThreatIndicator]:
        """Lädt Indikator-Details aus der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM threat_indicators WHERE indicator = ?', (indicator_value,))
            row = cursor.fetchone()
            conn.close()

            if row:
                return self._row_to_indicator(row)
            return None

        except Exception as e:
            self.logger.error(f"Fehler beim Laden des Indikators {indicator_value}: {e}")
            return None

    def _row_to_indicator(self, row) -> ThreatIndicator:
        """Konvertiert Datenbank-Row zu ThreatIndicator"""
        tags = set(json.loads(row[7]) if row[7] else [])
        metadata = json.loads(row[8]) if row[8] else {}

        return ThreatIndicator(
            indicator=row[0],
            type=row[1],
            category=row[2],
            confidence=row[3],
            source=row[4],
            first_seen=row[5],
            last_seen=row[6],
            tags=tags,
            metadata=metadata
        )

    def _log_match(self, indicator: ThreatIndicator, query: str, client_ip: str):
        """Protokolliert Threat Match"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO threat_matches 
                (indicator, query_domain, client_ip, timestamp, action, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                indicator.indicator,
                query,
                client_ip,
                time.time(),
                'blocked',
                indicator.confidence
            ))

            conn.commit()
            conn.close()

            # Statistiken aktualisieren
            self.stats['matches_today'] += 1

        except Exception as e:
            self.logger.error(f"Fehler beim Protokollieren des Matches: {e}")

    def _cleanup_cache(self):
        """Bereinigt veraltete Cache-Einträge"""
        try:
            with self.lock:
                # Domain Cache auf 10000 Einträge begrenzen
                if len(self.domain_cache) > 10000:
                    # Älteste 20% entfernen
                    items_to_remove = len(self.domain_cache) // 5
                    keys_to_remove = list(self.domain_cache.keys())[:items_to_remove]

                    for key in keys_to_remove:
                        del self.domain_cache[key]

                # IP Cache auf 5000 Einträge begrenzen
                if len(self.ip_cache) > 5000:
                    items_to_remove = len(self.ip_cache) // 5
                    keys_to_remove = list(self.ip_cache.keys())[:items_to_remove]

                    for key in keys_to_remove:
                        del self.ip_cache[key]

        except Exception as e:
            self.logger.error(f"Fehler beim Cache-Cleanup: {e}")

    def add_custom_indicator(self, indicator: str, threat_type: str, category: str, 
                           confidence: float = 0.9) -> bool:
        """Fügt benutzerdefinierten Threat-Indikator hinzu"""
        try:
            current_time = time.time()
            threat_indicator = ThreatIndicator(
                indicator=indicator,
                type=threat_type,
                category=category,
                confidence=confidence,
                source='manual',
                first_seen=current_time,
                last_seen=current_time,
                tags={'custom', 'manual'}
            )

            self._store_indicators([threat_indicator], 'manual')
            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Hinzufügen des Custom Indikators: {e}")
            return False

    def remove_indicator(self, indicator: str) -> bool:
        """Entfernt Threat-Indikator"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM threat_indicators WHERE indicator = ?', (indicator,))
            conn.commit()
            conn.close()

            # Cache aktualisieren
            with self.lock:
                self.domain_cache.pop(indicator, None)
                self.ip_cache.pop(indicator, None)

            return True

        except Exception as e:
            self.logger.error(f"Fehler beim Entfernen des Indikators {indicator}: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Gibt Threat Intelligence Statistiken zurück"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Aktuelle Statistiken aus DB laden
            cursor.execute('SELECT COUNT(*) FROM threat_indicators')
            total_indicators = cursor.fetchone()[0]

            cursor.execute('SELECT category, COUNT(*) FROM threat_indicators GROUP BY category')
            category_stats = dict(cursor.fetchall())

            # Matches der letzten 24h
            yesterday = time.time() - 86400
            cursor.execute('SELECT COUNT(*) FROM threat_matches WHERE timestamp > ?', (yesterday,))
            matches_24h = cursor.fetchone()[0]

            conn.close()

            return {
                'total_indicators': total_indicators,
                'active_feeds': len([f for f in self.feeds.values() if f.enabled]),
                'category_breakdown': category_stats,
                'matches_24h': matches_24h,
                'cache_size': len(self.domain_cache) + len(self.ip_cache),
                'last_update': self.stats['last_update']
            }

        except Exception as e:
            self.logger.error(f"Fehler beim Laden der Statistiken: {e}")
            return self.stats

    def export_indicators(self, format: str = 'json', category: str = None) -> str:
        """Exportiert Threat-Indikatoren"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if category:
                cursor.execute('SELECT * FROM threat_indicators WHERE category = ?', (category,))
            else:
                cursor.execute('SELECT * FROM threat_indicators')

            rows = cursor.fetchall()
            conn.close()

            indicators = [self._row_to_indicator(row) for row in rows]

            if format == 'json':
                return json.dumps([{
                    'indicator': ind.indicator,
                    'type': ind.type,
                    'category': ind.category,
                    'confidence': ind.confidence,
                    'source': ind.source,
                    'tags': list(ind.tags)
                } for ind in indicators], indent=2)

            elif format == 'csv':
                lines = ['indicator,type,category,confidence,source,tags']
                for ind in indicators:
                    lines.append(f'{ind.indicator},{ind.type},{ind.category},{ind.confidence},{ind.source},"{";".join(ind.tags)}"')
                return '\n'.join(lines)

            else:
                return '\n'.join([ind.indicator for ind in indicators])

        except Exception as e:
            self.logger.error(f"Fehler beim Exportieren der Indikatoren: {e}")
            return ""

# Global Instance für einfachen Zugriff
threat_intelligence = None

def get_threat_intelligence() -> ThreatIntelligenceEngine:
    """Gibt globale ThreatIntelligenceEngine Instanz zurück"""
    global threat_intelligence
    if threat_intelligence is None:
        threat_intelligence = ThreatIntelligenceEngine()
    return threat_intelligence
