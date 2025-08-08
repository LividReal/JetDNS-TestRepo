"""
JetDNS Threat Intelligence System
Integriert verschiedene Threat Intelligence Feeds für DNS-Sicherheit
"""

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
import aiohttp
import requests

logger = logging.getLogger(__name__)

class ThreatIntelligenceManager:
    """Verwaltet Threat Intelligence Feeds und Domain-Blocking"""

    # Standard Threat Intelligence Feeds
    THREAT_FEEDS = {
        'malware_domains': [
            {
                'name': 'Malware Domain List',
                'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
                'format': 'hosts',
                'category': 'malware'
            },
            {
                'name': 'URLVoid',
                'url': 'http://www.urlvoid.com/downloads/hostlist.txt',
                'format': 'domains',
                'category': 'malware'
            }
        ],
        'phishing_domains': [
            {
                'name': 'OpenPhish',
                'url': 'https://openphish.com/feed.txt',
                'format': 'urls',
                'category': 'phishing'
            },
            {
                'name': 'PhishTank',
                'url': 'https://data.phishtank.com/data/online-valid.csv',
                'format': 'csv',
                'category': 'phishing'
            }
        ],
        'ad_blocking': [
            {
                'name': 'StevenBlack Hosts',
                'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'format': 'hosts',
                'category': 'ads'
            },
            {
                'name': 'EasyList',
                'url': 'https://easylist.to/easylist/easylist.txt',
                'format': 'adblock',
                'category': 'ads'
            }
        ],
        'trackers': [
            {
                'name': 'Disconnect Tracking',
                'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
                'format': 'domains',
                'category': 'tracking'
            }
        ]
    }

    # DGA Detection Patterns
    DGA_PATTERNS = [
        # Längere Random-Strings
        re.compile(r'^[a-z0-9]{10,}\.com$'),
        re.compile(r'^[bcdfghjklmnpqrstvwxyz]{8,}\.net$'),

        # Typische DGA-Muster
        re.compile(r'^[a-z]{3}[0-9]{3,8}[a-z]{2,4}\.(com|net|org)$'),
        re.compile(r'^[0-9]{4,8}[a-z]{4,8}\.(com|net|org|info)$'),

        # Conficker-ähnliche Muster
        re.compile(r'^[a-z]{7,12}\.biz$'),
        re.compile(r'^[a-z]{8,15}\.info$'),
    ]

    def __init__(self, db_path='/var/lib/jetdns/threat_intel.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Thread-Safe Cache
        self.cache = {}
        self.cache_lock = threading.RLock()

        # Update Status
        self.last_update = {}
        self.update_in_progress = set()

        # Statistiken
        self.stats = {
            'blocked_domains': 0,
            'total_threats': 0,
            'last_updated': None,
            'feeds_status': {}
        }

        # Initialize Database
        self._init_database()

        # Load existing threats
        self._load_threats_from_db()

        # Start background updater
        self._start_background_updater()

    def _init_database(self):
        """Initialisiert SQLite Datenbank für Threat Intelligence"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Haupttabelle für Bedrohungen
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        category TEXT NOT NULL,
                        source TEXT NOT NULL,
                        confidence INTEGER DEFAULT 50,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        metadata TEXT
                    )
                ''')

                # Whitelist für falsche Positive
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        added_by TEXT DEFAULT 'admin',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Feed-Status Tabelle
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS feed_status (
                        feed_name TEXT PRIMARY KEY,
                        last_update DATETIME,
                        last_success DATETIME,
                        entries_count INTEGER DEFAULT 0,
                        error_message TEXT
                    )
                ''')

                # Indizes für Performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON threats(domain)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_category ON threats(category)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_confidence ON threats(confidence)')

                conn.commit()
                logger.info("Threat Intelligence Datenbank initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Initialisieren der TI-Datenbank: {e}")

    def _load_threats_from_db(self):
        """Lädt Bedrohungen aus der Datenbank in den Cache"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT domain, category, confidence, metadata
                    FROM threats 
                    WHERE confidence >= 30
                ''')

                with self.cache_lock:
                    for domain, category, confidence, metadata in cursor.fetchall():
                        self.cache[domain.lower()] = {
                            'category': category,
                            'confidence': confidence,
                            'metadata': json.loads(metadata) if metadata else {}
                        }

                logger.info(f"Threat Intelligence: {len(self.cache)} Bedrohungen geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der Bedrohungen: {e}")

    def is_malicious_domain(self, domain):
        """Prüft ob eine Domain als bösartig eingestuft ist"""
        domain = domain.lower().strip()

        # Whitelist prüfen
        if self._is_whitelisted(domain):
            return False, "whitelisted"

        # Cache prüfen
        with self.cache_lock:
            if domain in self.cache:
                threat_info = self.cache[domain]
                return True, {
                    'category': threat_info['category'],
                    'confidence': threat_info['confidence'],
                    'reason': f"Threat Intelligence: {threat_info['category']}"
                }

        # DGA Detection
        if self._is_dga_domain(domain):
            return True, {
                'category': 'dga',
                'confidence': 80,
                'reason': 'Domain Generation Algorithm detected'
            }

        # Subdomain-Check (für bekannte bösartige Hauptdomains)
        parent_domain = self._get_parent_domain(domain)
        if parent_domain != domain and parent_domain in self.cache:
            threat_info = self.cache[parent_domain]
            return True, {
                'category': threat_info['category'],
                'confidence': max(30, threat_info['confidence'] - 20),
                'reason': f"Subdomain of malicious domain: {parent_domain}"
            }

        # Newly Seen Domain Detection (optional)
        if self._is_newly_seen_domain(domain):
            return True, {
                'category': 'newly_seen',
                'confidence': 40,
                'reason': 'Newly registered domain'
            }

        return False, None

    def _is_whitelisted(self, domain):
        """Prüft ob Domain auf Whitelist steht"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute(
                    'SELECT COUNT(*) FROM whitelist WHERE domain = ?',
                    (domain,)
                )
                return cursor.fetchone()[0] > 0
        except:
            return False

    def _is_dga_domain(self, domain):
        """Erkennt Domain Generation Algorithm (DGA) Domains"""
        try:
            # Einfache heuristische Checks
            domain_parts = domain.split('.')
            if len(domain_parts) < 2:
                return False

            hostname = domain_parts[0]
            tld = domain_parts[-1]

            # Zu kurz oder zu lang
            if len(hostname) < 4 or len(hostname) > 63:
                return False

            # Pattern-basierte Erkennung
            for pattern in self.DGA_PATTERNS:
                if pattern.match(domain):
                    return True

            # Entropie-basierte Erkennung
            entropy = self._calculate_entropy(hostname)
            if entropy > 4.0 and len(hostname) > 8:
                # Hohe Entropie deutet auf zufällige Generierung hin
                return True

            # Vokal/Konsonant Verhältnis
            vowels = sum(1 for c in hostname.lower() if c in 'aeiou')
            consonants = len(hostname) - vowels

            if consonants > 0:
                ratio = vowels / consonants
                if ratio < 0.1 or ratio > 3.0:  # Unnatürliches Verhältnis
                    return True

            return False

        except Exception:
            return False

    def _calculate_entropy(self, text):
        """Berechnet Shannon-Entropie eines Strings"""
        import math
        from collections import Counter

        if not text:
            return 0

        counter = Counter(text.lower())
        length = len(text)

        entropy = 0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _is_newly_seen_domain(self, domain):
        """Erkennt neue/verdächtige Domains (OpenDNS-Style)"""
        try:
            # Extrahiere Hauptdomain
            main_domain = self._get_parent_domain(domain)

            # Prüfe auf verdächtige TLDs
            suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.su', '.cc', '.pw'}
            if any(main_domain.endswith(tld) for tld in suspicious_tlds):
                return True

            # Weitere Heuristiken könnten hier implementiert werden:
            # - WHOIS-Abfrage für Registrierungsdatum
            # - Reputation Checks
            # - DNS-History

            return False

        except Exception:
            return False

    def _get_parent_domain(self, domain):
        """Extrahiert Hauptdomain aus FQDN"""
        try:
            from urllib.parse import urlparse

            # Standard TLDs und 2-Level TLDs
            two_level_tlds = {
                'co.uk', 'co.jp', 'com.au', 'co.za', 'com.br',
                'co.in', 'com.mx', 'co.nz', 'com.tr', 'co.kr'
            }

            parts = domain.lower().split('.')

            if len(parts) <= 2:
                return domain

            # Prüfe auf 2-Level TLD
            potential_tld = '.'.join(parts[-2:])
            if potential_tld in two_level_tlds:
                if len(parts) >= 3:
                    return '.'.join(parts[-3:])

            # Standard Fall: domain.tld
            return '.'.join(parts[-2:])

        except Exception:
            return domain

    async def update_threat_feeds(self, feed_categories=None):
        """Aktualisiert Threat Intelligence Feeds"""
        if feed_categories is None:
            feed_categories = list(self.THREAT_FEEDS.keys())

        tasks = []
        for category in feed_categories:
            if category in self.THREAT_FEEDS:
                for feed in self.THREAT_FEEDS[category]:
                    if feed['name'] not in self.update_in_progress:
                        self.update_in_progress.add(feed['name'])
                        task = asyncio.create_task(self._update_single_feed(feed))
                        tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Verarbeite Ergebnisse
            success_count = 0
            for result in results:
                if not isinstance(result, Exception):
                    success_count += 1

            logger.info(f"Feed Update abgeschlossen: {success_count}/{len(tasks)} erfolgreich")

            # Statistiken aktualisieren
            self.stats['last_updated'] = datetime.now()
            self._update_stats()

    async def _update_single_feed(self, feed):
        """Aktualisiert einen einzelnen Threat Feed"""
        feed_name = feed['name']

        try:
            logger.info(f"Aktualisiere Feed: {feed_name}")

            # HTTP Request mit Timeout
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(feed['url']) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Verarbeite Feed basierend auf Format
                        threats = self._parse_feed_content(content, feed)

                        # Speichere in Datenbank
                        saved_count = self._save_threats_to_db(threats, feed_name)

                        # Update Feed Status
                        self._update_feed_status(feed_name, success=True, 
                                               count=saved_count)

                        logger.info(f"Feed {feed_name}: {saved_count} Bedrohungen aktualisiert")

                    else:
                        raise Exception(f"HTTP {response.status}")

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren von {feed_name}: {e}")
            self._update_feed_status(feed_name, success=False, error=str(e))

        finally:
            self.update_in_progress.discard(feed_name)

    def _parse_feed_content(self, content, feed):
        """Parst Feed-Content basierend auf Format"""
        threats = []
        lines = content.strip().split('\n')

        try:
            if feed['format'] == 'hosts':
                threats = self._parse_hosts_format(lines, feed['category'])
            elif feed['format'] == 'domains':
                threats = self._parse_domains_format(lines, feed['category'])
            elif feed['format'] == 'urls':
                threats = self._parse_urls_format(lines, feed['category'])
            elif feed['format'] == 'csv':
                threats = self._parse_csv_format(content, feed['category'])
            elif feed['format'] == 'adblock':
                threats = self._parse_adblock_format(lines, feed['category'])

        except Exception as e:
            logger.error(f"Fehler beim Parsen von {feed['name']}: {e}")

        return threats

    def _parse_hosts_format(self, lines, category):
        """Parst hosts-Format (127.0.0.1 domain.com)"""
        threats = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].strip()
                if self._is_valid_domain(domain):
                    threats.append({
                        'domain': domain,
                        'category': category,
                        'confidence': 70
                    })

        return threats

    def _parse_domains_format(self, lines, category):
        """Parst einfache Domain-Liste"""
        threats = []

        for line in lines:
            domain = line.strip()
            if domain and not domain.startswith('#') and self._is_valid_domain(domain):
                threats.append({
                    'domain': domain,
                    'category': category,
                    'confidence': 80
                })

        return threats

    def _parse_urls_format(self, lines, category):
        """Parst URL-Liste und extrahiert Domains"""
        threats = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            try:
                parsed = urlparse(line)
                domain = parsed.netloc.lower()
                if self._is_valid_domain(domain):
                    threats.append({
                        'domain': domain,
                        'category': category,
                        'confidence': 90
                    })
            except:
                continue

        return threats

    def _parse_csv_format(self, content, category):
        """Parst CSV-Format (z.B. PhishTank)"""
        import csv
        from io import StringIO

        threats = []

        try:
            csv_reader = csv.DictReader(StringIO(content))
            for row in csv_reader:
                if 'url' in row:
                    try:
                        parsed = urlparse(row['url'])
                        domain = parsed.netloc.lower()
                        if self._is_valid_domain(domain):
                            threats.append({
                                'domain': domain,
                                'category': category,
                                'confidence': 95
                            })
                    except:
                        continue
        except:
            pass

        return threats

    def _parse_adblock_format(self, lines, category):
        """Parst AdBlock-Format"""
        threats = []
        domain_pattern = re.compile(r'\|\|([a-zA-Z0-9\-\.]+)\^')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('!'):
                continue

            match = domain_pattern.search(line)
            if match:
                domain = match.group(1).lower()
                if self._is_valid_domain(domain):
                    threats.append({
                        'domain': domain,
                        'category': category,
                        'confidence': 60
                    })

        return threats

    def _is_valid_domain(self, domain):
        """Validiert Domain-Namen"""
        if not domain or len(domain) > 255:
            return False

        # Entferne Port falls vorhanden
        domain = domain.split(':')[0]

        # Basis-Validierung
        domain_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        )

        return bool(domain_pattern.match(domain))

    def _save_threats_to_db(self, threats, source):
        """Speichert Bedrohungen in Datenbank"""
        saved_count = 0

        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for threat in threats:
                    try:
                        conn.execute('''
                            INSERT OR REPLACE INTO threats 
                            (domain, category, source, confidence, last_seen, metadata)
                            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                        ''', (
                            threat['domain'],
                            threat['category'],
                            source,
                            threat['confidence'],
                            json.dumps(threat.get('metadata', {}))
                        ))
                        saved_count += 1
                    except sqlite3.IntegrityError:
                        # Domain bereits vorhanden, aktualisiere last_seen
                        conn.execute('''
                            UPDATE threats 
                            SET last_seen = CURRENT_TIMESTAMP,
                                confidence = MAX(confidence, ?)
                            WHERE domain = ?
                        ''', (threat['confidence'], threat['domain']))

                conn.commit()

                # Cache aktualisieren
                self._load_threats_from_db()

        except Exception as e:
            logger.error(f"Fehler beim Speichern der Bedrohungen: {e}")

        return saved_count

    def _update_feed_status(self, feed_name, success=True, count=0, error=None):
        """Aktualisiert Status eines Feeds"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                if success:
                    conn.execute('''
                        INSERT OR REPLACE INTO feed_status 
                        (feed_name, last_update, last_success, entries_count, error_message)
                        VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, NULL)
                    ''', (feed_name, count))
                else:
                    conn.execute('''
                        INSERT OR REPLACE INTO feed_status 
                        (feed_name, last_update, entries_count, error_message)
                        VALUES (?, CURRENT_TIMESTAMP, COALESCE((SELECT entries_count FROM feed_status WHERE feed_name = ?), 0), ?)
                    ''', (feed_name, feed_name, error))

                conn.commit()

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren des Feed-Status: {e}")

    def _update_stats(self):
        """Aktualisiert interne Statistiken"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Gesamtanzahl Bedrohungen
                cursor = conn.execute('SELECT COUNT(*) FROM threats')
                self.stats['total_threats'] = cursor.fetchone()[0]

                # Blockierte Domains (heute)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM threats 
                    WHERE last_seen >= date('now')
                ''')
                self.stats['blocked_domains'] = cursor.fetchone()[0]

                # Feed Status
                cursor = conn.execute('''
                    SELECT feed_name, last_update, last_success, entries_count, error_message
                    FROM feed_status
                ''')

                feeds_status = {}
                for name, last_update, last_success, count, error in cursor.fetchall():
                    feeds_status[name] = {
                        'last_update': last_update,
                        'last_success': last_success,
                        'entries_count': count,
                        'status': 'error' if error else 'ok',
                        'error_message': error
                    }

                self.stats['feeds_status'] = feeds_status

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren der Statistiken: {e}")

    def _start_background_updater(self):
        """Startet Background Thread für regelmäßige Updates"""
        def updater():
            while True:
                try:
                    # Täglich um 3:00 Uhr aktualisieren
                    now = datetime.now()
                    next_update = now.replace(hour=3, minute=0, second=0, microsecond=0)

                    if next_update <= now:
                        next_update += timedelta(days=1)

                    sleep_seconds = (next_update - now).total_seconds()
                    time.sleep(sleep_seconds)

                    # Update ausführen
                    logger.info("Starte automatisches Threat Intelligence Update")
                    asyncio.run(self.update_threat_feeds())

                except Exception as e:
                    logger.error(f"Fehler im Background Updater: {e}")
                    time.sleep(3600)  # Bei Fehler 1h warten

        thread = threading.Thread(target=updater, daemon=True)
        thread.start()

    def add_to_whitelist(self, domain, reason="Manual whitelist"):
        """Fügt Domain zur Whitelist hinzu"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO whitelist (domain, reason)
                    VALUES (?, ?)
                ''', (domain.lower(), reason))
                conn.commit()

            logger.info(f"Domain zur Whitelist hinzugefügt: {domain}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Hinzufügen zur Whitelist: {e}")
            return False

    def remove_from_whitelist(self, domain):
        """Entfernt Domain von der Whitelist"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('DELETE FROM whitelist WHERE domain = ?', (domain.lower(),))
                conn.commit()

            return cursor.rowcount > 0

        except Exception as e:
            logger.error(f"Fehler beim Entfernen von der Whitelist: {e}")
            return False

    def get_statistics(self):
        """Gibt aktuelle Statistiken zurück"""
        self._update_stats()
        return self.stats.copy()

    def get_threat_info(self, domain):
        """Gibt detaillierte Informationen über eine Bedrohung zurück"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT category, source, confidence, first_seen, last_seen, metadata
                    FROM threats 
                    WHERE domain = ?
                ''', (domain.lower(),))

                row = cursor.fetchone()
                if row:
                    return {
                        'domain': domain,
                        'category': row[0],
                        'source': row[1],
                        'confidence': row[2],
                        'first_seen': row[3],
                        'last_seen': row[4],
                        'metadata': json.loads(row[5]) if row[5] else {}
                    }

        except Exception as e:
            logger.error(f"Fehler beim Abrufen der Threat-Info: {e}")

        return None

    def search_threats(self, query, category=None, limit=100):
        """Sucht nach Bedrohungen"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                sql = 'SELECT domain, category, confidence FROM threats WHERE domain LIKE ?'
                params = [f'%{query}%']

                if category:
                    sql += ' AND category = ?'
                    params.append(category)

                sql += ' ORDER BY confidence DESC LIMIT ?'
                params.append(limit)

                cursor = conn.execute(sql, params)

                results = []
                for domain, cat, confidence in cursor.fetchall():
                    results.append({
                        'domain': domain,
                        'category': cat,
                        'confidence': confidence
                    })

                return results

        except Exception as e:
            logger.error(f"Fehler bei der Threat-Suche: {e}")
            return []

if __name__ == '__main__':
    # Test der Threat Intelligence
    import asyncio

    logging.basicConfig(level=logging.INFO)

    async def test_threat_intel():
        ti = ThreatIntelligenceManager('/tmp/test_threat_intel.db')

        # Test Domain-Check
        test_domains = [
            'google.com',
            'malware-example.com',
            'phishing-test.net',
            'abcdef12345.com'  # DGA-ähnlich
        ]

        for domain in test_domains:
            is_malicious, info = ti.is_malicious_domain(domain)
            print(f"{domain}: {'MALICIOUS' if is_malicious else 'SAFE'} - {info}")

        # Test Feed Update (mit kleinem Test-Feed)
        # await ti.update_threat_feeds(['ad_blocking'])

        # Statistiken anzeigen
        stats = ti.get_statistics()
        print(f"Statistiken: {stats}")

    asyncio.run(test_threat_intel())
