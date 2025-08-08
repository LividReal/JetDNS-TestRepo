"""
JetDNS Query Analyzer
Analysiert DNS-Queries und erstellt Statistiken
"""

import json
import logging
import sqlite3
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import re
import ipaddress

logger = logging.getLogger(__name__)

class QueryAnalyzer:
    """Analysiert DNS-Queries und erstellt umfassende Statistiken"""

    def __init__(self, db_path='/var/lib/jetdns/queries.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # In-Memory Cache für Performance
        self.recent_queries = deque(maxlen=1000)
        self.stats_cache = {
            'queries_total': 0,
            'queries_per_second': 0,
            'blocked_queries': 0,
            'cache_hits': 0,
            'top_domains': defaultdict(int),
            'client_stats': defaultdict(int),
            'query_types': defaultdict(int)
        }

        # Thread Safety
        self.lock = threading.RLock()

        # Database Setup
        self._init_database()

        # Load existing stats
        self._load_stats_from_db()

    def _init_database(self):
        """Initialisiert SQLite Datenbank für Query-Logs"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS dns_queries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        client_ip TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        query_class TEXT DEFAULT 'IN',
                        response_type TEXT NOT NULL,
                        response_time INTEGER NOT NULL,
                        cached BOOLEAN DEFAULT 0,
                        blocked BOOLEAN DEFAULT 0,
                        blocked_reason TEXT,
                        upstream_server TEXT,
                        client_country TEXT,
                        client_asn TEXT
                    )
                ''')

                # Indices für Performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_queries(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON dns_queries(domain)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_client_ip ON dns_queries(client_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_blocked ON dns_queries(blocked)')

                # Statistik-Tabelle
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS query_stats (
                        date DATE PRIMARY KEY,
                        total_queries INTEGER DEFAULT 0,
                        blocked_queries INTEGER DEFAULT 0,
                        cache_hits INTEGER DEFAULT 0,
                        unique_domains INTEGER DEFAULT 0,
                        unique_clients INTEGER DEFAULT 0,
                        avg_response_time REAL DEFAULT 0
                    )
                ''')

                conn.commit()
                logger.info("Query Analyzer Datenbank initialisiert")

        except Exception as e:
            logger.error(f"Fehler beim Initialisieren der Datenbank: {e}")

    def _load_stats_from_db(self):
        """Lädt aktuelle Statistiken aus der Datenbank"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Heutige Statistiken
                today = datetime.now().date()
                cursor = conn.execute(
                    'SELECT * FROM query_stats WHERE date = ?',
                    (today,)
                )
                row = cursor.fetchone()

                if row:
                    self.stats_cache.update({
                        'queries_total': row[1],
                        'blocked_queries': row[2],
                        'cache_hits': row[3]
                    })

                # Top Domains (letzte 24h)
                cursor = conn.execute('''
                    SELECT domain, COUNT(*) as count 
                    FROM dns_queries 
                    WHERE timestamp > datetime('now', '-1 day')
                    GROUP BY domain 
                    ORDER BY count DESC 
                    LIMIT 100
                ''')

                for domain, count in cursor.fetchall():
                    self.stats_cache['top_domains'][domain] = count

        except Exception as e:
            logger.error(f"Fehler beim Laden der Statistiken: {e}")

    def log_query(self, query_data):
        """Protokolliert eine DNS-Query"""
        try:
            with self.lock:
                # Zu Recent Queries hinzufügen
                self.recent_queries.append({
                    'timestamp': datetime.now(),
                    'client_ip': query_data.get('client_ip', ''),
                    'domain': query_data.get('domain', ''),
                    'qtype': query_data.get('query_type', 'A'),
                    'response_time': query_data.get('response_time', 0),
                    'cached': query_data.get('cached', False),
                    'blocked': query_data.get('blocked', False),
                    'blocked_reason': query_data.get('blocked_reason', ''),
                    'upstream_server': query_data.get('upstream_server', '')
                })

                # Stats aktualisieren
                self.stats_cache['queries_total'] += 1
                if query_data.get('blocked', False):
                    self.stats_cache['blocked_queries'] += 1
                if query_data.get('cached', False):
                    self.stats_cache['cache_hits'] += 1

                # Domain/Client Statistiken
                domain = query_data.get('domain', '')
                if domain:
                    self.stats_cache['top_domains'][domain] += 1

                client_ip = query_data.get('client_ip', '')
                if client_ip:
                    self.stats_cache['client_stats'][client_ip] += 1

                query_type = query_data.get('query_type', 'A')
                self.stats_cache['query_types'][query_type] += 1

            # Asynchron in DB speichern
            self._save_query_to_db(query_data)

        except Exception as e:
            logger.error(f"Fehler beim Protokollieren der Query: {e}")

    def _save_query_to_db(self, query_data):
        """Speichert Query in Datenbank"""
        try:
            # GeoIP Info erweitern (optional)
            client_country, client_asn = self._get_client_geo_info(query_data.get('client_ip', ''))

            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    INSERT INTO dns_queries (
                        client_ip, domain, query_type, query_class,
                        response_type, response_time, cached, blocked,
                        blocked_reason, upstream_server, client_country, client_asn
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    query_data.get('client_ip', ''),
                    query_data.get('domain', ''),
                    query_data.get('query_type', 'A'),
                    query_data.get('query_class', 'IN'),
                    query_data.get('response_type', 'ANSWER'),
                    query_data.get('response_time', 0),
                    query_data.get('cached', False),
                    query_data.get('blocked', False),
                    query_data.get('blocked_reason', ''),
                    query_data.get('upstream_server', ''),
                    client_country,
                    client_asn
                ))
                conn.commit()

        except Exception as e:
            logger.error(f"Fehler beim Speichern in DB: {e}")

    def _get_client_geo_info(self, client_ip):
        """Ermittelt GeoIP-Informationen für Client (optional)"""
        try:
            # Versuche private/lokale IPs zu identifizieren
            ip_obj = ipaddress.ip_address(client_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return "Local", "Local"

            # Hier könnte MaxMind GeoIP2 Integration erfolgen
            # from geoip2 import database, errors
            # with database.Reader('/path/to/GeoLite2-City.mmdb') as reader:
            #     response = reader.city(client_ip)
            #     return response.country.name, response.traits.autonomous_system_organization

            return "Unknown", "Unknown"

        except Exception:
            return "Unknown", "Unknown"

    def get_recent_queries(self, limit=50):
        """Gibt die letzten DNS-Queries zurück"""
        with self.lock:
            queries = list(self.recent_queries)[-limit:]
            return [q for q in reversed(queries)]

    def get_total_queries(self):
        """Gibt Gesamtanzahl der Queries zurück"""
        return self.stats_cache['queries_total']

    def get_queries_per_second(self):
        """Berechnet Queries pro Sekunde (letzte Minute)"""
        try:
            with self.lock:
                now = datetime.now()
                minute_ago = now - timedelta(minutes=1)

                # Zähle Queries der letzten Minute
                recent_count = sum(1 for q in self.recent_queries 
                                 if q['timestamp'] > minute_ago)

                return round(recent_count / 60, 1)
        except:
            return 0

    def get_blocked_queries(self):
        """Gibt Anzahl blockierter Queries zurück"""
        return self.stats_cache['blocked_queries']

    def get_cache_hit_rate(self):
        """Berechnet Cache Hit Rate"""
        total = self.stats_cache['queries_total']
        hits = self.stats_cache['cache_hits']

        if total > 0:
            return round((hits / total) * 100, 1)
        return 0.0

    def get_top_domains(self, limit=10):
        """Gibt Top-Domains zurück"""
        with self.lock:
            sorted_domains = sorted(
                self.stats_cache['top_domains'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]

            total_queries = max(1, sum(count for _, count in sorted_domains))

            return [{
                'name': domain,
                'count': count,
                'percentage': round((count / total_queries) * 100, 1)
            } for domain, count in sorted_domains]

    def get_client_statistics(self, limit=10):
        """Gibt Client-Statistiken zurück"""
        with self.lock:
            sorted_clients = sorted(
                self.stats_cache['client_stats'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:limit]

            return [{
                'ip': client_ip,
                'queries': count,
                'country': self._get_client_geo_info(client_ip)[0]
            } for client_ip, count in sorted_clients]

    def get_query_type_distribution(self):
        """Gibt Verteilung der Query-Typen zurück"""
        with self.lock:
            total = sum(self.stats_cache['query_types'].values())
            if total == 0:
                return []

            return [{
                'type': qtype,
                'count': count,
                'percentage': round((count / total) * 100, 1)
            } for qtype, count in sorted(
                self.stats_cache['query_types'].items(),
                key=lambda x: x[1],
                reverse=True
            )]

    def get_hourly_statistics(self, hours=24):
        """Gibt stündliche Statistiken zurück"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT 
                        strftime('%H', timestamp) as hour,
                        COUNT(*) as total_queries,
                        SUM(blocked) as blocked_queries,
                        SUM(cached) as cache_hits,
                        AVG(response_time) as avg_response_time
                    FROM dns_queries 
                    WHERE timestamp > datetime('now', '-{} hours')
                    GROUP BY strftime('%Y-%m-%d %H', timestamp)
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''.format(hours), (hours,))

                stats = []
                for row in cursor.fetchall():
                    stats.append({
                        'hour': row[0],
                        'total_queries': row[1],
                        'blocked_queries': row[2] or 0,
                        'cache_hits': row[3] or 0,
                        'avg_response_time': round(row[4] or 0, 2)
                    })

                return stats

        except Exception as e:
            logger.error(f"Fehler bei stündlichen Statistiken: {e}")
            return []

    def get_threat_statistics(self):
        """Gibt Bedrohungs-Statistiken zurück"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Blockierte Domains nach Kategorie
                cursor = conn.execute('''
                    SELECT blocked_reason, COUNT(*) as count
                    FROM dns_queries 
                    WHERE blocked = 1 AND timestamp > datetime('now', '-7 days')
                    GROUP BY blocked_reason
                    ORDER BY count DESC
                    LIMIT 10
                ''')

                threat_categories = []
                for reason, count in cursor.fetchall():
                    if reason:
                        threat_categories.append({
                            'category': reason,
                            'count': count
                        })

                # Bedrohliche Domains
                cursor = conn.execute('''
                    SELECT domain, COUNT(*) as attempts, blocked_reason
                    FROM dns_queries 
                    WHERE blocked = 1 AND timestamp > datetime('now', '-24 hours')
                    GROUP BY domain, blocked_reason
                    ORDER BY attempts DESC
                    LIMIT 20
                ''')

                threat_domains = []
                for domain, attempts, reason in cursor.fetchall():
                    threat_domains.append({
                        'domain': domain,
                        'attempts': attempts,
                        'reason': reason or 'Unknown'
                    })

                return {
                    'threat_categories': threat_categories,
                    'threat_domains': threat_domains
                }

        except Exception as e:
            logger.error(f"Fehler bei Bedrohungsstatistiken: {e}")
            return {'threat_categories': [], 'threat_domains': []}

    def get_analytics_data(self):
        """Gibt umfassende Analytics-Daten zurück"""
        try:
            return {
                'overview': {
                    'total_queries': self.get_total_queries(),
                    'queries_per_second': self.get_queries_per_second(),
                    'blocked_queries': self.get_blocked_queries(),
                    'cache_hit_rate': self.get_cache_hit_rate()
                },
                'top_domains': self.get_top_domains(20),
                'client_stats': self.get_client_statistics(15),
                'query_types': self.get_query_type_distribution(),
                'hourly_stats': self.get_hourly_statistics(24),
                'threat_stats': self.get_threat_statistics()
            }
        except Exception as e:
            logger.error(f"Fehler bei Analytics-Daten: {e}")
            return {
                'overview': {},
                'top_domains': [],
                'client_stats': [],
                'query_types': [],
                'hourly_stats': [],
                'threat_stats': {}
            }

    def get_basic_stats(self):
        """Gibt Basis-Statistiken zurück (für Fallback ohne Redis)"""
        return {
            'queries_total': self.get_total_queries(),
            'queries_per_second': self.get_queries_per_second(),
            'blocked_queries': self.get_blocked_queries(),
            'cache_hit_rate': self.get_cache_hit_rate(),
            'cache_entries': 0  # Placeholder
        }

    def cleanup_old_data(self, days_to_keep=30):
        """Bereinigt alte Daten aus der Datenbank"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cutoff_date = datetime.now() - timedelta(days=days_to_keep)

                cursor = conn.execute(
                    'DELETE FROM dns_queries WHERE timestamp < ?',
                    (cutoff_date,)
                )

                deleted_count = cursor.rowcount
                conn.commit()

                # VACUUM für Speicherplatz-Optimierung
                conn.execute('VACUUM')

                logger.info(f"Bereinigung: {deleted_count} alte Queries entfernt")

        except Exception as e:
            logger.error(f"Fehler bei der Datenbereinigung: {e}")

    def export_data(self, start_date=None, end_date=None, format='json'):
        """Exportiert Query-Daten in verschiedenen Formaten"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                query = 'SELECT * FROM dns_queries'
                params = []

                if start_date or end_date:
                    conditions = []
                    if start_date:
                        conditions.append('timestamp >= ?')
                        params.append(start_date)
                    if end_date:
                        conditions.append('timestamp <= ?')
                        params.append(end_date)

                    query += ' WHERE ' + ' AND '.join(conditions)

                query += ' ORDER BY timestamp DESC'

                cursor = conn.execute(query, params)
                columns = [description[0] for description in cursor.description]
                rows = cursor.fetchall()

                if format.lower() == 'json':
                    data = []
                    for row in rows:
                        data.append(dict(zip(columns, row)))
                    return json.dumps(data, default=str, indent=2)

                elif format.lower() == 'csv':
                    import csv
                    import io
                    output = io.StringIO()
                    writer = csv.writer(output)
                    writer.writerow(columns)
                    writer.writerows(rows)
                    return output.getvalue()

                else:
                    raise ValueError(f"Unbekanntes Export-Format: {format}")

        except Exception as e:
            logger.error(f"Fehler beim Datenexport: {e}")
            return None

    def update_daily_stats(self):
        """Aktualisiert tägliche Statistiken (für Cron-Job)"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                today = datetime.now().date()

                cursor = conn.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(blocked) as blocked,
                        SUM(cached) as cached,
                        COUNT(DISTINCT domain) as unique_domains,
                        COUNT(DISTINCT client_ip) as unique_clients,
                        AVG(response_time) as avg_response_time
                    FROM dns_queries 
                    WHERE DATE(timestamp) = ?
                ''', (today,))

                row = cursor.fetchone()
                if row:
                    conn.execute('''
                        INSERT OR REPLACE INTO query_stats 
                        (date, total_queries, blocked_queries, cache_hits, 
                         unique_domains, unique_clients, avg_response_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (today, row[0], row[1] or 0, row[2] or 0, 
                         row[3] or 0, row[4] or 0, row[5] or 0))

                    conn.commit()
                    logger.info(f"Tägliche Statistiken für {today} aktualisiert")

        except Exception as e:
            logger.error(f"Fehler bei täglichen Statistiken: {e}")

if __name__ == '__main__':
    # Test der Funktionalität
    analyzer = QueryAnalyzer()

    # Test-Query hinzufügen
    test_query = {
        'client_ip': '192.168.1.100',
        'domain': 'example.com',
        'query_type': 'A',
        'response_time': 25,
        'cached': False,
        'blocked': False
    }

    analyzer.log_query(test_query)
    print("Test-Query hinzugefügt")

    # Statistiken anzeigen
    print(f"Gesamte Queries: {analyzer.get_total_queries()}")
    print(f"Top Domains: {analyzer.get_top_domains(5)}")
