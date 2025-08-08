"""
JetDNS Analytics Manager
Erweiterte Statistiken, Reporting und Datenanalyse
"""

import asyncio
import csv
import json
import logging
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import aiofiles
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class QueryRecord:
    """DNS Query Record für Analytics"""
    timestamp: datetime
    client_ip: str
    domain: str
    qtype: str
    response_time: float
    status: str  # allowed, blocked, cached, nxdomain
    block_reason: str = ""
    upstream_server: str = ""
    client_group: str = ""
    category: str = ""

@dataclass
class ClientStats:
    """Client-spezifische Statistiken"""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    group_id: str = ""
    total_queries: int = 0
    blocked_queries: int = 0
    cached_queries: int = 0
    avg_response_time: float = 0.0
    top_domains: List[Tuple[str, int]] = None
    first_seen: datetime = None
    last_seen: datetime = None

    def __post_init__(self):
        if self.top_domains is None:
            self.top_domains = []

@dataclass
class DomainStats:
    """Domain-spezifische Statistiken"""
    domain: str
    query_count: int = 0
    unique_clients: int = 0
    block_count: int = 0
    cache_hit_rate: float = 0.0
    avg_response_time: float = 0.0
    categories: List[str] = None
    first_seen: datetime = None
    last_seen: datetime = None

    def __post_init__(self):
        if self.categories is None:
            self.categories = []

class AnalyticsManager:
    """Analytics und Reporting Manager"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = {}

        # Database
        self.db_path = Path("/var/lib/jetdns/analytics.db")
        self.db_connection = None

        # In-Memory Caches
        self.query_buffer: List[QueryRecord] = []
        self.client_cache: Dict[str, ClientStats] = {}
        self.domain_cache: Dict[str, DomainStats] = {}

        # Real-time stats
        self.realtime_stats = {
            'queries_total': 0,
            'queries_blocked': 0,
            'queries_cached': 0,
            'queries_per_second': 0,
            'avg_response_time': 0.0,
            'top_blocked_domains': [],
            'top_clients': [],
            'threat_detections': 0
        }

        # Aggregated data
        self.hourly_stats = defaultdict(lambda: {
            'queries': 0, 'blocked': 0, 'cached': 0, 'response_time': []
        })

        self.lock = asyncio.Lock()

    async def initialize(self):
        """Initialisiert Analytics Manager"""
        await self._load_config()

        if not self.config.get('enabled', True):
            logger.info("Analytics deaktiviert")
            return

        await self._setup_database()
        await self._load_cached_data()

        # Background tasks
        asyncio.create_task(self._buffer_flush_task())
        asyncio.create_task(self._stats_aggregation_task())
        asyncio.create_task(self._cleanup_task())

        if self.config.get('scheduled_reports', {}).get('enabled', False):
            asyncio.create_task(self._scheduled_reports_task())

        logger.info("📊 Analytics Manager initialisiert")

    async def _load_config(self):
        """Lädt Analytics Konfiguration"""
        self.config = self.config_manager.get_config('analytics')

    async def _setup_database(self):
        """Richtet SQLite Datenbank ein"""
        try:
            # Erstelle Verzeichnis falls nicht vorhanden
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            self.db_connection = sqlite3.connect(str(self.db_path))
            cursor = self.db_connection.cursor()

            # Query Records Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS query_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    client_ip TEXT,
                    domain TEXT,
                    qtype TEXT,
                    response_time REAL,
                    status TEXT,
                    block_reason TEXT,
                    upstream_server TEXT,
                    client_group TEXT,
                    category TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Hourly Stats Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hourly_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hour_timestamp DATETIME,
                    queries_total INTEGER,
                    queries_blocked INTEGER,
                    queries_cached INTEGER,
                    avg_response_time REAL,
                    unique_clients INTEGER,
                    unique_domains INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Client Stats Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS client_stats (
                    ip_address TEXT PRIMARY KEY,
                    hostname TEXT,
                    mac_address TEXT,
                    group_id TEXT,
                    total_queries INTEGER,
                    blocked_queries INTEGER,
                    cached_queries INTEGER,
                    avg_response_time REAL,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Domain Stats Tabelle
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domain_stats (
                    domain TEXT PRIMARY KEY,
                    query_count INTEGER,
                    unique_clients INTEGER,
                    block_count INTEGER,
                    cache_hit_rate REAL,
                    avg_response_time REAL,
                    categories TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Indizes für bessere Performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_timestamp ON query_records(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_client ON query_records(client_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_domain ON query_records(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hourly_timestamp ON hourly_stats(hour_timestamp)')

            self.db_connection.commit()
            logger.info("📊 Analytics Datenbank eingerichtet")

        except Exception as e:
            logger.error(f"Fehler bei Datenbank-Setup: {e}")
            raise

    async def _load_cached_data(self):
        """Lädt gecachte Daten aus Datenbank"""
        try:
            cursor = self.db_connection.cursor()

            # Lade Client Stats
            cursor.execute('SELECT * FROM client_stats')
            for row in cursor.fetchall():
                client_stats = ClientStats(
                    ip_address=row[0],
                    hostname=row[1] or "",
                    mac_address=row[2] or "",
                    group_id=row[3] or "",
                    total_queries=row[4],
                    blocked_queries=row[5],
                    cached_queries=row[6],
                    avg_response_time=row[7],
                    first_seen=datetime.fromisoformat(row[8]) if row[8] else None,
                    last_seen=datetime.fromisoformat(row[9]) if row[9] else None
                )
                self.client_cache[row[0]] = client_stats

            # Lade Domain Stats
            cursor.execute('SELECT * FROM domain_stats')
            for row in cursor.fetchall():
                domain_stats = DomainStats(
                    domain=row[0],
                    query_count=row[1],
                    unique_clients=row[2],
                    block_count=row[3],
                    cache_hit_rate=row[4],
                    avg_response_time=row[5],
                    categories=json.loads(row[6]) if row[6] else [],
                    first_seen=datetime.fromisoformat(row[7]) if row[7] else None,
                    last_seen=datetime.fromisoformat(row[8]) if row[8] else None
                )
                self.domain_cache[row[0]] = domain_stats

            logger.info(f"📊 {len(self.client_cache)} Client Stats und {len(self.domain_cache)} Domain Stats geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der cached Daten: {e}")

    async def log_query(self, query_record: QueryRecord):
        """Loggt DNS Query für Analytics"""
        if not self.config.get('data_collection', {}).get('query_logs', True):
            return

        async with self.lock:
            # Zu Buffer hinzufügen
            self.query_buffer.append(query_record)

            # Real-time Stats aktualisieren
            await self._update_realtime_stats(query_record)

            # Cache aktualisieren
            await self._update_client_cache(query_record)
            await self._update_domain_cache(query_record)

    async def _update_realtime_stats(self, record: QueryRecord):
        """Aktualisiert Real-time Statistiken"""
        self.realtime_stats['queries_total'] += 1

        if record.status == 'blocked':
            self.realtime_stats['queries_blocked'] += 1
        elif record.status == 'cached':
            self.realtime_stats['queries_cached'] += 1

        # Response Time aktualisieren (gleitender Durchschnitt)
        current_avg = self.realtime_stats['avg_response_time']
        total_queries = self.realtime_stats['queries_total']

        self.realtime_stats['avg_response_time'] = (
            (current_avg * (total_queries - 1) + record.response_time) / total_queries
        )

    async def _update_client_cache(self, record: QueryRecord):
        """Aktualisiert Client Cache"""
        ip = record.client_ip

        if ip not in self.client_cache:
            self.client_cache[ip] = ClientStats(
                ip_address=ip,
                group_id=record.client_group,
                first_seen=record.timestamp
            )

        client_stats = self.client_cache[ip]
        client_stats.total_queries += 1
        client_stats.last_seen = record.timestamp

        if record.status == 'blocked':
            client_stats.blocked_queries += 1
        elif record.status == 'cached':
            client_stats.cached_queries += 1

        # Response Time (gleitender Durchschnitt)
        if client_stats.total_queries > 1:
            client_stats.avg_response_time = (
                (client_stats.avg_response_time * (client_stats.total_queries - 1) + record.response_time) 
                / client_stats.total_queries
            )
        else:
            client_stats.avg_response_time = record.response_time

    async def _update_domain_cache(self, record: QueryRecord):
        """Aktualisiert Domain Cache"""
        domain = record.domain

        if domain not in self.domain_cache:
            self.domain_cache[domain] = DomainStats(
                domain=domain,
                first_seen=record.timestamp
            )

        domain_stats = self.domain_cache[domain]
        domain_stats.query_count += 1
        domain_stats.last_seen = record.timestamp

        if record.status == 'blocked':
            domain_stats.block_count += 1

        # Response Time (gleitender Durchschnitt)
        if domain_stats.query_count > 1:
            domain_stats.avg_response_time = (
                (domain_stats.avg_response_time * (domain_stats.query_count - 1) + record.response_time) 
                / domain_stats.query_count
            )
        else:
            domain_stats.avg_response_time = record.response_time

        # Kategorie hinzufügen
        if record.category and record.category not in domain_stats.categories:
            domain_stats.categories.append(record.category)

    async def _buffer_flush_task(self):
        """Schreibt Query Buffer regelmäßig in Datenbank"""
        while True:
            try:
                await asyncio.sleep(60)  # Minütlich

                if not self.query_buffer:
                    continue

                async with self.lock:
                    buffer_copy = self.query_buffer.copy()
                    self.query_buffer.clear()

                # Schreibe in Datenbank
                cursor = self.db_connection.cursor()

                for record in buffer_copy:
                    cursor.execute('''
                        INSERT INTO query_records (
                            timestamp, client_ip, domain, qtype, response_time,
                            status, block_reason, upstream_server, client_group, category
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        record.timestamp.isoformat(),
                        record.client_ip,
                        record.domain,
                        record.qtype,
                        record.response_time,
                        record.status,
                        record.block_reason,
                        record.upstream_server,
                        record.client_group,
                        record.category
                    ))

                self.db_connection.commit()

                if buffer_copy:
                    logger.debug(f"📊 {len(buffer_copy)} Query Records in Datenbank geschrieben")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler beim Buffer Flush: {e}")

    async def _stats_aggregation_task(self):
        """Aggregiert Statistiken stündlich"""
        while True:
            try:
                await asyncio.sleep(3600)  # Stündlich

                now = datetime.now()
                hour_start = now.replace(minute=0, second=0, microsecond=0)
                hour_end = hour_start + timedelta(hours=1)

                await self._aggregate_hourly_stats(hour_start, hour_end)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Statistik-Aggregation: {e}")

    async def _aggregate_hourly_stats(self, hour_start: datetime, hour_end: datetime):
        """Aggregiert Statistiken für eine Stunde"""
        try:
            cursor = self.db_connection.cursor()

            # Query-Statistiken für die Stunde
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_queries,
                    SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_queries,
                    SUM(CASE WHEN status = 'cached' THEN 1 ELSE 0 END) as cached_queries,
                    AVG(response_time) as avg_response_time,
                    COUNT(DISTINCT client_ip) as unique_clients,
                    COUNT(DISTINCT domain) as unique_domains
                FROM query_records 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (hour_start.isoformat(), hour_end.isoformat()))

            result = cursor.fetchone()

            if result and result[0] > 0:  # Nur wenn Queries vorhanden
                cursor.execute('''
                    INSERT OR REPLACE INTO hourly_stats (
                        hour_timestamp, queries_total, queries_blocked, queries_cached,
                        avg_response_time, unique_clients, unique_domains
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    hour_start.isoformat(),
                    result[0],
                    result[1],
                    result[2],
                    result[3] or 0,
                    result[4],
                    result[5]
                ))

                self.db_connection.commit()
                logger.debug(f"📊 Stündliche Statistiken aggregiert: {hour_start}")

        except Exception as e:
            logger.error(f"Fehler bei stündlicher Aggregation: {e}")

    async def get_dashboard_stats(self) -> Dict:
        """Gibt Dashboard-Statistiken zurück"""
        try:
            # Aktuelle Real-time Stats
            stats = self.realtime_stats.copy()

            # Top Blocked Domains (letzte 24h)
            cursor = self.db_connection.cursor()
            cursor.execute('''
                SELECT domain, COUNT(*) as count
                FROM query_records 
                WHERE status = 'blocked' AND timestamp >= ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
            ''', ((datetime.now() - timedelta(days=1)).isoformat(),))

            stats['top_blocked_domains'] = [
                {'domain': row[0], 'count': row[1]} 
                for row in cursor.fetchall()
            ]

            # Top Clients (letzte 24h)
            cursor.execute('''
                SELECT client_ip, COUNT(*) as count
                FROM query_records 
                WHERE timestamp >= ?
                GROUP BY client_ip
                ORDER BY count DESC
                LIMIT 10
            ''', ((datetime.now() - timedelta(days=1)).isoformat(),))

            stats['top_clients'] = [
                {
                    'ip': row[0], 
                    'queries': row[1],
                    'hostname': self.client_cache.get(row[0], ClientStats(row[0])).hostname
                } 
                for row in cursor.fetchall()
            ]

            # Queries per Second (letzte Minute)
            cursor.execute('''
                SELECT COUNT(*) FROM query_records 
                WHERE timestamp >= ?
            ''', ((datetime.now() - timedelta(minutes=1)).isoformat(),))

            recent_queries = cursor.fetchone()[0]
            stats['queries_per_second'] = round(recent_queries / 60, 2)

            return stats

        except Exception as e:
            logger.error(f"Fehler bei Dashboard-Statistiken: {e}")
            return self.realtime_stats.copy()

    async def get_time_series_data(self, hours: int = 24) -> Dict:
        """Gibt Zeitreihen-Daten für Charts zurück"""
        try:
            cursor = self.db_connection.cursor()

            start_time = datetime.now() - timedelta(hours=hours)

            cursor.execute('''
                SELECT 
                    hour_timestamp,
                    queries_total,
                    queries_blocked,
                    queries_cached,
                    avg_response_time
                FROM hourly_stats 
                WHERE hour_timestamp >= ?
                ORDER BY hour_timestamp
            ''', (start_time.isoformat(),))

            results = cursor.fetchall()

            timestamps = []
            queries = []
            blocked = []
            cached = []
            response_times = []

            for row in results:
                timestamps.append(row[0])
                queries.append(row[1])
                blocked.append(row[2])
                cached.append(row[3])
                response_times.append(row[4])

            return {
                'timestamps': timestamps,
                'queries': queries,
                'blocked': blocked,
                'cached': cached,
                'response_times': response_times
            }

        except Exception as e:
            logger.error(f"Fehler bei Zeitreihen-Daten: {e}")
            return {
                'timestamps': [], 'queries': [], 'blocked': [], 
                'cached': [], 'response_times': []
            }

    async def get_client_report(self, client_ip: str, days: int = 7) -> Dict:
        """Erstellt detaillierten Client-Report"""
        try:
            cursor = self.db_connection.cursor()
            start_time = datetime.now() - timedelta(days=days)

            # Basis-Statistiken
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_queries,
                    SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_queries,
                    SUM(CASE WHEN status = 'cached' THEN 1 ELSE 0 END) as cached_queries,
                    AVG(response_time) as avg_response_time
                FROM query_records 
                WHERE client_ip = ? AND timestamp >= ?
            ''', (client_ip, start_time.isoformat()))

            stats = cursor.fetchone()

            # Top Domains
            cursor.execute('''
                SELECT domain, COUNT(*) as count, 
                       SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count
                FROM query_records 
                WHERE client_ip = ? AND timestamp >= ?
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 20
            ''', (client_ip, start_time.isoformat()))

            top_domains = [
                {'domain': row[0], 'queries': row[1], 'blocked': row[2]}
                for row in cursor.fetchall()
            ]

            # Stündliche Aktivität
            cursor.execute('''
                SELECT 
                    strftime('%H', timestamp) as hour,
                    COUNT(*) as count
                FROM query_records 
                WHERE client_ip = ? AND timestamp >= ?
                GROUP BY hour
                ORDER BY hour
            ''', (client_ip, start_time.isoformat()))

            hourly_activity = {row[0]: row[1] for row in cursor.fetchall()}

            client_info = self.client_cache.get(client_ip, ClientStats(client_ip))

            return {
                'client_ip': client_ip,
                'hostname': client_info.hostname,
                'mac_address': client_info.mac_address,
                'group_id': client_info.group_id,
                'period_days': days,
                'total_queries': stats[0] if stats else 0,
                'blocked_queries': stats[1] if stats else 0,
                'cached_queries': stats[2] if stats else 0,
                'avg_response_time': round(stats[3] or 0, 3),
                'block_rate': round((stats[1] / stats[0] * 100) if stats and stats[0] > 0 else 0, 2),
                'cache_hit_rate': round((stats[2] / stats[0] * 100) if stats and stats[0] > 0 else 0, 2),
                'top_domains': top_domains,
                'hourly_activity': hourly_activity
            }

        except Exception as e:
            logger.error(f"Fehler bei Client-Report für {client_ip}: {e}")
            return {'error': str(e)}

    async def export_data(self, format: str = 'csv', days: int = 7, 
                         client_ip: str = None) -> str:
        """Exportiert Analytics-Daten"""
        try:
            cursor = self.db_connection.cursor()
            start_time = datetime.now() - timedelta(days=days)

            # Query zusammenbauen
            query = '''
                SELECT timestamp, client_ip, domain, qtype, response_time, 
                       status, block_reason, upstream_server, client_group, category
                FROM query_records 
                WHERE timestamp >= ?
            '''
            params = [start_time.isoformat()]

            if client_ip:
                query += ' AND client_ip = ?'
                params.append(client_ip)

            query += ' ORDER BY timestamp DESC'

            cursor.execute(query, params)
            results = cursor.fetchall()

            if format.lower() == 'csv':
                output = StringIO()
                writer = csv.writer(output)

                # Header
                writer.writerow([
                    'Timestamp', 'Client IP', 'Domain', 'Query Type', 'Response Time (ms)',
                    'Status', 'Block Reason', 'Upstream Server', 'Client Group', 'Category'
                ])

                # Daten
                for row in results:
                    writer.writerow([
                        row[0], row[1], row[2], row[3], f"{row[4]*1000:.1f}",
                        row[5], row[6] or '', row[7] or '', row[8] or '', row[9] or ''
                    ])

                return output.getvalue()

            elif format.lower() == 'json':
                data = []
                for row in results:
                    data.append({
                        'timestamp': row[0],
                        'client_ip': row[1],
                        'domain': row[2],
                        'qtype': row[3],
                        'response_time_ms': round(row[4] * 1000, 1),
                        'status': row[5],
                        'block_reason': row[6] or '',
                        'upstream_server': row[7] or '',
                        'client_group': row[8] or '',
                        'category': row[9] or ''
                    })

                return json.dumps(data, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.error(f"Fehler beim Datenexport: {e}")
            return json.dumps({'error': str(e)}, indent=2)

    async def _cleanup_task(self):
        """Bereinigt alte Daten"""
        while True:
            try:
                await asyncio.sleep(86400)  # Täglich

                retention_days = self.config.get('retention_days', 90)
                cutoff_date = datetime.now() - timedelta(days=retention_days)

                cursor = self.db_connection.cursor()

                # Lösche alte Query Records
                cursor.execute(
                    'DELETE FROM query_records WHERE timestamp < ?',
                    (cutoff_date.isoformat(),)
                )

                deleted_queries = cursor.rowcount

                # Lösche alte Hourly Stats (behalte länger)
                hourly_cutoff = datetime.now() - timedelta(days=retention_days * 2)
                cursor.execute(
                    'DELETE FROM hourly_stats WHERE hour_timestamp < ?',
                    (hourly_cutoff.isoformat(),)
                )

                deleted_hourly = cursor.rowcount

                self.db_connection.commit()

                if deleted_queries > 0 or deleted_hourly > 0:
                    logger.info(f"📊 Analytics Bereinigung: {deleted_queries} Query Records, {deleted_hourly} Hourly Stats gelöscht")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Analytics-Bereinigung: {e}")

    async def _scheduled_reports_task(self):
        """Erstellt geplante Reports"""
        while True:
            try:
                frequency = self.config.get('scheduled_reports', {}).get('frequency', 'weekly')

                if frequency == 'daily':
                    await asyncio.sleep(86400)  # 24 Stunden
                elif frequency == 'weekly':
                    await asyncio.sleep(604800)  # 7 Tage
                else:  # monthly
                    await asyncio.sleep(2592000)  # 30 Tage

                # Erstelle Report
                await self._generate_scheduled_report(frequency)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei geplanten Reports: {e}")

    async def _generate_scheduled_report(self, frequency: str):
        """Generiert geplanten Report"""
        try:
            if frequency == 'daily':
                days = 1
            elif frequency == 'weekly':
                days = 7
            else:  # monthly
                days = 30

            # Basis-Statistiken
            dashboard_stats = await self.get_dashboard_stats()

            # Time Series Daten
            time_series = await self.get_time_series_data(hours=days*24)

            report = {
                'period': frequency,
                'generated_at': datetime.now().isoformat(),
                'summary': dashboard_stats,
                'time_series': time_series
            }

            # Report speichern/senden würde hier implementiert
            logger.info(f"📊 {frequency.capitalize()} Report generiert")

        except Exception as e:
            logger.error(f"Fehler bei Report-Generierung: {e}")

    async def get_analytics_summary(self) -> Dict:
        """Gibt Analytics-Zusammenfassung zurück"""
        return {
            'enabled': self.config.get('enabled', True),
            'retention_days': self.config.get('retention_days', 90),
            'buffer_size': len(self.query_buffer),
            'cached_clients': len(self.client_cache),
            'cached_domains': len(self.domain_cache),
            'realtime_stats': self.realtime_stats
        }

    def close(self):
        """Schließt Datenbank-Verbindung"""
        if self.db_connection:
            self.db_connection.close()
            logger.info("📊 Analytics Datenbank geschlossen")
