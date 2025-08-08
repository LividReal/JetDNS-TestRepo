"""
Advanced Statistics and Analytics Engine
Comprehensive DNS query analysis, threat tracking, and performance monitoring
"""

import asyncio
import logging
import sqlite3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading
import os

try:
    import pandas as pd
    import numpy as np
    ANALYTICS_AVAILABLE = True
except ImportError:
    ANALYTICS_AVAILABLE = False


@dataclass
class QueryLog:
    timestamp: float
    query_id: str
    client_ip: str
    domain: str
    query_type: str
    response_type: str
    response_time: float
    upstream_server: Optional[str] = None
    blocked_reason: Optional[str] = None
    threat_level: Optional[str] = None
    cache_hit: bool = False
    client_subnet: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class ThreatEvent:
    timestamp: float
    domain: str
    client_ip: str
    threat_type: str
    threat_level: str
    threat_score: float
    blocked: bool
    source: str
    additional_data: Dict[str, Any]


@dataclass
class NetworkClient:
    ip: str
    first_seen: float
    last_seen: float
    query_count: int
    blocked_count: int
    top_domains: List[str]
    threat_score: float
    client_type: str  # desktop, mobile, server, etc.
    hostname: Optional[str] = None


class AdvancedStatisticsManager:
    """Comprehensive statistics and analytics engine"""

    def __init__(self, db_config: dict, analytics_config: dict):
        self.db_config = db_config
        self.analytics_config = analytics_config
        self.logger = logging.getLogger(__name__)

        # Database
        self.db_path = db_config.get('path', 'data/dns_statistics.db')
        self.connection = None

        # In-memory data structures for performance
        self.recent_queries = deque(maxlen=10000)  # Last 10k queries
        self.query_stats = {
            'total': 0,
            'blocked': 0,
            'cached': 0,
            'forwarded': 0,
            'threats': 0
        }

        # Time-series data (last 24 hours)
        self.hourly_stats = defaultdict(lambda: {'total': 0, 'blocked': 0, 'cached': 0})

        # Client tracking
        self.active_clients = {}  # ip -> NetworkClient

        # Domain statistics
        self.domain_stats = defaultdict(lambda: {'count': 0, 'blocked': 0, 'first_seen': time.time()})

        # Threat tracking
        self.recent_threats = deque(maxlen=1000)
        self.threat_categories = defaultdict(int)

        # Performance metrics
        self.response_times = deque(maxlen=1000)
        self.performance_history = []

        # Background tasks
        self.stats_lock = threading.RLock()
        self.cleanup_task = None
        self.aggregation_task = None

        # Real-time analytics
        self.realtime_enabled = analytics_config.get('realtime', True)
        self.retention_days = analytics_config.get('retention_days', 30)

    async def initialize(self):
        """Initialize statistics manager"""
        try:
            # Create database tables
            await self._create_database_schema()

            # Load recent data into memory
            await self._load_recent_data()

            # Start background tasks
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            self.aggregation_task = asyncio.create_task(self._aggregation_loop())

            self.logger.info("📊 Statistics Manager initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize statistics manager: {e}")
            raise

    async def log_query(self, dns_query, dns_response, response_time: float):
        """Log DNS query with comprehensive details"""
        try:
            # Create query log entry
            query_log = QueryLog(
                timestamp=time.time(),
                query_id=f"{dns_query.query_id}_{int(time.time() * 1000000)}",
                client_ip=dns_query.client_ip,
                domain=dns_query.domain,
                query_type=dns_query.qtype,
                response_type=dns_response.response_type.value,
                response_time=response_time,
                upstream_server=dns_response.upstream_server,
                blocked_reason=dns_response.blocked_reason,
                cache_hit=dns_response.cache_hit,
                client_subnet=dns_query.client_subnet,
                user_agent=dns_query.user_agent
            )

            # Add to recent queries
            with self.stats_lock:
                self.recent_queries.append(query_log)

                # Update statistics
                self.query_stats['total'] += 1

                if dns_response.response_type.value == 'blocked':
                    self.query_stats['blocked'] += 1
                elif dns_response.response_type.value == 'cached':
                    self.query_stats['cached'] += 1
                elif dns_response.response_type.value == 'answer':
                    self.query_stats['forwarded'] += 1

                # Update domain statistics
                domain_stat = self.domain_stats[dns_query.domain]
                domain_stat['count'] += 1
                if dns_response.response_type.value == 'blocked':
                    domain_stat['blocked'] += 1

                # Update client statistics
                await self._update_client_stats(dns_query, dns_response)

                # Update hourly statistics
                hour_key = int(time.time() // 3600)
                hourly = self.hourly_stats[hour_key]
                hourly['total'] += 1
                if dns_response.response_type.value == 'blocked':
                    hourly['blocked'] += 1
                elif dns_response.response_type.value == 'cached':
                    hourly['cached'] += 1

                # Track response time
                self.response_times.append(response_time)

            # Store in database (async)
            asyncio.create_task(self._store_query_log(query_log))

        except Exception as e:
            self.logger.error(f"Error logging query: {e}")

    async def log_threat(self, domain: str, client_ip: str, threat_data: Dict):
        """Log threat detection event"""
        try:
            threat_event = ThreatEvent(
                timestamp=time.time(),
                domain=domain,
                client_ip=client_ip,
                threat_type=threat_data.get('threat_type', 'unknown'),
                threat_level=threat_data.get('threat_level', 'low'),
                threat_score=threat_data.get('threat_score', 0.0),
                blocked=threat_data.get('blocked', False),
                source=threat_data.get('source', 'internal'),
                additional_data=threat_data.get('additional_data', {})
            )

            with self.stats_lock:
                self.recent_threats.append(threat_event)
                self.threat_categories[threat_event.threat_type] += 1

                if threat_event.blocked:
                    self.query_stats['threats'] += 1

            # Store in database
            asyncio.create_task(self._store_threat_event(threat_event))

            self.logger.info(f"🚨 Threat logged: {domain} ({threat_event.threat_type})")

        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")

    async def get_recent_queries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent DNS queries"""
        try:
            with self.stats_lock:
                queries = list(self.recent_queries)[-limit:]

            return [self._query_log_to_dict(query) for query in reversed(queries)]

        except Exception as e:
            self.logger.error(f"Error getting recent queries: {e}")
            return []

    async def get_top_domains(self, limit: int = 20, period_hours: int = 24) -> List[Dict[str, Any]]:
        """Get top queried domains"""
        try:
            # Get from database for accuracy
            query = """
                SELECT domain, COUNT(*) as count, 
                       SUM(CASE WHEN response_type = 'blocked' THEN 1 ELSE 0 END) as blocked_count
                FROM query_logs 
                WHERE timestamp > ? 
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            """

            cutoff_time = time.time() - (period_hours * 3600)

            async with self._get_db_connection() as conn:
                cursor = conn.execute(query, (cutoff_time, limit))
                rows = cursor.fetchall()

                return [
                    {
                        'domain': row[0],
                        'count': row[1],
                        'blocked_count': row[2],
                        'block_rate': (row[2] / row[1] * 100) if row[1] > 0 else 0,
                        'category': await self._get_domain_category(row[0])
                    }
                    for row in rows
                ]

        except Exception as e:
            self.logger.error(f"Error getting top domains: {e}")
            # Fallback to in-memory data
            with self.stats_lock:
                sorted_domains = sorted(
                    self.domain_stats.items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )[:limit]

                return [
                    {
                        'domain': domain,
                        'count': stats['count'],
                        'blocked_count': stats['blocked'],
                        'block_rate': (stats['blocked'] / stats['count'] * 100) if stats['count'] > 0 else 0,
                        'category': 'Unknown'
                    }
                    for domain, stats in sorted_domains
                ]

    async def get_top_blocked(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top blocked domains"""
        try:
            query = """
                SELECT domain, COUNT(*) as count,
                       AVG(CASE WHEN threat_level IS NOT NULL THEN 1 ELSE 0 END) as threat_rate
                FROM query_logs 
                WHERE response_type = 'blocked' 
                AND timestamp > ?
                GROUP BY domain 
                ORDER BY count DESC 
                LIMIT ?
            """

            cutoff_time = time.time() - (24 * 3600)  # Last 24 hours

            async with self._get_db_connection() as conn:
                cursor = conn.execute(query, (cutoff_time, limit))
                rows = cursor.fetchall()

                return [
                    {
                        'domain': row[0],
                        'count': row[1],
                        'threat_rate': row[2] * 100,
                        'category': await self._get_domain_category(row[0]),
                        'block_reason': await self._get_common_block_reason(row[0])
                    }
                    for row in rows
                ]

        except Exception as e:
            self.logger.error(f"Error getting top blocked domains: {e}")
            return []

    async def get_threat_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get threat detection timeline"""
        try:
            query = """
                SELECT 
                    datetime((timestamp / 3600) * 3600, 'unixepoch') as hour,
                    threat_type,
                    threat_level,
                    COUNT(*) as count
                FROM threat_events 
                WHERE timestamp > ?
                GROUP BY hour, threat_type, threat_level
                ORDER BY hour DESC
            """

            cutoff_time = time.time() - (hours * 3600)

            async with self._get_db_connection() as conn:
                cursor = conn.execute(query, (cutoff_time,))
                rows = cursor.fetchall()

                # Group by hour
                timeline = defaultdict(lambda: {'total': 0, 'by_type': defaultdict(int), 'by_level': defaultdict(int)})

                for row in rows:
                    hour = row[0]
                    threat_type = row[1]
                    threat_level = row[2]
                    count = row[3]

                    timeline[hour]['total'] += count
                    timeline[hour]['by_type'][threat_type] += count
                    timeline[hour]['by_level'][threat_level] += count

                return [
                    {
                        'timestamp': hour,
                        'total_threats': data['total'],
                        'threat_types': dict(data['by_type']),
                        'threat_levels': dict(data['by_level'])
                    }
                    for hour, data in sorted(timeline.items())
                ]

        except Exception as e:
            self.logger.error(f"Error getting threat timeline: {e}")
            return []

    async def get_network_topology(self) -> Dict[str, Any]:
        """Get network topology data for visualization"""
        try:
            topology = {
                'nodes': [],
                'links': [],
                'subnets': []
            }

            with self.stats_lock:
                # Add client nodes
                for ip, client in self.active_clients.items():
                    subnet = '.'.join(ip.split('.')[:3]) + '.0/24'

                    topology['nodes'].append({
                        'id': ip,
                        'type': 'client',
                        'label': client.hostname or ip,
                        'subnet': subnet,
                        'query_count': client.query_count,
                        'blocked_count': client.blocked_count,
                        'threat_score': client.threat_score,
                        'client_type': client.client_type,
                        'last_seen': client.last_seen
                    })

                # Group by subnet
                subnets = defaultdict(list)
                for ip in self.active_clients:
                    subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                    subnets[subnet].append(ip)

                # Add subnet information
                for subnet, ips in subnets.items():
                    total_queries = sum(self.active_clients[ip].query_count for ip in ips)
                    total_blocked = sum(self.active_clients[ip].blocked_count for ip in ips)
                    avg_threat_score = sum(self.active_clients[ip].threat_score for ip in ips) / len(ips)

                    topology['subnets'].append({
                        'subnet': subnet,
                        'client_count': len(ips),
                        'total_queries': total_queries,
                        'total_blocked': total_blocked,
                        'avg_threat_score': avg_threat_score
                    })

            return topology

        except Exception as e:
            self.logger.error(f"Error getting network topology: {e}")
            return {'nodes': [], 'links': [], 'subnets': []}

    async def get_analytics(self) -> Dict[str, Any]:
        """Get comprehensive analytics data"""
        try:
            current_time = time.time()

            # Calculate averages and rates
            total_queries = self.query_stats['total']
            avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

            analytics = {
                'queries_total': total_queries,
                'queries_blocked': self.query_stats['blocked'],
                'queries_cached': self.query_stats['cached'],
                'queries_forwarded': self.query_stats['forwarded'],
                'threats_detected': self.query_stats['threats'],
                'unique_clients': len(self.active_clients),
                'unique_domains': len(self.domain_stats),
                'average_response_time': avg_response_time,
                'cache_hit_rate': (self.query_stats['cached'] / max(total_queries, 1)) * 100,
                'block_rate': (self.query_stats['blocked'] / max(total_queries, 1)) * 100,
                'threat_rate': (self.query_stats['threats'] / max(total_queries, 1)) * 100,
            }

            # Add time-series data
            analytics['hourly_data'] = await self._get_hourly_timeline()

            # Add top threat categories
            with self.stats_lock:
                analytics['top_threat_categories'] = [
                    {'category': category, 'count': count}
                    for category, count in sorted(self.threat_categories.items(), 
                                                key=lambda x: x[1], reverse=True)[:10]
                ]

            return analytics

        except Exception as e:
            self.logger.error(f"Error getting analytics: {e}")
            return {}

    async def get_query_details(self, query_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific query"""
        try:
            query = """
                SELECT * FROM query_logs WHERE query_id = ?
            """

            async with self._get_db_connection() as conn:
                cursor = conn.execute(query, (query_id,))
                row = cursor.fetchone()

                if not row:
                    return {'found': False}

                # Convert to dictionary
                columns = [desc[0] for desc in cursor.description]
                query_data = dict(zip(columns, row))

                # Add additional context
                query_data['found'] = True
                query_data['timestamp_formatted'] = datetime.fromtimestamp(
                    query_data['timestamp']
                ).strftime('%Y-%m-%d %H:%M:%S')

                # Get related queries from same client
                related_query = """
                    SELECT domain, response_type, COUNT(*) as count
                    FROM query_logs 
                    WHERE client_ip = ? 
                    AND timestamp BETWEEN ? AND ?
                    AND query_id != ?
                    GROUP BY domain, response_type
                    ORDER BY count DESC
                    LIMIT 10
                """

                time_window = 3600  # 1 hour
                cursor = conn.execute(related_query, (
                    query_data['client_ip'],
                    query_data['timestamp'] - time_window,
                    query_data['timestamp'] + time_window,
                    query_id
                ))

                query_data['related_queries'] = [
                    {'domain': row[0], 'response_type': row[1], 'count': row[2]}
                    for row in cursor.fetchall()
                ]

                return query_data

        except Exception as e:
            self.logger.error(f"Error getting query details: {e}")
            return {'found': False, 'error': str(e)}

    async def get_threats_blocked_today(self) -> int:
        """Get number of threats blocked today"""
        try:
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_time = today_start.timestamp()

            with self.stats_lock:
                count = sum(
                    1 for threat in self.recent_threats
                    if threat.timestamp >= cutoff_time and threat.blocked
                )

            return count

        except Exception as e:
            self.logger.error(f"Error getting threats blocked today: {e}")
            return 0

    async def get_top_threat_categories(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top threat categories"""
        try:
            with self.stats_lock:
                return [
                    {'category': category.replace('_', ' ').title(), 'count': count}
                    for category, count in sorted(
                        self.threat_categories.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:limit]
                ]

        except Exception as e:
            self.logger.error(f"Error getting threat categories: {e}")
            return []

    async def get_total_queries_today(self) -> int:
        """Get total queries processed today"""
        try:
            today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            cutoff_time = today_start.timestamp()

            # Count from recent queries
            with self.stats_lock:
                count = sum(
                    1 for query in self.recent_queries
                    if query.timestamp >= cutoff_time
                )

            # If we don't have enough in memory, query database
            if len(self.recent_queries) < 10000:
                query = "SELECT COUNT(*) FROM query_logs WHERE timestamp >= ?"
                async with self._get_db_connection() as conn:
                    cursor = conn.execute(query, (cutoff_time,))
                    db_count = cursor.fetchone()[0]
                    return db_count

            return count

        except Exception as e:
            self.logger.error(f"Error getting total queries today: {e}")
            return 0

    # Private methods
    async def _create_database_schema(self):
        """Create database schema"""
        try:
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

            async with self._get_db_connection() as conn:
                # Query logs table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS query_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        query_id TEXT UNIQUE NOT NULL,
                        client_ip TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        response_type TEXT NOT NULL,
                        response_time REAL NOT NULL,
                        upstream_server TEXT,
                        blocked_reason TEXT,
                        threat_level TEXT,
                        cache_hit BOOLEAN DEFAULT 0,
                        client_subnet TEXT,
                        user_agent TEXT
                    )
                ''')

                # Threat events table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        domain TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        threat_level TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        blocked BOOLEAN DEFAULT 0,
                        source TEXT NOT NULL,
                        additional_data TEXT
                    )
                ''')

                # Network clients table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS network_clients (
                        ip TEXT PRIMARY KEY,
                        hostname TEXT,
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        query_count INTEGER DEFAULT 0,
                        blocked_count INTEGER DEFAULT 0,
                        threat_score REAL DEFAULT 0,
                        client_type TEXT DEFAULT 'unknown'
                    )
                ''')

                # Hourly statistics table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS hourly_stats (
                        hour_timestamp INTEGER PRIMARY KEY,
                        total_queries INTEGER DEFAULT 0,
                        blocked_queries INTEGER DEFAULT 0,
                        cached_queries INTEGER DEFAULT 0,
                        forwarded_queries INTEGER DEFAULT 0,
                        unique_clients INTEGER DEFAULT 0,
                        unique_domains INTEGER DEFAULT 0,
                        avg_response_time REAL DEFAULT 0
                    )
                ''')

                # Create indexes
                conn.execute('CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_query_logs_client_ip ON query_logs(client_ip)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp)')

                conn.commit()

        except Exception as e:
            self.logger.error(f"Error creating database schema: {e}")
            raise

    async def _get_db_connection(self):
        """Get database connection with context manager"""
        class AsyncConnection:
            def __init__(self, db_path):
                self.db_path = db_path
                self.conn = None

            async def __aenter__(self):
                self.conn = sqlite3.connect(self.db_path)
                self.conn.row_factory = sqlite3.Row
                return self.conn

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                if self.conn:
                    self.conn.close()

        return AsyncConnection(self.db_path)

    async def _load_recent_data(self):
        """Load recent data into memory structures"""
        try:
            cutoff_time = time.time() - (24 * 3600)  # Last 24 hours

            async with self._get_db_connection() as conn:
                # Load recent queries
                cursor = conn.execute('''
                    SELECT * FROM query_logs 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC 
                    LIMIT 5000
                ''', (cutoff_time,))

                for row in cursor.fetchall():
                    query_log = QueryLog(
                        timestamp=row['timestamp'],
                        query_id=row['query_id'],
                        client_ip=row['client_ip'],
                        domain=row['domain'],
                        query_type=row['query_type'],
                        response_type=row['response_type'],
                        response_time=row['response_time'],
                        upstream_server=row['upstream_server'],
                        blocked_reason=row['blocked_reason'],
                        threat_level=row['threat_level'],
                        cache_hit=bool(row['cache_hit']),
                        client_subnet=row['client_subnet'],
                        user_agent=row['user_agent']
                    )

                    self.recent_queries.appendleft(query_log)

                    # Update statistics
                    self.query_stats['total'] += 1
                    if query_log.response_type == 'blocked':
                        self.query_stats['blocked'] += 1
                    elif query_log.response_type == 'cached':
                        self.query_stats['cached'] += 1
                    elif query_log.response_type == 'answer':
                        self.query_stats['forwarded'] += 1

                # Load network clients
                cursor = conn.execute('SELECT * FROM network_clients WHERE last_seen > ?', (cutoff_time,))
                for row in cursor.fetchall():
                    self.active_clients[row['ip']] = NetworkClient(
                        ip=row['ip'],
                        hostname=row['hostname'],
                        first_seen=row['first_seen'],
                        last_seen=row['last_seen'],
                        query_count=row['query_count'],
                        blocked_count=row['blocked_count'],
                        threat_score=row['threat_score'],
                        client_type=row['client_type'],
                        top_domains=[]  # Load separately if needed
                    )

            self.logger.info(f"📊 Loaded {len(self.recent_queries)} recent queries and {len(self.active_clients)} active clients")

        except Exception as e:
            self.logger.error(f"Error loading recent data: {e}")

    async def _store_query_log(self, query_log: QueryLog):
        """Store query log in database"""
        try:
            async with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO query_logs (
                        timestamp, query_id, client_ip, domain, query_type, 
                        response_type, response_time, upstream_server, blocked_reason, 
                        threat_level, cache_hit, client_subnet, user_agent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    query_log.timestamp, query_log.query_id, query_log.client_ip,
                    query_log.domain, query_log.query_type, query_log.response_type,
                    query_log.response_time, query_log.upstream_server,
                    query_log.blocked_reason, query_log.threat_level,
                    query_log.cache_hit, query_log.client_subnet, query_log.user_agent
                ))
                conn.commit()

        except Exception as e:
            self.logger.debug(f"Error storing query log: {e}")

    async def _store_threat_event(self, threat_event: ThreatEvent):
        """Store threat event in database"""
        try:
            async with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT INTO threat_events (
                        timestamp, domain, client_ip, threat_type, threat_level,
                        threat_score, blocked, source, additional_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    threat_event.timestamp, threat_event.domain, threat_event.client_ip,
                    threat_event.threat_type, threat_event.threat_level,
                    threat_event.threat_score, threat_event.blocked,
                    threat_event.source, json.dumps(threat_event.additional_data)
                ))
                conn.commit()

        except Exception as e:
            self.logger.debug(f"Error storing threat event: {e}")

    async def _update_client_stats(self, dns_query, dns_response):
        """Update client statistics"""
        try:
            client_ip = dns_query.client_ip
            current_time = time.time()

            if client_ip not in self.active_clients:
                self.active_clients[client_ip] = NetworkClient(
                    ip=client_ip,
                    first_seen=current_time,
                    last_seen=current_time,
                    query_count=0,
                    blocked_count=0,
                    top_domains=[],
                    threat_score=0.0,
                    client_type=self._detect_client_type(dns_query.user_agent)
                )

            client = self.active_clients[client_ip]
            client.last_seen = current_time
            client.query_count += 1

            if dns_response.response_type.value == 'blocked':
                client.blocked_count += 1
                client.threat_score += 0.1  # Small increase for blocked queries

            # Update top domains (simplified)
            if dns_query.domain not in client.top_domains:
                client.top_domains.append(dns_query.domain)
                if len(client.top_domains) > 10:
                    client.top_domains.pop(0)

        except Exception as e:
            self.logger.debug(f"Error updating client stats: {e}")

    def _detect_client_type(self, user_agent: Optional[str]) -> str:
        """Detect client type from user agent"""
        if not user_agent:
            return 'unknown'

        ua_lower = user_agent.lower()

        if 'mobile' in ua_lower or 'android' in ua_lower or 'iphone' in ua_lower:
            return 'mobile'
        elif 'server' in ua_lower or 'bot' in ua_lower or 'crawler' in ua_lower:
            return 'server'
        elif 'windows' in ua_lower or 'macintosh' in ua_lower or 'linux' in ua_lower:
            return 'desktop'
        else:
            return 'unknown'

    def _query_log_to_dict(self, query_log: QueryLog) -> Dict[str, Any]:
        """Convert QueryLog to dictionary"""
        return {
            'timestamp': query_log.timestamp,
            'query_id': query_log.query_id,
            'client_ip': query_log.client_ip,
            'domain': query_log.domain,
            'type': query_log.query_type,
            'status': query_log.response_type,
            'response_time': query_log.response_time,
            'upstream_server': query_log.upstream_server,
            'blocked_reason': query_log.blocked_reason,
            'threat_level': query_log.threat_level,
            'cache_hit': query_log.cache_hit
        }

    async def _get_domain_category(self, domain: str) -> str:
        """Get domain category (placeholder)"""
        # This would integrate with content filtering system
        return 'Unknown'

    async def _get_common_block_reason(self, domain: str) -> Optional[str]:
        """Get most common block reason for domain"""
        try:
            query = """
                SELECT blocked_reason, COUNT(*) as count
                FROM query_logs 
                WHERE domain = ? AND blocked_reason IS NOT NULL
                GROUP BY blocked_reason
                ORDER BY count DESC
                LIMIT 1
            """

            async with self._get_db_connection() as conn:
                cursor = conn.execute(query, (domain,))
                row = cursor.fetchone()
                return row[0] if row else None

        except Exception as e:
            self.logger.debug(f"Error getting block reason: {e}")
            return None

    async def _get_hourly_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get hourly timeline data"""
        try:
            timeline = []
            current_hour = int(time.time() // 3600)

            for i in range(hours):
                hour_key = current_hour - i
                hourly_data = self.hourly_stats.get(hour_key, {'total': 0, 'blocked': 0, 'cached': 0})

                timeline.append({
                    'hour': datetime.fromtimestamp(hour_key * 3600).strftime('%H:%M'),
                    'total': hourly_data['total'],
                    'blocked': hourly_data['blocked'],
                    'cached': hourly_data['cached'],
                    'forwarded': hourly_data['total'] - hourly_data['blocked'] - hourly_data['cached']
                })

            return list(reversed(timeline))

        except Exception as e:
            self.logger.error(f"Error getting hourly timeline: {e}")
            return []

    # Background tasks
    async def _cleanup_loop(self):
        """Background cleanup task"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour

                # Clean old data from database
                cutoff_time = time.time() - (self.retention_days * 24 * 3600)

                async with self._get_db_connection() as conn:
                    # Clean old query logs
                    cursor = conn.execute('DELETE FROM query_logs WHERE timestamp < ?', (cutoff_time,))
                    deleted_queries = cursor.rowcount

                    # Clean old threat events
                    cursor = conn.execute('DELETE FROM threat_events WHERE timestamp < ?', (cutoff_time,))
                    deleted_threats = cursor.rowcount

                    # Clean old hourly stats
                    hour_cutoff = int(cutoff_time // 3600)
                    cursor = conn.execute('DELETE FROM hourly_stats WHERE hour_timestamp < ?', (hour_cutoff,))

                    conn.commit()

                    if deleted_queries > 0 or deleted_threats > 0:
                        self.logger.info(f"🧹 Cleaned {deleted_queries} old queries, {deleted_threats} old threats")

            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")

    async def _aggregation_loop(self):
        """Background aggregation task"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                # Update network clients in database
                async with self._get_db_connection() as conn:
                    with self.stats_lock:
                        for ip, client in self.active_clients.items():
                            conn.execute('''
                                INSERT OR REPLACE INTO network_clients 
                                (ip, hostname, first_seen, last_seen, query_count, 
                                 blocked_count, threat_score, client_type)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                client.ip, client.hostname, client.first_seen,
                                client.last_seen, client.query_count,
                                client.blocked_count, client.threat_score, client.client_type
                            ))

                    conn.commit()

            except Exception as e:
                self.logger.error(f"Aggregation loop error: {e}")

    async def start_collection(self):
        """Start statistics collection (placeholder for main.py)"""
        # This is called from main.py to indicate stats collection is active
        pass

    async def stop(self):
        """Stop statistics manager"""
        try:
            if self.cleanup_task:
                self.cleanup_task.cancel()
            if self.aggregation_task:
                self.aggregation_task.cancel()

            self.logger.info("🛑 Statistics Manager stopped")

        except Exception as e:
            self.logger.error(f"Error stopping statistics manager: {e}")
