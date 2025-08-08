"""
JetDNS PowerDNS-Compatible Backend System
Multi-Backend Support für verschiedene Datenquellen wie PowerDNS
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import dns.rdatatype
import dns.rdataclass
import dns.name

logger = logging.getLogger(__name__)

class BackendType(Enum):
    """Backend Types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    CASSANDRA = "cassandra"
    ORACLE = "oracle"
    LDAP = "ldap"
    BIND = "bind"
    LUA = "lua"
    PIPE = "pipe"
    REMOTE = "remote"
    REDIS = "redis"
    ETCD = "etcd"
    CONSUL = "consul"

@dataclass
class DNSRecord:
    """DNS Record Representation"""
    name: str
    type: str
    content: str
    ttl: int = 300
    priority: int = 0
    disabled: bool = False
    auth: bool = True
    ordername: str = ""
    domain_id: Optional[int] = None
    change_date: Optional[int] = None

@dataclass
class DNSDomain:
    """DNS Domain Representation"""
    name: str
    type: str = "NATIVE"  # NATIVE, MASTER, SLAVE
    master: str = ""
    last_check: Optional[int] = None
    notified_serial: Optional[int] = None
    account: str = ""
    options: str = ""
    catalog: str = ""

class DNSBackend(ABC):
    """Abstract DNS Backend Interface"""

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize backend connection"""
        pass

    @abstractmethod
    async def lookup(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records"""
        pass

    @abstractmethod
    async def list(self, domain_id: int, include_disabled: bool = False) -> List[DNSRecord]:
        """List all records in domain"""
        pass

    @abstractmethod
    async def get_domains(self) -> List[DNSDomain]:
        """Get all domains"""
        pass

    @abstractmethod
    async def create_domain(self, domain: DNSDomain) -> bool:
        """Create new domain"""
        pass

    @abstractmethod
    async def delete_domain(self, domain_name: str) -> bool:
        """Delete domain"""
        pass

class MySQLBackend(DNSBackend):
    """MySQL Backend (PowerDNS-compatible)"""

    def __init__(self, config: Dict):
        self.config = config
        self.pool = None
        self.connection = None

    async def initialize(self) -> bool:
        """Initialize MySQL connection"""
        try:
            import mysql.connector.pooling

            mysql_config = {
                'host': self.config.get('host', 'localhost'),
                'port': self.config.get('port', 3306),
                'user': self.config.get('user', 'powerdns'),
                'password': self.config.get('password', ''),
                'database': self.config.get('database', 'powerdns'),
                'pool_name': 'jetdns_pool',
                'pool_size': self.config.get('pool_size', 10),
                'pool_reset_session': True,
                'autocommit': True
            }

            self.pool = mysql.connector.pooling.MySQLConnectionPool(**mysql_config)

            # Test connection
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()

            logger.info("MySQL Backend initialisiert")
            return True

        except Exception as e:
            logger.error(f"MySQL Backend Initialisierung fehlgeschlagen: {e}")
            return False

    async def lookup(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records from MySQL"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)

                # PowerDNS-kompatible Query
                if qtype == "ANY":
                    query = """
                        SELECT r.name, r.type, r.content, r.ttl, r.prio as priority,
                               r.disabled, r.auth, r.ordername, r.domain_id, r.change_date
                        FROM records r
                        JOIN domains d ON r.domain_id = d.id
                        WHERE r.name = %s AND r.disabled = 0
                        ORDER BY r.type, r.prio
                    """
                    cursor.execute(query, (qname,))
                else:
                    query = """
                        SELECT r.name, r.type, r.content, r.ttl, r.prio as priority,
                               r.disabled, r.auth, r.ordername, r.domain_id, r.change_date
                        FROM records r
                        JOIN domains d ON r.domain_id = d.id
                        WHERE r.name = %s AND r.type = %s AND r.disabled = 0
                        ORDER BY r.prio
                    """
                    cursor.execute(query, (qname, qtype))

                results = cursor.fetchall()

                return [
                    DNSRecord(
                        name=row['name'],
                        type=row['type'],
                        content=row['content'],
                        ttl=row['ttl'],
                        priority=row['priority'] or 0,
                        disabled=bool(row['disabled']),
                        auth=bool(row['auth']),
                        ordername=row['ordername'] or "",
                        domain_id=row['domain_id'],
                        change_date=row['change_date']
                    )
                    for row in results
                ]

        except Exception as e:
            logger.error(f"MySQL lookup error: {e}")
            return []

    async def list(self, domain_id: int, include_disabled: bool = False) -> List[DNSRecord]:
        """List all records in domain"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)

                if include_disabled:
                    query = """
                        SELECT name, type, content, ttl, prio as priority,
                               disabled, auth, ordername, domain_id, change_date
                        FROM records
                        WHERE domain_id = %s
                        ORDER BY name, type, prio
                    """
                else:
                    query = """
                        SELECT name, type, content, ttl, prio as priority,
                               disabled, auth, ordername, domain_id, change_date
                        FROM records
                        WHERE domain_id = %s AND disabled = 0
                        ORDER BY name, type, prio
                    """

                cursor.execute(query, (domain_id,))
                results = cursor.fetchall()

                return [
                    DNSRecord(
                        name=row['name'],
                        type=row['type'],
                        content=row['content'],
                        ttl=row['ttl'],
                        priority=row['priority'] or 0,
                        disabled=bool(row['disabled']),
                        auth=bool(row['auth']),
                        ordername=row['ordername'] or "",
                        domain_id=row['domain_id'],
                        change_date=row['change_date']
                    )
                    for row in results
                ]

        except Exception as e:
            logger.error(f"MySQL list error: {e}")
            return []

    async def get_domains(self) -> List[DNSDomain]:
        """Get all domains from MySQL"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)

                query = """
                    SELECT name, type, master, last_check, notified_serial,
                           account, options, catalog
                    FROM domains
                    ORDER BY name
                """

                cursor.execute(query)
                results = cursor.fetchall()

                return [
                    DNSDomain(
                        name=row['name'],
                        type=row['type'],
                        master=row['master'] or "",
                        last_check=row['last_check'],
                        notified_serial=row['notified_serial'],
                        account=row['account'] or "",
                        options=row['options'] or "",
                        catalog=row['catalog'] or ""
                    )
                    for row in results
                ]

        except Exception as e:
            logger.error(f"MySQL get_domains error: {e}")
            return []

    async def create_domain(self, domain: DNSDomain) -> bool:
        """Create new domain in MySQL"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()

                query = """
                    INSERT INTO domains (name, type, master, account, options, catalog)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """

                cursor.execute(query, (
                    domain.name,
                    domain.type,
                    domain.master,
                    domain.account,
                    domain.options,
                    domain.catalog
                ))

                conn.commit()
                return True

        except Exception as e:
            logger.error(f"MySQL create_domain error: {e}")
            return False

    async def delete_domain(self, domain_name: str) -> bool:
        """Delete domain from MySQL"""
        try:
            with self.pool.get_connection() as conn:
                cursor = conn.cursor()

                # Delete records first (foreign key constraint)
                cursor.execute("DELETE FROM records WHERE domain_id IN (SELECT id FROM domains WHERE name = %s)", (domain_name,))

                # Delete domain
                cursor.execute("DELETE FROM domains WHERE name = %s", (domain_name,))

                conn.commit()
                return True

        except Exception as e:
            logger.error(f"MySQL delete_domain error: {e}")
            return False

class PostgreSQLBackend(DNSBackend):
    """PostgreSQL Backend (PowerDNS-compatible)"""

    def __init__(self, config: Dict):
        self.config = config
        self.pool = None

    async def initialize(self) -> bool:
        """Initialize PostgreSQL connection"""
        try:
            import asyncpg

            dsn = f"postgresql://{self.config.get('user', 'powerdns')}:{self.config.get('password', '')}@{self.config.get('host', 'localhost')}:{self.config.get('port', 5432)}/{self.config.get('database', 'powerdns')}"

            self.pool = await asyncpg.create_pool(
                dsn,
                min_size=self.config.get('min_connections', 2),
                max_size=self.config.get('max_connections', 10)
            )

            # Test connection
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")

            logger.info("PostgreSQL Backend initialisiert")
            return True

        except Exception as e:
            logger.error(f"PostgreSQL Backend Initialisierung fehlgeschlagen: {e}")
            return False

    async def lookup(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records from PostgreSQL"""
        try:
            async with self.pool.acquire() as conn:
                if qtype == "ANY":
                    query = """
                        SELECT r.name, r.type, r.content, r.ttl, r.prio as priority,
                               r.disabled, r.auth, r.ordername, r.domain_id, r.change_date
                        FROM records r
                        JOIN domains d ON r.domain_id = d.id
                        WHERE r.name = $1 AND r.disabled = false
                        ORDER BY r.type, r.prio
                    """
                    rows = await conn.fetch(query, qname)
                else:
                    query = """
                        SELECT r.name, r.type, r.content, r.ttl, r.prio as priority,
                               r.disabled, r.auth, r.ordername, r.domain_id, r.change_date
                        FROM records r
                        JOIN domains d ON r.domain_id = d.id
                        WHERE r.name = $1 AND r.type = $2 AND r.disabled = false
                        ORDER BY r.prio
                    """
                    rows = await conn.fetch(query, qname, qtype)

                return [
                    DNSRecord(
                        name=row['name'],
                        type=row['type'],
                        content=row['content'],
                        ttl=row['ttl'],
                        priority=row['priority'] or 0,
                        disabled=row['disabled'],
                        auth=row['auth'],
                        ordername=row['ordername'] or "",
                        domain_id=row['domain_id'],
                        change_date=row['change_date']
                    )
                    for row in rows
                ]

        except Exception as e:
            logger.error(f"PostgreSQL lookup error: {e}")
            return []

    # Weitere PostgreSQL-spezifische Implementierungen...
    async def list(self, domain_id: int, include_disabled: bool = False) -> List[DNSRecord]:
        """List all records in domain"""
        # Similar to MySQL but with PostgreSQL syntax
        return []

    async def get_domains(self) -> List[DNSDomain]:
        """Get all domains"""
        return []

    async def create_domain(self, domain: DNSDomain) -> bool:
        """Create new domain"""
        return False

    async def delete_domain(self, domain_name: str) -> bool:
        """Delete domain"""
        return False

class MongoDBBackend(DNSBackend):
    """MongoDB Backend for modern NoSQL DNS storage"""

    def __init__(self, config: Dict):
        self.config = config
        self.client = None
        self.db = None

    async def initialize(self) -> bool:
        """Initialize MongoDB connection"""
        try:
            from motor.motor_asyncio import AsyncIOMotorClient

            connection_string = f"mongodb://{self.config.get('user', '')}:{self.config.get('password', '')}@{self.config.get('host', 'localhost')}:{self.config.get('port', 27017)}/{self.config.get('database', 'jetdns')}"

            self.client = AsyncIOMotorClient(connection_string)
            self.db = self.client[self.config.get('database', 'jetdns')]

            # Test connection
            await self.client.admin.command('ping')

            # Create indexes
            await self.db.records.create_index([("name", 1), ("type", 1)])
            await self.db.records.create_index([("domain_id", 1)])
            await self.db.domains.create_index([("name", 1)], unique=True)

            logger.info("MongoDB Backend initialisiert")
            return True

        except Exception as e:
            logger.error(f"MongoDB Backend Initialisierung fehlgeschlagen: {e}")
            return False

    async def lookup(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records from MongoDB"""
        try:
            if qtype == "ANY":
                cursor = self.db.records.find({
                    "name": qname,
                    "disabled": {"$ne": True}
                }).sort([("type", 1), ("priority", 1)])
            else:
                cursor = self.db.records.find({
                    "name": qname,
                    "type": qtype,
                    "disabled": {"$ne": True}
                }).sort([("priority", 1)])

            records = []
            async for doc in cursor:
                records.append(DNSRecord(
                    name=doc['name'],
                    type=doc['type'],
                    content=doc['content'],
                    ttl=doc.get('ttl', 300),
                    priority=doc.get('priority', 0),
                    disabled=doc.get('disabled', False),
                    auth=doc.get('auth', True),
                    ordername=doc.get('ordername', ""),
                    domain_id=doc.get('domain_id'),
                    change_date=doc.get('change_date')
                ))

            return records

        except Exception as e:
            logger.error(f"MongoDB lookup error: {e}")
            return []

    # Weitere MongoDB-Implementierungen...
    async def list(self, domain_id: int, include_disabled: bool = False) -> List[DNSRecord]:
        return []

    async def get_domains(self) -> List[DNSDomain]:
        return []

    async def create_domain(self, domain: DNSDomain) -> bool:
        return False

    async def delete_domain(self, domain_name: str) -> bool:
        return False

class RedisBackend(DNSBackend):
    """Redis Backend for high-performance caching"""

    def __init__(self, config: Dict):
        self.config = config
        self.redis = None

    async def initialize(self) -> bool:
        """Initialize Redis connection"""
        try:
            import aioredis

            redis_url = f"redis://{self.config.get('host', 'localhost')}:{self.config.get('port', 6379)}/{self.config.get('db', 0)}"

            self.redis = await aioredis.from_url(redis_url)

            # Test connection
            await self.redis.ping()

            logger.info("Redis Backend initialisiert")
            return True

        except Exception as e:
            logger.error(f"Redis Backend Initialisierung fehlgeschlagen: {e}")
            return False

    async def lookup(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records from Redis"""
        try:
            # Redis key structure: dns:records:{name}:{type}
            if qtype == "ANY":
                # Get all types for name
                pattern = f"dns:records:{qname}:*"
                keys = await self.redis.keys(pattern)
            else:
                keys = [f"dns:records:{qname}:{qtype}"]

            records = []
            for key in keys:
                data = await self.redis.hgetall(key)

                if data:
                    records.append(DNSRecord(
                        name=data.get('name', qname),
                        type=data.get('type', qtype),
                        content=data.get('content', ''),
                        ttl=int(data.get('ttl', 300)),
                        priority=int(data.get('priority', 0)),
                        disabled=data.get('disabled', 'false').lower() == 'true',
                        auth=data.get('auth', 'true').lower() == 'true'
                    ))

            return records

        except Exception as e:
            logger.error(f"Redis lookup error: {e}")
            return []

    # Weitere Redis-Implementierungen...
    async def list(self, domain_id: int, include_disabled: bool = False) -> List[DNSRecord]:
        return []

    async def get_domains(self) -> List[DNSDomain]:
        return []

    async def create_domain(self, domain: DNSDomain) -> bool:
        return False

    async def delete_domain(self, domain_name: str) -> bool:
        return False

class PowerDNSBackendManager:
    """PowerDNS-Compatible Backend Manager"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.backends: Dict[str, DNSBackend] = {}
        self.primary_backend: Optional[DNSBackend] = None
        self.config = {}

        # Backend Factory
        self.backend_classes = {
            BackendType.MYSQL: MySQLBackend,
            BackendType.POSTGRESQL: PostgreSQLBackend,
            BackendType.MONGODB: MongoDBBackend,
            BackendType.REDIS: RedisBackend,
            # Weitere Backends können hier hinzugefügt werden
        }

        # Query Cache
        self.cache: Dict[str, Tuple[List[DNSRecord], float]] = {}
        self.cache_ttl = 300

        # Statistics
        self.stats = {
            'queries': 0,
            'cache_hits': 0,
            'backend_errors': 0,
            'domains_loaded': 0
        }

    async def initialize(self):
        """Initialize Backend Manager"""
        await self._load_config()
        await self._initialize_backends()

        # Background tasks
        asyncio.create_task(self._cache_cleanup_task())

        logger.info(f"🔧 PowerDNS Backend Manager initialisiert - {len(self.backends)} Backends")

    async def _load_config(self):
        """Load backend configuration"""
        self.config = self.config_manager.get_config('powerdns_backends', {
            'enabled': True,
            'primary_backend': 'mysql',
            'cache_ttl': 300,
            'backends': {
                'mysql': {
                    'type': 'mysql',
                    'host': 'localhost',
                    'port': 3306,
                    'user': 'powerdns',
                    'password': 'powerdns',
                    'database': 'powerdns',
                    'enabled': True
                },
                'postgresql': {
                    'type': 'postgresql',
                    'host': 'localhost',
                    'port': 5432,
                    'user': 'powerdns',
                    'password': 'powerdns',
                    'database': 'powerdns',
                    'enabled': False
                },
                'mongodb': {
                    'type': 'mongodb',
                    'host': 'localhost',
                    'port': 27017,
                    'database': 'jetdns',
                    'enabled': False
                },
                'redis': {
                    'type': 'redis',
                    'host': 'localhost',
                    'port': 6379,
                    'db': 0,
                    'enabled': True
                }
            }
        })

        self.cache_ttl = self.config.get('cache_ttl', 300)

    async def _initialize_backends(self):
        """Initialize configured backends"""
        backends_config = self.config.get('backends', {})
        primary_backend_name = self.config.get('primary_backend', 'mysql')

        for backend_name, backend_config in backends_config.items():
            if not backend_config.get('enabled', False):
                continue

            backend_type = BackendType(backend_config['type'])

            if backend_type in self.backend_classes:
                backend_class = self.backend_classes[backend_type]
                backend = backend_class(backend_config)

                try:
                    if await backend.initialize():
                        self.backends[backend_name] = backend

                        # Set primary backend
                        if backend_name == primary_backend_name:
                            self.primary_backend = backend

                        logger.info(f"Backend '{backend_name}' ({backend_type.value}) initialisiert")
                    else:
                        logger.error(f"Backend '{backend_name}' Initialisierung fehlgeschlagen")

                except Exception as e:
                    logger.error(f"Backend '{backend_name}' Fehler: {e}")

        if not self.primary_backend and self.backends:
            # Fallback to first available backend
            self.primary_backend = next(iter(self.backends.values()))
            logger.warning("Primary Backend nicht verfügbar, verwende Fallback")

    async def lookup_records(self, qname: str, qtype: str, domain_id: Optional[int] = None) -> List[DNSRecord]:
        """Lookup DNS records across backends"""
        self.stats['queries'] += 1

        # Check cache first
        cache_key = f"{qname}:{qtype}:{domain_id}"
        if cache_key in self.cache:
            records, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return records
            else:
                del self.cache[cache_key]

        # Try primary backend first
        if self.primary_backend:
            try:
                records = await self.primary_backend.lookup(qname, qtype, domain_id)
                if records:
                    # Cache results
                    self.cache[cache_key] = (records, time.time())
                    return records
            except Exception as e:
                logger.error(f"Primary backend lookup error: {e}")
                self.stats['backend_errors'] += 1

        # Try other backends
        for backend_name, backend in self.backends.items():
            if backend == self.primary_backend:
                continue

            try:
                records = await backend.lookup(qname, qtype, domain_id)
                if records:
                    # Cache results
                    self.cache[cache_key] = (records, time.time())
                    return records
            except Exception as e:
                logger.error(f"Backend '{backend_name}' lookup error: {e}")
                self.stats['backend_errors'] += 1

        return []

    async def get_all_domains(self) -> List[DNSDomain]:
        """Get all domains from primary backend"""
        if not self.primary_backend:
            return []

        try:
            domains = await self.primary_backend.get_domains()
            self.stats['domains_loaded'] = len(domains)
            return domains
        except Exception as e:
            logger.error(f"Get domains error: {e}")
            return []

    async def create_domain(self, domain: DNSDomain) -> bool:
        """Create domain in primary backend"""
        if not self.primary_backend:
            return False

        try:
            result = await self.primary_backend.create_domain(domain)
            if result:
                # Clear cache
                self.cache.clear()
            return result
        except Exception as e:
            logger.error(f"Create domain error: {e}")
            return False

    async def delete_domain(self, domain_name: str) -> bool:
        """Delete domain from primary backend"""
        if not self.primary_backend:
            return False

        try:
            result = await self.primary_backend.delete_domain(domain_name)
            if result:
                # Clear cache
                self.cache.clear()
            return result
        except Exception as e:
            logger.error(f"Delete domain error: {e}")
            return False

    async def _cache_cleanup_task(self):
        """Background task for cache cleanup"""
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes

                current_time = time.time()
                expired_keys = [
                    key for key, (_, timestamp) in self.cache.items()
                    if current_time - timestamp >= self.cache_ttl
                ]

                for key in expired_keys:
                    del self.cache[key]

                if expired_keys:
                    logger.debug(f"Cleaned {len(expired_keys)} expired cache entries")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

    async def get_backend_stats(self) -> Dict:
        """Get backend statistics"""
        backend_info = {}

        for name, backend in self.backends.items():
            backend_info[name] = {
                'type': type(backend).__name__,
                'is_primary': backend == self.primary_backend,
                'available': True  # Could add health check here
            }

        return {
            'enabled': self.config.get('enabled', True),
            'primary_backend': self.config.get('primary_backend'),
            'backends': backend_info,
            'cache_entries': len(self.cache),
            'cache_ttl': self.cache_ttl,
            'stats': self.stats
        }

    def get_backend(self, name: str) -> Optional[DNSBackend]:
        """Get specific backend by name"""
        return self.backends.get(name)

    async def health_check(self) -> Dict[str, bool]:
        """Check health of all backends"""
        health_status = {}

        for name, backend in self.backends.items():
            try:
                # Simple health check - try to get domains
                await backend.get_domains()
                health_status[name] = True
            except Exception as e:
                logger.debug(f"Backend {name} health check failed: {e}")
                health_status[name] = False

        return health_status

    def reload_config(self):
        """Reload backend configuration"""
        asyncio.create_task(self._load_config())
        logger.info("🔧 PowerDNS Backend Konfiguration neu geladen")
