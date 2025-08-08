"""
Advanced Recursive DNS Engine
Implements recursive DNS resolution with intelligent caching and validation
"""

import asyncio
import logging
import time
import socket
import random
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import dns.resolver
import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
import dns.exception
from dns.resolver import Resolver, NXDOMAIN, NoAnswer
import ipaddress


class RecursionResult(Enum):
    SUCCESS = "success"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    ERROR = "error"
    REFUSED = "refused"
    LOOP_DETECTED = "loop_detected"


@dataclass
class RecursiveQuery:
    qname: str
    qtype: str
    qclass: str = "IN"
    client_ip: str = "127.0.0.1"
    query_id: int = 0
    recursion_depth: int = 0
    trace: List[str] = None
    start_time: float = 0


@dataclass
class RecursionConfig:
    """Configuration constraints for recursive DNS"""
    max_depth: int = 16                    # RFC recommended max
    timeout_per_query: float = 5.0         # Seconds per upstream query
    total_timeout: float = 30.0            # Total resolution timeout
    max_queries_per_second: int = 1000     # Rate limiting
    max_referrals: int = 20                # Max NS referrals to follow
    min_ttl: int = 60                      # Minimum cache TTL
    max_ttl: int = 86400                   # Maximum cache TTL (24h)
    allowed_networks: List[str] = None     # Client IP restrictions
    root_hints_file: str = "/etc/dns/root.hints"
    enable_dnssec: bool = False
    enable_qname_minimization: bool = True
    enable_prefetch: bool = False


class RecursiveDNSEngine:
    """Advanced recursive DNS resolver with built-in constraints and validation"""

    def __init__(self, config: RecursionConfig, cache_manager=None, statistics=None):
        self.config = config
        self.cache_manager = cache_manager
        self.statistics = statistics
        self.logger = logging.getLogger(__name__)

        # Runtime state
        self.active_queries: Dict[str, RecursiveQuery] = {}
        self.query_counts: Dict[str, int] = {}  # Per-client query counting
        self.root_servers: List[str] = []
        self.referral_cache: Dict[str, List[str]] = {}

        # Performance tracking
        self.resolution_times: List[float] = []
        self.success_rate: float = 0.0

        # Validation constraints
        self._setup_validation_rules()

    def _setup_validation_rules(self):
        """Setup DNS validation rules and constraints"""
        self.validation_rules = {
            'domain_name': {
                'max_length': 253,
                'label_max_length': 63,
                'allowed_chars': set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.')
            },
            'ttl': {
                'min': self.config.min_ttl,
                'max': self.config.max_ttl,
                'default': 3600
            },
            'ip_address': {
                'private_ranges': [
                    ipaddress.IPv4Network('10.0.0.0/8'),
                    ipaddress.IPv4Network('172.16.0.0/12'),
                    ipaddress.IPv4Network('192.168.0.0/16'),
                    ipaddress.IPv4Network('127.0.0.0/8')
                ]
            }
        }

    async def initialize(self):
        """Initialize recursive DNS engine"""
        try:
            # Load root hints
            await self._load_root_hints()

            # Validate configuration
            self._validate_config()

            # Setup allowed networks
            if self.config.allowed_networks:
                self.allowed_networks = [
                    ipaddress.IPv4Network(net) for net in self.config.allowed_networks
                ]
            else:
                self.allowed_networks = None

            # Start background tasks
            asyncio.create_task(self._cleanup_active_queries())
            asyncio.create_task(self._update_root_hints_periodically())

            self.logger.info("🔄 Recursive DNS Engine initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize recursive DNS engine: {e}")
            raise

    async def resolve_recursive(self, qname: str, qtype: str, 
                               client_ip: str = "127.0.0.1") -> Tuple[RecursionResult, Optional[dns.message.Message], str]:
        """
        Main recursive resolution function with full validation
        """
        start_time = time.time()

        try:
            # Validate client permissions
            if not self._validate_client_access(client_ip):
                return RecursionResult.REFUSED, None, "Client not authorized for recursion"

            # Rate limiting check
            if not self._check_rate_limit(client_ip):
                return RecursionResult.REFUSED, None, "Rate limit exceeded"

            # Validate query parameters
            validation_error = self._validate_query_params(qname, qtype)
            if validation_error:
                return RecursionResult.ERROR, None, validation_error

            # Create recursive query context
            query = RecursiveQuery(
                qname=qname.lower().rstrip('.'),
                qtype=qtype.upper(),
                client_ip=client_ip,
                query_id=random.randint(1000, 9999),
                trace=[],
                start_time=start_time
            )

            # Check for active query loop
            query_key = f"{qname}:{qtype}:{client_ip}"
            if query_key in self.active_queries:
                return RecursionResult.LOOP_DETECTED, None, "Query loop detected"

            self.active_queries[query_key] = query

            try:
                # Attempt resolution
                result, response, message = await self._perform_recursive_resolution(query)

                # Record performance metrics
                resolution_time = time.time() - start_time
                self.resolution_times.append(resolution_time)

                # Keep only last 1000 measurements
                if len(self.resolution_times) > 1000:
                    self.resolution_times = self.resolution_times[-1000:]

                # Update statistics
                if self.statistics:
                    await self.statistics.record_recursive_query(
                        query, result, resolution_time
                    )

                self.logger.debug(f"Recursive resolution: {qname} {qtype} -> {result.value} ({resolution_time:.3f}s)")

                return result, response, message

            finally:
                # Always cleanup active query
                self.active_queries.pop(query_key, None)

        except asyncio.TimeoutError:
            return RecursionResult.TIMEOUT, None, "Total resolution timeout exceeded"
        except Exception as e:
            self.logger.error(f"Recursive resolution error for {qname} {qtype}: {e}")
            return RecursionResult.ERROR, None, f"Internal resolver error: {e}"

    async def _perform_recursive_resolution(self, query: RecursiveQuery) -> Tuple[RecursionResult, Optional[dns.message.Message], str]:
        """Perform the actual recursive resolution"""

        # Check cache first
        if self.cache_manager:
            cached_response = await self.cache_manager.get(f"recursive:{query.qname}:{query.qtype}")
            if cached_response:
                try:
                    response = dns.message.from_wire(cached_response)
                    return RecursionResult.SUCCESS, response, "Cached response"
                except:
                    pass

        # Start from root servers
        current_servers = self.root_servers.copy()
        current_domain = query.qname

        for depth in range(self.config.max_depth):
            query.recursion_depth = depth
            query.trace.append(f"Depth {depth}: querying for {current_domain}")

            # Try each server in current set
            for server in current_servers:
                try:
                    # Create DNS query message
                    dns_query = dns.message.make_query(
                        current_domain, 
                        dns.rdatatype.from_text(query.qtype)
                    )

                    # Apply QNAME minimization if enabled
                    if self.config.enable_qname_minimization and depth > 0:
                        dns_query = self._apply_qname_minimization(dns_query, current_domain)

                    # Perform query with timeout
                    response = await asyncio.wait_for(
                        self._query_server(server, dns_query),
                        timeout=self.config.timeout_per_query
                    )

                    if not response:
                        continue

                    # Validate response
                    if not self._validate_dns_response(response):
                        self.logger.warning(f"Invalid response from {server}")
                        continue

                    # Check response code
                    rcode = response.rcode()

                    if rcode == dns.rcode.NXDOMAIN:
                        # Authoritative NXDOMAIN
                        if response.flags & dns.flags.AA:
                            await self._cache_response(query, response, 3600)  # Cache NXDOMAIN
                            return RecursionResult.NXDOMAIN, response, "Domain does not exist"
                        continue

                    elif rcode == dns.rcode.REFUSED:
                        continue  # Try next server

                    elif rcode != dns.rcode.NOERROR:
                        continue  # Try next server

                    # Check if we have an answer
                    if response.answer:
                        # We found an answer!
                        await self._cache_response(query, response)
                        return RecursionResult.SUCCESS, response, f"Resolved via {server}"

                    # Look for referrals in authority section
                    elif response.authority:
                        referrals = self._extract_referrals(response)
                        if referrals:
                            # Update current servers for next iteration
                            current_servers = await self._resolve_referrals(referrals)
                            if current_servers:
                                break  # Continue with new servers

                except asyncio.TimeoutError:
                    self.logger.debug(f"Timeout querying {server} for {current_domain}")
                    continue
                except Exception as e:
                    self.logger.debug(f"Error querying {server}: {e}")
                    continue

            else:
                # No servers responded successfully
                break

        # Resolution failed
        return RecursionResult.ERROR, None, "No authoritative answer found"

    async def _query_server(self, server: str, query: dns.message.Message) -> Optional[dns.message.Message]:
        """Query a specific DNS server"""
        try:
            # Try UDP first, then TCP if needed
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None, dns.query.udp, query, server, self.config.timeout_per_query
                )
                return response
            except dns.exception.Timeout:
                # Retry with TCP for large responses
                response = await asyncio.get_event_loop().run_in_executor(
                    None, dns.query.tcp, query, server, self.config.timeout_per_query
                )
                return response

        except Exception as e:
            self.logger.debug(f"Query failed to {server}: {e}")
            return None

    def _validate_client_access(self, client_ip: str) -> bool:
        """Validate if client is allowed to use recursion"""
        if not self.allowed_networks:
            return True  # No restrictions

        try:
            client_addr = ipaddress.IPv4Address(client_ip)
            return any(client_addr in network for network in self.allowed_networks)
        except ValueError:
            return False

    def _check_rate_limit(self, client_ip: str) -> bool:
        """Check rate limiting for client"""
        current_time = time.time()

        # Reset counters every second
        if not hasattr(self, '_last_rate_reset') or current_time - self._last_rate_reset > 1.0:
            self.query_counts.clear()
            self._last_rate_reset = current_time

        # Increment counter for client
        self.query_counts[client_ip] = self.query_counts.get(client_ip, 0) + 1

        return self.query_counts[client_ip] <= self.config.max_queries_per_second

    def _validate_query_params(self, qname: str, qtype: str) -> Optional[str]:
        """Validate query parameters against DNS constraints"""

        # Validate domain name
        if not qname or len(qname) > self.validation_rules['domain_name']['max_length']:
            return f"Domain name too long (max {self.validation_rules['domain_name']['max_length']} chars)"

        # Check domain name format
        if not qname.replace('-', '').replace('.', '').replace('_', '').isalnum():
            invalid_chars = set(qname) - self.validation_rules['domain_name']['allowed_chars']
            if invalid_chars:
                return f"Domain name contains invalid characters: {invalid_chars}"

        # Check label lengths
        labels = qname.split('.')
        for label in labels:
            if len(label) > self.validation_rules['domain_name']['label_max_length']:
                return f"Domain label '{label}' too long (max {self.validation_rules['domain_name']['label_max_length']} chars)"

        # Validate query type
        try:
            dns.rdatatype.from_text(qtype)
        except dns.rdatatype.UnknownRdatatype:
            return f"Unknown DNS record type: {qtype}"

        # Additional security checks
        if qname.lower().startswith('.') or qname.lower().endswith('..'):
            return "Invalid domain name format"

        return None  # Valid

    def _validate_dns_response(self, response: dns.message.Message) -> bool:
        """Validate DNS response for security and correctness"""

        # Basic message validation
        if not response or not hasattr(response, 'rcode'):
            return False

        # Check for response flags consistency
        if response.flags & dns.flags.QR == 0:
            return False  # Must be a response

        # Validate TTL values in all sections
        for section in [response.answer, response.authority, response.additional]:
            for rrset in section:
                if rrset.ttl < 0 or rrset.ttl > self.validation_rules['ttl']['max']:
                    self.logger.warning(f"Invalid TTL in response: {rrset.ttl}")
                    return False

        return True

    def _extract_referrals(self, response: dns.message.Message) -> List[str]:
        """Extract NS referrals from authority section"""
        referrals = []

        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rdata in rrset:
                    ns_name = str(rdata.target).rstrip('.')
                    referrals.append(ns_name)

        return referrals

    async def _resolve_referrals(self, referrals: List[str]) -> List[str]:
        """Resolve NS names to IP addresses"""
        resolved_servers = []

        for ns_name in referrals[:self.config.max_referrals]:  # Limit referrals
            try:
                # Try to resolve NS name to IP
                resolver = Resolver()
                resolver.timeout = self.config.timeout_per_query

                try:
                    answers = resolver.resolve(ns_name, 'A')
                    for rdata in answers:
                        ip = str(rdata)
                        if self._validate_server_ip(ip):
                            resolved_servers.append(ip)
                            if len(resolved_servers) >= 8:  # Limit server count
                                break
                except (NXDOMAIN, NoAnswer):
                    continue

            except Exception as e:
                self.logger.debug(f"Failed to resolve referral {ns_name}: {e}")
                continue

        return resolved_servers

    def _validate_server_ip(self, ip: str) -> bool:
        """Validate server IP address for security"""
        try:
            addr = ipaddress.IPv4Address(ip)

            # Reject private/reserved addresses for public recursion
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                return False

            # Reject broadcast and multicast
            if addr.is_multicast or str(addr).endswith('.255'):
                return False

            return True
        except ValueError:
            return False

    async def _cache_response(self, query: RecursiveQuery, response: dns.message.Message, ttl: Optional[int] = None):
        """Cache DNS response with proper TTL handling"""
        if not self.cache_manager:
            return

        try:
            # Calculate appropriate TTL
            if ttl is None:
                ttl = self._calculate_response_ttl(response)

            # Enforce TTL constraints
            ttl = max(self.config.min_ttl, min(ttl, self.config.max_ttl))

            # Cache the response
            cache_key = f"recursive:{query.qname}:{query.qtype}"
            await self.cache_manager.set(cache_key, response.to_wire(), ttl)

        except Exception as e:
            self.logger.debug(f"Failed to cache response: {e}")

    def _calculate_response_ttl(self, response: dns.message.Message) -> int:
        """Calculate appropriate TTL from response"""
        min_ttl = self.config.max_ttl

        # Find minimum TTL from all sections
        for section in [response.answer, response.authority, response.additional]:
            for rrset in section:
                min_ttl = min(min_ttl, rrset.ttl)

        return min_ttl if min_ttl < self.config.max_ttl else self.validation_rules['ttl']['default']

    def _apply_qname_minimization(self, query: dns.message.Message, domain: str) -> dns.message.Message:
        """Apply QNAME minimization for privacy"""
        # Simplified implementation - in production would be more sophisticated
        return query

    async def _load_root_hints(self):
        """Load root DNS server hints"""
        try:
            # Default root servers (simplified)
            self.root_servers = [
                "198.41.0.4",    # a.root-servers.net
                "170.247.170.2", # b.root-servers.net  
                "192.33.4.12",   # c.root-servers.net
                "199.7.91.13",   # d.root-servers.net
                "192.203.230.10" # e.root-servers.net
            ]

            # In production, load from root hints file
            # if os.path.exists(self.config.root_hints_file):
            #     self.root_servers = parse_root_hints_file(self.config.root_hints_file)

            self.logger.info(f"Loaded {len(self.root_servers)} root servers")

        except Exception as e:
            self.logger.error(f"Failed to load root hints: {e}")
            raise

    def _validate_config(self):
        """Validate configuration constraints"""
        errors = []

        if self.config.max_depth < 1 or self.config.max_depth > 30:
            errors.append("max_depth must be between 1 and 30")

        if self.config.timeout_per_query < 0.1 or self.config.timeout_per_query > 60:
            errors.append("timeout_per_query must be between 0.1 and 60 seconds")

        if self.config.total_timeout < self.config.timeout_per_query:
            errors.append("total_timeout must be >= timeout_per_query")

        if self.config.max_queries_per_second < 1 or self.config.max_queries_per_second > 100000:
            errors.append("max_queries_per_second must be between 1 and 100,000")

        if self.config.min_ttl < 0 or self.config.max_ttl < self.config.min_ttl:
            errors.append("Invalid TTL configuration")

        if errors:
            raise ValueError(f"Invalid recursive DNS configuration: {', '.join(errors)}")

    async def _cleanup_active_queries(self):
        """Cleanup stale active queries"""
        while True:
            try:
                await asyncio.sleep(60)  # Cleanup every minute

                current_time = time.time()
                stale_queries = []

                for key, query in self.active_queries.items():
                    if current_time - query.start_time > self.config.total_timeout:
                        stale_queries.append(key)

                for key in stale_queries:
                    self.active_queries.pop(key, None)

                if stale_queries:
                    self.logger.debug(f"Cleaned up {len(stale_queries)} stale queries")

            except Exception as e:
                self.logger.error(f"Error in query cleanup: {e}")

    async def _update_root_hints_periodically(self):
        """Update root hints periodically"""
        while True:
            try:
                await asyncio.sleep(86400 * 7)  # Weekly
                await self._load_root_hints()
                self.logger.info("Root hints updated")
            except Exception as e:
                self.logger.error(f"Error updating root hints: {e}")

    def get_performance_metrics(self) -> Dict[str, any]:
        """Get performance metrics for monitoring"""
        if not self.resolution_times:
            return {
                'avg_resolution_time': 0,
                'active_queries': len(self.active_queries),
                'success_rate': 0
            }

        avg_time = sum(self.resolution_times) / len(self.resolution_times)

        return {
            'avg_resolution_time': round(avg_time, 3),
            'active_queries': len(self.active_queries),
            'total_resolutions': len(self.resolution_times),
            'success_rate': self.success_rate,
            'root_servers_count': len(self.root_servers)
        }
