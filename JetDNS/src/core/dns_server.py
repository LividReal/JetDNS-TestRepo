"""
High-Performance DNS Server Core
Supports UDP/TCP/DoH/DoT with advanced features like GeoDNS, Load Balancing, DNSSEC
"""
from idlelib import query

# Advanced Security Features
self.brand_protection = None
self.bandwidth_throttling = None
self.application_layer_filtering = None

import asyncio
import logging
import socket
import ssl
import time
import json
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import struct
import hashlib

import dns.message
import dns.query
import dns.resolver
import dns.zone
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.flags
from dns.resolver import Resolver
from dns.exception import DNSException


class QueryType(Enum):
    STANDARD = "standard"
    RECURSIVE = "recursive"
    AUTHORITATIVE = "authoritative"
    FORWARDED = "forwarded"


class ResponseType(Enum):
    ANSWER = "answer"
    BLOCKED = "blocked"
    REDIRECTED = "redirected"
    NXDOMAIN = "nxdomain"
    CACHED = "cached"


@dataclass
class DNSQuery:
    query_id: int
    domain: str
    qtype: str
    qclass: str
    client_ip: str
    timestamp: float
    protocol: str  # UDP/TCP/DoH/DoT
    original_message: dns.message.Message
    client_subnet: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class DNSResponse:
    query: DNSQuery
    response_type: ResponseType
    answer: Optional[dns.message.Message]
    response_time: float
    cache_hit: bool = False
    blocked_reason: Optional[str] = None
    upstream_server: Optional[str] = None
    authoritative: bool = False


class AdvancedDNSServer:
    """High-Performance DNS Server with Enterprise Features"""

    def __init__(self, config: dict, cache_manager=None, ad_blocker=None, 
                 statistics=None, threat_intelligence=None, content_filter=None):
        self.config = config
        self.cache_manager = cache_manager
        self.ad_blocker = ad_blocker
        self.statistics = statistics
        self.threat_intelligence = threat_intelligence
        self.content_filter = content_filter
        self.logger = logging.getLogger(__name__)

        # Server configuration
        self.listen_address = config.get('listen_address', '0.0.0.0')
        self.listen_port = config.get('listen_port', 53)
        self.max_connections = config.get('max_connections', 1000)
        self.query_timeout = config.get('timeout', 5)

        # Protocol support
        self.udp_enabled = True
        self.tcp_enabled = True
        self.doh_enabled = config.get('doh_enabled', False)
        self.dot_enabled = config.get('dot_enabled', False)

        # Upstream servers
        self.upstream_servers = config.get('upstream_servers', ['8.8.8.8', '1.1.1.1'])
        self.upstream_resolvers = []

        # Server state
        self.running = False
        self.servers = []
        self.connection_pool = {}
        self.query_queue = asyncio.Queue()
        self.response_cache = {}

        # Performance counters
        self.stats = {
            'queries_total': 0,
            'queries_cached': 0,
            'queries_blocked': 0,
            'queries_forwarded': 0,
            'response_times': [],
            'active_connections': 0
        }

        # Authoritative zones
        self.authoritative_zones = {}

        # Load balancer
        self.upstream_health = {}
        self.upstream_weights = {}

        # GeoDNS database
        self.geo_database = None

        # Rate limiting
        self.rate_limits = {}

    async def initialize(self):
        """Initialize DNS server components"""
        try:
            # Initialize upstream resolvers
            await self._initialize_upstream_resolvers()

            # Load authoritative zones if enabled
            if self.config.get('authoritative_enabled', False):
                await self._load_authoritative_zones()

            # Initialize GeoDNS if enabled
            if self.config.get('geo_dns', False):
                await self._initialize_geo_dns()

            # Initialize rate limiting
            await self._initialize_rate_limiting()

            # Start background tasks
            asyncio.create_task(self._cleanup_task())
            asyncio.create_task(self._health_check_task())
            asyncio.create_task(self._stats_collection_task())

            self.logger.info("🔧 DNS Server components initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize DNS server: {e}")
            raise

    async def start(self):
        """Start DNS server on all protocols"""
        try:
            self.running = True

            # Start UDP server
            if self.udp_enabled:
                udp_server = await self._start_udp_server()
                self.servers.append(udp_server)
                self.logger.info(f"🌐 UDP DNS server started on {self.listen_address}:{self.listen_port}")

            # Start TCP server
            if self.tcp_enabled:
                tcp_server = await self._start_tcp_server()
                self.servers.append(tcp_server)
                self.logger.info(f"🌐 TCP DNS server started on {self.listen_address}:{self.listen_port}")

            # Start DNS-over-HTTPS server
            if self.doh_enabled:
                doh_server = await self._start_doh_server()
                self.servers.append(doh_server)
                doh_port = self.config.get('doh_port', 443)
                self.logger.info(f"🔐 DNS-over-HTTPS server started on port {doh_port}")

            # Start DNS-over-TLS server
            if self.dot_enabled:
                dot_server = await self._start_dot_server()
                self.servers.append(dot_server)
                dot_port = self.config.get('dot_port', 853)
                self.logger.info(f"🔐 DNS-over-TLS server started on port {dot_port}")

            # Start query processor
            for i in range(4):  # 4 worker tasks
                asyncio.create_task(self._process_queries())

            self.logger.info("🚀 DNS Server fully operational!")

        except Exception as e:
            self.logger.error(f"Failed to start DNS server: {e}")
            raise

    async def _start_udp_server(self):
        """Start UDP DNS server"""
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPDNSProtocol(self),
            local_addr=(self.listen_address, self.listen_port),
            reuse_port=True
        )
        return transport

    async def _start_tcp_server(self):
        """Start TCP DNS server"""
        server = await asyncio.start_server(
            self._handle_tcp_client,
            self.listen_address,
            self.listen_port,
            reuse_port=True,
            limit=65536
        )
        return server

    async def _start_doh_server(self):
        """Start DNS-over-HTTPS server"""
        from aiohttp import web, ClientSession

        app = web.Application()
        app.router.add_post('/dns-query', self._handle_doh_request)
        app.router.add_get('/dns-query', self._handle_doh_get_request)

        # SSL context for HTTPS
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('config/ssl/cert.pem', 'config/ssl/key.pem')

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(
            runner, 
            self.listen_address, 
            self.config.get('doh_port', 443),
            ssl_context=ssl_context
        )
        await site.start()
        return runner

    async def _start_dot_server(self):
        """Start DNS-over-TLS server"""
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('config/ssl/cert.pem', 'config/ssl/key.pem')

        server = await asyncio.start_server(
            self._handle_dot_client,
            self.listen_address,
            self.config.get('dot_port', 853),
            ssl=ssl_context,
            reuse_port=True
        )
        return server

    async def handle_query(self, query_data: bytes, client_ip: str, protocol: str = 'UDP') -> bytes:
        """Main query handler"""
        start_time = time.time()

        try:
            # Parse DNS message
            try:
                message = dns.message.from_wire(query_data)
            except Exception as e:
                self.logger.warning(f"Invalid DNS query from {client_ip}: {e}")
                return self._create_format_error_response()

            # Extract query information
            if not message.question:
                return self._create_format_error_response()

            question = message.question[0]
            domain = str(question.name).rstrip('.')
            qtype = dns.rdatatype.to_text(question.rdtype)
            qclass = dns.rdataclass.to_text(question.rdclass)

            # Create DNS query object
            dns_query = DNSQuery(
                query_id=message.id,
                domain=domain,
                qtype=qtype,
                qclass=qclass,
                client_ip=client_ip,
                timestamp=start_time,
                protocol=protocol,
                original_message=message
            )

            # Check rate limiting
            if await self._is_rate_limited(client_ip):
                self.logger.warning(f"Rate limited client: {client_ip}")
                return self._create_refused_response(message)

            # Add to statistics
            self.stats['queries_total'] += 1

            # Process query
            response = await self._process_single_query(dns_query)

            # Record response time
            response_time = time.time() - start_time
            self.stats['response_times'].append(response_time)

            # Keep only last 1000 response times
            if len(self.stats['response_times']) > 1000:
                self.stats['response_times'] = self.stats['response_times'][-1000:]

            # Log query if enabled
            if self.statistics:
                await self.statistics.log_query(dns_query, response, response_time)

            return response.answer.to_wire() if response.answer else self._create_servfail_response(message)

        except Exception as e:
            self.logger.error(f"Error processing query from {client_ip}: {e}")
            return self._create_servfail_response(message if 'message' in locals() else None)

    async def _process_single_query(self, query: DNSQuery) -> DNSResponse:
        """Process a single DNS query with all filtering and intelligence"""

        # Check cache first
        cache_key = f"{query.domain}:{query.qtype}:{query.qclass}"
        if self.cache_manager:
            cached_response = await self.cache_manager.get(cache_key)
            if cached_response:
                self.stats['queries_cached'] += 1
                return DNSResponse(
                    query=query,
                    response_type=ResponseType.CACHED,
                    answer=dns.message.from_wire(cached_response),
                    response_time=0.001,
                    cache_hit=True
                )

        # Check authoritative zones first
        if query.domain in self.authoritative_zones:
            return await self._handle_authoritative_query(query)

        # Apply threat intelligence
        if self.threat_intelligence:
            threat_intel = await self.threat_intelligence.analyze_domain(
                query.domain, query.client_ip
            )

            if threat_intel.threat_level.value >= 3:  # HIGH or CRITICAL
                blocked_response = self._create_blocked_response(
                    query.original_message, 
                    f"Threat detected: {threat_intel.threat_level.name}"
                )
                self.stats['queries_blocked'] += 1

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.BLOCKED,
                    answer=blocked_response,
                    response_time=0.001,
                    blocked_reason=f"Threat: {threat_intel.threat_level.name}"
                )

        # Apply content filtering
        if self.content_filter:
            filter_result = await self.content_filter.filter_domain(
                query.domain, query.client_ip
            )

            if filter_result.action.value == "block":
                blocked_response = self._create_blocked_response(
                    query.original_message,
                    filter_result.reason
                )
                self.stats['queries_blocked'] += 1

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.BLOCKED,
                    answer=blocked_response,
                    response_time=0.001,
                    blocked_reason=filter_result.reason
                )

            elif filter_result.action.value == "redirect":
                if filter_result.redirect_url:
                    redirect_response = self._create_redirect_response(
                        query.original_message,
                        filter_result.redirect_url
                    )
                    return DNSResponse(
                        query=query,
                        response_type=ResponseType.REDIRECTED,
                        answer=redirect_response,
                        response_time=0.001
                    )

        # Apply ad blocking
        if self.ad_blocker:
            block_result = await self.ad_blocker.should_block(query.domain)
            if block_result['blocked']:
                blocked_response = self._create_blocked_response(
                    query.original_message,
                    block_result['reason']
                )
                self.stats['queries_blocked'] += 1

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.BLOCKED,
                    answer=blocked_response,
                    response_time=0.001,
                    blocked_reason=block_result['reason']
                )

        # Forward to upstream servers
        response = await self._forward_query(query)

        # Cache successful responses
        if response.answer and self.cache_manager:
            await self.cache_manager.set(
                cache_key,
                response.answer.to_wire(),
                ttl=self._extract_ttl(response.answer)
            )

        return response

    async def _forward_query(self, query: DNSQuery) -> DNSResponse:
        """Forward query to upstream servers with load balancing"""
        start_time = time.time()

        # Select best upstream server
        upstream_server = await self._select_upstream_server(query)

        try:
            # Use appropriate resolver
            resolver = None
            for res in self.upstream_resolvers:
                if upstream_server in res.nameservers:
                    resolver = res
                    break

            if not resolver:
                # Create temporary resolver
                resolver = Resolver()
                resolver.nameservers = [upstream_server]
                resolver.timeout = self.query_timeout
                resolver.lifetime = self.query_timeout

            # Perform the query
            try:
                if query.qtype == 'A':
                    answers = resolver.resolve(query.domain, 'A')
                elif query.qtype == 'AAAA':
                    answers = resolver.resolve(query.domain, 'AAAA')
                elif query.qtype == 'MX':
                    answers = resolver.resolve(query.domain, 'MX')
                elif query.qtype == 'TXT':
                    answers = resolver.resolve(query.domain, 'TXT')
                elif query.qtype == 'CNAME':
                    answers = resolver.resolve(query.domain, 'CNAME')
                elif query.qtype == 'NS':
                    answers = resolver.resolve(query.domain, 'NS')
                elif query.qtype == 'PTR':
                    answers = resolver.resolve(query.domain, 'PTR')
                else:
                    # Generic query
                    answers = resolver.resolve(query.domain, query.qtype)

                # Create response message
                response_msg = dns.message.make_response(query.original_message)
                response_msg.answer = [answers.rrset]

                # Update upstream server health
                response_time = time.time() - start_time
                await self._update_upstream_health(upstream_server, True, response_time)

                self.stats['queries_forwarded'] += 1

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.ANSWER,
                    answer=response_msg,
                    response_time=response_time,
                    upstream_server=upstream_server
                )

            except dns.resolver.NXDOMAIN:
                # Domain does not exist
                response_msg = dns.message.make_response(query.original_message)
                response_msg.set_rcode(dns.rcode.NXDOMAIN)

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.NXDOMAIN,
                    answer=response_msg,
                    response_time=time.time() - start_time,
                    upstream_server=upstream_server
                )

        except Exception as e:
            self.logger.error(f"Error forwarding query to {upstream_server}: {e}")

            # Update upstream server health
            await self._update_upstream_health(upstream_server, False, 0)

            # Try next upstream server
            remaining_servers = [s for s in self.upstream_servers if s != upstream_server]
            if remaining_servers:
                query_copy = query
                return await self._forward_query_to_server(query_copy, remaining_servers[0])

            # All servers failed
            return DNSResponse(
                query=query,
                response_type=ResponseType.NXDOMAIN,
                answer=self._create_servfail_response(query.original_message),
                response_time=time.time() - start_time
            )

    async def _select_upstream_server(self, query: DNSQuery) -> str:
        """Select the best upstream server using load balancing and health checks"""

        # Filter healthy servers
        healthy_servers = []
        for server in self.upstream_servers:
            health = self.upstream_health.get(server, {'healthy': True, 'response_time': 0.05})
            if health['healthy']:
                healthy_servers.append((server, health['response_time']))

        if not healthy_servers:
            # No healthy servers, use first available
            return self.upstream_servers[0]

        # GeoDNS selection if enabled
        if self.config.get('geo_dns', False):
            geo_server = await self._get_geo_optimal_server(query.client_ip, healthy_servers)
            if geo_server:
                return geo_server

        # Load balancing algorithms
        algorithm = self.config.get('load_balancing', {}).get('algorithm', 'round_robin')

        if algorithm == 'least_connections':
            # Select server with least active connections (placeholder)
            return min(healthy_servers, key=lambda x: x[1])[0]
        elif algorithm == 'response_time':
            # Select fastest server
            return min(healthy_servers, key=lambda x: x[1])[0]
        elif algorithm == 'weighted':
            # Weighted selection (placeholder)
            return healthy_servers[0][0]
        else:
            # Round robin (default)
            current_time = int(time.time())
            index = current_time % len(healthy_servers)
            return healthy_servers[index][0]

    async def _handle_authoritative_query(self, query: DNSQuery) -> DNSResponse:
        """Handle authoritative DNS queries"""
        zone = self.authoritative_zones.get(query.domain)

        if not zone:
            return DNSResponse(
                query=query,
                response_type=ResponseType.NXDOMAIN,
                answer=self._create_nxdomain_response(query.original_message),
                response_time=0.001,
                authoritative=True
            )

        try:
            # Look up record in zone
            rdataset = zone.get_rdataset(query.domain, query.qtype)

            if rdataset:
                response_msg = dns.message.make_response(query.original_message)
                response_msg.answer = [dns.rrset.from_rdata(query.domain, 300, rdataset)]
                response_msg.flags |= dns.flags.AA  # Authoritative Answer

                return DNSResponse(
                    query=query,
                    response_type=ResponseType.ANSWER,
                    answer=response_msg,
                    response_time=0.001,
                    authoritative=True
                )
        except:
            pass

        # Record not found
        return DNSResponse(
            query=query,
            response_type=ResponseType.NXDOMAIN,
            answer=self._create_nxdomain_response(query.original_message),
            response_time=0.001,
            authoritative=True
        )

    # Helper methods for creating DNS responses
    def _create_blocked_response(self, original_message: dns.message.Message, reason: str) -> dns.message.Message:
        """Create response for blocked domains"""
        response = dns.message.make_response(original_message)

        # Return NXDOMAIN for blocked domains
        response.set_rcode(dns.rcode.NXDOMAIN)

        # Add custom TXT record with block reason if requested
        if self.config.get('include_block_reason', False):
            txt_data = f"Blocked: {reason}"
            # Add TXT record logic here

        return response

    def _create_redirect_response(self, original_message: dns.message.Message, redirect_ip: str) -> dns.message.Message:
        """Create response that redirects to specific IP"""
        response = dns.message.make_response(original_message)

        # Create A record pointing to redirect IP
        if original_message.question:
            question = original_message.question[0]
            rdata = dns.rdata.from_text('IN', 'A', redirect_ip)
            rrset = dns.rrset.from_rdata(question.name, 300, rdata)
            response.answer = [rrset]

        return response

    def _create_servfail_response(self, original_message: dns.message.Message) -> bytes:
        """Create SERVFAIL response"""
        if original_message:
            response = dns.message.make_response(original_message)
            response.set_rcode(dns.rcode.SERVFAIL)
            return response.to_wire()
        else:
            # Create minimal SERVFAIL response
            response = dns.message.Message()
            response.set_rcode(dns.rcode.SERVFAIL)
            return response.to_wire()

    def _create_format_error_response(self) -> bytes:
        """Create FORMERR response for malformed queries"""
        response = dns.message.Message()
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()

    def _create_refused_response(self, original_message: dns.message.Message) -> bytes:
        """Create REFUSED response"""
        response = dns.message.make_response(original_message)
        response.set_rcode(dns.rcode.REFUSED)
        return response.to_wire()

    def _create_nxdomain_response(self, original_message: dns.message.Message) -> dns.message.Message:
        """Create NXDOMAIN response"""
        response = dns.message.make_response(original_message)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    def _extract_ttl(self, message: dns.message.Message) -> int:
        """Extract TTL from DNS message"""
        if message.answer:
            return message.answer[0].ttl
        return 300  # Default 5 minutes

    # Protocol handlers
    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle TCP DNS client connection"""
        client_ip = writer.get_extra_info('peername')[0]
        self.stats['active_connections'] += 1

        try:
            while True:
                # Read message length (2 bytes)
                length_data = await reader.read(2)
                if not length_data:
                    break

                message_length = struct.unpack('!H', length_data)[0]

                # Read message data
                message_data = await reader.read(message_length)
                if not message_data:
                    break

                # Process query
                response_data = await self.handle_query(message_data, client_ip, 'TCP')

                # Send response with length prefix
                response_length = struct.pack('!H', len(response_data))
                writer.write(response_length + response_data)
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"TCP client error: {e}")
        finally:
            self.stats['active_connections'] -= 1
            writer.close()

    async def _handle_doh_request(self, request):
        """Handle DNS-over-HTTPS POST request"""
        from aiohttp import web

        try:
            query_data = await request.read()
            client_ip = request.remote

            response_data = await self.handle_query(query_data, client_ip, 'DoH')

            return web.Response(
                body=response_data,
                content_type='application/dns-message',
                headers={'Cache-Control': 'max-age=300'}
            )
        except Exception as e:
            self.logger.error(f"DoH request error: {e}")
            return web.Response(status=400)

    async def _handle_doh_get_request(self, request):
        """Handle DNS-over-HTTPS GET request"""
        from aiohttp import web
        import base64

        try:
            dns_param = request.query.get('dns', '')
            if not dns_param:
                return web.Response(status=400, text="Missing 'dns' parameter")

            # Decode base64url
            query_data = base64.urlsafe_b64decode(dns_param + '==')
            client_ip = request.remote

            response_data = await self.handle_query(query_data, client_ip, 'DoH')

            return web.Response(
                body=response_data,
                content_type='application/dns-message',
                headers={'Cache-Control': 'max-age=300'}
            )
        except Exception as e:
            self.logger.error(f"DoH GET request error: {e}")
            return web.Response(status=400)

    async def _handle_dot_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle DNS-over-TLS client connection"""
        client_ip = writer.get_extra_info('peername')[0]
        self.stats['active_connections'] += 1

        try:
            while True:
                # Read message length (2 bytes)  
                length_data = await reader.read(2)
                if not length_data:
                    break

                message_length = struct.unpack('!H', length_data)[0]

                # Read message data
                message_data = await reader.read(message_length)
                if not message_data:
                    break

                # Process query
                response_data = await self.handle_query(message_data, client_ip, 'DoT')

                # Send response with length prefix
                response_length = struct.pack('!H', len(response_data))
                writer.write(response_length + response_data)
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.debug(f"DoT client error: {e}")
        finally:
            self.stats['active_connections'] -= 1
            writer.close()

    # Background tasks
    async def _process_queries(self):
        """Background query processing worker"""
        while self.running:
            try:
                query = await asyncio.wait_for(self.query_queue.get(), timeout=1.0)
                # Process query
                await self._process_single_query(query)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Query processing error: {e}")

    async def _cleanup_task(self):
        """Background cleanup task"""
        while self.running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                # Clean old cache entries
                current_time = time.time()
                expired_keys = []

                for key, data in self.response_cache.items():
                    if current_time - data['timestamp'] > data.get('ttl', 300):
                        expired_keys.append(key)

                for key in expired_keys:
                    del self.response_cache[key]

                # Clean old rate limit entries
                for client_ip in list(self.rate_limits.keys()):
                    rate_data = self.rate_limits[client_ip]
                    if current_time - rate_data['last_reset'] > 60:  # Reset every minute
                        del self.rate_limits[client_ip]

                self.logger.debug(f"Cleanup: Removed {len(expired_keys)} cache entries")

            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")

    async def _health_check_task(self):
        """Background health check for upstream servers"""
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds

                for server in self.upstream_servers:
                    try:
                        start_time = time.time()

                        # Simple health check query
                        resolver = Resolver()
                        resolver.nameservers = [server]
                        resolver.timeout = 5

                        await asyncio.get_event_loop().run_in_executor(
                            None, resolver.resolve, 'google.com', 'A'
                        )

                        response_time = time.time() - start_time
                        await self._update_upstream_health(server, True, response_time)

                    except Exception as e:
                        self.logger.warning(f"Upstream server {server} health check failed: {e}")
                        await self._update_upstream_health(server, False, 0)

            except Exception as e:
                self.logger.error(f"Health check task error: {e}")

    async def _stats_collection_task(self):
        """Background statistics collection"""
        while self.running:
            try:
                await asyncio.sleep(60)  # Collect every minute

                # Calculate average response time
                if self.stats['response_times']:
                    avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times'])
                else:
                    avg_response_time = 0

                # Log statistics
                self.logger.info(
                    f"📊 Stats: Queries={self.stats['queries_total']}, "
                    f"Cached={self.stats['queries_cached']}, "
                    f"Blocked={self.stats['queries_blocked']}, "
                    f"Avg Response={avg_response_time:.3f}s"
                )

            except Exception as e:
                self.logger.error(f"Stats collection error: {e}")

    # Utility methods
    async def _initialize_upstream_resolvers(self):
        """Initialize upstream DNS resolvers"""
        for server in self.upstream_servers:
            resolver = Resolver()
            resolver.nameservers = [server]
            resolver.timeout = self.query_timeout
            resolver.lifetime = self.query_timeout
            self.upstream_resolvers.append(resolver)

            # Initialize health status
            self.upstream_health[server] = {
                'healthy': True,
                'response_time': 0.05,
                'last_check': time.time()
            }

        self.logger.info(f"🔄 Initialized {len(self.upstream_resolvers)} upstream resolvers")

    async def _load_authoritative_zones(self):
        """Load authoritative DNS zones"""
        try:
            zones_dir = self.config.get('zones_directory', 'config/dns_zones')
            import os

            if os.path.exists(zones_dir):
                for filename in os.listdir(zones_dir):
                    if filename.endswith('.zone'):
                        zone_file = os.path.join(zones_dir, filename)
                        zone_name = filename[:-5]  # Remove .zone extension

                        try:
                            zone = dns.zone.from_file(zone_file, zone_name)
                            self.authoritative_zones[zone_name] = zone
                            self.logger.info(f"📄 Loaded authoritative zone: {zone_name}")
                        except Exception as e:
                            self.logger.error(f"Failed to load zone {zone_file}: {e}")

        except Exception as e:
            self.logger.error(f"Error loading authoritative zones: {e}")

    async def _initialize_geo_dns(self):
        """Initialize GeoDNS functionality"""
        try:
            # In production, load GeoIP database
            geo_db_path = self.config.get('geo_database', 'data/GeoLite2-Country.mmdb')
            # Placeholder for GeoIP integration
            self.logger.info("🌍 GeoDNS initialized (placeholder)")
        except Exception as e:
            self.logger.warning(f"Could not initialize GeoDNS: {e}")

    async def _initialize_rate_limiting(self):
        """Initialize rate limiting"""
        self.rate_limit_config = self.config.get('performance', {}).get('rate_limiting', {})
        self.rate_limit_enabled = self.rate_limit_config.get('enabled', False)
        self.requests_per_second = self.rate_limit_config.get('requests_per_second', 100)
        self.burst_limit = self.rate_limit_config.get('burst_limit', 200)

        if self.rate_limit_enabled:
            self.logger.info(f"⏱️  Rate limiting enabled: {self.requests_per_second} req/s")

    async def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client is rate limited"""
        if not self.rate_limit_enabled:
            return False

        current_time = time.time()

        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = {
                'requests': 0,
                'last_reset': current_time,
                'burst_used': 0
            }

        rate_data = self.rate_limits[client_ip]

        # Reset counter if needed
        if current_time - rate_data['last_reset'] >= 1.0:
            rate_data['requests'] = 0
            rate_data['last_reset'] = current_time
            rate_data['burst_used'] = 0

        # Check rate limit
        rate_data['requests'] += 1

        if rate_data['requests'] > self.requests_per_second:
            if rate_data['burst_used'] < self.burst_limit:
                rate_data['burst_used'] += 1
                return False
            else:
                return True

        return False

    async def _update_upstream_health(self, server: str, healthy: bool, response_time: float):
        """Update upstream server health status"""
        if server in self.upstream_health:
            self.upstream_health[server].update({
                'healthy': healthy,
                'response_time': response_time,
                'last_check': time.time()
            })

    async def _get_geo_optimal_server(self, client_ip: str, servers: List[Tuple[str, float]]) -> Optional[str]:
        """Get geographically optimal server (placeholder)"""
        # In production, this would use GeoIP to find closest server
        return None

    async def _forward_query_to_server(self, query: DNSQuery, server: str) -> DNSResponse:
        """Forward query to specific upstream server"""
        start_time = time.time()

        try:
            resolver = Resolver()
            resolver.nameservers = [server]
            resolver.timeout = self.query_timeout

            answers = resolver.resolve(query.domain, query.qtype)

            response_msg = dns.message.make_response(query.original_message)
            response_msg.answer = [answers.rrset]

            return DNSResponse(
                query=query,
                response_type=ResponseType.ANSWER,
                answer=response_msg,
                response_time=time.time() - start_time,
                upstream_server=server
            )

        except Exception as e:
            return DNSResponse(
                query=query,
                response_type=ResponseType.NXDOMAIN,
                answer=self._create_servfail_response(query.original_message),
                response_time=time.time() - start_time
            )

    async def stop(self):
        """Stop DNS server gracefully"""
        self.running = False

        # Close all servers
        for server in self.servers:
            if hasattr(server, 'close'):
                server.close()
                if hasattr(server, 'wait_closed'):
                    await server.wait_closed()

        # Application Layer Filtering (DPI) - Deep Packet Inspection
        if self.application_layer_filtering:
            try:
                dpi_analysis = await self.application_layer_filtering.analyze_packet(
                    query.original_message, 
                    query.client_ip,
                    self.listen_address,
                    0,  # source port unknown in DNS context
                    self.listen_port
                )

                # Check if packet should be blocked based on DPI
                if dpi_analysis.threat_level.value in ['high', 'critical']:
                    self.stats['dpi_blocked'] += 1
                    self.logger.warning(f"DPI blocked query from {query.client_ip} for {qname}: {dpi_analysis.threats_detected}")
                    return self._create_blocked_response(query, f"DPI blocked: {', '.join(dpi_analysis.threats_detected[:3])}")

            except Exception as e:
                self.logger.error(f"Error in DPI analysis: {e}")

        # Bandwidth Throttling check
        if self.bandwidth_throttling:
            try:
                should_throttle, reason, delay = await self.bandwidth_throttling.should_throttle_request(
                    query.client_ip, len(query.original_message)
                )

                if should_throttle:
                    if delay:
                        # Graceful throttling - add delay
                        await asyncio.sleep(delay)
                        await self.bandwidth_throttling.record_throttled_request(query.client_ip, f"delayed_{reason}")
                    else:
                        # Hard throttling - block request
                        await self.bandwidth_throttling.record_throttled_request(query.client_ip, reason)
                        self.stats['bandwidth_throttled'] += 1
                        self.logger.debug(f"Bandwidth throttled query from {query.client_ip}: {reason}")
                        return self._create_refused_response(query, f"Throttled: {reason}")

            except Exception as e:
                self.logger.error(f"Error in bandwidth throttling: {e}")

        # Brand Protection - Typosquatting detection
        if self.brand_protection:
            try:
                threat = await self.brand_protection.analyze_domain_query(qname, query.client_ip)
                if threat and threat.risk_level in ['high', 'critical']:
                    self.stats['typosquatting_blocked'] += 1
                    self.logger.warning(f"Brand protection blocked {qname} from {query.client_ip}: {threat.threat_type} (similarity: {threat.similarity_score:.2f})")

                    # Create custom response for typosquatting
                    if threat.threat_type == 'typosquatting':
                        return self._create_blocked_response(query, f"Potential typosquatting detected: {qname}")
                    elif threat.threat_type == 'homograph_attack':
                        return self._create_blocked_response(query, f"Homograph attack detected: {qname}")
                    else:
                        return self._create_blocked_response(query, f"Brand protection triggered: {threat.threat_type}")

            except Exception as e:
                self.logger.error(f"Error in brand protection: {e}")

        self.logger.info("🛑 DNS Server stopped")

    def get_stats(self) -> Dict:
        """Get server statistics"""
        avg_response_time = 0
        if self.stats['response_times']:
            avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times'])
from ..security.brand_protection import BrandProtectionEngine
from ..security.bandwidth_throttling import BandwidthThrottlingEngine
from ..security.application_layer_filtering import ApplicationLayerFilteringEngine

        return {
            'queries_total': self.stats['queries_total'],
            'queries_cached': self.stats['queries_cached'],
            'queries_blocked': self.stats['queries_blocked'],
            'queries_forwarded': self.stats['queries_forwarded'],
            'active_connections': self.stats['active_connections'],
            'average_response_time': avg_response_time,
            'cache_hit_rate': (self.stats['queries_cached'] / max(self.stats['queries_total'], 1)) * 100,
            'block_rate': (self.stats['queries_blocked'] / max(self.stats['queries_total'], 1)) * 100,
            'upstream_health': self.upstream_health,
            'authoritative_zones': list(self.authoritative_zones.keys())
        }

# Add advanced security statistics
if self.brand_protection:
    try:
        brand_stats = await self.brand_protection.get_threat_statistics()
        stats_data['brand_protection'] = brand_stats
    except Exception as e:
        self.logger.error(f"Error getting brand protection stats: {e}")

if self.bandwidth_throttling:
    try:
        throttling_stats = await self.bandwidth_throttling.get_throttling_statistics()
        stats_data['bandwidth_throttling'] = throttling_stats
    except Exception as e:
        self.logger.error(f"Error getting bandwidth throttling stats: {e}")

if self.application_layer_filtering:
    try:
        dpi_stats = await self.application_layer_filtering.get_dpi_statistics()
        stats_data['application_layer_filtering'] = dpi_stats
    except Exception as e:
        self.logger.error(f"Error getting DPI stats: {e}")


class UDPDNSProtocol(asyncio.DatagramProtocol):
    """UDP Protocol handler for DNS server"""

    def __init__(self, dns_server: AdvancedDNSServer):
        self.dns_server = dns_server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP DNS query"""
        client_ip, client_port = addr

        # Process query asynchronously
        asyncio.create_task(self._handle_query(data, client_ip, client_port))

    async def _handle_query(self, data: bytes, client_ip: str, client_port: int):
        """Handle UDP DNS query asynchronously"""
        try:
            response_data = await self.dns_server.handle_query(data, client_ip, 'UDP')
            self.transport.sendto(response_data, (client_ip, client_port))
        except Exception as e:
            self.dns_server.logger.error(f"UDP query handling error: {e}")
