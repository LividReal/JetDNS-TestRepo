"""
JetDNS Response Policy Zones (RPZ) Manager
Erweiterte Policy-Implementierung für granulare DNS-Kontrolle
"""

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset
import dns.zone

logger = logging.getLogger(__name__)

class RPZAction(Enum):
    """RPZ Policy Actions"""
    NXDOMAIN = "NXDOMAIN"
    NODATA = "NODATA"
    DROP = "DROP"
    TCP_ONLY = "TCP-Only"
    TRUNCATE = "TRUNCATE"
    REDIRECT = "REDIRECT"
    PASSTHRU = "PASSTHRU"
    LOCAL_DATA = "LOCAL-DATA"

class RPZTrigger(Enum):
    """RPZ Trigger Types"""
    QNAME = "QNAME"
    CLIENT_IP = "CLIENT-IP"
    IP = "IP"
    NSDNAME = "NSDNAME"
    NSIP = "NSIP"

@dataclass
class RPZRule:
    """RPZ Policy Rule"""
    id: str
    name: str
    trigger: RPZTrigger
    pattern: str
    action: RPZAction
    substitute: str = ""
    priority: int = 100
    enabled: bool = True
    created_at: datetime = None
    updated_at: datetime = None
    hit_count: int = 0
    description: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class RPZZone:
    """RPZ Zone Configuration"""
    name: str
    description: str
    enabled: bool = True
    priority: int = 1
    policy_action: RPZAction = RPZAction.NXDOMAIN
    rules: Dict[str, RPZRule] = None
    feeds: List[str] = None
    auto_update: bool = False
    update_interval: int = 3600  # Sekunden
    last_update: datetime = None

    def __post_init__(self):
        if self.rules is None:
            self.rules = {}
        if self.feeds is None:
            self.feeds = []

class RPZManager:
    """Response Policy Zones Manager"""

    def __init__(self, config_manager, threat_intelligence=None):
        self.config_manager = config_manager
        self.threat_intelligence = threat_intelligence
        self.config = {}

        # RPZ Zones
        self.zones: Dict[str, RPZZone] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}

        # Performance Caches
        self.query_cache: Dict[str, Tuple[RPZAction, str, int]] = {}  # query -> (action, substitute, ttl)
        self.negative_cache: Set[str] = set()  # Queries die keine RPZ Matches haben

        # Statistiken
        self.stats = {
            'total_zones': 0,
            'total_rules': 0,
            'queries_processed': 0,
            'policy_hits': 0,
            'cache_hits': 0,
            'actions': {action.value: 0 for action in RPZAction}
        }

        self.lock = asyncio.Lock()

    async def initialize(self):
        """Initialisiert RPZ Manager"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("RPZ (Response Policy Zones) deaktiviert")
            return

        await self._load_zones()
        await self._compile_patterns()

        # Background Tasks
        asyncio.create_task(self._zone_update_task())
        asyncio.create_task(self._cache_cleanup_task())
        asyncio.create_task(self._statistics_task())

        logger.info(f"🛡️  RPZ Manager initialisiert - {len(self.zones)} Zones, {sum(len(z.rules) for z in self.zones.values())} Rules")

    async def _load_config(self):
        """Lädt RPZ Konfiguration"""
        self.config = self.config_manager.get_config('rpz', {
            'enabled': True,
            'cache_size': 10000,
            'cache_ttl': 300,
            'max_rules_per_zone': 100000,
            'performance_mode': True,
            'log_policy_hits': True,
            'default_zones': [
                {
                    'name': 'malware-protection',
                    'description': 'Malware and Phishing Protection',
                    'priority': 1,
                    'policy_action': 'NXDOMAIN',
                    'feeds': [
                        'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                        'https://someonewhocares.org/hosts/zero/hosts'
                    ],
                    'auto_update': True
                },
                {
                    'name': 'threat-intelligence',
                    'description': 'Threat Intelligence Feeds',
                    'priority': 2,
                    'policy_action': 'NXDOMAIN',
                    'feeds': [],
                    'auto_update': True
                },
                {
                    'name': 'custom-policies',
                    'description': 'Custom Organization Policies',
                    'priority': 10,
                    'policy_action': 'REDIRECT',
                    'feeds': [],
                    'auto_update': False
                }
            ]
        })

    async def _load_zones(self):
        """Lädt RPZ Zones"""
        try:
            default_zones = self.config.get('default_zones', [])

            for zone_config in default_zones:
                zone = RPZZone(
                    name=zone_config['name'],
                    description=zone_config['description'],
                    priority=zone_config.get('priority', 1),
                    policy_action=RPZAction(zone_config.get('policy_action', 'NXDOMAIN')),
                    feeds=zone_config.get('feeds', []),
                    auto_update=zone_config.get('auto_update', False)
                )

                self.zones[zone.name] = zone

                # Lade Rules für Zone
                if zone.auto_update and zone.feeds:
                    await self._update_zone_from_feeds(zone.name)

            # Custom Zones aus Konfiguration
            custom_zones = self.config_manager.get_config('rpz_zones', {})
            for zone_name, zone_data in custom_zones.items():
                if zone_name not in self.zones:
                    zone = RPZZone(
                        name=zone_name,
                        description=zone_data.get('description', ''),
                        enabled=zone_data.get('enabled', True),
                        priority=zone_data.get('priority', 5),
                        policy_action=RPZAction(zone_data.get('policy_action', 'NXDOMAIN'))
                    )

                    # Lade Rules
                    for rule_id, rule_data in zone_data.get('rules', {}).items():
                        rule = RPZRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            trigger=RPZTrigger(rule_data['trigger']),
                            pattern=rule_data['pattern'],
                            action=RPZAction(rule_data.get('action', zone.policy_action.value)),
                            substitute=rule_data.get('substitute', ''),
                            priority=rule_data.get('priority', 100),
                            enabled=rule_data.get('enabled', True),
                            description=rule_data.get('description', ''),
                            tags=rule_data.get('tags', [])
                        )

                        zone.rules[rule_id] = rule

                    self.zones[zone_name] = zone

            self.stats['total_zones'] = len(self.zones)
            self.stats['total_rules'] = sum(len(z.rules) for z in self.zones.values())

        except Exception as e:
            logger.error(f"Fehler beim Laden der RPZ Zones: {e}")

    async def _compile_patterns(self):
        """Kompiliert Regex-Pattern für bessere Performance"""
        try:
            async with self.lock:
                self.compiled_patterns.clear()

                for zone in self.zones.values():
                    if not zone.enabled:
                        continue

                    for rule in zone.rules.values():
                        if not rule.enabled:
                            continue

                        pattern_key = f"{zone.name}:{rule.id}"

                        try:
                            if rule.trigger == RPZTrigger.QNAME:
                                # Domain Pattern kompilieren
                                if '*' in rule.pattern:
                                    # Wildcard zu Regex
                                    regex_pattern = rule.pattern.replace('.', r'\.')
                                    regex_pattern = regex_pattern.replace('*', r'[^.]*')
                                    regex_pattern = f'^{regex_pattern}$'
                                else:
                                    # Exakte Domain oder Suffix
                                    if rule.pattern.startswith('.'):
                                        # Suffix Match
                                        regex_pattern = re.escape(rule.pattern) + '$'
                                    else:
                                        # Exakte Domain
                                        regex_pattern = f'^{re.escape(rule.pattern)}$'

                                self.compiled_patterns[pattern_key] = re.compile(regex_pattern, re.IGNORECASE)

                            elif rule.trigger == RPZTrigger.CLIENT_IP:
                                # IP/CIDR Pattern
                                import ipaddress
                                try:
                                    ipaddress.ip_network(rule.pattern, strict=False)
                                    # Valid IP/CIDR - keine Regex nötig
                                except ValueError:
                                    logger.warning(f"Ungültiges IP Pattern in Rule {rule.id}: {rule.pattern}")

                        except Exception as e:
                            logger.error(f"Pattern Compilation fehlgeschlagen für Rule {rule.id}: {e}")

                logger.info(f"🛡️  {len(self.compiled_patterns)} RPZ Patterns kompiliert")

        except Exception as e:
            logger.error(f"Fehler bei Pattern-Compilation: {e}")

    async def check_rpz_policy(self, query: dns.message.Message, 
                              client_ip: str, response: dns.message.Message = None) -> Optional[Tuple[RPZAction, str]]:
        """Prüft Query gegen RPZ Policies"""

        if not self.config.get('enabled', False):
            return None

        self.stats['queries_processed'] += 1

        try:
            if not query.question:
                return None

            question = query.question[0]
            qname = str(question.name).lower().rstrip('.')
            qtype = dns.rdatatype.to_text(question.rdtype)

            # Cache Check
            cache_key = f"{client_ip}:{qname}:{qtype}"

            if cache_key in self.query_cache:
                action, substitute, expire_time = self.query_cache[cache_key]
                if time.time() < expire_time:
                    self.stats['cache_hits'] += 1
                    return action, substitute
                else:
                    del self.query_cache[cache_key]

            if cache_key in self.negative_cache:
                return None

            # Policy Check
            policy_result = await self._evaluate_policies(qname, qtype, client_ip, response)

            # Cache Result
            cache_ttl = self.config.get('cache_ttl', 300)
            expire_time = time.time() + cache_ttl

            if policy_result:
                action, substitute = policy_result
                self.query_cache[cache_key] = (action, substitute, expire_time)
                self.stats['policy_hits'] += 1
                self.stats['actions'][action.value] += 1

                if self.config.get('log_policy_hits', True):
                    logger.info(f"RPZ Policy Hit: {qname} -> {action.value} ({substitute})")

                return policy_result
            else:
                self.negative_cache.add(cache_key)

                # Negative Cache Cleanup
                if len(self.negative_cache) > self.config.get('cache_size', 10000):
                    self.negative_cache.clear()

        except Exception as e:
            logger.error(f"Fehler bei RPZ Policy Check: {e}")

        return None

    async def _evaluate_policies(self, qname: str, qtype: str, client_ip: str, 
                               response: dns.message.Message = None) -> Optional[Tuple[RPZAction, str]]:
        """Evaluiert RPZ Policies in Prioritäts-Reihenfolge"""

        # Sortiere Zones nach Priorität
        sorted_zones = sorted(
            [z for z in self.zones.values() if z.enabled],
            key=lambda x: x.priority
        )

        for zone in sorted_zones:
            # Sortiere Rules nach Priorität
            sorted_rules = sorted(
                [r for r in zone.rules.values() if r.enabled],
                key=lambda x: x.priority
            )

            for rule in sorted_rules:
                match_result = await self._evaluate_rule(rule, zone, qname, qtype, client_ip, response)

                if match_result:
                    # Rule Hit - update statistics
                    rule.hit_count += 1
                    rule.updated_at = datetime.now()

                    action = rule.action if rule.action != RPZAction.PASSTHRU else None
                    if action is None:
                        continue  # PASSTHRU - prüfe nächste Rule

                    substitute = rule.substitute

                    # Spezielle Action-Verarbeitung
                    if action == RPZAction.REDIRECT:
                        if not substitute:
                            substitute = "blocked.jetdns.local"
                    elif action == RPZAction.LOCAL_DATA:
                        if not substitute:
                            substitute = "127.0.0.1"

                    return action, substitute

        return None

    async def _evaluate_rule(self, rule: RPZRule, zone: RPZZone, qname: str, qtype: str, 
                           client_ip: str, response: dns.message.Message = None) -> bool:
        """Evaluiert einzelne RPZ Rule"""

        try:
            if rule.trigger == RPZTrigger.QNAME:
                return await self._match_qname(rule, zone, qname)

            elif rule.trigger == RPZTrigger.CLIENT_IP:
                return await self._match_client_ip(rule, client_ip)

            elif rule.trigger == RPZTrigger.IP:
                if response:
                    return await self._match_response_ip(rule, response)

            elif rule.trigger == RPZTrigger.NSDNAME:
                if response:
                    return await self._match_ns_domain(rule, response)

            elif rule.trigger == RPZTrigger.NSIP:
                if response:
                    return await self._match_ns_ip(rule, response)

        except Exception as e:
            logger.debug(f"Rule evaluation error for {rule.id}: {e}")

        return False

    async def _match_qname(self, rule: RPZRule, zone: RPZZone, qname: str) -> bool:
        """Matcht QNAME gegen Rule Pattern"""

        pattern_key = f"{zone.name}:{rule.id}"

        if pattern_key in self.compiled_patterns:
            # Regex Match
            return bool(self.compiled_patterns[pattern_key].match(qname))
        else:
            # Fallback: String Match
            if '*' in rule.pattern:
                # Einfacher Wildcard Match
                pattern = rule.pattern.replace('*', '')
                return pattern in qname
            else:
                # Exakt oder Suffix
                if rule.pattern.startswith('.'):
                    return qname.endswith(rule.pattern)
                else:
                    return qname == rule.pattern

        return False

    async def _match_client_ip(self, rule: RPZRule, client_ip: str) -> bool:
        """Matcht Client IP gegen Rule Pattern"""

        try:
            import ipaddress

            client_addr = ipaddress.ip_address(client_ip)

            if '/' in rule.pattern:
                # CIDR Block
                network = ipaddress.ip_network(rule.pattern, strict=False)
                return client_addr in network
            else:
                # Einzelne IP
                rule_addr = ipaddress.ip_address(rule.pattern)
                return client_addr == rule_addr

        except ValueError:
            return False

    async def _match_response_ip(self, rule: RPZRule, response: dns.message.Message) -> bool:
        """Matcht Response IP Adressen gegen Rule Pattern"""

        try:
            import ipaddress

            for rrset in response.answer:
                if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                    for rdata in rrset:
                        ip_str = str(rdata)

                        if await self._match_client_ip(rule, ip_str):
                            return True

        except Exception as e:
            logger.debug(f"Response IP matching error: {e}")

        return False

    async def _match_ns_domain(self, rule: RPZRule, response: dns.message.Message) -> bool:
        """Matcht NS Domain Namen gegen Rule Pattern"""

        try:
            for rrset in response.authority + response.answer:
                if rrset.rdtype == dns.rdatatype.NS:
                    for rdata in rrset:
                        ns_name = str(rdata.target).lower().rstrip('.')

                        # Verwende QNAME Matching Logic
                        temp_rule = RPZRule(
                            id="temp",
                            name="temp",
                            trigger=RPZTrigger.QNAME,
                            pattern=rule.pattern,
                            action=rule.action
                        )

                        if await self._match_qname(temp_rule, None, ns_name):
                            return True

        except Exception as e:
            logger.debug(f"NS domain matching error: {e}")

        return False

    async def _match_ns_ip(self, rule: RPZRule, response: dns.message.Message) -> bool:
        """Matcht NS IP Adressen gegen Rule Pattern"""

        # Ähnlich wie _match_response_ip aber für NS Records
        return await self._match_response_ip(rule, response)

    async def apply_rpz_action(self, query: dns.message.Message, action: RPZAction, 
                             substitute: str) -> dns.message.Message:
        """Wendet RPZ Action auf Query an"""

        try:
            if action == RPZAction.NXDOMAIN:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NXDOMAIN)
                return response

            elif action == RPZAction.NODATA:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NOERROR)
                # Keine Answer Records
                return response

            elif action == RPZAction.DROP:
                # Keine Response senden
                return None

            elif action == RPZAction.TRUNCATE:
                response = dns.message.make_response(query)
                response.flags |= dns.flags.TC
                return response

            elif action == RPZAction.TCP_ONLY:
                # Forciere TCP
                response = dns.message.make_response(query)
                response.flags |= dns.flags.TC
                return response

            elif action == RPZAction.REDIRECT:
                response = dns.message.make_response(query)
                question = query.question[0]

                # Erstelle Redirect Record
                if question.rdtype == dns.rdatatype.A:
                    # Redirect zu IP
                    try:
                        import ipaddress
                        ipaddress.IPv4Address(substitute)  # Validate IP

                        rdata = dns.rdata.from_text('IN', 'A', substitute)
                        rrset = dns.rrset.from_rdata(question.name, 300, rdata)
                        response.answer = [rrset]
                    except ValueError:
                        # Redirect zu Domain (CNAME)
                        rdata = dns.rdata.from_text('IN', 'CNAME', substitute)
                        rrset = dns.rrset.from_rdata(question.name, 300, rdata)
                        response.answer = [rrset]

                return response

            elif action == RPZAction.LOCAL_DATA:
                response = dns.message.make_response(query)
                question = query.question[0]

                # Custom Data
                try:
                    rdata = dns.rdata.from_text('IN', dns.rdatatype.to_text(question.rdtype), substitute)
                    rrset = dns.rrset.from_rdata(question.name, 300, rdata)
                    response.answer = [rrset]
                except Exception:
                    # Fallback zu A Record
                    rdata = dns.rdata.from_text('IN', 'A', substitute)
                    rrset = dns.rrset.from_rdata(question.name, 300, rdata)
                    response.answer = [rrset]

                return response

        except Exception as e:
            logger.error(f"Fehler bei RPZ Action {action.value}: {e}")

        # Fallback: NXDOMAIN
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    async def add_rule(self, zone_name: str, rule_data: Dict) -> bool:
        """Fügt neue RPZ Rule hinzu"""

        try:
            if zone_name not in self.zones:
                return False

            rule = RPZRule(
                id=rule_data.get('id', f"rule_{len(self.zones[zone_name].rules)}"),
                name=rule_data['name'],
                trigger=RPZTrigger(rule_data['trigger']),
                pattern=rule_data['pattern'],
                action=RPZAction(rule_data.get('action', 'NXDOMAIN')),
                substitute=rule_data.get('substitute', ''),
                priority=rule_data.get('priority', 100),
                enabled=rule_data.get('enabled', True),
                description=rule_data.get('description', ''),
                tags=rule_data.get('tags', [])
            )

            self.zones[zone_name].rules[rule.id] = rule

            # Pattern neu kompilieren
            await self._compile_patterns()

            # Konfiguration speichern
            await self._save_zone_config(zone_name)

            logger.info(f"RPZ Rule hinzugefügt: {zone_name}:{rule.id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Hinzufügen der RPZ Rule: {e}")
            return False

    async def _update_zone_from_feeds(self, zone_name: str):
        """Aktualisiert Zone aus Feeds"""

        if zone_name not in self.zones:
            return

        zone = self.zones[zone_name]

        try:
            import aiohttp

            for feed_url in zone.feeds:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(feed_url, timeout=30) as response:
                            if response.status == 200:
                                content = await response.text()
                                await self._parse_feed_content(zone_name, content, feed_url)

                except Exception as e:
                    logger.error(f"Feed Update fehlgeschlagen für {feed_url}: {e}")

            zone.last_update = datetime.now()
            logger.info(f"RPZ Zone {zone_name} von Feeds aktualisiert")

        except Exception as e:
            logger.error(f"Fehler beim Zone Feed Update: {e}")

    async def _parse_feed_content(self, zone_name: str, content: str, feed_url: str):
        """Parst Feed Content und erstellt Rules"""

        lines = content.strip().split('\n')
        rules_added = 0

        for line in lines:
            line = line.strip()

            # Skip Kommentare und leere Zeilen
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # Hosts Format: IP DOMAIN
            if line.startswith(('127.0.0.1', '0.0.0.0', '::1')):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].lower()

                    if self._is_valid_domain(domain):
                        rule_id = f"feed_{hash(domain)}_{rules_added}"

                        rule = RPZRule(
                            id=rule_id,
                            name=f"Feed: {domain}",
                            trigger=RPZTrigger.QNAME,
                            pattern=domain,
                            action=RPZAction.NXDOMAIN,
                            description=f"Auto-generated from {feed_url}",
                            tags=['feed', 'auto-generated']
                        )

                        self.zones[zone_name].rules[rule_id] = rule
                        rules_added += 1

        logger.info(f"RPZ Zone {zone_name}: {rules_added} Rules aus Feed hinzugefügt")

    def _is_valid_domain(self, domain: str) -> bool:
        """Validiert Domain Name"""

        if not domain or len(domain) > 253:
            return False

        # Einfache Validierung
        if domain in ['localhost', 'local', 'broadcasthost']:
            return False

        # Regex für Domain Validierung
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )

        return bool(domain_pattern.match(domain))

    async def _save_zone_config(self, zone_name: str):
        """Speichert Zone Konfiguration"""

        if zone_name not in self.zones:
            return

        zone = self.zones[zone_name]

        # Konvertiere zu Dict für Speicherung
        zone_config = {
            'description': zone.description,
            'enabled': zone.enabled,
            'priority': zone.priority,
            'policy_action': zone.policy_action.value,
            'rules': {}
        }

        for rule_id, rule in zone.rules.items():
            zone_config['rules'][rule_id] = {
                'name': rule.name,
                'trigger': rule.trigger.value,
                'pattern': rule.pattern,
                'action': rule.action.value,
                'substitute': rule.substitute,
                'priority': rule.priority,
                'enabled': rule.enabled,
                'description': rule.description,
                'tags': rule.tags
            }

        # Speichere in Konfiguration
        zones_config = self.config_manager.get_config('rpz_zones', {})
        zones_config[zone_name] = zone_config
        self.config_manager.set_value('rpz_zones', zones_config)

    async def _zone_update_task(self):
        """Background Task für Zone Updates"""

        while True:
            try:
                await asyncio.sleep(300)  # Alle 5 Minuten prüfen

                for zone in self.zones.values():
                    if zone.auto_update and zone.feeds:
                        # Prüfe ob Update nötig
                        if not zone.last_update or \
                           (datetime.now() - zone.last_update).total_seconds() > 3600:  # 1 Stunde
                            await self._update_zone_from_feeds(zone.name)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Zone Update Task: {e}")

    async def _cache_cleanup_task(self):
        """Background Task für Cache Cleanup"""

        while True:
            try:
                await asyncio.sleep(600)  # Alle 10 Minuten

                # Query Cache bereinigen
                current_time = time.time()
                expired_keys = [
                    key for key, (_, _, expire_time) in self.query_cache.items()
                    if current_time >= expire_time
                ]

                for key in expired_keys:
                    del self.query_cache[key]

                # Negative Cache periodisch leeren
                if len(self.negative_cache) > self.config.get('cache_size', 10000) * 0.8:
                    self.negative_cache.clear()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Cache Cleanup: {e}")

    async def _statistics_task(self):
        """Background Task für Statistiken"""

        while True:
            try:
                await asyncio.sleep(60)  # Minütlich

                # Update Statistiken
                self.stats['total_zones'] = len([z for z in self.zones.values() if z.enabled])
                self.stats['total_rules'] = sum(
                    len([r for r in z.rules.values() if r.enabled]) 
                    for z in self.zones.values() if z.enabled
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Statistics Task: {e}")

    async def get_rpz_stats(self) -> Dict:
        """Gibt RPZ Statistiken zurück"""

        zone_stats = {}
        for zone_name, zone in self.zones.items():
            zone_stats[zone_name] = {
                'enabled': zone.enabled,
                'priority': zone.priority,
                'rules_count': len(zone.rules),
                'enabled_rules': len([r for r in zone.rules.values() if r.enabled]),
                'last_update': zone.last_update.isoformat() if zone.last_update else None,
                'total_hits': sum(r.hit_count for r in zone.rules.values())
            }

        return {
            'enabled': self.config.get('enabled', False),
            'zones': zone_stats,
            'cache_size': len(self.query_cache),
            'negative_cache_size': len(self.negative_cache),
            'compiled_patterns': len(self.compiled_patterns),
            'stats': self.stats
        }

    async def export_zone(self, zone_name: str, format: str = 'json') -> Optional[str]:
        """Exportiert RPZ Zone"""

        if zone_name not in self.zones:
            return None

        zone = self.zones[zone_name]

        if format == 'json':
            import json

            export_data = {
                'zone': {
                    'name': zone.name,
                    'description': zone.description,
                    'priority': zone.priority,
                    'policy_action': zone.policy_action.value,
                    'enabled': zone.enabled
                },
                'rules': []
            }

            for rule in zone.rules.values():
                export_data['rules'].append({
                    'id': rule.id,
                    'name': rule.name,
                    'trigger': rule.trigger.value,
                    'pattern': rule.pattern,
                    'action': rule.action.value,
                    'substitute': rule.substitute,
                    'priority': rule.priority,
                    'enabled': rule.enabled,
                    'description': rule.description,
                    'tags': rule.tags,
                    'hit_count': rule.hit_count
                })

            return json.dumps(export_data, indent=2, ensure_ascii=False)

        return None

    def reload_config(self):
        """Lädt RPZ Konfiguration neu"""
        asyncio.create_task(self._load_config())
        asyncio.create_task(self._load_zones())
        asyncio.create_task(self._compile_patterns())
        logger.info("🛡️  RPZ Konfiguration neu geladen")
