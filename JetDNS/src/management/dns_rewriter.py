"""
JetDNS DNS Rewriter System
Implementiert DNS Rewrites, Custom DNS Rules und Domain-Umleitung
"""

import asyncio
import logging
import re
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import dns.message
import dns.rdata
import dns.rdatatype
import dns.rrset

logger = logging.getLogger(__name__)

class RewriteType(Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NXDOMAIN = "NXDOMAIN"
    NODATA = "NODATA"

@dataclass
class RewriteRule:
    """DNS Rewrite Regel"""
    id: str
    domain: str
    rule_type: RewriteType
    answer: str
    ttl: int = 300
    priority: int = 0
    enabled: bool = True
    description: str = ""
    wildcard: bool = False
    regex: bool = False
    compiled_pattern: Optional[re.Pattern] = None

class DNSRewriter:
    """DNS Rewriter für Custom DNS Rules und Domain-Umleitung"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.rules: Dict[str, RewriteRule] = {}
        self.domain_cache: Dict[str, List[RewriteRule]] = {}
        self.lock = asyncio.Lock()

        # Lade Konfiguration
        self._load_rules()

    async def initialize(self):
        """Initialisiert den DNS Rewriter"""
        await self._compile_rules()
        logger.info(f"🔧 DNS Rewriter initialisiert mit {len(self.rules)} Regeln")

    def _load_rules(self):
        """Lädt DNS Rewrite Regeln aus Konfiguration"""
        try:
            rewrite_config = self.config_manager.get_config('dns_rewrites')

            if not rewrite_config.get('enabled', True):
                logger.info("DNS Rewrites deaktiviert")
                return

            rules_list = rewrite_config.get('rules', [])

            for i, rule_data in enumerate(rules_list):
                rule_id = rule_data.get('id', f"rule_{i}")

                try:
                    rule = RewriteRule(
                        id=rule_id,
                        domain=rule_data['domain'],
                        rule_type=RewriteType(rule_data.get('type', 'A')),
                        answer=rule_data['answer'],
                        ttl=rule_data.get('ttl', 300),
                        priority=rule_data.get('priority', 0),
                        enabled=rule_data.get('enabled', True),
                        description=rule_data.get('description', ''),
                        wildcard='*' in rule_data['domain'],
                        regex=rule_data.get('regex', False)
                    )

                    self.rules[rule_id] = rule

                except Exception as e:
                    logger.error(f"Fehler beim Laden der Regel {rule_id}: {e}")

            logger.info(f"📜 {len(self.rules)} DNS Rewrite Regeln geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der DNS Rewrite Regeln: {e}")

    async def _compile_rules(self):
        """Kompiliert Regex-Pattern für bessere Performance"""
        async with self.lock:
            for rule in self.rules.values():
                try:
                    if rule.regex:
                        # Regex-Pattern kompilieren
                        rule.compiled_pattern = re.compile(rule.domain, re.IGNORECASE)
                    elif rule.wildcard:
                        # Wildcard zu Regex konvertieren
                        pattern = rule.domain.replace('.', r'\.').replace('*', r'[^.]*')
                        rule.compiled_pattern = re.compile(f'^{pattern}$', re.IGNORECASE)

                except Exception as e:
                    logger.error(f"Fehler beim Kompilieren der Regel {rule.id}: {e}")
                    rule.enabled = False

    async def check_rewrite(self, domain: str, qtype: str) -> Optional[RewriteRule]:
        """Prüft ob Domain eine Rewrite-Regel hat"""

        # Normalisiere Domain
        domain = domain.lower().rstrip('.')

        # Cache-Lookup
        cache_key = f"{domain}:{qtype}"
        if cache_key in self.domain_cache:
            rules = self.domain_cache[cache_key]
            return rules[0] if rules else None

        # Finde passende Regeln
        matching_rules = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Typ-Prüfung
            if rule.rule_type.value != qtype and rule.rule_type.value not in ['NXDOMAIN', 'NODATA']:
                continue

            if await self._domain_matches_rule(domain, rule):
                matching_rules.append(rule)

        # Sortiere nach Priorität (höher = wichtiger)
        matching_rules.sort(key=lambda r: r.priority, reverse=True)

        # Cache Ergebnis
        self.domain_cache[cache_key] = matching_rules

        return matching_rules[0] if matching_rules else None

    async def _domain_matches_rule(self, domain: str, rule: RewriteRule) -> bool:
        """Prüft ob Domain zu Regel passt"""
        try:
            if rule.compiled_pattern:
                # Regex oder Wildcard Pattern
                return bool(rule.compiled_pattern.match(domain))
            else:
                # Exakte Übereinstimmung
                return domain == rule.domain.lower().rstrip('.')

        except Exception as e:
            logger.error(f"Fehler beim Domain-Matching für Regel {rule.id}: {e}")
            return False

    async def apply_rewrite(self, original_message: dns.message.Message, 
                          rule: RewriteRule) -> dns.message.Message:
        """Wendet Rewrite-Regel auf DNS-Nachricht an"""
        try:
            response = dns.message.make_response(original_message)
            question = original_message.question[0]

            if rule.rule_type == RewriteType.NXDOMAIN:
                response.set_rcode(dns.rcode.NXDOMAIN)
                return response

            elif rule.rule_type == RewriteType.NODATA:
                # Leere Antwort (NOERROR aber ohne Answer Records)
                response.set_rcode(dns.rcode.NOERROR)
                return response

            # Erstelle Answer Record basierend auf Typ
            elif rule.rule_type == RewriteType.A:
                if self._is_valid_ipv4(rule.answer):
                    rdata = dns.rdata.from_text('IN', 'A', rule.answer)
                    rrset = dns.rrset.from_rdata(question.name, rule.ttl, rdata)
                    response.answer = [rrset]
                else:
                    logger.error(f"Ungültige IPv4 Adresse in Regel {rule.id}: {rule.answer}")
                    response.set_rcode(dns.rcode.SERVFAIL)

            elif rule.rule_type == RewriteType.AAAA:
                if self._is_valid_ipv6(rule.answer):
                    rdata = dns.rdata.from_text('IN', 'AAAA', rule.answer)
                    rrset = dns.rrset.from_rdata(question.name, rule.ttl, rdata)
                    response.answer = [rrset]
                else:
                    logger.error(f"Ungültige IPv6 Adresse in Regel {rule.id}: {rule.answer}")
                    response.set_rcode(dns.rcode.SERVFAIL)

            elif rule.rule_type == RewriteType.CNAME:
                if self._is_valid_domain(rule.answer):
                    rdata = dns.rdata.from_text('IN', 'CNAME', rule.answer)
                    rrset = dns.rrset.from_rdata(question.name, rule.ttl, rdata)
                    response.answer = [rrset]
                else:
                    logger.error(f"Ungültige Domain in CNAME Regel {rule.id}: {rule.answer}")
                    response.set_rcode(dns.rcode.SERVFAIL)

            elif rule.rule_type == RewriteType.TXT:
                rdata = dns.rdata.from_text('IN', 'TXT', f'"{rule.answer}"')
                rrset = dns.rrset.from_rdata(question.name, rule.ttl, rdata)
                response.answer = [rrset]

            elif rule.rule_type == RewriteType.MX:
                # Format: "priority target" z.B. "10 mail.example.com"
                try:
                    parts = rule.answer.split(' ', 1)
                    if len(parts) == 2:
                        priority = int(parts[0])
                        target = parts[1]
                        rdata = dns.rdata.from_text('IN', 'MX', f"{priority} {target}")
                        rrset = dns.rrset.from_rdata(question.name, rule.ttl, rdata)
                        response.answer = [rrset]
                    else:
                        logger.error(f"Ungültiges MX Format in Regel {rule.id}: {rule.answer}")
                        response.set_rcode(dns.rcode.SERVFAIL)
                except ValueError as e:
                    logger.error(f"Fehler beim Parsen der MX Regel {rule.id}: {e}")
                    response.set_rcode(dns.rcode.SERVFAIL)

            return response

        except Exception as e:
            logger.error(f"Fehler beim Anwenden der Rewrite-Regel {rule.id}: {e}")
            response = dns.message.make_response(original_message)
            response.set_rcode(dns.rcode.SERVFAIL)
            return response

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Prüft ob IP eine gültige IPv4 Adresse ist"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Prüft ob IP eine gültige IPv6 Adresse ist"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Prüft ob String eine gültige Domain ist"""
        if not domain or len(domain) > 255:
            return False

        # Einfache Domain-Validierung
        allowed = re.compile(r'^[a-zA-Z0-9.-]+$')
        return bool(allowed.match(domain))

    async def add_rule(self, rule_data: Dict) -> bool:
        """Fügt neue Rewrite-Regel hinzu"""
        try:
            rule_id = rule_data.get('id', f"rule_{len(self.rules)}")

            rule = RewriteRule(
                id=rule_id,
                domain=rule_data['domain'],
                rule_type=RewriteType(rule_data.get('type', 'A')),
                answer=rule_data['answer'],
                ttl=rule_data.get('ttl', 300),
                priority=rule_data.get('priority', 0),
                enabled=rule_data.get('enabled', True),
                description=rule_data.get('description', ''),
                wildcard='*' in rule_data['domain'],
                regex=rule_data.get('regex', False)
            )

            # Kompiliere Pattern
            if rule.regex or rule.wildcard:
                await self._compile_single_rule(rule)

            async with self.lock:
                self.rules[rule_id] = rule
                self.domain_cache.clear()  # Cache invalidieren

            await self._save_rules()

            logger.info(f"📜 DNS Rewrite Regel hinzugefügt: {rule_id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Hinzufügen der DNS Regel: {e}")
            return False

    async def _compile_single_rule(self, rule: RewriteRule):
        """Kompiliert Pattern für einzelne Regel"""
        try:
            if rule.regex:
                rule.compiled_pattern = re.compile(rule.domain, re.IGNORECASE)
            elif rule.wildcard:
                pattern = rule.domain.replace('.', r'\.').replace('*', r'[^.]*')
                rule.compiled_pattern = re.compile(f'^{pattern}$', re.IGNORECASE)
        except Exception as e:
            logger.error(f"Fehler beim Kompilieren der Regel {rule.id}: {e}")
            rule.enabled = False

    async def update_rule(self, rule_id: str, rule_data: Dict) -> bool:
        """Aktualisiert bestehende Regel"""
        if rule_id not in self.rules:
            return False

        try:
            rule = self.rules[rule_id]

            rule.domain = rule_data.get('domain', rule.domain)
            rule.rule_type = RewriteType(rule_data.get('type', rule.rule_type.value))
            rule.answer = rule_data.get('answer', rule.answer)
            rule.ttl = rule_data.get('ttl', rule.ttl)
            rule.priority = rule_data.get('priority', rule.priority)
            rule.enabled = rule_data.get('enabled', rule.enabled)
            rule.description = rule_data.get('description', rule.description)
            rule.wildcard = '*' in rule.domain
            rule.regex = rule_data.get('regex', rule.regex)

            # Neu kompilieren
            if rule.regex or rule.wildcard:
                await self._compile_single_rule(rule)

            async with self.lock:
                self.domain_cache.clear()  # Cache invalidieren

            await self._save_rules()

            logger.info(f"📜 DNS Rewrite Regel aktualisiert: {rule_id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren der DNS Regel {rule_id}: {e}")
            return False

    async def delete_rule(self, rule_id: str) -> bool:
        """Löscht Rewrite-Regel"""
        if rule_id not in self.rules:
            return False

        try:
            async with self.lock:
                del self.rules[rule_id]
                self.domain_cache.clear()  # Cache invalidieren

            await self._save_rules()

            logger.info(f"📜 DNS Rewrite Regel gelöscht: {rule_id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Löschen der DNS Regel {rule_id}: {e}")
            return False

    async def get_all_rules(self) -> List[Dict]:
        """Gibt alle Regeln zurück"""
        rules = []
        for rule in self.rules.values():
            rules.append({
                'id': rule.id,
                'domain': rule.domain,
                'type': rule.rule_type.value,
                'answer': rule.answer,
                'ttl': rule.ttl,
                'priority': rule.priority,
                'enabled': rule.enabled,
                'description': rule.description,
                'wildcard': rule.wildcard,
                'regex': rule.regex
            })
        return sorted(rules, key=lambda r: r['priority'], reverse=True)

    async def get_rule_stats(self) -> Dict:
        """Gibt Statistiken über Regeln zurück"""
        total_rules = len(self.rules)
        enabled_rules = sum(1 for r in self.rules.values() if r.enabled)

        type_counts = {}
        for rule in self.rules.values():
            rule_type = rule.rule_type.value
            type_counts[rule_type] = type_counts.get(rule_type, 0) + 1

        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': total_rules - enabled_rules,
            'type_distribution': type_counts,
            'cache_entries': len(self.domain_cache)
        }

    async def _save_rules(self):
        """Speichert Regeln in Konfiguration"""
        try:
            rules_list = []
            for rule in self.rules.values():
                rules_list.append({
                    'id': rule.id,
                    'domain': rule.domain,
                    'type': rule.rule_type.value,
                    'answer': rule.answer,
                    'ttl': rule.ttl,
                    'priority': rule.priority,
                    'enabled': rule.enabled,
                    'description': rule.description,
                    'regex': rule.regex
                })

            self.config_manager.set_value('dns_rewrites', 'rules', rules_list)

        except Exception as e:
            logger.error(f"Fehler beim Speichern der DNS Rewrite Regeln: {e}")

    async def clear_cache(self):
        """Leert den Domain-Cache"""
        async with self.lock:
            self.domain_cache.clear()
        logger.info("📜 DNS Rewriter Cache geleert")

    async def test_rule(self, domain: str, qtype: str) -> Dict:
        """Testet eine Domain gegen alle Regeln"""
        rule = await self.check_rewrite(domain, qtype)

        return {
            'domain': domain,
            'qtype': qtype,
            'matched_rule': {
                'id': rule.id,
                'rule_type': rule.rule_type.value,
                'answer': rule.answer,
                'description': rule.description
            } if rule else None,
            'would_rewrite': rule is not None
        }

    def reload_config(self):
        """Lädt Konfiguration neu"""
        self.rules.clear()
        self.domain_cache.clear()
        self._load_rules()
        asyncio.create_task(self._compile_rules())
        logger.info("📜 DNS Rewriter Konfiguration neu geladen")
