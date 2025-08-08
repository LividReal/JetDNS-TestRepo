"""
JetDNS Parental Controls System
Implementiert umfassende Parental Controls mit zeitbasierten Beschränkungen
"""

import asyncio
import logging
import re
from datetime import datetime, time, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import pytz

logger = logging.getLogger(__name__)

class FilterAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDIRECT = "redirect"

class ContentCategory(Enum):
    ADULT = "adult"
    VIOLENCE = "violence"
    DRUGS = "drugs"
    GAMBLING = "gambling"
    SOCIAL_MEDIA = "social_media"
    STREAMING = "streaming"
    GAMING = "gaming"
    NEWS = "news"
    SHOPPING = "shopping"
    EDUCATION = "education"

@dataclass
class TimeSlot:
    """Zeitfenster für Beschränkungen"""
    name: str
    days: List[str]  # ['mon', 'tue', ...]
    start_time: time
    end_time: time
    strict_mode: bool = False
    blocked_categories: List[ContentCategory] = None
    allowed_sites: List[str] = None
    time_limit_minutes: Optional[int] = None

@dataclass
class FilterRule:
    """Content Filter Regel"""
    id: str
    name: str
    category: ContentCategory
    action: FilterAction
    domains: List[str]
    keywords: List[str]
    priority: int = 0
    enabled: bool = True

class ParentalControls:
    """Parental Controls Management System"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.timezone = pytz.timezone('Europe/Berlin')

        # Filter Regeln
        self.filter_rules: Dict[str, FilterRule] = {}
        self.category_domains: Dict[ContentCategory, Set[str]] = {}

        # Zeitbasierte Beschränkungen
        self.time_slots: Dict[str, TimeSlot] = {}
        self.client_usage: Dict[str, Dict] = {}  # IP -> usage data

        # Service-Definitionen
        self.service_definitions = {
            'social_media': [
                'facebook.com', 'www.facebook.com', 'm.facebook.com',
                'instagram.com', 'www.instagram.com',
                'twitter.com', 'www.twitter.com', 'x.com',
                'snapchat.com', 'www.snapchat.com',
                'tiktok.com', 'www.tiktok.com',
                'discord.com', 'discord.gg',
                'whatsapp.com', 'web.whatsapp.com',
                'telegram.org', 'web.telegram.org',
                'linkedin.com', 'www.linkedin.com',
                'reddit.com', 'www.reddit.com',
                'pinterest.com', 'www.pinterest.com'
            ],
            'streaming': [
                'youtube.com', 'www.youtube.com', 'm.youtube.com',
                'netflix.com', 'www.netflix.com',
                'twitch.tv', 'www.twitch.tv',
                'hulu.com', 'www.hulu.com',
                'disney.com', 'disneyplus.com',
                'amazon.com', 'primevideo.com',
                'spotify.com', 'www.spotify.com',
                'soundcloud.com', 'www.soundcloud.com',
                'deezer.com', 'www.deezer.com',
                'apple.com'  # Apple Music/TV
            ],
            'gaming': [
                'steam.com', 'store.steampowered.com',
                'epicgames.com', 'www.epicgames.com',
                'battle.net', 'us.battle.net', 'eu.battle.net',
                'roblox.com', 'www.roblox.com',
                'minecraft.net', 'www.minecraft.net',
                'fortnite.com', 'www.fortnite.com',
                'xbox.com', 'www.xbox.com',
                'playstation.com', 'www.playstation.com',
                'nintendo.com', 'www.nintendo.com',
                'origin.com', 'www.origin.com',
                'ubisoft.com', 'www.ubisoft.com'
            ],
            'adult': [
                # Wird aus externen Blocklists geladen
            ]
        }

        self.lock = asyncio.Lock()

    async def initialize(self):
        """Initialisiert Parental Controls"""
        await self._load_config()
        await self._load_category_domains()
        await self._setup_usage_tracking()

        # Starte Background Tasks
        asyncio.create_task(self._usage_cleanup_task())
        asyncio.create_task(self._update_safe_search_task())

        logger.info("🔒 Parental Controls initialisiert")

    async def _load_config(self):
        """Lädt Parental Controls Konfiguration"""
        config = self.config_manager.get_config('parental_controls')

        if not config.get('enabled', False):
            logger.info("Parental Controls deaktiviert")
            return

        # Lade Zeitzone
        timezone_str = config.get('time_restrictions', {}).get('timezone', 'Europe/Berlin')
        try:
            self.timezone = pytz.timezone(timezone_str)
        except Exception as e:
            logger.warning(f"Ungültige Zeitzone {timezone_str}, verwende UTC: {e}")
            self.timezone = pytz.UTC

        # Lade Service-Definitionen
        blocked_services = config.get('blocked_services', {})
        for service_name, domains in blocked_services.items():
            if domains and service_name in self.service_definitions:
                self.service_definitions[service_name].extend(domains)

        logger.info(f"🔒 Parental Controls Konfiguration geladen")

    async def _load_category_domains(self):
        """Lädt Domain-Listen für Content-Kategorien"""
        try:
            # Lade aus Service-Definitionen
            for service, domains in self.service_definitions.items():
                if service == 'social_media':
                    category = ContentCategory.SOCIAL_MEDIA
                elif service == 'streaming':
                    category = ContentCategory.STREAMING
                elif service == 'gaming':
                    category = ContentCategory.GAMING
                elif service == 'adult':
                    category = ContentCategory.ADULT
                else:
                    continue

                self.category_domains[category] = set(domains)

            # Zusätzliche Kategorien
            self.category_domains[ContentCategory.GAMBLING] = {
                'bet365.com', 'pokerstars.com', 'casino.com', 'bwin.com',
                'unibet.com', 'betfair.com', 'williamhill.com'
            }

            self.category_domains[ContentCategory.DRUGS] = {
                'drugstore.com', 'pharmacy.com'  # Placeholder
            }

            self.category_domains[ContentCategory.VIOLENCE] = {
                # Wird aus externen Listen geladen
            }

            logger.info(f"📋 {sum(len(domains) for domains in self.category_domains.values())} Domains in Kategorien geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der Category-Domains: {e}")

    async def _setup_usage_tracking(self):
        """Richtet Usage-Tracking für Zeitlimits ein"""
        # Initialisiere Usage-Daten
        self.client_usage = {}

    async def check_parental_filter(self, domain: str, client_ip: str, 
                                  client_settings: Dict) -> Dict:
        """Prüft Domain gegen Parental Controls"""

        # Prüfe ob Parental Controls für Client aktiviert
        if not client_settings.get('parental_controls', False):
            return {
                'allowed': True,
                'reason': 'Parental Controls deaktiviert',
                'action': FilterAction.ALLOW
            }

        # Normalisiere Domain
        domain = domain.lower().rstrip('.')

        # Prüfe aktuelle Zeitbeschränkungen
        current_restrictions = await self._get_current_time_restrictions(client_ip, client_settings)

        if current_restrictions['active']:
            # Prüfe ob Domain in aktuellen Beschränkungen blockiert ist
            block_result = await self._check_time_based_blocking(
                domain, current_restrictions
            )

            if not block_result['allowed']:
                return block_result

        # Prüfe Content-Kategorien
        category_result = await self._check_content_category(domain, client_settings)
        if not category_result['allowed']:
            return category_result

        # Prüfe Custom Keywords
        keyword_result = await self._check_keywords(domain, client_settings)
        if not keyword_result['allowed']:
            return keyword_result

        # Prüfe Safe Search Enforcement
        if client_settings.get('safe_search', True):
            safe_search_result = await self._check_safe_search(domain)
            if not safe_search_result['allowed']:
                return safe_search_result

        return {
            'allowed': True,
            'reason': 'Keine Einschränkungen',
            'action': FilterAction.ALLOW
        }

    async def _get_current_time_restrictions(self, client_ip: str, 
                                           client_settings: Dict) -> Dict:
        """Ermittelt aktuelle Zeitbeschränkungen"""
        restrictions = {
            'active': False,
            'slot_name': None,
            'strict_mode': False,
            'blocked_categories': [],
            'blocked_services': [],
            'allowed_sites': [],
            'time_limit_remaining': None
        }

        time_restrictions = client_settings.get('time_restrictions', {})
        if not time_restrictions.get('enabled'):
            return restrictions

        # Aktuelle Zeit in konfigurierter Zeitzone
        now = datetime.now(self.timezone)
        current_day = now.strftime('%a').lower()[:3]  # mon, tue, wed, ...
        current_time = now.time()

        schedules = time_restrictions.get('schedule', {})

        for slot_id, slot_data in schedules.items():
            if current_day in slot_data.get('days', []):
                # Parse Zeit-Range
                hours = slot_data.get('hours', '')
                if '-' in hours:
                    try:
                        start_str, end_str = hours.split('-')
                        start_time = datetime.strptime(start_str, '%H:%M').time()
                        end_time = datetime.strptime(end_str, '%H:%M').time()

                        # Prüfe ob aktuelle Zeit in Range liegt
                        if start_time <= current_time <= end_time:
                            restrictions.update({
                                'active': True,
                                'slot_name': slot_data.get('name', slot_id),
                                'strict_mode': slot_data.get('strict_mode', False),
                                'blocked_services': slot_data.get('blocked_services', []),
                                'allowed_sites': slot_data.get('allowed_sites', [])
                            })

                            # Prüfe Zeitlimit
                            time_limit = slot_data.get('time_limit_minutes')
                            if time_limit:
                                remaining = await self._calculate_remaining_time(
                                    client_ip, slot_id, time_limit
                                )
                                restrictions['time_limit_remaining'] = remaining

                            break

                    except ValueError:
                        logger.warning(f"Ungültiges Zeitformat in Schedule {slot_id}: {hours}")

        return restrictions

    async def _check_time_based_blocking(self, domain: str, restrictions: Dict) -> Dict:
        """Prüft zeitbasierte Blockierung"""

        # Strict Mode - alles außer Allowed Sites blockieren
        if restrictions['strict_mode']:
            allowed_sites = restrictions.get('allowed_sites', [])

            # Prüfe ob Domain explizit erlaubt ist
            for allowed_site in allowed_sites:
                if domain == allowed_site.lower() or domain.endswith('.' + allowed_site.lower()):
                    return {
                        'allowed': True,
                        'reason': f'Explizit erlaubt: {allowed_site}',
                        'action': FilterAction.ALLOW
                    }

            # Im Strict Mode - blockiere alles andere
            return {
                'allowed': False,
                'reason': f'Strict Mode aktiv: {restrictions["slot_name"]}',
                'action': FilterAction.BLOCK,
                'category': 'time_restriction'
            }

        # Non-Strict Mode - nur bestimmte Services blockieren
        blocked_services = restrictions.get('blocked_services', [])

        for service in blocked_services:
            service_domains = self.service_definitions.get(service, [])

            for service_domain in service_domains:
                if domain == service_domain.lower() or domain.endswith('.' + service_domain.lower()):
                    return {
                        'allowed': False,
                        'reason': f'Service blockiert: {service}',
                        'action': FilterAction.BLOCK,
                        'category': service
                    }

        # Prüfe Zeitlimit
        if restrictions.get('time_limit_remaining') is not None:
            if restrictions['time_limit_remaining'] <= 0:
                return {
                    'allowed': False,
                    'reason': 'Zeitlimit erreicht',
                    'action': FilterAction.BLOCK,
                    'category': 'time_limit'
                }

        return {
            'allowed': True,
            'reason': 'Keine zeitbasierten Beschränkungen',
            'action': FilterAction.ALLOW
        }

    async def _check_content_category(self, domain: str, client_settings: Dict) -> Dict:
        """Prüft Content-Kategorien"""

        # Prüfe alle Kategorien
        for category, domains in self.category_domains.items():
            for cat_domain in domains:
                if domain == cat_domain.lower() or domain.endswith('.' + cat_domain.lower()):
                    # Prüfe ob Kategorie blockiert werden soll
                    if await self._is_category_blocked(category, client_settings):
                        return {
                            'allowed': False,
                            'reason': f'Content-Kategorie blockiert: {category.value}',
                            'action': FilterAction.BLOCK,
                            'category': category.value
                        }

        return {
            'allowed': True,
            'reason': 'Keine problematischen Kategorien',
            'action': FilterAction.ALLOW
        }

    async def _is_category_blocked(self, category: ContentCategory, 
                                 client_settings: Dict) -> bool:
        """Prüft ob Kategorie für Client blockiert ist"""

        # Default-Kategorien für Parental Controls
        default_blocked = {
            ContentCategory.ADULT,
            ContentCategory.VIOLENCE,
            ContentCategory.DRUGS,
            ContentCategory.GAMBLING
        }

        # Prüfe Content-Filter Einstellungen
        content_filtering = self.config_manager.get_config('parental_controls').get('content_filtering', {})

        if content_filtering.get('enabled', True):
            blocked_categories = content_filtering.get('categories', [])

            if category.value in blocked_categories:
                return True

        # Default-Verhalten
        return category in default_blocked

    async def _check_keywords(self, domain: str, client_settings: Dict) -> Dict:
        """Prüft Custom Keywords"""

        content_filtering = self.config_manager.get_config('parental_controls').get('content_filtering', {})
        custom_keywords = content_filtering.get('custom_keywords', [])

        for keyword in custom_keywords:
            if keyword.lower() in domain.lower():
                return {
                    'allowed': False,
                    'reason': f'Keyword blockiert: {keyword}',
                    'action': FilterAction.BLOCK,
                    'category': 'custom_keyword'
                }

        return {
            'allowed': True,
            'reason': 'Keine blockierten Keywords',
            'action': FilterAction.ALLOW
        }

    async def _check_safe_search(self, domain: str) -> Dict:
        """Prüft Safe Search Enforcement"""

        # Safe Search Domains
        safe_search_domains = {
            'google.com': 'forcesafesearch.google.com',
            'www.google.com': 'forcesafesearch.google.com',
            'bing.com': 'strict.bing.com',
            'www.bing.com': 'strict.bing.com',
            'youtube.com': 'restrictmoderate.youtube.com',
            'www.youtube.com': 'restrictmoderate.youtube.com',
            'duckduckgo.com': 'safe.duckduckgo.com'
        }

        if domain in safe_search_domains:
            return {
                'allowed': True,  # Erlaubt, aber mit Redirect
                'reason': 'Safe Search Redirect',
                'action': FilterAction.REDIRECT,
                'redirect_target': safe_search_domains[domain]
            }

        return {
            'allowed': True,
            'reason': 'Keine Safe Search Regel',
            'action': FilterAction.ALLOW
        }

    async def _calculate_remaining_time(self, client_ip: str, slot_id: str, 
                                      limit_minutes: int) -> int:
        """Berechnet verbleibende Zeit in Minuten"""

        if client_ip not in self.client_usage:
            self.client_usage[client_ip] = {}

        client_data = self.client_usage[client_ip]
        today = datetime.now(self.timezone).date().isoformat()

        # Initialisiere tägliche Nutzung
        if today not in client_data:
            client_data[today] = {}

        slot_usage = client_data[today].get(slot_id, 0)  # Minuten
        remaining = max(0, limit_minutes - slot_usage)

        return remaining

    async def record_usage(self, client_ip: str, domain: str, duration_seconds: int = 1):
        """Zeichnet Nutzung für Zeitlimits auf"""

        if client_ip not in self.client_usage:
            return

        # Ermittle aktuelle Zeitbeschränkungen
        # (vereinfacht - würde normalerweise Client-Settings benötigen)
        now = datetime.now(self.timezone)
        today = now.date().isoformat()

        if client_ip not in self.client_usage:
            self.client_usage[client_ip] = {}

        if today not in self.client_usage[client_ip]:
            self.client_usage[client_ip][today] = {}

        # Addiere Nutzungszeit (konvertiere zu Minuten)
        minutes = duration_seconds / 60

        # Für jetzt - addiere zu "general" slot
        current_usage = self.client_usage[client_ip][today].get('general', 0)
        self.client_usage[client_ip][today]['general'] = current_usage + minutes

    async def get_parental_stats(self) -> Dict:
        """Gibt Parental Controls Statistiken zurück"""

        total_categories = len(self.category_domains)
        total_domains = sum(len(domains) for domains in self.category_domains.values())

        # Zähle aktive Zeitbeschränkungen
        active_restrictions = 0
        now = datetime.now(self.timezone)
        current_day = now.strftime('%a').lower()[:3]
        current_time = now.time()

        config = self.config_manager.get_config('client_groups')
        for group_data in config.get('groups', {}).values():
            time_restrictions = group_data.get('time_restrictions', {})
            if time_restrictions.get('enabled'):
                schedules = time_restrictions.get('schedule', {})
                for slot_data in schedules.values():
                    if current_day in slot_data.get('days', []):
                        hours = slot_data.get('hours', '')
                        if '-' in hours:
                            try:
                                start_str, end_str = hours.split('-')
                                start_time = datetime.strptime(start_str, '%H:%M').time()
                                end_time = datetime.strptime(end_str, '%H:%M').time()
                                if start_time <= current_time <= end_time:
                                    active_restrictions += 1
                            except ValueError:
                                pass

        return {
            'enabled': self.config_manager.get_config('parental_controls').get('enabled', False),
            'total_categories': total_categories,
            'total_blocked_domains': total_domains,
            'active_time_restrictions': active_restrictions,
            'tracked_clients': len(self.client_usage),
            'safe_search_enforced': self.config_manager.get_config('parental_controls').get('global_settings', {}).get('safe_search_enforce', False)
        }

    async def _usage_cleanup_task(self):
        """Bereinigt alte Usage-Daten"""
        while True:
            try:
                await asyncio.sleep(3600)  # Stündlich

                cutoff_date = (datetime.now(self.timezone) - timedelta(days=7)).date().isoformat()

                async with self.lock:
                    for client_ip, client_data in list(self.client_usage.items()):
                        # Entferne alte Daten
                        for date_str in list(client_data.keys()):
                            if date_str < cutoff_date:
                                del client_data[date_str]

                        # Entferne leere Client-Einträge
                        if not client_data:
                            del self.client_usage[client_ip]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Usage-Bereinigung: {e}")

    async def _update_safe_search_task(self):
        """Aktualisiert Safe Search Domain-Listen"""
        while True:
            try:
                await asyncio.sleep(86400)  # Täglich

                # Hier könnten neue Safe Search Domains geladen werden
                # Für now - Placeholder

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Safe Search Update: {e}")

    async def add_blocked_domain(self, category: str, domain: str) -> bool:
        """Fügt Domain zu blockierten Domains hinzu"""
        try:
            cat_enum = ContentCategory(category)

            if cat_enum not in self.category_domains:
                self.category_domains[cat_enum] = set()

            self.category_domains[cat_enum].add(domain.lower())

            logger.info(f"🔒 Domain {domain} zu Kategorie {category} hinzugefügt")
            return True

        except (ValueError, Exception) as e:
            logger.error(f"Fehler beim Hinzufügen der Domain {domain}: {e}")
            return False

    async def remove_blocked_domain(self, category: str, domain: str) -> bool:
        """Entfernt Domain aus blockierten Domains"""
        try:
            cat_enum = ContentCategory(category)

            if cat_enum in self.category_domains:
                self.category_domains[cat_enum].discard(domain.lower())

            logger.info(f"🔒 Domain {domain} aus Kategorie {category} entfernt")
            return True

        except (ValueError, Exception) as e:
            logger.error(f"Fehler beim Entfernen der Domain {domain}: {e}")
            return False

    def reload_config(self):
        """Lädt Konfiguration neu"""
        asyncio.create_task(self._load_config())
        asyncio.create_task(self._load_category_domains())
        logger.info("🔒 Parental Controls Konfiguration neu geladen")
