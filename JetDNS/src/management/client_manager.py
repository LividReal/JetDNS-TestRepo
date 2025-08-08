"""
JetDNS Client Management System
Verwaltung von Client-Gruppen und individuellen Einstellungen
"""

import asyncio
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ClientStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BLOCKED = "blocked"
    RESTRICTED = "restricted"

@dataclass
class Client:
    """Client-Informationen"""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    group_id: str = "default"
    status: ClientStatus = ClientStatus.ACTIVE
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    query_count: int = 0
    blocked_count: int = 0
    custom_settings: Optional[Dict] = None
    tags: List[str] = None
    description: str = ""

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.custom_settings is None:
            self.custom_settings = {}
        if self.first_seen is None:
            self.first_seen = datetime.now()

@dataclass
class ClientGroup:
    """Client-Gruppe Konfiguration"""
    id: str
    name: str
    description: str
    blocklists: List[str]
    safe_search: bool
    threat_intelligence: bool
    custom_rules: List[str]
    parental_controls: bool
    time_restrictions: Dict
    priority: int = 0

class ClientManager:
    """Verwaltung von Clients und Gruppen"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.clients: Dict[str, Client] = {}
        self.groups: Dict[str, ClientGroup] = {}
        self.ip_to_mac: Dict[str, str] = {}
        self.mac_to_ip: Dict[str, str] = {}
        self.lock = asyncio.Lock()

        # Lade Konfiguration
        self._load_config()

        # Auto-Discovery Task
        self._discovery_task = None
        self._cleanup_task = None

    async def initialize(self):
        """Initialisiert den Client Manager"""
        await self._load_clients()
        await self._load_groups()

        # Starte Background Tasks
        self._discovery_task = asyncio.create_task(self._auto_discovery())
        self._cleanup_task = asyncio.create_task(self._cleanup_inactive_clients())

        logger.info("🔧 Client Manager initialisiert")

    def _load_config(self):
        """Lädt Client-Konfiguration"""
        client_config = self.config_manager.get_config('client_groups')

        # Lade Gruppen
        for group_id, group_data in client_config.get('groups', {}).items():
            self.groups[group_id] = ClientGroup(
                id=group_id,
                name=group_data.get('name', group_id),
                description=group_data.get('description', ''),
                blocklists=group_data.get('blocklists', []),
                safe_search=group_data.get('safe_search', True),
                threat_intelligence=group_data.get('threat_intelligence', True),
                custom_rules=group_data.get('custom_rules', []),
                parental_controls=group_data.get('parental_controls', False),
                time_restrictions=group_data.get('time_restrictions', {})
            )

    async def _load_clients(self):
        """Lädt gespeicherte Client-Daten"""
        try:
            client_config = self.config_manager.get_config('client_groups')
            clients_data = client_config.get('clients', {})

            for ip, client_data in clients_data.items():
                if isinstance(client_data, str):
                    # Legacy Format: IP -> Group ID
                    self.clients[ip] = Client(
                        ip_address=ip,
                        group_id=client_data
                    )
                else:
                    # Neues Format: Vollständige Client-Daten
                    self.clients[ip] = Client(
                        ip_address=ip,
                        mac_address=client_data.get('mac_address'),
                        hostname=client_data.get('hostname'),
                        group_id=client_data.get('group_id', 'default'),
                        status=ClientStatus(client_data.get('status', 'active')),
                        query_count=client_data.get('query_count', 0),
                        blocked_count=client_data.get('blocked_count', 0),
                        custom_settings=client_data.get('custom_settings', {}),
                        tags=client_data.get('tags', []),
                        description=client_data.get('description', '')
                    )

                    # Parse Timestamps
                    if 'first_seen' in client_data:
                        self.clients[ip].first_seen = datetime.fromisoformat(client_data['first_seen'])
                    if 'last_seen' in client_data:
                        self.clients[ip].last_seen = datetime.fromisoformat(client_data['last_seen'])

            logger.info(f"📱 {len(self.clients)} Clients geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der Client-Daten: {e}")

    async def _load_groups(self):
        """Lädt Gruppen-Konfiguration"""
        logger.info(f"👥 {len(self.groups)} Client-Gruppen geladen")

    async def register_client(self, ip_address: str, mac_address: str = None, 
                            hostname: str = None) -> Client:
        """Registriert einen neuen Client oder aktualisiert bestehenden"""
        async with self.lock:
            now = datetime.now()

            if ip_address in self.clients:
                # Bestehender Client aktualisieren
                client = self.clients[ip_address]
                client.last_seen = now

                if mac_address and not client.mac_address:
                    client.mac_address = mac_address
                    self.ip_to_mac[ip_address] = mac_address
                    self.mac_to_ip[mac_address] = ip_address

                if hostname and not client.hostname:
                    client.hostname = hostname

            else:
                # Neuer Client
                group_id = await self._determine_group(ip_address, mac_address, hostname)

                client = Client(
                    ip_address=ip_address,
                    mac_address=mac_address,
                    hostname=hostname,
                    group_id=group_id,
                    first_seen=now,
                    last_seen=now
                )

                self.clients[ip_address] = client

                if mac_address:
                    self.ip_to_mac[ip_address] = mac_address
                    self.mac_to_ip[mac_address] = ip_address

                logger.info(f"📱 Neuer Client registriert: {ip_address} -> Gruppe: {group_id}")

            await self._save_clients()
            return client

    async def _determine_group(self, ip_address: str, mac_address: str = None, 
                             hostname: str = None) -> str:
        """Bestimmt automatisch die passende Gruppe für einen Client"""
        config = self.config_manager.get_config('client_groups')

        # Standard-Gruppe
        default_group = config.get('default_group', 'default')

        if not config.get('auto_assign', True):
            return default_group

        try:
            ip = ipaddress.ip_address(ip_address)

            # Prüfe spezielle IP-Bereiche
            if ip.is_private:
                # Lokale Netzwerk-Heuristiken
                if str(ip).startswith('192.168.1.'):
                    # Hauptnetzwerk - Familie
                    return 'family'
                elif str(ip).startswith('192.168.10.'):
                    # Business-Netzwerk
                    return 'business'

            # Hostname-basierte Zuordnung
            if hostname:
                hostname_lower = hostname.lower()
                if any(keyword in hostname_lower for keyword in ['phone', 'mobile', 'android', 'iphone']):
                    return 'family'
                elif any(keyword in hostname_lower for keyword in ['server', 'work', 'office', 'pc']):
                    return 'business'

        except Exception as e:
            logger.debug(f"Fehler bei Gruppen-Bestimmung für {ip_address}: {e}")

        return default_group

    async def get_client_settings(self, ip_address: str) -> Dict:
        """Gibt die effektiven Einstellungen für einen Client zurück"""
        async with self.lock:
            client = self.clients.get(ip_address)

            if not client:
                # Unbekannter Client - verwende Standard-Gruppe
                client = await self.register_client(ip_address)

            # Hole Gruppen-Einstellungen
            group = self.groups.get(client.group_id)
            if not group:
                group = self.groups.get('default')

            if not group:
                # Fallback auf minimale Einstellungen
                return {
                    'blocklists': ['malware'],
                    'safe_search': False,
                    'threat_intelligence': True,
                    'parental_controls': False,
                    'time_restrictions': {}
                }

            # Basis-Einstellungen aus Gruppe
            settings = {
                'group_id': group.id,
                'group_name': group.name,
                'blocklists': group.blocklists.copy(),
                'safe_search': group.safe_search,
                'threat_intelligence': group.threat_intelligence,
                'custom_rules': group.custom_rules.copy(),
                'parental_controls': group.parental_controls,
                'time_restrictions': group.time_restrictions.copy()
            }

            # Client-spezifische Überschreibungen
            if client.custom_settings:
                settings.update(client.custom_settings)

            # Prüfe Zeitbeschränkungen
            settings['current_restrictions'] = await self._get_current_restrictions(client)

            return settings

    async def _get_current_restrictions(self, client: Client) -> Dict:
        """Ermittelt aktuelle Zeitbeschränkungen für Client"""
        restrictions = {
            'blocked_services': [],
            'strict_mode': False,
            'active_schedule': None
        }

        group = self.groups.get(client.group_id)
        if not group or not group.time_restrictions.get('enabled'):
            return restrictions

        now = datetime.now()
        current_day = now.strftime('%a').lower()[:3]  # mon, tue, wed, ...
        current_time = now.time()

        for schedule_id, schedule in group.time_restrictions.get('schedule', {}).items():
            if current_day in schedule.get('days', []):
                # Parse Zeit-Range
                hours = schedule.get('hours', '')
                if '-' in hours:
                    start_str, end_str = hours.split('-')
                    try:
                        start_time = datetime.strptime(start_str, '%H:%M').time()
                        end_time = datetime.strptime(end_str, '%H:%M').time()

                        if start_time <= current_time <= end_time:
                            restrictions['blocked_services'] = schedule.get('blocked_services', [])
                            restrictions['strict_mode'] = schedule.get('strict_mode', False)
                            restrictions['active_schedule'] = schedule.get('name', schedule_id)
                            break

                    except ValueError:
                        logger.warning(f"Ungültiges Zeitformat in Schedule {schedule_id}: {hours}")

        return restrictions

    async def update_client_stats(self, ip_address: str, query_count: int = 1, blocked: bool = False):
        """Aktualisiert Client-Statistiken"""
        async with self.lock:
            if ip_address in self.clients:
                client = self.clients[ip_address]
                client.query_count += query_count
                if blocked:
                    client.blocked_count += 1
                client.last_seen = datetime.now()

    async def set_client_group(self, ip_address: str, group_id: str) -> bool:
        """Setzt die Gruppe eines Clients"""
        async with self.lock:
            if group_id not in self.groups:
                return False

            if ip_address not in self.clients:
                await self.register_client(ip_address)

            self.clients[ip_address].group_id = group_id
            await self._save_clients()

            logger.info(f"📱 Client {ip_address} zu Gruppe {group_id} verschoben")
            return True

    async def set_client_custom_settings(self, ip_address: str, settings: Dict) -> bool:
        """Setzt client-spezifische Einstellungen"""
        async with self.lock:
            if ip_address not in self.clients:
                await self.register_client(ip_address)

            self.clients[ip_address].custom_settings = settings
            await self._save_clients()

            logger.info(f"📱 Custom Settings für Client {ip_address} aktualisiert")
            return True

    async def get_all_clients(self) -> List[Dict]:
        """Gibt alle Clients zurück"""
        async with self.lock:
            clients = []
            for client in self.clients.values():
                clients.append({
                    'ip_address': client.ip_address,
                    'mac_address': client.mac_address,
                    'hostname': client.hostname,
                    'group_id': client.group_id,
                    'group_name': self.groups.get(client.group_id, {}).name if self.groups.get(client.group_id) else 'Unknown',
                    'status': client.status.value,
                    'first_seen': client.first_seen.isoformat() if client.first_seen else None,
                    'last_seen': client.last_seen.isoformat() if client.last_seen else None,
                    'query_count': client.query_count,
                    'blocked_count': client.blocked_count,
                    'tags': client.tags,
                    'description': client.description
                })
            return clients

    async def get_all_groups(self) -> List[Dict]:
        """Gibt alle Gruppen zurück"""
        groups = []
        for group in self.groups.values():
            client_count = sum(1 for c in self.clients.values() if c.group_id == group.id)
            groups.append({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'client_count': client_count,
                'blocklists': group.blocklists,
                'safe_search': group.safe_search,
                'threat_intelligence': group.threat_intelligence,
                'parental_controls': group.parental_controls,
                'time_restrictions': group.time_restrictions
            })
        return groups

    async def create_group(self, group_data: Dict) -> bool:
        """Erstellt eine neue Client-Gruppe"""
        try:
            group = ClientGroup(
                id=group_data['id'],
                name=group_data['name'],
                description=group_data.get('description', ''),
                blocklists=group_data.get('blocklists', []),
                safe_search=group_data.get('safe_search', True),
                threat_intelligence=group_data.get('threat_intelligence', True),
                custom_rules=group_data.get('custom_rules', []),
                parental_controls=group_data.get('parental_controls', False),
                time_restrictions=group_data.get('time_restrictions', {})
            )

            self.groups[group.id] = group
            await self._save_groups()

            logger.info(f"👥 Neue Gruppe erstellt: {group.id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Erstellen der Gruppe: {e}")
            return False

    async def update_group(self, group_id: str, group_data: Dict) -> bool:
        """Aktualisiert eine bestehende Gruppe"""
        if group_id not in self.groups:
            return False

        try:
            group = self.groups[group_id]
            group.name = group_data.get('name', group.name)
            group.description = group_data.get('description', group.description)
            group.blocklists = group_data.get('blocklists', group.blocklists)
            group.safe_search = group_data.get('safe_search', group.safe_search)
            group.threat_intelligence = group_data.get('threat_intelligence', group.threat_intelligence)
            group.custom_rules = group_data.get('custom_rules', group.custom_rules)
            group.parental_controls = group_data.get('parental_controls', group.parental_controls)
            group.time_restrictions = group_data.get('time_restrictions', group.time_restrictions)

            await self._save_groups()

            logger.info(f"👥 Gruppe aktualisiert: {group_id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren der Gruppe {group_id}: {e}")
            return False

    async def delete_group(self, group_id: str) -> bool:
        """Löscht eine Gruppe (Clients werden auf default verschoben)"""
        if group_id not in self.groups or group_id == 'default':
            return False

        try:
            # Verschiebe alle Clients zur Standard-Gruppe
            async with self.lock:
                for client in self.clients.values():
                    if client.group_id == group_id:
                        client.group_id = 'default'

            del self.groups[group_id]
            await self._save_groups()
            await self._save_clients()

            logger.info(f"👥 Gruppe gelöscht: {group_id}")
            return True

        except Exception as e:
            logger.error(f"Fehler beim Löschen der Gruppe {group_id}: {e}")
            return False

    async def _save_clients(self):
        """Speichert Client-Daten in Konfiguration"""
        try:
            clients_data = {}
            for ip, client in self.clients.items():
                clients_data[ip] = {
                    'mac_address': client.mac_address,
                    'hostname': client.hostname,
                    'group_id': client.group_id,
                    'status': client.status.value,
                    'first_seen': client.first_seen.isoformat() if client.first_seen else None,
                    'last_seen': client.last_seen.isoformat() if client.last_seen else None,
                    'query_count': client.query_count,
                    'blocked_count': client.blocked_count,
                    'custom_settings': client.custom_settings,
                    'tags': client.tags,
                    'description': client.description
                }

            # Aktualisiere Konfiguration
            self.config_manager.set_value('client_groups', 'clients', clients_data, save=False)

        except Exception as e:
            logger.error(f"Fehler beim Speichern der Client-Daten: {e}")

    async def _save_groups(self):
        """Speichert Gruppen-Daten in Konfiguration"""
        try:
            groups_data = {}
            for group_id, group in self.groups.items():
                groups_data[group_id] = {
                    'name': group.name,
                    'description': group.description,
                    'blocklists': group.blocklists,
                    'safe_search': group.safe_search,
                    'threat_intelligence': group.threat_intelligence,
                    'custom_rules': group.custom_rules,
                    'parental_controls': group.parental_controls,
                    'time_restrictions': group.time_restrictions
                }

            self.config_manager.set_value('client_groups', 'groups', groups_data, save=False)
            self.config_manager.save_config()

        except Exception as e:
            logger.error(f"Fehler beim Speichern der Gruppen-Daten: {e}")

    async def _auto_discovery(self):
        """Automatische Client-Erkennung im Netzwerk"""
        while True:
            try:
                await asyncio.sleep(300)  # Alle 5 Minuten

                # Hier könnte ARP-Tabelle, DHCP-Leases, etc. gescannt werden
                # Für now - Placeholder

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Auto-Discovery: {e}")

    async def _cleanup_inactive_clients(self):
        """Bereinigt inaktive Clients"""
        while True:
            try:
                await asyncio.sleep(3600)  # Stündlich

                cutoff_time = datetime.now() - timedelta(days=30)
                to_remove = []

                async with self.lock:
                    for ip, client in self.clients.items():
                        if client.last_seen and client.last_seen < cutoff_time:
                            to_remove.append(ip)

                    for ip in to_remove:
                        del self.clients[ip]
                        if ip in self.ip_to_mac:
                            mac = self.ip_to_mac[ip]
                            del self.ip_to_mac[ip]
                            del self.mac_to_ip[mac]

                if to_remove:
                    await self._save_clients()
                    logger.info(f"🧹 {len(to_remove)} inaktive Clients bereinigt")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Client-Bereinigung: {e}")

    async def shutdown(self):
        """Beendet den Client Manager"""
        if self._discovery_task:
            self._discovery_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()

        await self._save_clients()
        logger.info("Client Manager beendet")
