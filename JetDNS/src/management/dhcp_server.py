"""
JetDNS DHCP Server
Integrierter DHCP Server für vollständige Netzwerkverwaltung
"""

import asyncio
import logging
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv4Network
import json

logger = logging.getLogger(__name__)

@dataclass
class DHCPLease:
    """DHCP Lease Information"""
    mac_address: str
    ip_address: str
    hostname: str = ""
    lease_start: datetime = None
    lease_end: datetime = None
    client_id: str = ""
    vendor_class: str = ""
    is_static: bool = False
    last_seen: datetime = None

@dataclass
class DHCPReservation:
    """Statische DHCP Reservierung"""
    mac_address: str
    ip_address: str
    hostname: str
    description: str = ""

class DHCPPacket:
    """DHCP Packet Parser/Builder"""

    DHCP_OPCODES = {
        'BOOTREQUEST': 1,
        'BOOTREPLY': 2
    }

    DHCP_MESSAGE_TYPES = {
        'DHCPDISCOVER': 1,
        'DHCPOFFER': 2,
        'DHCPREQUEST': 3,
        'DHCPDECLINE': 4,
        'DHCPACK': 5,
        'DHCPNAK': 6,
        'DHCPRELEASE': 7,
        'DHCPINFORM': 8
    }

    DHCP_OPTIONS = {
        1: 'subnet_mask',
        3: 'router',
        6: 'dns_servers',
        15: 'domain_name',
        28: 'broadcast_address',
        51: 'lease_time',
        53: 'message_type',
        54: 'server_identifier',
        55: 'parameter_request_list',
        61: 'client_identifier',
        255: 'end'
    }

    def __init__(self, data: bytes = None):
        if data:
            self.parse(data)
        else:
            self.initialize_empty()

    def initialize_empty(self):
        """Initialisiert leeres Packet"""
        self.op = self.DHCP_OPCODES['BOOTREPLY']
        self.htype = 1  # Ethernet
        self.hlen = 6   # MAC address length
        self.hops = 0
        self.xid = 0
        self.secs = 0
        self.flags = 0
        self.ciaddr = '0.0.0.0'  # Client IP
        self.yiaddr = '0.0.0.0'  # Your IP
        self.siaddr = '0.0.0.0'  # Server IP
        self.giaddr = '0.0.0.0'  # Gateway IP
        self.chaddr = b'\x00' * 16  # Client hardware address
        self.sname = b'\x00' * 64   # Server name
        self.file = b'\x00' * 128   # Boot file name
        self.options = {}

    def parse(self, data: bytes):
        """Parst DHCP Packet aus Bytes"""
        if len(data) < 240:
            raise ValueError("DHCP packet too short")

        # Header parsen
        header = struct.unpack('!BBBBLHHLLLL', data[:28])
        self.op = header[0]
        self.htype = header[1]
        self.hlen = header[2]
        self.hops = header[3]
        self.xid = header[4]
        self.secs = header[5]
        self.flags = header[6]
        self.ciaddr = socket.inet_ntoa(struct.pack('!L', header[7]))
        self.yiaddr = socket.inet_ntoa(struct.pack('!L', header[8]))
        self.siaddr = socket.inet_ntoa(struct.pack('!L', header[9]))
        self.giaddr = socket.inet_ntoa(struct.pack('!L', header[10]))

        # MAC Address
        self.chaddr = data[28:44]
        self.mac_address = ':'.join([f'{b:02x}' for b in self.chaddr[:6]])

        # Server name und file
        self.sname = data[44:108]
        self.file = data[108:236]

        # Magic Cookie prüfen
        magic = struct.unpack('!L', data[236:240])[0]
        if magic != 0x63825363:
            raise ValueError("Invalid DHCP magic cookie")

        # Optionen parsen
        self.options = {}
        self._parse_options(data[240:])

    def _parse_options(self, data: bytes):
        """Parst DHCP Optionen"""
        i = 0
        while i < len(data):
            if data[i] == 255:  # End option
                break

            if data[i] == 0:  # Pad option
                i += 1
                continue

            if i + 1 >= len(data):
                break

            option_code = data[i]
            option_length = data[i + 1]

            if i + 2 + option_length > len(data):
                break

            option_data = data[i + 2:i + 2 + option_length]

            # Interpretiere häufige Optionen
            if option_code == 53:  # Message Type
                self.options['message_type'] = option_data[0]
            elif option_code == 61:  # Client Identifier
                self.options['client_id'] = option_data
            elif option_code == 55:  # Parameter Request List
                self.options['param_request'] = list(option_data)
            elif option_code == 12:  # Hostname
                self.options['hostname'] = option_data.decode('utf-8', errors='ignore').rstrip('\x00')
            else:
                self.options[option_code] = option_data

            i += 2 + option_length

    def build(self) -> bytes:
        """Baut DHCP Packet zu Bytes zusammen"""

        # Header
        packet = struct.pack('!BBBBLHHLLLL',
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            struct.unpack('!L', socket.inet_aton(self.ciaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.yiaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.siaddr))[0],
            struct.unpack('!L', socket.inet_aton(self.giaddr))[0]
        )

        # Hardware address
        packet += self.chaddr

        # Server name und file
        packet += self.sname
        packet += self.file

        # Magic cookie
        packet += struct.pack('!L', 0x63825363)

        # Optionen
        for option_code, option_data in self.options.items():
            if isinstance(option_code, int):
                if isinstance(option_data, int):
                    packet += struct.pack('!BB', option_code, 1)
                    packet += struct.pack('!B', option_data)
                elif isinstance(option_data, str):
                    data_bytes = option_data.encode('utf-8')
                    packet += struct.pack('!BB', option_code, len(data_bytes))
                    packet += data_bytes
                elif isinstance(option_data, bytes):
                    packet += struct.pack('!BB', option_code, len(option_data))
                    packet += option_data
                elif isinstance(option_data, list):
                    if option_code == 6:  # DNS servers
                        dns_data = b''.join([socket.inet_aton(dns) for dns in option_data])
                        packet += struct.pack('!BB', option_code, len(dns_data))
                        packet += dns_data

        # End option
        packet += b'\xff'

        # Padding to minimum size
        while len(packet) < 300:
            packet += b'\x00'

        return packet

class DHCPServer:
    """DHCP Server Implementation"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = {}

        # Server state
        self.running = False
        self.server_socket = None

        # Lease management
        self.leases: Dict[str, DHCPLease] = {}  # IP -> Lease
        self.mac_to_ip: Dict[str, str] = {}     # MAC -> IP
        self.reservations: Dict[str, DHCPReservation] = {}  # MAC -> Reservation

        # Network configuration
        self.server_ip = ""
        self.subnet = None
        self.available_ips = set()
        self.lease_time = 86400  # 24 hours

        self.lock = asyncio.Lock()

    async def initialize(self):
        """Initialisiert den DHCP Server"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("DHCP Server deaktiviert")
            return

        await self._setup_network()
        await self._load_leases()
        await self._load_reservations()

        # Background tasks
        asyncio.create_task(self._lease_cleanup_task())

        logger.info("🌐 DHCP Server initialisiert")

    async def _load_config(self):
        """Lädt DHCP Konfiguration"""
        self.config = self.config_manager.get_config('dhcp')

    async def _setup_network(self):
        """Richtet Netzwerk-Konfiguration ein"""
        try:
            # Server IP (automatisch erkannt oder konfiguriert)
            self.server_ip = self.config.get('server_ip', '192.168.1.1')

            # Subnet berechnen
            range_start = self.config.get('range_start', '192.168.1.100')
            range_end = self.config.get('range_end', '192.168.1.200')
            subnet_mask = self.config.get('subnet_mask', '255.255.255.0')

            # Verfügbare IPs ermitteln
            start_ip = IPv4Address(range_start)
            end_ip = IPv4Address(range_end)

            self.available_ips = set()
            current_ip = start_ip
            while current_ip <= end_ip:
                self.available_ips.add(str(current_ip))
                current_ip += 1

            self.lease_time = self.config.get('lease_time', 86400)

            logger.info(f"🌐 DHCP Pool: {range_start} - {range_end} ({len(self.available_ips)} IPs)")

        except Exception as e:
            logger.error(f"Fehler bei Netzwerk-Setup: {e}")
            raise

    async def _load_leases(self):
        """Lädt bestehende Leases"""
        try:
            # Würde normalerweise aus Datei/DB laden
            # Für now - leer starten
            self.leases = {}

        except Exception as e:
            logger.error(f"Fehler beim Laden der Leases: {e}")

    async def _load_reservations(self):
        """Lädt statische Reservierungen"""
        try:
            static_leases = self.config.get('static_leases', {})

            for mac_address, lease_data in static_leases.items():
                reservation = DHCPReservation(
                    mac_address=mac_address.lower(),
                    ip_address=lease_data['ip'],
                    hostname=lease_data.get('hostname', ''),
                    description=lease_data.get('description', '')
                )

                self.reservations[mac_address.lower()] = reservation

                # Reservierte IPs aus verfügbarem Pool entfernen
                if lease_data['ip'] in self.available_ips:
                    self.available_ips.remove(lease_data['ip'])

            logger.info(f"🌐 {len(self.reservations)} statische Reservierungen geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der Reservierungen: {e}")

    async def start(self):
        """Startet den DHCP Server"""
        if not self.config.get('enabled', False):
            logger.info("DHCP Server ist deaktiviert")
            return

        try:
            # Socket erstellen
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # An DHCP Port binden
            self.server_socket.bind(('', 67))
            self.server_socket.setblocking(False)

            self.running = True

            # Server loop starten
            asyncio.create_task(self._server_loop())

            logger.info(f"🌐 DHCP Server gestartet auf Port 67")

        except Exception as e:
            logger.error(f"Fehler beim Starten des DHCP Servers: {e}")
            raise

    async def _server_loop(self):
        """Haupt-Server-Loop"""
        while self.running:
            try:
                # Warte auf DHCP Packet
                data, addr = await asyncio.get_event_loop().sock_recvfrom(self.server_socket, 1024)

                # Verarbeite Packet asynchron
                asyncio.create_task(self._handle_dhcp_packet(data, addr))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler im DHCP Server Loop: {e}")

    async def _handle_dhcp_packet(self, data: bytes, addr: Tuple[str, int]):
        """Verarbeitet eingehende DHCP Pakete"""
        try:
            packet = DHCPPacket(data)

            # Nur BOOTREQUEST verarbeiten
            if packet.op != DHCPPacket.DHCP_OPCODES['BOOTREQUEST']:
                return

            message_type = packet.options.get('message_type')

            if message_type == DHCPPacket.DHCP_MESSAGE_TYPES['DHCPDISCOVER']:
                await self._handle_discover(packet, addr)
            elif message_type == DHCPPacket.DHCP_MESSAGE_TYPES['DHCPREQUEST']:
                await self._handle_request(packet, addr)
            elif message_type == DHCPPacket.DHCP_MESSAGE_TYPES['DHCPRELEASE']:
                await self._handle_release(packet, addr)
            elif message_type == DHCPPacket.DHCP_MESSAGE_TYPES['DHCPINFORM']:
                await self._handle_inform(packet, addr)

        except Exception as e:
            logger.error(f"Fehler bei DHCP Packet-Verarbeitung: {e}")

    async def _handle_discover(self, packet: DHCPPacket, addr: Tuple[str, int]):
        """Behandelt DHCP DISCOVER"""
        mac_address = packet.mac_address

        # Prüfe auf statische Reservierung
        if mac_address in self.reservations:
            offered_ip = self.reservations[mac_address].ip_address
        else:
            # Prüfe auf bestehende Lease
            if mac_address in self.mac_to_ip:
                offered_ip = self.mac_to_ip[mac_address]
            else:
                # Neue IP zuweisen
                offered_ip = await self._allocate_ip(mac_address)

        if not offered_ip:
            logger.warning(f"Keine verfügbare IP für MAC {mac_address}")
            return

        # DHCP OFFER senden
        await self._send_offer(packet, offered_ip, addr)

        logger.debug(f"DHCP OFFER gesendet: {offered_ip} für {mac_address}")

    async def _handle_request(self, packet: DHCPPacket, addr: Tuple[str, int]):
        """Behandelt DHCP REQUEST"""
        mac_address = packet.mac_address
        requested_ip = packet.ciaddr if packet.ciaddr != '0.0.0.0' else packet.yiaddr

        # Validiere Request
        if await self._validate_request(mac_address, requested_ip):
            # Erstelle Lease
            await self._create_lease(mac_address, requested_ip, packet)

            # DHCP ACK senden
            await self._send_ack(packet, requested_ip, addr)

            logger.info(f"DHCP LEASE vergeben: {requested_ip} → {mac_address}")
        else:
            # DHCP NAK senden
            await self._send_nak(packet, addr)

            logger.warning(f"DHCP REQUEST abgelehnt: {requested_ip} für {mac_address}")

    async def _handle_release(self, packet: DHCPPacket, addr: Tuple[str, int]):
        """Behandelt DHCP RELEASE"""
        mac_address = packet.mac_address
        released_ip = packet.ciaddr

        if released_ip in self.leases and self.leases[released_ip].mac_address == mac_address:
            await self._release_lease(released_ip)
            logger.info(f"DHCP RELEASE: {released_ip} von {mac_address} freigegeben")

    async def _handle_inform(self, packet: DHCPPacket, addr: Tuple[str, int]):
        """Behandelt DHCP INFORM"""
        # Sende Konfigurationsinformationen ohne IP-Lease
        await self._send_ack(packet, packet.ciaddr, addr, inform=True)

    async def _allocate_ip(self, mac_address: str) -> Optional[str]:
        """Weist neue IP-Adresse zu"""
        async with self.lock:
            for ip in self.available_ips:
                if ip not in self.leases:
                    return ip

            # Prüfe auf abgelaufene Leases
            now = datetime.now()
            for ip, lease in list(self.leases.items()):
                if lease.lease_end < now:
                    await self._release_lease(ip)
                    return ip

        return None

    async def _validate_request(self, mac_address: str, requested_ip: str) -> bool:
        """Validiert DHCP REQUEST"""

        # Prüfe ob IP im gültigen Bereich
        if requested_ip not in self.available_ips and requested_ip not in [r.ip_address for r in self.reservations.values()]:
            return False

        # Prüfe statische Reservierung
        if mac_address in self.reservations:
            return self.reservations[mac_address].ip_address == requested_ip

        # Prüfe bestehende Lease
        if requested_ip in self.leases:
            return self.leases[requested_ip].mac_address == mac_address

        # Neue IP-Zuweisung
        return requested_ip in self.available_ips

    async def _create_lease(self, mac_address: str, ip_address: str, packet: DHCPPacket):
        """Erstellt neue Lease"""
        now = datetime.now()
        lease_end = now + timedelta(seconds=self.lease_time)

        hostname = packet.options.get('hostname', '')
        client_id = packet.options.get('client_id', b'').hex() if packet.options.get('client_id') else ''

        lease = DHCPLease(
            mac_address=mac_address,
            ip_address=ip_address,
            hostname=hostname,
            lease_start=now,
            lease_end=lease_end,
            client_id=client_id,
            last_seen=now
        )

        async with self.lock:
            self.leases[ip_address] = lease
            self.mac_to_ip[mac_address] = ip_address

    async def _release_lease(self, ip_address: str):
        """Gibt Lease frei"""
        async with self.lock:
            if ip_address in self.leases:
                lease = self.leases[ip_address]
                del self.leases[ip_address]

                if lease.mac_address in self.mac_to_ip:
                    del self.mac_to_ip[lease.mac_address]

    async def _send_offer(self, request_packet: DHCPPacket, offered_ip: str, addr: Tuple[str, int]):
        """Sendet DHCP OFFER"""
        response = DHCPPacket()

        response.op = DHCPPacket.DHCP_OPCODES['BOOTREPLY']
        response.htype = request_packet.htype
        response.hlen = request_packet.hlen
        response.xid = request_packet.xid
        response.yiaddr = offered_ip
        response.siaddr = self.server_ip
        response.chaddr = request_packet.chaddr

        # DHCP Optionen
        response.options = {
            53: DHCPPacket.DHCP_MESSAGE_TYPES['DHCPOFFER'],  # Message Type
            54: self.server_ip,  # Server Identifier
            51: self.lease_time,  # Lease Time
            1: self.config.get('subnet_mask', '255.255.255.0'),  # Subnet Mask
            3: self.config.get('gateway', self.server_ip),  # Router
            6: self.config.get('dns_servers', [self.server_ip]),  # DNS Servers
            15: self.config.get('domain_name', 'local'),  # Domain Name
        }

        await self._send_response(response, ('255.255.255.255', 68))

    async def _send_ack(self, request_packet: DHCPPacket, ip_address: str, 
                       addr: Tuple[str, int], inform: bool = False):
        """Sendet DHCP ACK"""
        response = DHCPPacket()

        response.op = DHCPPacket.DHCP_OPCODES['BOOTREPLY']
        response.htype = request_packet.htype
        response.hlen = request_packet.hlen
        response.xid = request_packet.xid

        if not inform:
            response.yiaddr = ip_address

        response.siaddr = self.server_ip
        response.chaddr = request_packet.chaddr

        # DHCP Optionen
        response.options = {
            53: DHCPPacket.DHCP_MESSAGE_TYPES['DHCPACK'],  # Message Type
            54: self.server_ip,  # Server Identifier
        }

        if not inform:
            response.options[51] = self.lease_time  # Lease Time

        response.options.update({
            1: self.config.get('subnet_mask', '255.255.255.0'),  # Subnet Mask
            3: self.config.get('gateway', self.server_ip),  # Router
            6: self.config.get('dns_servers', [self.server_ip]),  # DNS Servers
            15: self.config.get('domain_name', 'local'),  # Domain Name
        })

        await self._send_response(response, ('255.255.255.255', 68))

    async def _send_nak(self, request_packet: DHCPPacket, addr: Tuple[str, int]):
        """Sendet DHCP NAK"""
        response = DHCPPacket()

        response.op = DHCPPacket.DHCP_OPCODES['BOOTREPLY']
        response.htype = request_packet.htype
        response.hlen = request_packet.hlen
        response.xid = request_packet.xid
        response.siaddr = self.server_ip
        response.chaddr = request_packet.chaddr

        response.options = {
            53: DHCPPacket.DHCP_MESSAGE_TYPES['DHCPNAK'],  # Message Type
            54: self.server_ip,  # Server Identifier
        }

        await self._send_response(response, ('255.255.255.255', 68))

    async def _send_response(self, response: DHCPPacket, target: Tuple[str, int]):
        """Sendet DHCP Response"""
        try:
            data = response.build()
            await asyncio.get_event_loop().sock_sendto(self.server_socket, data, target)
        except Exception as e:
            logger.error(f"Fehler beim Senden der DHCP Response: {e}")

    async def get_dhcp_stats(self) -> Dict:
        """Gibt DHCP Statistiken zurück"""
        active_leases = len(self.leases)
        available_ips = len(self.available_ips) - active_leases
        static_reservations = len(self.reservations)

        # Berechne Auslastung
        total_ips = len(self.available_ips)
        utilization = (active_leases / total_ips * 100) if total_ips > 0 else 0

        return {
            'enabled': self.config.get('enabled', False),
            'running': self.running,
            'server_ip': self.server_ip,
            'lease_time': self.lease_time,
            'total_ips': total_ips,
            'active_leases': active_leases,
            'available_ips': available_ips,
            'static_reservations': static_reservations,
            'utilization_percent': round(utilization, 2)
        }

    async def get_all_leases(self) -> List[Dict]:
        """Gibt alle aktiven Leases zurück"""
        leases = []
        now = datetime.now()

        for lease in self.leases.values():
            remaining_time = (lease.lease_end - now).total_seconds() if lease.lease_end > now else 0

            leases.append({
                'ip_address': lease.ip_address,
                'mac_address': lease.mac_address,
                'hostname': lease.hostname,
                'lease_start': lease.lease_start.isoformat() if lease.lease_start else None,
                'lease_end': lease.lease_end.isoformat() if lease.lease_end else None,
                'remaining_seconds': max(0, int(remaining_time)),
                'is_static': lease.is_static,
                'last_seen': lease.last_seen.isoformat() if lease.last_seen else None
            })

        return sorted(leases, key=lambda x: IPv4Address(x['ip_address']))

    async def _lease_cleanup_task(self):
        """Bereinigt abgelaufene Leases"""
        while self.running:
            try:
                await asyncio.sleep(300)  # Alle 5 Minuten

                now = datetime.now()
                expired_ips = []

                async with self.lock:
                    for ip, lease in self.leases.items():
                        if lease.lease_end < now:
                            expired_ips.append(ip)

                for ip in expired_ips:
                    await self._release_lease(ip)
                    logger.debug(f"Abgelaufene DHCP Lease bereinigt: {ip}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fehler bei Lease-Bereinigung: {e}")

    async def stop(self):
        """Stoppt den DHCP Server"""
        self.running = False

        if self.server_socket:
            self.server_socket.close()

        logger.info("🌐 DHCP Server gestoppt")
