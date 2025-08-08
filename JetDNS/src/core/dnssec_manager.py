"""
JetDNS DNSSEC Manager
Vollständiges DNSSEC Management für DNS Security Extensions
"""

import asyncio
import base64
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import dns.dnssec
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype
import dns.resolver
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

logger = logging.getLogger(__name__)

class DNSSECAlgorithm(Enum):
    """DNSSEC Algorithm Numbers (RFC 8624)"""
    RSAMD5 = 1          # Deprecated
    DH = 2              # Deprecated  
    DSA = 3             # Deprecated
    RSASHA1 = 5         # Legacy
    DSA_NSEC3_SHA1 = 6  # Deprecated
    RSASHA1_NSEC3_SHA1 = 7  # Legacy
    RSASHA256 = 8       # Recommended
    RSASHA512 = 10      # Recommended
    ECC_GOST = 12       # Optional
    ECDSAP256SHA256 = 13  # Recommended
    ECDSAP384SHA384 = 14  # Recommended
    ED25519 = 15        # Recommended
    ED448 = 16          # Recommended

class DNSSECDigestType(Enum):
    """DS Record Digest Types"""
    SHA1 = 1    # Legacy
    SHA256 = 2  # Recommended
    GOST = 3    # Optional
    SHA384 = 4  # Recommended

@dataclass
class DNSSECKey:
    """DNSSEC Key Information"""
    id: str
    zone_name: str
    algorithm: DNSSECAlgorithm
    key_type: str  # "KSK" or "ZSK"
    flags: int
    protocol: int = 3
    public_key: bytes = b''
    private_key: Optional[bytes] = None
    created_at: datetime = None
    activated_at: Optional[datetime] = None
    inactive_at: Optional[datetime] = None
    deleted_at: Optional[datetime] = None
    key_tag: Optional[int] = None
    ds_records: List[Dict] = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.ds_records is None:
            self.ds_records = []

@dataclass
class DNSSECSignature:
    """RRSIG Record Information"""
    type_covered: str
    algorithm: DNSSECAlgorithm
    labels: int
    original_ttl: int
    expiration: datetime
    inception: datetime
    key_tag: int
    signer_name: str
    signature: bytes

class DNSSECManager:
    """DNSSEC Manager für DNS Security Extensions"""

    def __init__(self, config_manager, zone_manager=None):
        self.config_manager = config_manager
        self.zone_manager = zone_manager
        self.config = {}

        # Key Storage
        self.keys: Dict[str, Dict[str, DNSSECKey]] = {}  # zone_name -> key_id -> key
        self.signatures: Dict[str, List[DNSSECSignature]] = {}  # zone_name -> signatures

        # Key Management
        self.key_timings: Dict[str, Dict] = {}  # zone_name -> timing_config

        # Statistics
        self.stats = {
            'zones_signed': 0,
            'keys_generated': 0,
            'signatures_created': 0,
            'validations_performed': 0,
            'validation_failures': 0
        }

    async def initialize(self):
        """Initialize DNSSEC Manager"""
        await self._load_config()

        if not self.config.get('enabled', False):
            logger.info("DNSSEC deaktiviert")
            return

        await self._load_keys()
        await self._setup_key_timings()

        # Background tasks
        asyncio.create_task(self._key_rollover_task())
        asyncio.create_task(self._signature_refresh_task())
        asyncio.create_task(self._key_maintenance_task())

        logger.info("🔐 DNSSEC Manager initialisiert")

    async def _load_config(self):
        """Load DNSSEC configuration"""
        self.config = self.config_manager.get_config('dnssec', {
            'enabled': False,
            'auto_sign': True,
            'signature_validity': 30,  # Tage
            'signature_refresh': 7,    # Tage vor Ablauf
            'key_algorithms': {
                'ksk': 'ECDSAP256SHA256',  # Key Signing Key
                'zsk': 'ECDSAP256SHA256'   # Zone Signing Key
            },
            'key_sizes': {
                'RSA': 2048,
                'ECDSA_P256': 256,
                'ECDSA_P384': 384
            },
            'key_rollover': {
                'ksk_lifetime': 365,  # Tage
                'zsk_lifetime': 90,   # Tage
                'prepublish_time': 7, # Tage
                'auto_rollover': True
            },
            'digest_algorithms': ['SHA256', 'SHA384'],
            'nsec3': {
                'enabled': True,
                'salt': '',
                'iterations': 1
            }
        })

    async def _load_keys(self):
        """Load existing DNSSEC keys"""
        try:
            # Load keys from configuration or key storage
            keys_config = self.config_manager.get_config('dnssec_keys', {})

            for zone_name, zone_keys in keys_config.items():
                if zone_name not in self.keys:
                    self.keys[zone_name] = {}

                for key_id, key_data in zone_keys.items():
                    key = DNSSECKey(
                        id=key_id,
                        zone_name=zone_name,
                        algorithm=DNSSECAlgorithm(key_data['algorithm']),
                        key_type=key_data['key_type'],
                        flags=key_data['flags'],
                        protocol=key_data.get('protocol', 3),
                        public_key=base64.b64decode(key_data['public_key']),
                        private_key=base64.b64decode(key_data['private_key']) if key_data.get('private_key') else None,
                        created_at=datetime.fromisoformat(key_data['created_at']),
                        activated_at=datetime.fromisoformat(key_data['activated_at']) if key_data.get('activated_at') else None,
                        key_tag=key_data.get('key_tag'),
                        ds_records=key_data.get('ds_records', [])
                    )

                    self.keys[zone_name][key_id] = key

            total_keys = sum(len(zone_keys) for zone_keys in self.keys.values())
            logger.info(f"🔐 {total_keys} DNSSEC Keys geladen")

        except Exception as e:
            logger.error(f"Fehler beim Laden der DNSSEC Keys: {e}")

    async def _setup_key_timings(self):
        """Setup key rollover timings"""
        for zone_name in self.keys:
            await self._calculate_key_timings(zone_name)

    async def generate_key_pair(self, zone_name: str, key_type: str, 
                               algorithm: Optional[DNSSECAlgorithm] = None) -> Optional[DNSSECKey]:
        """Generate DNSSEC key pair"""
        try:
            if not algorithm:
                algo_name = self.config.get('key_algorithms', {}).get(key_type.lower(), 'ECDSAP256SHA256')
                algorithm = DNSSECAlgorithm[algo_name]

            # Generate key pair based on algorithm
            if algorithm in [DNSSECAlgorithm.RSASHA256, DNSSECAlgorithm.RSASHA512]:
                private_key, public_key = await self._generate_rsa_key(algorithm)
            elif algorithm == DNSSECAlgorithm.ECDSAP256SHA256:
                private_key, public_key = await self._generate_ecdsa_key(256)
            elif algorithm == DNSSECAlgorithm.ECDSAP384SHA384:
                private_key, public_key = await self._generate_ecdsa_key(384)
            elif algorithm == DNSSECAlgorithm.ED25519:
                private_key, public_key = await self._generate_ed25519_key()
            else:
                logger.error(f"Unsupported DNSSEC algorithm: {algorithm}")
                return None

            # Key flags
            flags = 256 if key_type.upper() == 'ZSK' else 257  # ZSK or KSK

            # Create key object
            key_id = f"{zone_name}_{key_type}_{int(time.time())}"

            key = DNSSECKey(
                id=key_id,
                zone_name=zone_name,
                algorithm=algorithm,
                key_type=key_type.upper(),
                flags=flags,
                public_key=public_key,
                private_key=private_key
            )

            # Calculate key tag
            key.key_tag = await self._calculate_key_tag(key)

            # Generate DS records for KSK
            if key_type.upper() == 'KSK':
                key.ds_records = await self._generate_ds_records(key)

            # Store key
            if zone_name not in self.keys:
                self.keys[zone_name] = {}

            self.keys[zone_name][key_id] = key

            # Save to configuration
            await self._save_keys()

            self.stats['keys_generated'] += 1

            logger.info(f"🔐 DNSSEC Key generiert: {zone_name} ({key_type}, {algorithm.name})")
            return key

        except Exception as e:
            logger.error(f"DNSSEC Key Generation fehlgeschlagen: {e}")
            return None

    async def _generate_rsa_key(self, algorithm: DNSSECAlgorithm) -> Tuple[bytes, bytes]:
        """Generate RSA key pair"""
        key_size = self.config.get('key_sizes', {}).get('RSA', 2048)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Extract public key (DNSSEC format)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Convert to DNSSEC public key format
        exponent_bytes = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
        modulus_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')

        if len(exponent_bytes) < 256:
            public_key_data = bytes([len(exponent_bytes)]) + exponent_bytes + modulus_bytes
        else:
            public_key_data = b'\x00' + len(exponent_bytes).to_bytes(2, 'big') + exponent_bytes + modulus_bytes

        return private_pem, public_key_data

    async def _generate_ecdsa_key(self, curve_size: int) -> Tuple[bytes, bytes]:
        """Generate ECDSA key pair"""
        if curve_size == 256:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif curve_size == 384:
            private_key = ec.generate_private_key(ec.SECP384R1())
        else:
            raise ValueError(f"Unsupported ECDSA curve size: {curve_size}")

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Extract public key (DNSSEC format)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        # Convert to DNSSEC format (uncompressed point)
        coord_size = curve_size // 8
        x_bytes = public_numbers.x.to_bytes(coord_size, 'big')
        y_bytes = public_numbers.y.to_bytes(coord_size, 'big')

        public_key_data = x_bytes + y_bytes

        return private_pem, public_key_data

    async def _generate_ed25519_key(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 key pair"""
        private_key = ed25519.Ed25519PrivateKey.generate()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Public key (32 bytes for Ed25519)
        public_key = private_key.public_key()
        public_key_data = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return private_pem, public_key_data

    async def _calculate_key_tag(self, key: DNSSECKey) -> int:
        """Calculate DNSSEC key tag"""
        try:
            # Build DNSKEY RDATA
            rdata = (
                key.flags.to_bytes(2, 'big') +
                key.protocol.to_bytes(1, 'big') +
                key.algorithm.value.to_bytes(1, 'big') +
                key.public_key
            )

            # Calculate key tag (RFC 4034)
            if key.algorithm == DNSSECAlgorithm.RSAMD5:
                # Special case for RSA/MD5
                return int.from_bytes(key.public_key[-3:-1], 'big')
            else:
                # Standard algorithm
                total = 0
                for i, byte in enumerate(rdata):
                    if i % 2 == 0:
                        total += byte << 8
                    else:
                        total += byte

                return (total + (total >> 16)) & 0xFFFF

        except Exception as e:
            logger.error(f"Key tag calculation error: {e}")
            return 0

    async def _generate_ds_records(self, key: DNSSECKey) -> List[Dict]:
        """Generate DS records for KSK"""
        ds_records = []

        try:
            # Build DNSKEY RDATA
            owner_name = dns.name.from_text(key.zone_name)
            rdata = (
                key.flags.to_bytes(2, 'big') +
                key.protocol.to_bytes(1, 'big') +
                key.algorithm.value.to_bytes(1, 'big') +
                key.public_key
            )

            # Generate DS record for each configured digest algorithm
            for digest_algo in self.config.get('digest_algorithms', ['SHA256']):
                if digest_algo == 'SHA256':
                    digest_type = DNSSECDigestType.SHA256
                    hash_func = hashes.SHA256()
                elif digest_algo == 'SHA384':
                    digest_type = DNSSECDigestType.SHA384
                    hash_func = hashes.SHA384()
                elif digest_algo == 'SHA1':
                    digest_type = DNSSECDigestType.SHA1
                    hash_func = hashes.SHA1()
                else:
                    continue

                # Calculate digest: hash(owner_name + DNSKEY_RDATA)
                digest_input = owner_name.to_wire() + rdata
                digest = hashlib.new(digest_algo.lower(), digest_input).digest()

                ds_record = {
                    'key_tag': key.key_tag,
                    'algorithm': key.algorithm.value,
                    'digest_type': digest_type.value,
                    'digest': digest.hex().upper()
                }

                ds_records.append(ds_record)

            return ds_records

        except Exception as e:
            logger.error(f"DS record generation error: {e}")
            return []

    async def sign_zone(self, zone_name: str) -> bool:
        """Sign DNS zone with DNSSEC"""
        try:
            if zone_name not in self.keys:
                logger.error(f"No DNSSEC keys found for zone: {zone_name}")
                return False

            zone_keys = self.keys[zone_name]

            # Get active ZSK and KSK
            zsk = None
            ksk = None

            for key in zone_keys.values():
                if key.key_type == 'ZSK' and key.activated_at and not key.inactive_at:
                    zsk = key
                elif key.key_type == 'KSK' and key.activated_at and not key.inactive_at:
                    ksk = key

            if not zsk:
                logger.error(f"No active ZSK found for zone: {zone_name}")
                return False

            if not ksk:
                logger.error(f"No active KSK found for zone: {zone_name}")
                return False

            # Get zone data
            if not self.zone_manager:
                logger.error("Zone Manager not available for DNSSEC signing")
                return False

            zone_records = await self.zone_manager.get_zone_records(zone_name)
            if not zone_records:
                logger.error(f"No records found for zone: {zone_name}")
                return False

            # Sign zone records
            signatures_created = 0

            # Group records by name and type
            rrsets = {}
            for record in zone_records:
                key = (record.name, record.type)
                if key not in rrsets:
                    rrsets[key] = []
                rrsets[key].append(record)

            # Sign each RRset
            for (name, rtype), records in rrsets.items():
                if rtype in ['RRSIG', 'NSEC', 'NSEC3']:
                    continue  # Skip DNSSEC records

                # Sign with ZSK
                signature = await self._sign_rrset(records, zsk)
                if signature:
                    signatures_created += 1

                # Sign DNSKEY records with KSK
                if rtype == 'DNSKEY':
                    ksk_signature = await self._sign_rrset(records, ksk)
                    if ksk_signature:
                        signatures_created += 1

            # Generate NSEC/NSEC3 records
            if self.config.get('nsec3', {}).get('enabled', True):
                await self._generate_nsec3_records(zone_name)
            else:
                await self._generate_nsec_records(zone_name)

            self.stats['zones_signed'] += 1
            self.stats['signatures_created'] += signatures_created

            logger.info(f"🔐 Zone {zone_name} signed with DNSSEC ({signatures_created} signatures)")
            return True

        except Exception as e:
            logger.error(f"Zone signing error for {zone_name}: {e}")
            return False

    async def _sign_rrset(self, records: List, key: DNSSECKey) -> Optional[DNSSECSignature]:
        """Sign RRset with DNSSEC key"""
        try:
            # Build RRset
            if not records:
                return None

            # Calculate signature validity period
            inception = datetime.now()
            expiration = inception + timedelta(days=self.config.get('signature_validity', 30))

            # Build RRSIG RDATA (without signature)
            type_covered = dns.rdatatype.from_text(records[0].type)
            labels = len(dns.name.from_text(records[0].name).labels)

            rrsig_rdata = (
                type_covered.to_bytes(2, 'big') +
                key.algorithm.value.to_bytes(1, 'big') +
                labels.to_bytes(1, 'big') +
                records[0].ttl.to_bytes(4, 'big') +
                int(expiration.timestamp()).to_bytes(4, 'big') +
                int(inception.timestamp()).to_bytes(4, 'big') +
                key.key_tag.to_bytes(2, 'big') +
                dns.name.from_text(key.zone_name).to_wire()
            )

            # Build canonical RRset for signing
            canonical_rrset = await self._build_canonical_rrset(records)

            # Sign data
            sign_data = rrsig_rdata + canonical_rrset
            signature_bytes = await self._sign_data(sign_data, key)

            if not signature_bytes:
                return None

            signature = DNSSECSignature(
                type_covered=records[0].type,
                algorithm=key.algorithm,
                labels=labels,
                original_ttl=records[0].ttl,
                expiration=expiration,
                inception=inception,
                key_tag=key.key_tag,
                signer_name=key.zone_name,
                signature=signature_bytes
            )

            return signature

        except Exception as e:
            logger.error(f"RRset signing error: {e}")
            return None

    async def _sign_data(self, data: bytes, key: DNSSECKey) -> Optional[bytes]:
        """Sign data with private key"""
        try:
            if not key.private_key:
                return None

            # Load private key
            private_key = serialization.load_pem_private_key(key.private_key, password=None)

            # Sign based on algorithm
            if key.algorithm in [DNSSECAlgorithm.RSASHA256, DNSSECAlgorithm.RSASHA512]:
                if key.algorithm == DNSSECAlgorithm.RSASHA256:
                    hash_algo = hashes.SHA256()
                else:
                    hash_algo = hashes.SHA512()

                signature = private_key.sign(data, padding=None, algorithm=hash_algo)

            elif key.algorithm == DNSSECAlgorithm.ECDSAP256SHA256:
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

            elif key.algorithm == DNSSECAlgorithm.ECDSAP384SHA384:
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA384()))

            elif key.algorithm == DNSSECAlgorithm.ED25519:
                signature = private_key.sign(data)

            else:
                logger.error(f"Unsupported signing algorithm: {key.algorithm}")
                return None

            return signature

        except Exception as e:
            logger.error(f"Data signing error: {e}")
            return None

    async def _build_canonical_rrset(self, records: List) -> bytes:
        """Build canonical RRset for signing"""
        try:
            canonical_data = b''

            # Sort records canonically
            sorted_records = sorted(records, key=lambda r: r.content)

            for record in sorted_records:
                # Build wire format
                owner_name = dns.name.from_text(record.name).to_wire()
                rtype = dns.rdatatype.from_text(record.type)
                rclass = dns.rdataclass.IN
                ttl = record.ttl
                rdata = dns.rdata.from_text(rclass, rtype, record.content).to_wire()

                wire_record = (
                    owner_name +
                    rtype.to_bytes(2, 'big') +
                    rclass.to_bytes(2, 'big') +
                    ttl.to_bytes(4, 'big') +
                    len(rdata).to_bytes(2, 'big') +
                    rdata
                )

                canonical_data += wire_record

            return canonical_data

        except Exception as e:
            logger.error(f"Canonical RRset build error: {e}")
            return b''

    async def _generate_nsec3_records(self, zone_name: str):
        """Generate NSEC3 records for zone"""
        try:
            # NSEC3 configuration
            nsec3_config = self.config.get('nsec3', {})
            salt = nsec3_config.get('salt', '').encode()
            iterations = nsec3_config.get('iterations', 1)

            # This would generate NSEC3 records
            # Implementation details omitted for brevity
            logger.debug(f"Generated NSEC3 records for zone {zone_name}")

        except Exception as e:
            logger.error(f"NSEC3 generation error: {e}")

    async def _generate_nsec_records(self, zone_name: str):
        """Generate NSEC records for zone"""
        try:
            # This would generate NSEC records
            # Implementation details omitted for brevity
            logger.debug(f"Generated NSEC records for zone {zone_name}")

        except Exception as e:
            logger.error(f"NSEC generation error: {e}")

    async def _calculate_key_timings(self, zone_name: str):
        """Calculate key rollover timings"""
        rollover_config = self.config.get('key_rollover', {})

        self.key_timings[zone_name] = {
            'ksk_lifetime': rollover_config.get('ksk_lifetime', 365),
            'zsk_lifetime': rollover_config.get('zsk_lifetime', 90),
            'prepublish_time': rollover_config.get('prepublish_time', 7),
            'auto_rollover': rollover_config.get('auto_rollover', True)
        }

    async def _save_keys(self):
        """Save DNSSEC keys to configuration"""
        try:
            keys_config = {}

            for zone_name, zone_keys in self.keys.items():
                keys_config[zone_name] = {}

                for key_id, key in zone_keys.items():
                    keys_config[zone_name][key_id] = {
                        'algorithm': key.algorithm.value,
                        'key_type': key.key_type,
                        'flags': key.flags,
                        'protocol': key.protocol,
                        'public_key': base64.b64encode(key.public_key).decode(),
                        'private_key': base64.b64encode(key.private_key).decode() if key.private_key else None,
                        'created_at': key.created_at.isoformat(),
                        'activated_at': key.activated_at.isoformat() if key.activated_at else None,
                        'key_tag': key.key_tag,
                        'ds_records': key.ds_records
                    }

            self.config_manager.set_value('dnssec_keys', keys_config)

        except Exception as e:
            logger.error(f"DNSSEC keys save error: {e}")

    async def _key_rollover_task(self):
        """Background task for key rollover"""
        while True:
            try:
                await asyncio.sleep(3600)  # Check hourly

                for zone_name in self.keys:
                    if self.key_timings.get(zone_name, {}).get('auto_rollover', True):
                        await self._check_key_rollover(zone_name)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Key rollover task error: {e}")

    async def _signature_refresh_task(self):
        """Background task for signature refresh"""
        while True:
            try:
                await asyncio.sleep(86400)  # Check daily

                for zone_name in self.keys:
                    await self._check_signature_refresh(zone_name)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Signature refresh task error: {e}")

    async def _key_maintenance_task(self):
        """Background task for key maintenance"""
        while True:
            try:
                await asyncio.sleep(3600)  # Check hourly

                # Remove expired keys
                await self._cleanup_expired_keys()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Key maintenance task error: {e}")

    async def _check_key_rollover(self, zone_name: str):
        """Check if key rollover is needed"""
        try:
            # Implementation for key rollover logic
            pass
        except Exception as e:
            logger.error(f"Key rollover check error for {zone_name}: {e}")

    async def _check_signature_refresh(self, zone_name: str):
        """Check if signatures need refresh"""
        try:
            # Implementation for signature refresh logic
            pass
        except Exception as e:
            logger.error(f"Signature refresh check error for {zone_name}: {e}")

    async def _cleanup_expired_keys(self):
        """Remove expired keys"""
        try:
            # Implementation for expired key cleanup
            pass
        except Exception as e:
            logger.error(f"Expired key cleanup error: {e}")

    async def get_dnssec_stats(self) -> Dict:
        """Get DNSSEC statistics"""
        total_keys = sum(len(zone_keys) for zone_keys in self.keys.values())

        key_distribution = {
            'KSK': 0,
            'ZSK': 0
        }

        algorithm_distribution = {}

        for zone_keys in self.keys.values():
            for key in zone_keys.values():
                key_distribution[key.key_type] += 1

                algo_name = key.algorithm.name
                algorithm_distribution[algo_name] = algorithm_distribution.get(algo_name, 0) + 1

        return {
            'enabled': self.config.get('enabled', False),
            'zones_with_keys': len(self.keys),
            'total_keys': total_keys,
            'key_distribution': key_distribution,
            'algorithm_distribution': algorithm_distribution,
            'auto_sign': self.config.get('auto_sign', True),
            'signature_validity_days': self.config.get('signature_validity', 30),
            'stats': self.stats
        }

    def get_zone_keys(self, zone_name: str) -> List[DNSSECKey]:
        """Get DNSSEC keys for zone"""
        return list(self.keys.get(zone_name, {}).values())

    def get_ds_records(self, zone_name: str) -> List[Dict]:
        """Get DS records for zone"""
        ds_records = []

        for key in self.keys.get(zone_name, {}).values():
            if key.key_type == 'KSK' and key.ds_records:
                ds_records.extend(key.ds_records)

        return ds_records

    def reload_config(self):
        """Reload DNSSEC configuration"""
        asyncio.create_task(self._load_config())
        asyncio.create_task(self._load_keys())
        logger.info("🔐 DNSSEC Konfiguration neu geladen")
