"""
JetDNS Configuration Manager
Zentrale Verwaltung aller JetDNS Konfigurationen
"""

import json
import logging
import os
import shutil
import threading
import yaml
from datetime import datetime
from pathlib import Path
import configparser
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ConfigManager:
    """Zentrale Konfigurationsverwaltung für JetDNS"""

    # Standard-Konfiguration
    DEFAULT_CONFIG = {
        'general': {
            'version': '1.0.0',
            'language': 'de',
            'timezone': 'Europe/Berlin',
            'log_level': 'INFO'
        },
        'dns': {
            'listen_address': '0.0.0.0',
            'listen_port': 53,
            'query_timeout': 5,
            'max_connections': 1000,
            'worker_threads': 4
        },
        'cache': {
            'enabled': True,
            'max_size': 10000,
            'ttl_min': 300,
            'ttl_max': 3600,
            'negative_ttl': 300
        },
        'upstream': {
            'servers': '8.8.8.8,1.1.1.1,9.9.9.9',
            'health_check_interval': 30,
            'timeout': 5,
            'load_balancing': True
        },
        'security': {
            'threat_intelligence': True,
            'ad_blocking': True,
            'safe_search': True,
            'dns_tunneling_protection': False,
            'dnssec_validation': False,
            'rate_limiting': True,
            'rate_limit_requests_per_second': 100,
            'rate_limit_burst': 200
        },
        'web': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 80,
            'protocol': 'http',
            'ssl_cert': '',
            'ssl_key': ''
        },
        'logging': {
            'query_logging': True,
            'log_file': '/var/log/jetdns/jetdns.log',
            'access_log': '/var/log/jetdns/access.log',
            'max_log_size': '10MB',
            'log_retention_days': 30
        },
        'performance': {
            'connection_pool_size': 100,
            'query_queue_size': 10000,
            'statistics_collection': True,
            'real_time_updates': True
        },
        'blocklists': {
            'enabled': True,
            'auto_update': True,
            'update_interval': 24,  # Stunden
            'sources': [
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'https://someonewhocares.org/hosts/zero/hosts'
            ]
        },
        'client_groups': {
            'enabled': True,
            'default_group': 'default',
            'auto_assign': True,
            'groups': {
                'default': {
                    'name': 'Standard',
                    'description': 'Standard-Filterregeln für alle Clients',
                    'blocklists': ['ads', 'malware'],
                    'safe_search': True,
                    'threat_intelligence': True,
                    'custom_rules': [],
                    'parental_controls': False,
                    'time_restrictions': {}
                },
                'family': {
                    'name': 'Familie',
                    'description': 'Familien-freundliche Einstellungen',
                    'blocklists': ['ads', 'malware', 'adult'],
                    'safe_search': True,
                    'threat_intelligence': True,
                    'custom_rules': [],
                    'parental_controls': True,
                    'time_restrictions': {
                        'enabled': True,
                        'schedule': {
                            'school_time': {
                                'name': 'Schulzeit',
                                'days': ['mon', 'tue', 'wed', 'thu', 'fri'],
                                'hours': '08:00-15:00',
                                'strict_mode': True,
                                'blocked_services': ['youtube', 'tiktok', 'instagram', 'snapchat']
                            },
                            'evening': {
                                'name': 'Abends',
                                'days': ['sun', 'mon', 'tue', 'wed', 'thu'],
                                'hours': '20:00-22:00',
                                'strict_mode': False,
                                'blocked_services': ['adult']
                            }
                        }
                    }
                },
                'business': {
                    'name': 'Business',
                    'description': 'Geschäfts-Einstellungen',
                    'blocklists': ['malware', 'phishing'],
                    'safe_search': False,
                    'threat_intelligence': True,
                    'custom_rules': [],
                    'parental_controls': False,
                    'time_restrictions': {
                        'enabled': True,
                        'schedule': {
                            'work_hours': {
                                'name': 'Arbeitszeit',
                                'days': ['mon', 'tue', 'wed', 'thu', 'fri'],
                                'hours': '09:00-17:00',
                                'strict_mode': True,
                                'blocked_services': ['social_media', 'streaming']
                            }
                        }
                    }
                },
                'unrestricted': {
                    'name': 'Uneingeschränkt',
                    'description': 'Keine Beschränkungen',
                    'blocklists': ['malware'],
                    'safe_search': False,
                    'threat_intelligence': True,
                    'custom_rules': [],
                    'parental_controls': False,
                    'time_restrictions': {}
                }
            },
            'clients': {},  # IP -> group_id mapping
            'custom_clients': {}  # IP -> custom settings
        },
        'dns_rewrites': {
            'enabled': True,
            'rules': [
                {
                    'domain': '*.local',
                    'type': 'A',
                    'answer': '192.168.1.1',
                    'description': 'Lokale Domains auf Router weiterleiten'
                }
            ],
            'wildcard_support': True,
            'regex_support': False
        },
        'parental_controls': {
            'enabled': True,
            'global_settings': {
                'safe_search_enforce': True,
                'youtube_restricted_mode': True,
                'block_bypass_methods': True
            },
            'blocked_services': {
                'social_media': [
                    'facebook.com', 'instagram.com', 'twitter.com', 'snapchat.com',
                    'tiktok.com', 'discord.com', 'whatsapp.com', 'telegram.org'
                ],
                'streaming': [
                    'youtube.com', 'netflix.com', 'twitch.tv', 'hulu.com',
                    'disney.com', 'amazon.com', 'spotify.com', 'soundcloud.com'
                ],
                'gaming': [
                    'steam.com', 'epicgames.com', 'battle.net', 'roblox.com',
                    'minecraft.net', 'fortnite.com', 'xbox.com', 'playstation.com'
                ],
                'adult': [
                    # Wird dynamisch aus Blocklisten geladen
                ]
            },
            'time_restrictions': {
                'enabled': True,
                'timezone': 'Europe/Berlin',
                'schedules': {}
            },
            'content_filtering': {
                'enabled': True,
                'categories': ['adult', 'violence', 'drugs', 'gambling'],
                'custom_keywords': []
            }
        },
        'dhcp': {
            'enabled': False,
            'interface': 'eth0',
            'range_start': '192.168.1.100',
            'range_end': '192.168.1.200',
            'subnet_mask': '255.255.255.0',
            'gateway': '192.168.1.1',
            'dns_servers': ['127.0.0.1'],
            'lease_time': 86400,  # 24 Stunden in Sekunden
            'domain_name': 'local',
            'static_leases': {
                # MAC -> IP mapping
                'aa:bb:cc:dd:ee:ff': {
                    'ip': '192.168.1.50',
                    'hostname': 'server',
                    'description': 'Main Server'
                }
            },
            'reservations': [],
            'options': {
                'router': '192.168.1.1',
                'domain_name_servers': '127.0.0.1',
                'domain_name': 'local',
                'broadcast_address': '192.168.1.255'
            }
        },
        'analytics': {
            'enabled': True,
            'retention_days': 90,
            'detailed_logging': True,
            'real_time_stats': True,
            'export_formats': ['csv', 'json', 'pdf'],
            'scheduled_reports': {
                'enabled': True,
                'frequency': 'weekly',  # daily, weekly, monthly
                'email_recipients': [],
                'include_charts': True
            },
            'data_collection': {
                'query_logs': True,
                'client_stats': True,
                'performance_metrics': True,
                'threat_intel_stats': True,
                'bandwidth_usage': True
            },
            'privacy': {
                'anonymize_ips': False,
                'data_minimization': False,
                'gdpr_compliance': True
            }
        },
        'api': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 8080,
            'authentication': {
                'method': 'api_key',  # api_key, jwt, basic
                'api_keys': {},
                'jwt_secret': '',
                'session_timeout': 3600
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_minute': 60,
                'burst_size': 10
            },
            'cors': {
                'enabled': True,
                'origins': ['*'],
                'methods': ['GET', 'POST', 'PUT', 'DELETE'],
                'headers': ['*']
            },
            'webhooks': {
                'enabled': True,
                'endpoints': [],
                'events': ['query_blocked', 'threat_detected', 'system_alert']
            },
            'documentation': {
                'enabled': True,
                'swagger_ui': True,
                'redoc': True
            }
        },
        'monitoring': {
            'enabled': True,
            'health_checks': {
                'interval': 60,
                'endpoints': ['/health', '/metrics'],
                'timeout': 10
            },
            'metrics': {
                'prometheus': {
                    'enabled': True,
                    'port': 9090,
                    'path': '/metrics'
                },
                'influxdb': {
                    'enabled': False,
                    'url': 'http://localhost:8086',
                    'database': 'jetdns'
                }
            },
            'alerting': {
                'enabled': True,
                'channels': {
                    'email': {
                        'enabled': False,
                        'smtp_server': '',
                        'recipients': []
                    },
                    'webhook': {
                        'enabled': False,
                        'url': ''
                    }
                },
                'rules': [
                    {
                        'name': 'High Query Rate',
                        'condition': 'queries_per_second > 1000',
                        'severity': 'warning'
                    },
                    {
                        'name': 'Server Offline',
                        'condition': 'dns_server_status == false',
                        'severity': 'critical'
                    }
                ]
            }
        }
    }

    def __init__(self, config_path='/etc/jetdns/jetdns.conf'):
        self.config_path = Path(config_path)
        self.config_dir = self.config_path.parent
        self.lock = threading.RLock()
        self.config = {}

        # Backup-Verzeichnis
        self.backup_dir = self.config_dir / 'backups'
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Konfiguration laden
        self.load_config()

    def load_config(self):
        """Lädt Konfiguration aus Datei oder erstellt Standard-Konfiguration"""
        try:
            with self.lock:
                if self.config_path.exists():
                    # Bestehende Konfiguration laden
                    if self.config_path.suffix.lower() == '.yaml':
                        self._load_yaml_config()
                    else:
                        self._load_ini_config()

                    # Mit Standard-Werten ergänzen
                    self._merge_default_config()

                    logger.info(f"Konfiguration geladen von: {self.config_path}")
                else:
                    # Standard-Konfiguration erstellen
                    logger.info("Erstelle Standard-Konfiguration")
                    self.config = self._deep_copy_dict(self.DEFAULT_CONFIG)
                    self.save_config()

        except Exception as e:
            logger.error(f"Fehler beim Laden der Konfiguration: {e}")
            logger.info("Verwende Standard-Konfiguration")
            self.config = self._deep_copy_dict(self.DEFAULT_CONFIG)

    def _load_yaml_config(self):
        """Lädt YAML-Konfigurationsdatei"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"YAML-Konfiguration konnte nicht geladen werden: {e}")
            self.config = {}

    def _load_ini_config(self):
        """Lädt INI-Konfigurationsdatei"""
        try:
            parser = configparser.ConfigParser()
            parser.read(self.config_path, encoding='utf-8')

            self.config = {}
            for section_name in parser.sections():
                self.config[section_name] = {}
                for key, value in parser.items(section_name):
                    # Typen-Konvertierung
                    self.config[section_name][key] = self._convert_value(value)

        except Exception as e:
            logger.error(f"INI-Konfiguration konnte nicht geladen werden: {e}")
            self.config = {}

    def _convert_value(self, value):
        """Konvertiert String-Werte in passende Python-Typen"""
        if isinstance(value, str):
            value_lower = value.lower()

            # Boolean
            if value_lower in ('true', 'yes', '1', 'on'):
                return True
            elif value_lower in ('false', 'no', '0', 'off'):
                return False

            # Integer
            try:
                return int(value)
            except ValueError:
                pass

            # Float
            try:
                return float(value)
            except ValueError:
                pass

        return value

    def _merge_default_config(self):
        """Ergänzt geladene Konfiguration mit Standard-Werten"""
        def merge_dicts(default, loaded):
            result = default.copy()
            for key, value in loaded.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dicts(result[key], value)
                else:
                    result[key] = value
            return result

        self.config = merge_dicts(self.DEFAULT_CONFIG, self.config)

    def _deep_copy_dict(self, d):
        """Erstellt Deep Copy eines Dictionary"""
        if isinstance(d, dict):
            return {k: self._deep_copy_dict(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [self._deep_copy_dict(item) for item in d]
        else:
            return d

    def save_config(self):
        """Speichert Konfiguration in Datei"""
        try:
            with self.lock:
                # Backup der aktuellen Konfiguration erstellen
                if self.config_path.exists():
                    self._create_backup()

                # Verzeichnis erstellen falls nicht vorhanden
                self.config_dir.mkdir(parents=True, exist_ok=True)

                # Konfiguration speichern
                if self.config_path.suffix.lower() == '.yaml':
                    self._save_yaml_config()
                else:
                    self._save_ini_config()

                logger.info(f"Konfiguration gespeichert: {self.config_path}")

        except Exception as e:
            logger.error(f"Fehler beim Speichern der Konfiguration: {e}")
            raise

    def _save_yaml_config(self):
        """Speichert Konfiguration als YAML"""
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, 
                     allow_unicode=True, indent=2)

    def _save_ini_config(self):
        """Speichert Konfiguration als INI"""
        parser = configparser.ConfigParser()

        for section_name, section_data in self.config.items():
            if isinstance(section_data, dict):
                parser.add_section(section_name)
                for key, value in section_data.items():
                    # Listen zu Strings konvertieren
                    if isinstance(value, list):
                        value = ','.join(str(v) for v in value)
                    parser.set(section_name, key, str(value))

        with open(self.config_path, 'w', encoding='utf-8') as f:
            parser.write(f)

    def _create_backup(self):
        """Erstellt Backup der aktuellen Konfiguration"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"jetdns_config_backup_{timestamp}.conf"
            backup_path = self.backup_dir / backup_name

            shutil.copy2(self.config_path, backup_path)

            # Alte Backups bereinigen (nur die letzten 10 behalten)
            backups = sorted(self.backup_dir.glob('jetdns_config_backup_*.conf'),
                           key=lambda x: x.stat().st_mtime, reverse=True)

            for old_backup in backups[10:]:
                old_backup.unlink()

            logger.debug(f"Konfiguration-Backup erstellt: {backup_path}")

        except Exception as e:
            logger.warning(f"Backup konnte nicht erstellt werden: {e}")

    def get_config(self, section=None):
        """Gibt Konfiguration oder Konfigurationsbereich zurück"""
        with self.lock:
            if section:
                return self.config.get(section, {})
            return self._deep_copy_dict(self.config)

    def get_value(self, section, key, default=None):
        """Gibt einzelnen Konfigurationswert zurück"""
        with self.lock:
            return self.config.get(section, {}).get(key, default)

    def set_value(self, section, key, value, save=True):
        """Setzt einzelnen Konfigurationswert"""
        try:
            with self.lock:
                if section not in self.config:
                    self.config[section] = {}

                old_value = self.config[section].get(key)
                self.config[section][key] = value

                if save:
                    self.save_config()

                logger.info(f"Konfiguration geändert: [{section}] {key} = {value} (vorher: {old_value})")

        except Exception as e:
            logger.error(f"Fehler beim Setzen der Konfiguration: {e}")
            raise

    def update_config(self, new_config, save=True):
        """Aktualisiert Konfiguration mit neuen Werten"""
        try:
            with self.lock:
                for section, section_data in new_config.items():
                    if isinstance(section_data, dict):
                        if section not in self.config:
                            self.config[section] = {}

                        for key, value in section_data.items():
                            self.config[section][key] = value
                    else:
                        # Direkte Werte auf Top-Level
                        self.config[section] = section_data

                if save:
                    self.save_config()

                logger.info("Konfiguration mit neuen Werten aktualisiert")

        except Exception as e:
            logger.error(f"Fehler beim Aktualisieren der Konfiguration: {e}")
            raise

    def validate_config(self):
        """Validiert die Konfiguration auf Korrektheit"""
        errors = []
        warnings = []

        try:
            with self.lock:
                # DNS Konfiguration validieren
                dns_config = self.config.get('dns', {})

                listen_port = dns_config.get('listen_port', 53)
                if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
                    errors.append(f"Ungültiger DNS Port: {listen_port}")
                elif listen_port != 53 and listen_port < 1024:
                    warnings.append(f"Non-standard DNS Port: {listen_port}")

                query_timeout = dns_config.get('query_timeout', 5)
                if not isinstance(query_timeout, (int, float)) or query_timeout <= 0:
                    errors.append(f"Ungültiger Query Timeout: {query_timeout}")

                # Web Konfiguration validieren
                web_config = self.config.get('web', {})
                if web_config.get('enabled', True):
                    web_port = web_config.get('port', 80)
                    if not isinstance(web_port, int) or not (1 <= web_port <= 65535):
                        errors.append(f"Ungültiger Web Port: {web_port}")

                    if web_config.get('protocol') == 'https':
                        ssl_cert = web_config.get('ssl_cert', '')
                        ssl_key = web_config.get('ssl_key', '')

                        if not ssl_cert or not Path(ssl_cert).exists():
                            errors.append("SSL-Zertifikat fehlt oder nicht gefunden")
                        if not ssl_key or not Path(ssl_key).exists():
                            errors.append("SSL-Schlüssel fehlt oder nicht gefunden")

                # Upstream Server validieren
                upstream_config = self.config.get('upstream', {})
                servers = upstream_config.get('servers', '')

                if isinstance(servers, str):
                    server_list = [s.strip() for s in servers.split(',') if s.strip()]
                elif isinstance(servers, list):
                    server_list = servers
                else:
                    server_list = []

                if not server_list:
                    warnings.append("Keine Upstream-Server konfiguriert")

                # Cache Konfiguration validieren
                cache_config = self.config.get('cache', {})
                max_size = cache_config.get('max_size', 10000)
                if not isinstance(max_size, int) or max_size < 0:
                    errors.append(f"Ungültige Cache-Größe: {max_size}")

        except Exception as e:
            errors.append(f"Validierungsfehler: {e}")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }

    def get_upstream_servers(self):
        """Gibt Liste der Upstream-Server zurück"""
        servers = self.get_value('upstream', 'servers', '')

        if isinstance(servers, str):
            return [s.strip() for s in servers.split(',') if s.strip()]
        elif isinstance(servers, list):
            return servers
        else:
            return []

    def set_upstream_servers(self, servers):
        """Setzt Liste der Upstream-Server"""
        if isinstance(servers, list):
            servers_str = ','.join(servers)
        else:
            servers_str = str(servers)

        self.set_value('upstream', 'servers', servers_str)

    def is_feature_enabled(self, feature):
        """Prüft ob ein Feature aktiviert ist"""
        feature_map = {
            'threat_intelligence': ('security', 'threat_intelligence'),
            'ad_blocking': ('security', 'ad_blocking'),
            'safe_search': ('security', 'safe_search'),
            'dns_tunneling_protection': ('security', 'dns_tunneling_protection'),
            'dnssec_validation': ('security', 'dnssec_validation'),
            'rate_limiting': ('security', 'rate_limiting'),
            'query_logging': ('logging', 'query_logging'),
            'web_interface': ('web', 'enabled'),
            'cache': ('cache', 'enabled')
        }

        if feature in feature_map:
            section, key = feature_map[feature]
            return self.get_value(section, key, False)

        return False

    def enable_feature(self, feature, enabled=True):
        """Aktiviert oder deaktiviert ein Feature"""
        feature_map = {
            'threat_intelligence': ('security', 'threat_intelligence'),
            'ad_blocking': ('security', 'ad_blocking'),
            'safe_search': ('security', 'safe_search'),
            'dns_tunneling_protection': ('security', 'dns_tunneling_protection'),
            'dnssec_validation': ('security', 'dnssec_validation'),
            'rate_limiting': ('security', 'rate_limiting'),
            'query_logging': ('logging', 'query_logging'),
            'web_interface': ('web', 'enabled'),
            'cache': ('cache', 'enabled')
        }

        if feature in feature_map:
            section, key = feature_map[feature]
            self.set_value(section, key, enabled)
            return True

        return False

    def get_blocklist_sources(self):
        """Gibt Liste der Blocklist-Quellen zurück"""
        return self.get_value('blocklists', 'sources', [])

    def add_blocklist_source(self, url):
        """Fügt neue Blocklist-Quelle hinzu"""
        sources = self.get_blocklist_sources()
        if url not in sources:
            sources.append(url)
            self.set_value('blocklists', 'sources', sources)

    def remove_blocklist_source(self, url):
        """Entfernt Blocklist-Quelle"""
        sources = self.get_blocklist_sources()
        if url in sources:
            sources.remove(url)
            self.set_value('blocklists', 'sources', sources)

    def export_config(self, format='yaml'):
        """Exportiert Konfiguration in verschiedenen Formaten"""
        try:
            with self.lock:
                if format.lower() == 'yaml':
                    return yaml.dump(self.config, default_flow_style=False, 
                                   allow_unicode=True, indent=2)
                elif format.lower() == 'json':
                    return json.dumps(self.config, indent=2, ensure_ascii=False)
                elif format.lower() == 'ini':
                    import io
                    output = io.StringIO()
                    parser = configparser.ConfigParser()

                    for section_name, section_data in self.config.items():
                        if isinstance(section_data, dict):
                            parser.add_section(section_name)
                            for key, value in section_data.items():
                                if isinstance(value, list):
                                    value = ','.join(str(v) for v in value)
                                parser.set(section_name, key, str(value))

                    parser.write(output)
                    return output.getvalue()
                else:
                    raise ValueError(f"Unbekanntes Export-Format: {format}")

        except Exception as e:
            logger.error(f"Fehler beim Konfigurationsexport: {e}")
            return None

    def import_config(self, config_data, format='yaml', merge=True):
        """Importiert Konfiguration aus verschiedenen Formaten"""
        try:
            with self.lock:
                if format.lower() == 'yaml':
                    imported_config = yaml.safe_load(config_data)
                elif format.lower() == 'json':
                    imported_config = json.loads(config_data)
                else:
                    raise ValueError(f"Unbekanntes Import-Format: {format}")

                if merge:
                    self.update_config(imported_config)
                else:
                    self.config = imported_config
                    self.save_config()

                logger.info(f"Konfiguration aus {format.upper()} importiert")

        except Exception as e:
            logger.error(f"Fehler beim Konfigurationsimport: {e}")
            raise

    def reset_to_defaults(self, section=None):
        """Setzt Konfiguration auf Standardwerte zurück"""
        try:
            with self.lock:
                if section:
                    if section in self.DEFAULT_CONFIG:
                        self.config[section] = self._deep_copy_dict(self.DEFAULT_CONFIG[section])
                        logger.info(f"Sektion '{section}' auf Standardwerte zurückgesetzt")
                    else:
                        raise ValueError(f"Unbekannte Sektion: {section}")
                else:
                    self.config = self._deep_copy_dict(self.DEFAULT_CONFIG)
                    logger.info("Gesamte Konfiguration auf Standardwerte zurückgesetzt")

                self.save_config()

        except Exception as e:
            logger.error(f"Fehler beim Zurücksetzen der Konfiguration: {e}")
            raise

if __name__ == '__main__':
    # Test der Funktionalität
    logging.basicConfig(level=logging.INFO)

    config_manager = ConfigManager('/tmp/test_jetdns.conf')

    # Konfiguration anzeigen
    print("Aktuelle Konfiguration:")
    print(json.dumps(config_manager.get_config(), indent=2))

    # Wert ändern
    config_manager.set_value('dns', 'listen_port', 5353)
    print(f"\nDNS Port: {config_manager.get_value('dns', 'listen_port')}")

    # Validierung
    validation = config_manager.validate_config()
    print(f"\nValidierung: {validation}")

    # Export
    yaml_export = config_manager.export_config('yaml')
    print(f"\nYAML Export:\n{yaml_export[:200]}...")
