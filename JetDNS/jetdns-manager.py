#!/usr/bin/env python3
"""
JetDNS Manager - Post-Setup Management Tool
Verwaltet JetDNS nach der initialen Konfiguration

Autor: JetDNS Team
Version: 1.0.0
Lizenz: MIT
"""

import argparse
import json
import logging
import os
import sys
import subprocess
import configparser
import platform
import psutil
from pathlib import Path
from datetime import datetime, timedelta
import shutil
import tempfile
import hashlib

# Logging konfigurieren
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JetDNSManager:
    """JetDNS Management-Klasse für Post-Setup Operationen"""

    VERSION = "1.0.0"

    def __init__(self):
        self.config_dir = Path('/etc/jetdns')
        self.config_file = self.config_dir / 'jetdns.conf'
        self.setup_complete_file = self.config_dir / '.setup_complete'
        self.backup_dir = Path('/opt/jetdns/backups')
        self.log_dir = Path('/var/log/jetdns')
        self.service_name = 'jetdns'

        # Stelle sicher, dass Backup-Verzeichnis existiert
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def is_setup_complete(self) -> bool:
        """Prüft ob JetDNS Setup abgeschlossen ist"""
        return self.setup_complete_file.exists()

    def load_config(self) -> configparser.ConfigParser:
        """Lädt JetDNS Konfiguration"""
        if not self.config_file.exists():
            raise FileNotFoundError(f"JetDNS Konfiguration nicht gefunden: {self.config_file}")

        config = configparser.ConfigParser()
        try:
            config.read(self.config_file, encoding='utf-8')
            return config
        except configparser.Error as e:
            raise ValueError(f"Fehlerhafte Konfigurationsdatei: {e}")

    def get_service_status(self) -> dict:
        """Ermittelt den Status des JetDNS Services"""
        status_info = {
            'active': False,
            'enabled': False,
            'uptime': None,
            'memory_usage': None,
            'cpu_usage': None
        }

        try:
            # Service Status
            result = subprocess.run(
                ['systemctl', 'is-active', self.service_name],
                capture_output=True, text=True, timeout=5
            )
            status_info['active'] = result.stdout.strip() == 'active'

            # Service enabled?
            result = subprocess.run(
                ['systemctl', 'is-enabled', self.service_name],
                capture_output=True, text=True, timeout=5
            )
            status_info['enabled'] = result.stdout.strip() == 'enabled'

            # Uptime
            if status_info['active']:
                result = subprocess.run(
                    ['systemctl', 'show', self.service_name, '--property=ActiveEnterTimestamp'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    timestamp_line = result.stdout.strip()
                    if '=' in timestamp_line:
                        timestamp_str = timestamp_line.split('=', 1)[1].strip()
                        if timestamp_str and timestamp_str != 'n/a':
                            try:
                                start_time = datetime.strptime(
                                    timestamp_str.split(' ')[1] + ' ' + timestamp_str.split(' ')[2],
                                    '%Y-%m-%d %H:%M:%S'
                                )
                                uptime = datetime.now() - start_time
                                status_info['uptime'] = str(uptime).split('.')[0]
                            except (ValueError, IndexError):
                                pass

            # Ressourcenverbrauch
            try:
                for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                    if 'jetdns' in proc.info['name'].lower():
                        status_info['memory_usage'] = proc.info['memory_info'].rss / 1024 / 1024  # MB
                        status_info['cpu_usage'] = proc.info['cpu_percent']
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logger.warning(f"Fehler beim Ermitteln des Service-Status: {e}")

        return status_info

    def status(self, detailed: bool = False):
        """Zeigt detaillierten Status von JetDNS"""
        print(f"🚀 JetDNS Manager v{self.VERSION}")
        print("=" * 50)

        if not self.is_setup_complete():
            print("❌ JetDNS ist nicht konfiguriert")
            print("   Führen Sie das initiale Setup durch:")
            print("   sudo jetdns-setup")
            return

        # Service Status
        service_status = self.get_service_status()
        status_icon = "✅" if service_status['active'] else "❌"
        print(f"\n📊 Service Status")
        print("-" * 20)
        print(f"{status_icon} Service: {'Aktiv' if service_status['active'] else 'Inaktiv'}")
        print(f"🔄 Autostart: {'Aktiviert' if service_status['enabled'] else 'Deaktiviert'}")

        if service_status['uptime']:
            print(f"⏱️  Uptime: {service_status['uptime']}")
        if service_status['memory_usage']:
            print(f"💾 RAM: {service_status['memory_usage']:.1f} MB")
        if service_status['cpu_usage']:
            print(f"⚡ CPU: {service_status['cpu_usage']:.1f}%")

        # Konfiguration
        try:
            config = self.load_config()
            print(f"\n🔧 Konfiguration")
            print("-" * 20)

            if config.has_section('dns'):
                print(f"🌐 Listen IP: {config.get('dns', 'listen_address', fallback='0.0.0.0')}")
                print(f"🔌 DNS Port: {config.get('dns', 'listen_port', fallback='53')}")

            if config.has_section('web'):
                host = config.get('web', 'host', fallback='0.0.0.0')
                port = config.get('web', 'port', fallback='80')
                protocol = config.get('web', 'protocol', fallback='http').upper()
                print(f"💻 Web Interface: {protocol}://{host}:{port}")

            if config.has_section('general'):
                print(f"🌍 Sprache: {config.get('general', 'language', fallback='de')}")

        except Exception as e:
            print(f"⚠️  Konfiguration: Fehler beim Lesen ({e})")

        # System-Informationen (nur bei --detailed)
        if detailed:
            print(f"\n💻 System")
            print("-" * 20)
            print(f"OS: {platform.system()} {platform.release()}")
            print(f"Python: {platform.python_version()}")

            # Festplattenspeicher
            try:
                disk_usage = shutil.disk_usage('/opt/jetdns')
                free_gb = disk_usage.free / (1024**3)
                total_gb = disk_usage.total / (1024**3)
                print(f"Festplatte: {free_gb:.1f}GB frei von {total_gb:.1f}GB")
            except:
                pass

            # Letzte Backups
            if self.backup_dir.exists():
                backups = sorted(
                    [d for d in self.backup_dir.iterdir() if d.is_dir()],
                    key=lambda x: x.stat().st_mtime,
                    reverse=True
                )[:3]

                if backups:
                    print(f"\n💾 Letzte Backups")
                    print("-" * 20)
                    for backup in backups:
                        mtime = datetime.fromtimestamp(backup.stat().st_mtime)
                        print(f"📁 {backup.name} ({mtime.strftime('%d.%m.%Y %H:%M')})")

    def backup(self, backup_name: str = None, compress: bool = False) -> str:
        """Erstellt vollständiges Backup mit optionaler Kompression"""
        if backup_name is None:
            backup_name = f"jetdns_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)

        print(f"📦 Erstelle Backup: {backup_name}")
        backup_components = []
        errors = []

        # Konfiguration sichern
        try:
            if self.config_dir.exists():
                shutil.copytree(self.config_dir, backup_path / 'config', dirs_exist_ok=True)
                print("✅ Konfiguration gesichert")
                backup_components.append('config')
        except Exception as e:
            error_msg = f"Konfiguration: {e}"
            print(f"❌ {error_msg}")
            errors.append(error_msg)

        # Logs sichern (nur letzte 7 Tage)
        try:
            if self.log_dir.exists():
                log_backup_dir = backup_path / 'logs'
                log_backup_dir.mkdir(exist_ok=True)

                cutoff_date = datetime.now() - timedelta(days=7)
                logs_copied = 0

                for log_file in self.log_dir.glob('*.log*'):
                    if datetime.fromtimestamp(log_file.stat().st_mtime) > cutoff_date:
                        shutil.copy2(log_file, log_backup_dir)
                        logs_copied += 1

                if logs_copied > 0:
                    print(f"✅ Logs gesichert ({logs_copied} Dateien)")
                    backup_components.append('logs')
                else:
                    print("ℹ️  Keine aktuellen Logs gefunden")
        except Exception as e:
            error_msg = f"Logs: {e}"
            print(f"⚠️  {error_msg}")
            errors.append(error_msg)

        # Custom Konfigurationen sichern
        custom_dirs = ['/opt/jetdns/custom', '/etc/jetdns/custom']
        for custom_dir in custom_dirs:
            custom_path = Path(custom_dir)
            if custom_path.exists():
                try:
                    shutil.copytree(custom_path, backup_path / custom_path.name, dirs_exist_ok=True)
                    print(f"✅ {custom_path.name} gesichert")
                    backup_components.append(custom_path.name)
                except Exception as e:
                    error_msg = f"{custom_path.name}: {e}"
                    print(f"⚠️  {error_msg}")
                    errors.append(error_msg)

        # Backup-Metadaten erstellen
        backup_info = {
            'created_at': datetime.now().isoformat(),
            'created_by': f"jetdns-manager v{self.VERSION}",
            'jetdns_version': self.VERSION,
            'system': {
                'os': platform.system(),
                'release': platform.release(),
                'python': platform.python_version()
            },
            'backup_type': 'full',
            'components': backup_components,
            'errors': errors,
            'compressed': compress
        }

        # Checksumme der wichtigsten Dateien
        checksums = {}
        for component in backup_components:
            component_path = backup_path / component
            if component_path.exists():
                checksums[component] = self._calculate_directory_checksum(component_path)
        backup_info['checksums'] = checksums

        # Backup-Info speichern
        with open(backup_path / 'backup_info.json', 'w', encoding='utf-8') as f:
            json.dump(backup_info, f, indent=2, ensure_ascii=False)

        # Optional: Backup komprimieren
        final_path = backup_path
        if compress:
            try:
                compressed_path = backup_path.with_suffix('.tar.gz')
                shutil.make_archive(str(backup_path), 'gztar', str(backup_path))
                shutil.rmtree(backup_path)
                final_path = compressed_path
                print(f"🗜️  Backup komprimiert")
            except Exception as e:
                print(f"⚠️  Komprimierung fehlgeschlagen: {e}")

        print(f"✅ Backup erstellt: {final_path}")
        if errors:
            print(f"⚠️  {len(errors)} Warnung(en) aufgetreten")

        return str(final_path)

    def _calculate_directory_checksum(self, directory: Path) -> str:
        """Berechnet MD5 Checksumme eines Verzeichnisses"""
        md5_hash = hashlib.md5()

        try:
            for file_path in sorted(directory.rglob('*')):
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            md5_hash.update(chunk)
        except Exception:
            return "error"

        return md5_hash.hexdigest()

    def list_backups(self):
        """Listet alle verfügbaren Backups auf"""
        if not self.backup_dir.exists():
            print("📂 Keine Backups gefunden")
            return

        backups = []

        # Verzeichnis-Backups
        for item in self.backup_dir.iterdir():
            if item.is_dir() and (item / 'backup_info.json').exists():
                backups.append(item)
            elif item.suffix in ['.tar', '.gz'] and 'backup' in item.name:
                backups.append(item)

        if not backups:
            print("📂 Keine Backups gefunden")
            return

        backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)

        print("📂 Verfügbare Backups:")
        print("-" * 50)

        for i, backup in enumerate(backups, 1):
            mtime = datetime.fromtimestamp(backup.stat().st_mtime)
            size = self._get_size(backup)
            compressed = "🗜️ " if backup.suffix in ['.tar', '.gz'] else ""

            print(f"{i:2d}. {compressed}{backup.name}")
            print(f"     📅 {mtime.strftime('%d.%m.%Y %H:%M:%S')}")
            print(f"     📊 {size}")

            # Backup-Info laden wenn verfügbar
            info_file = backup / 'backup_info.json' if backup.is_dir() else None
            if info_file and info_file.exists():
                try:
                    with open(info_file, 'r', encoding='utf-8') as f:
                        info = json.load(f)
                    components = ', '.join(info.get('components', []))
                    print(f"     📦 {components}")
                except:
                    pass
            print()

    def _get_size(self, path: Path) -> str:
        """Berechnet Größe eines Pfades (Datei oder Verzeichnis)"""
        try:
            if path.is_file():
                size = path.stat().st_size
            else:
                size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())

            # Format in menschenlesbarer Form
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        except:
            return "Unbekannt"

    def restore(self, backup_path: str, force: bool = False) -> bool:
        """Stellt Backup wieder her mit Validierung"""
        backup_path_obj = Path(backup_path)

        if not backup_path_obj.exists():
            print(f"❌ Backup nicht gefunden: {backup_path}")
            return False

        # Backup-Typ bestimmen
        is_compressed = backup_path_obj.suffix in ['.tar', '.gz', '.tgz']

        if is_compressed:
            # Temporär extrahieren
            temp_dir = Path(tempfile.mkdtemp())
            try:
                shutil.unpack_archive(str(backup_path_obj), str(temp_dir))
                # Suche nach dem eigentlichen Backup-Verzeichnis
                extracted_dirs = [d for d in temp_dir.iterdir() if d.is_dir()]
                if len(extracted_dirs) == 1:
                    backup_path_obj = extracted_dirs[0]
                else:
                    backup_path_obj = temp_dir
            except Exception as e:
                print(f"❌ Fehler beim Extrahieren: {e}")
                return False

        # Backup-Info validieren
        backup_info_file = backup_path_obj / 'backup_info.json'
        if not backup_info_file.exists():
            if not force:
                print("❌ Ungültiges Backup (backup_info.json fehlt)")
                print("    Verwenden Sie --force zum Überspringen der Validierung")
                return False
        else:
            try:
                with open(backup_info_file, 'r', encoding='utf-8') as f:
                    backup_info = json.load(f)

                print(f"📋 Backup-Informationen:")
                print(f"    Erstellt: {backup_info.get('created_at', 'Unbekannt')}")
                print(f"    Komponenten: {', '.join(backup_info.get('components', []))}")

                # Checksummen validieren wenn vorhanden
                if 'checksums' in backup_info:
                    print("🔍 Validiere Backup-Integrität...")
                    for component, expected_checksum in backup_info['checksums'].items():
                        component_path = backup_path_obj / component
                        if component_path.exists():
                            actual_checksum = self._calculate_directory_checksum(component_path)
                            if actual_checksum != expected_checksum:
                                print(f"⚠️  Checksumme für {component} stimmt nicht überein")

            except Exception as e:
                print(f"⚠️  Fehler beim Lesen der Backup-Informationen: {e}")

        if not force:
            confirm = input("❓ Backup wirklich wiederherstellen? [y/N]: ")
            if confirm.lower() not in ['y', 'yes', 'j', 'ja']:
                print("Wiederherstellung abgebrochen")
                return False

        print(f"🔄 Stelle Backup wieder her: {backup_path}")

        # Service stoppen
        service_was_running = False
        try:
            result = subprocess.run(['systemctl', 'is-active', self.service_name], 
                                  capture_output=True)
            service_was_running = result.returncode == 0

            if service_was_running:
                subprocess.run(['systemctl', 'stop', self.service_name], 
                             check=True, timeout=30)
                print("✅ Service gestoppt")
        except subprocess.TimeoutExpired:
            print("⚠️  Service-Stop Timeout - fahre fort")
        except Exception as e:
            print(f"⚠️  Service konnte nicht gestoppt werden: {e}")

        # Aktuelle Konfiguration sichern
        temp_backup = None
        if self.config_dir.exists():
            try:
                temp_backup = self.backup_dir / f"pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copytree(self.config_dir, temp_backup)
                print(f"💾 Aktuelle Konfiguration gesichert in: {temp_backup}")
            except Exception as e:
                print(f"⚠️  Backup der aktuellen Konfiguration fehlgeschlagen: {e}")

        # Konfiguration wiederherstellen
        restore_success = True
        try:
            config_backup = backup_path_obj / 'config'
            if config_backup.exists():
                if self.config_dir.exists():
                    shutil.rmtree(self.config_dir)
                shutil.copytree(config_backup, self.config_dir)
                print("✅ Konfiguration wiederhergestellt")
            else:
                print("⚠️  Keine Konfiguration im Backup gefunden")
        except Exception as e:
            print(f"❌ Konfiguration: {e}")
            restore_success = False

            # Versuche alte Konfiguration wiederherzustellen
            if temp_backup and temp_backup.exists():
                try:
                    if self.config_dir.exists():
                        shutil.rmtree(self.config_dir)
                    shutil.copytree(temp_backup, self.config_dir)
                    print("🔄 Alte Konfiguration wiederhergestellt")
                except:
                    pass

        # Service starten wenn er vorher lief
        if service_was_running:
            try:
                subprocess.run(['systemctl', 'start', self.service_name], 
                             check=True, timeout=30)
                print("✅ Service gestartet")
            except Exception as e:
                print(f"❌ Service-Start fehlgeschlagen: {e}")
                restore_success = False

        # Temporäre Dateien aufräumen
        if is_compressed and temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except:
                pass

        if restore_success:
            print("✅ Backup erfolgreich wiederhergestellt")
        else:
            print("❌ Wiederherstellung teilweise fehlgeschlagen")

        return restore_success

    def update_config(self, section: str, key: str, value: str):
        """Aktualisiert Konfiguration mit Backup"""
        # Backup vor Änderung erstellen
        try:
            backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(self.config_file, self.config_dir / backup_name)
            print(f"💾 Konfiguration gesichert als: {backup_name}")
        except Exception as e:
            print(f"⚠️  Backup fehlgeschlagen: {e}")

        try:
            config = self.load_config()

            if section not in config:
                config.add_section(section)

            old_value = config.get(section, key, fallback='<nicht gesetzt>')
            config.set(section, key, value)

            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)

            print(f"✅ Konfiguration aktualisiert:")
            print(f"   [{section}] {key}")
            print(f"   Vorher: {old_value}")
            print(f"   Nachher: {value}")

            # Prüfen ob Neustart erforderlich
            restart_required_sections = ['dns', 'web', 'upstream']
            if section in restart_required_sections:
                print("⚠️  Service-Neustart empfohlen: jetdns restart")

        except Exception as e:
            print(f"❌ Fehler beim Aktualisieren der Konfiguration: {e}")

    def restart_service(self):
        """Startet JetDNS Service neu mit Status-Check"""
        try:
            print("🔄 Starte Service neu...")

            # Status vor Neustart
            status_before = self.get_service_status()

            subprocess.run(['systemctl', 'restart', self.service_name], 
                         check=True, timeout=30)

            # Kurz warten und Status prüfen
            import time
            time.sleep(2)

            status_after = self.get_service_status()

            if status_after['active']:
                print("✅ Service erfolgreich neu gestartet")
                if status_before['active']:
                    print(f"   Uptime zurückgesetzt")
            else:
                print("❌ Service-Neustart fehlgeschlagen")
                print("   Prüfen Sie die Logs: jetdns logs")

        except subprocess.TimeoutExpired:
            print("❌ Service-Neustart Timeout")
        except Exception as e:
            print(f"❌ Service-Neustart fehlgeschlagen: {e}")

    def show_logs(self, lines: int = 50, follow: bool = False, service_only: bool = True):
        """Zeigt JetDNS Logs mit erweiterten Optionen"""
        try:
            cmd = ['journalctl']
            if service_only:
                cmd.extend(['-u', self.service_name])
            if follow:
                cmd.append('-f')
            else:
                cmd.extend(['-n', str(lines)])
            cmd.extend(['--no-pager', '--output=short-iso'])

            print(f"📋 JetDNS Logs (letzte {lines} Zeilen)")
            if follow:
                print("   Drücken Sie Ctrl+C zum Beenden")
            print("=" * 50)

            if follow:
                subprocess.run(cmd)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.stdout:
                    print(result.stdout)
                else:
                    print("Keine Logs gefunden")

        except subprocess.TimeoutExpired:
            print("❌ Timeout beim Abrufen der Logs")
        except KeyboardInterrupt:
            print("\n👋 Log-Verfolgung beendet")
        except Exception as e:
            print(f"❌ Fehler beim Anzeigen der Logs: {e}")

    def validate_config(self) -> bool:
        """Validiert die JetDNS Konfiguration"""
        try:
            config = self.load_config()
            errors = []
            warnings = []

            print("🔍 Validiere Konfiguration...")

            # DNS Sektion prüfen
            if not config.has_section('dns'):
                errors.append("DNS-Sektion fehlt")
            else:
                listen_addr = config.get('dns', 'listen_address', fallback='0.0.0.0')
                listen_port = config.getint('dns', 'listen_port', fallback=53)

                if listen_port < 1 or listen_port > 65535:
                    errors.append(f"Ungültiger DNS Port: {listen_port}")
                elif listen_port != 53 and listen_port < 1024:
                    warnings.append(f"Non-standard DNS Port: {listen_port}")

            # Web Sektion prüfen
            if config.has_section('web'):
                web_port = config.getint('web', 'port', fallback=80)
                if web_port < 1 or web_port > 65535:
                    errors.append(f"Ungültiger Web Port: {web_port}")

            # Upstream Server prüfen
            if config.has_section('upstream'):
                servers = config.get('upstream', 'servers', fallback='')
                if not servers.strip():
                    warnings.append("Keine Upstream-Server konfiguriert")

            # Ergebnisse anzeigen
            if errors:
                print("❌ Konfigurationsfehler gefunden:")
                for error in errors:
                    print(f"   • {error}")

            if warnings:
                print("⚠️  Warnungen:")
                for warning in warnings:
                    print(f"   • {warning}")

            if not errors and not warnings:
                print("✅ Konfiguration ist gültig")

            return len(errors) == 0

        except Exception as e:
            print(f"❌ Fehler bei der Validierung: {e}")
            return False

def main():
    """Hauptprogramm mit erweitertem Argument-Parsing"""
    parser = argparse.ArgumentParser(
        description='JetDNS Management Tool - Verwaltet JetDNS nach dem Setup',
        epilog="""
Beispiele:
  jetdns status --detailed          # Detaillierter Status
  jetdns backup --compress          # Komprimiertes Backup
  jetdns restore backup.tar.gz      # Backup wiederherstellen
  jetdns logs --follow              # Live-Logs verfolgen
  jetdns config dns listen_port 5353  # Port ändern
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('action', choices=[
        'status', 'backup', 'restore', 'restart', 'logs', 'config', 
        'list-backups', 'validate-config'
    ], help='Aktion die ausgeführt werden soll')

    # Backup Optionen
    parser.add_argument('--backup-name', help='Name für das Backup')
    parser.add_argument('--compress', action='store_true', 
                       help='Backup komprimieren (nur für backup)')

    # Restore Optionen
    parser.add_argument('--backup-path', help='Pfad zum Backup für Wiederherstellung')
    parser.add_argument('--force', action='store_true',
                       help='Validierung überspringen (nur für restore)')

    # Config Optionen
    parser.add_argument('section', nargs='?', help='Konfigurationssektion')
    parser.add_argument('key', nargs='?', help='Konfigurationsschlüssel')
    parser.add_argument('value', nargs='?', help='Konfigurationswert')

    # Log Optionen
    parser.add_argument('--lines', type=int, default=50, help='Anzahl Log-Zeilen')
    parser.add_argument('--follow', action='store_true', 
                       help='Logs live verfolgen (nur für logs)')

    # Status Optionen
    parser.add_argument('--detailed', action='store_true',
                       help='Detaillierte Informationen (nur für status)')

    # Debug Option
    parser.add_argument('--debug', action='store_true', help='Debug-Ausgaben aktivieren')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        manager = JetDNSManager()

        if args.action == 'status':
            manager.status(detailed=args.detailed)

        elif args.action == 'backup':
            manager.backup(args.backup_name, compress=args.compress)

        elif args.action == 'list-backups':
            manager.list_backups()

        elif args.action == 'restore':
            if not args.backup_path:
                print("❌ --backup-path ist erforderlich für restore")
                sys.exit(1)
            success = manager.restore(args.backup_path, force=args.force)
            sys.exit(0 if success else 1)

        elif args.action == 'restart':
            manager.restart_service()

        elif args.action == 'logs':
            manager.show_logs(args.lines, follow=args.follow)

        elif args.action == 'config':
            if not all([args.section, args.key, args.value]):
                print("❌ section, key und value sind erforderlich für config")
                print("   Beispiel: jetdns config dns listen_port 5353")
                sys.exit(1)
            manager.update_config(args.section, args.key, args.value)

        elif args.action == 'validate-config':
            success = manager.validate_config()
            sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n👋 Unterbrochen durch Benutzer")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unerwarteter Fehler: {e}")
        if args.debug:
            raise
        sys.exit(1)

if __name__ == '__main__':
    main()
