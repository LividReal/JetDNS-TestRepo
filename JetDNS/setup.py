#!/usr/bin/env python3
"""
JetDNS Setup Server
Läuft auf Port 8080 für die initiale Konfiguration
"""

import json
import os
import sys
import subprocess
import socket
import time
import hashlib
import threading
import shutil
import psutil
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, send_from_directory
import configparser
from pathlib import Path

app = Flask(__name__)
app.secret_key = 'jetdns-setup-secret-key-change-me'

# Konfigurationspfade
CONFIG_DIR = Path('/etc/jetdns')
CONFIG_FILE = CONFIG_DIR / 'jetdns.conf'
SETUP_COMPLETE_FILE = CONFIG_DIR / '.setup_complete'

def is_setup_complete():
    """Prüft ob das Setup bereits abgeschlossen wurde"""
    return SETUP_COMPLETE_FILE.exists()

def create_setup_lock():
    """Erstellt permanente Setup-Sperre mit Zeitstempel und Config-Hash"""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        import hashlib
        import time

        # Erstelle Setup-Lock mit Metadaten
        lock_data = {
            'completed_at': time.time(),
            'completed_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'setup_version': '1.0',
            'locked': True,
            'config_hash': hashlib.sha256(str(CONFIG_FILE).encode()).hexdigest()
        }

        # Schreibt Lock-Datei
        with open(SETUP_COMPLETE_FILE, 'w') as f:
            json.dump(lock_data, f, indent=2)

        # Setze immutable Flag (falls unterstützt)
        try:
            subprocess.run(['chattr', '+i', str(SETUP_COMPLETE_FILE)], 
                         check=False, capture_output=True)
        except:
            pass  # Ignore if chattr not available

        # Erstelle zusätzliche Backup-Lock-Datei
        backup_lock = CONFIG_DIR / '.jetdns_configured'
        backup_lock.touch()

        return True
    except Exception as e:
        print(f"Fehler beim Erstellen der Setup-Sperre: {e}")
        return False

def get_main_app_url():
    """Ermittelt die URL der Hauptanwendung aus der Konfiguration"""
    try:
        if CONFIG_FILE.exists():
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE)

            host = config.get('web', 'host', fallback='localhost')
            port = config.get('web', 'port', fallback='80')
            protocol = config.get('web', 'protocol', fallback='http')

            return f"{protocol}://{host}:{port}"
    except:
        pass

    # Fallback
    return "http://localhost"

def disable_setup_service():
    """Deaktiviert den Setup-Service permanent"""
    try:
        # Erstelle Service-Disable-Marker
        disable_file = CONFIG_DIR / '.setup_service_disabled'
        with open(disable_file, 'w') as f:
            f.write(f"Setup disabled at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        # Firewall-Regel für Port 8080 entfernen
        try:
            subprocess.run(['ufw', 'delete', 'allow', '8080/tcp'], 
                         check=False, capture_output=True)
        except:
            pass

        return True
    except Exception as e:
        print(f"Fehler beim Deaktivieren des Setup-Service: {e}")
        return False

def get_network_interfaces():
    """Ermittelt verfügbare Netzwerk-Interfaces mit Details"""
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        interfaces = []
        current_interface = None

        for line in result.stdout.split('\n'):
            if ': ' in line:
                if 'state UP' in line:
                    interface_name = line.split(':')[1].strip().split('@')[0]
                    if interface_name not in ['lo']:
                        current_interface = {
                            'name': interface_name,
                            'type': 'ethernet' if 'eth' in interface_name else 'wireless' if 'wlan' in interface_name else 'virtual',
                            'ip': None,
                            'status': 'UP'
                        }
            elif current_interface and 'inet ' in line:
                ip_info = line.strip().split()[1].split('/')[0]
                current_interface['ip'] = ip_info
                interfaces.append(current_interface)
                current_interface = None

        return interfaces if interfaces else [
            {'name': 'eth0', 'type': 'ethernet', 'ip': None, 'status': 'DOWN'}
        ]
    except Exception as e:
        print(f"Fehler beim Ermitteln der Netzwerk-Interfaces: {e}")
        return [{'name': 'eth0', 'type': 'ethernet', 'ip': None, 'status': 'UNKNOWN'}]

def get_system_info():
    """Sammelt umfassende Systeminformationen"""
    try:
        return {
            'hostname': socket.gethostname(),
            'platform': os.uname().sysname,
            'release': os.uname().release,
            'architecture': os.uname().machine,
            'cpu_count': os.cpu_count(),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            },
            'uptime': time.time() - psutil.boot_time()
        }
    except Exception as e:
        print(f"Fehler beim Sammeln der Systeminformationen: {e}")
        return {}

def check_port_availability(port, protocol='tcp'):
    """Prüft ob ein Port verfügbar ist"""
    try:
        if protocol == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result != 0  # True wenn Port frei ist
    except:
        return True

def create_config_backup():
    """Erstellt Backup der aktuellen Systemkonfiguration"""
    try:
        backup_dir = CONFIG_DIR / 'backups' / datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Backup wichtiger Systemdateien
        backup_files = [
            ('/etc/netplan', 'netplan'),
            ('/etc/resolv.conf', 'resolv.conf'),
            ('/etc/hosts', 'hosts'),
            ('/etc/hostname', 'hostname')
        ]

        backup_info = {
            'created_at': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'interfaces': get_network_interfaces(),
            'system': get_system_info()
        }

        for src, dst in backup_files:
            try:
                if os.path.exists(src):
                    if os.path.isdir(src):
                        shutil.copytree(src, backup_dir / dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, backup_dir / dst)
            except Exception as e:
                print(f"Backup-Warnung für {src}: {e}")

        # Backup-Info speichern
        with open(backup_dir / 'backup_info.json', 'w') as f:
            json.dump(backup_info, f, indent=2)

        return str(backup_dir)
    except Exception as e:
        print(f"Backup-Erstellung fehlgeschlagen: {e}")
        return None

def validate_ip_address(ip):
    """Validiert eine IP-Adresse"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def apply_network_configuration(config):
    """Wendet die Netzwerk-Konfiguration systemweit an"""
    try:
        interface = config.get('network_interface', 'eth0')
        server_ip = config.get('server_ip')

        if not validate_ip_address(server_ip):
            raise ValueError(f"Ungültige IP-Adresse: {server_ip}")

        # Netplan Konfiguration für Ubuntu/neuere Systeme
        netplan_config = f"""
network:
  version: 2
  renderer: networkd
  ethernets:
    {interface}:
      addresses:
        - {server_ip}/24
      gateway4: {'.'.join(server_ip.split('.')[:-1])}.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
"""

        # Backup der aktuellen Konfiguration
        backup_dir = Path('/etc/netplan/backup')
        backup_dir.mkdir(exist_ok=True)

        # Schreibt neue Netplan-Konfiguration
        netplan_file = Path('/etc/netplan/50-jetdns.yaml')
        with open(netplan_file, 'w') as f:
            f.write(netplan_config)

        # Anwenden der Netzwerk-Konfiguration
        subprocess.run(['netplan', 'apply'], check=True)

        print(f"Netzwerk-Konfiguration angewendet: {server_ip} auf {interface}")
        return True

    except Exception as e:
        print(f"Fehler bei der Netzwerk-Konfiguration: {e}")
        return False

def create_jetdns_config(config):
    """Erstellt die JetDNS Hauptkonfigurationsdatei"""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        jetdns_config = configparser.ConfigParser()

        # DNS Server Konfiguration
        jetdns_config['dns'] = {
            'listen_address': config.get('server_ip', '0.0.0.0'),
            'listen_port': str(config.get('dns_port', 53)),
            'upstream_servers': '8.8.8.8,8.8.4.4,1.1.1.1',
            'cache_size': '10000',
            'cache_ttl': '300'
        }

        # Web Interface Konfiguration
        jetdns_config['web'] = {
            'host': config.get('server_ip', '0.0.0.0'),
            'port': str(config.get('web_port', 80)),
            'protocol': config.get('protocol', 'http'),
            'ssl_cert': '/etc/jetdns/ssl/server.crt' if config.get('protocol') == 'https' else '',
            'ssl_key': '/etc/jetdns/ssl/server.key' if config.get('protocol') == 'https' else ''
        }

        # Allgemeine Einstellungen
        jetdns_config['general'] = {
            'language': config.get('language', 'de'),
            'timezone': 'Europe/Berlin',
            'debug': 'false'
        }

        # Sicherheitseinstellungen
        jetdns_config['security'] = {
            'threat_intelligence_enabled': 'true',
            'content_filtering_enabled': 'true',
            'logging_enabled': 'true'
        }

        with open(CONFIG_FILE, 'w') as f:
            jetdns_config.write(f)

        print(f"JetDNS Konfiguration erstellt: {CONFIG_FILE}")
        return True

    except Exception as e:
        print(f"Fehler beim Erstellen der Konfiguration: {e}")
        return False

def setup_ssl_certificates(config):
    """Erstellt SSL-Zertifikate wenn HTTPS gewählt wurde"""
    if config.get('protocol') != 'https' or not config.get('self_signed_cert'):
        return True

    try:
        ssl_dir = CONFIG_DIR / 'ssl'
        ssl_dir.mkdir(parents=True, exist_ok=True)

        cert_file = ssl_dir / 'server.crt'
        key_file = ssl_dir / 'server.key'

        # Generiert selbst-signiertes Zertifikat
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', str(key_file),
            '-out', str(cert_file),
            '-days', '365', '-nodes',
            '-subj', f"/C=DE/ST=Germany/L=City/O=JetDNS/CN={config.get('server_ip')}"
        ]

        subprocess.run(cmd, check=True)

        # Setze Berechtigungen
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)

        print("SSL-Zertifikate erfolgreich erstellt")
        return True

    except Exception as e:
        print(f"Fehler beim Erstellen der SSL-Zertifikate: {e}")
        return False

def configure_firewall(config):
    """Konfiguriert Firewall-Regeln für JetDNS"""
    try:
        dns_port = config.get('dns_port', 53)
        web_port = config.get('web_port', 80)

        # UFW Regeln falls UFW installiert ist
        try:
            subprocess.run(['ufw', 'allow', f'{dns_port}/udp'], check=True)
            subprocess.run(['ufw', 'allow', f'{dns_port}/tcp'], check=True)
            subprocess.run(['ufw', 'allow', f'{web_port}/tcp'], check=True)

            if config.get('protocol') == 'https':
                subprocess.run(['ufw', 'allow', '443/tcp'], check=True)

            print("UFW Firewall-Regeln konfiguriert")
        except:
            print("UFW nicht verfügbar oder bereits konfiguriert")

        return True

    except Exception as e:
        print(f"Firewall-Konfiguration fehlgeschlagen: {e}")
        return False

def create_systemd_service():
    """Erstellt Systemd Service für JetDNS"""
    try:
        service_content = """[Unit]
Description=JetDNS Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/jetdns --daemon
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s
User=jetdns
Group=jetdns

[Install]
WantedBy=multi-user.target
"""

        service_file = Path('/etc/systemd/system/jetdns.service')
        with open(service_file, 'w') as f:
            f.write(service_content)

        # Reload systemd und aktiviere Service
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'jetdns'], check=True)

        print("Systemd Service erstellt und aktiviert")
        return True

    except Exception as e:
        print(f"Fehler beim Erstellen des Systemd Service: {e}")
        return False

@app.route('/')
def index():
    """Zeigt Setup-Interface oder leitet zur Hauptanwendung weiter"""
    if is_setup_complete():
        main_url = get_main_app_url()

        # Zeige Sperrseite mit Weiterleitung
        return f"""
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>JetDNS - Setup bereits abgeschlossen</title>
            <meta http-equiv="refresh" content="5;url={main_url}">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {{ background: linear-gradient(135deg, #2563eb, #1e40af); min-height: 100vh; }}
                .container {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
                .card {{ border-radius: 20px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="card-body text-center p-5">
                        <div class="mb-4">
                            <i class="fas fa-shield-alt" style="font-size: 4rem; color: #059669;"></i>
                        </div>
                        <h2 class="text-success mb-3">JetDNS ist bereits konfiguriert!</h2>
                        <p class="text-muted mb-4">
                            Das initiale Setup wurde bereits erfolgreich abgeschlossen.<br>
                            Sie werden automatisch zur Hauptanwendung weitergeleitet...
                        </p>
                        <div class="mb-4">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Weiterleitung...</span>
                            </div>
                        </div>
                        <a href="{main_url}" class="btn btn-primary btn-lg">
                            <i class="fas fa-arrow-right me-2"></i>Zur JetDNS Verwaltung
                        </a>
                        <div class="mt-4 text-muted small">
                            <i class="fas fa-info-circle me-1"></i>
                            Das Setup kann aus Sicherheitsgründen nicht erneut ausgeführt werden.
                        </div>
                    </div>
                </div>
            </div>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
        </body>
        </html>
        """

    # Ermittle aktuelle Netzwerk-Informationen
    network_interfaces = get_network_interfaces()

    return render_template('setup.html', 
                         interfaces=network_interfaces)

@app.route('/api/setup/configure', methods=['GET'])
def configure_get_blocked():
    """Blockiert GET-Zugriffe auf Setup API nach Abschluss"""
    if is_setup_complete():
        return jsonify({
            'error': 'Setup bereits abgeschlossen',
            'setup_complete': True,
            'redirect_url': get_main_app_url()
        }), 403

    return jsonify({'message': 'Setup verfügbar', 'setup_complete': False})

@app.route('/setup')
@app.route('/configure')
@app.route('/install')
def setup_redirects():
    """Alle Setup-bezogenen URLs weiterleiten"""
    return index()

@app.route('/api/setup/configure', methods=['POST'])
def configure():
    """API Endpoint für die Konfiguration"""
    try:
        config = request.json

        print("Empfangene Konfiguration:", json.dumps(config, indent=2))

        # Validierung der Konfiguration
        required_fields = ['server_ip', 'dns_port', 'web_port', 'protocol', 'language']
        for field in required_fields:
            if field not in config:
                return jsonify({'error': f'Pflichtfeld fehlt: {field}'}), 400

        # IP-Adresse validieren
        if not validate_ip_address(config['server_ip']):
            return jsonify({'error': 'Ungültige IP-Adresse'}), 400

        success = True
        errors = []

        # 1. JetDNS Konfiguration erstellen
        if not create_jetdns_config(config):
            success = False
            errors.append('Konfigurationsdatei konnte nicht erstellt werden')

        # 2. SSL-Zertifikate einrichten (falls HTTPS)
        if not setup_ssl_certificates(config):
            success = False
            errors.append('SSL-Zertifikate konnten nicht erstellt werden')

        # 3. Firewall konfigurieren
        if not configure_firewall(config):
            success = False
            errors.append('Firewall-Konfiguration fehlgeschlagen')

        # 4. Systemd Service erstellen
        if not create_systemd_service():
            success = False
            errors.append('Systemd Service konnte nicht erstellt werden')

        # 5. Netzwerk-Konfiguration anwenden (als letztes!)
        if not apply_network_configuration(config):
            success = False
            errors.append('Netzwerk-Konfiguration fehlgeschlagen')

        if success:
            # Setup als abgeschlossen markieren mit permanenter Sperre
            if create_setup_lock():
                log("Setup-Sperre erfolgreich erstellt")
            else:
                warn("Setup-Sperre konnte nicht erstellt werden")

            # Setup-Service deaktivieren
            disable_setup_service()

            # Verzögerter Shutdown des Setup-Servers
            import threading
            def shutdown_setup_server():
                import time
                time.sleep(10)  # 10 Sekunden warten
                try:
                    # Versuche graceful shutdown
                    import os
                    os._exit(0)
                except:
                    pass

            shutdown_thread = threading.Thread(target=shutdown_setup_server)
            shutdown_thread.daemon = True
            shutdown_thread.start()

            return jsonify({
                'success': True, 
                'message': 'Konfiguration erfolgreich angewendet. Setup wird deaktiviert.',
                'redirect_url': f"{config['protocol']}://{config['server_ip']}:{config['web_port']}",
                'setup_locked': True
            })
        else:
            return jsonify({
                'success': False,
                'errors': errors
            }), 500

    except Exception as e:
        print(f"Konfigurationsfehler: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/setup/status')
def setup_status():
    """Gibt den Status des Setup-Prozesses zurück"""
    return jsonify({
        'setup_complete': is_setup_complete(),
        'network_interfaces': get_network_interfaces(),
        'system_info': get_system_info()
    })

@app.route('/api/setup/validate', methods=['POST'])
def validate_config():
    """Validiert Konfiguration vor der Anwendung"""
    try:
        config = request.json
        validation_results = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'suggestions': []
        }

        # IP-Adresse validieren
        server_ip = config.get('server_ip')
        if not validate_ip_address(server_ip):
            validation_results['valid'] = False
            validation_results['errors'].append('Ungültige IP-Adresse')

        # Port-Verfügbarkeit prüfen
        dns_port = config.get('dns_port', 53)
        web_port = config.get('web_port', 80)

        if not check_port_availability(dns_port, 'udp'):
            validation_results['warnings'].append(f'DNS Port {dns_port}/UDP ist bereits belegt')

        if not check_port_availability(web_port, 'tcp'):
            validation_results['warnings'].append(f'Web Port {web_port}/TCP ist bereits belegt')

        # IP-Bereich prüfen
        ip_parts = server_ip.split('.')
        if ip_parts[0] in ['10'] or (ip_parts[0] == '192' and ip_parts[1] == '168'):
            validation_results['suggestions'].append('Private IP-Adresse erkannt - ideal für lokale Netzwerke')
        elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
            validation_results['suggestions'].append('Private IP-Adresse erkannt - ideal für lokale Netzwerke')
        else:
            validation_results['warnings'].append('Öffentliche IP-Adresse - stellen Sie sicher, dass dies gewünscht ist')

        # HTTPS Empfehlung
        if config.get('protocol') == 'http' and config.get('web_port') != 80:
            validation_results['suggestions'].append('Erwägen Sie HTTPS für bessere Sicherheit')

        return jsonify(validation_results)

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/setup/backup', methods=['POST'])
def create_backup():
    """Erstellt Backup vor der Konfiguration"""
    try:
        backup_path = create_config_backup()
        if backup_path:
            return jsonify({
                'success': True,
                'backup_path': backup_path,
                'message': 'Backup erfolgreich erstellt'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Backup-Erstellung fehlgeschlagen'
            }), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/setup/test-connection', methods=['POST'])
def test_network_connection():
    """Testet Netzwerkverbindung zu angegebener IP"""
    try:
        config = request.json
        server_ip = config.get('server_ip')

        # Ping-Test
        ping_result = subprocess.run(['ping', '-c', '1', '-W', '2', server_ip], 
                                   capture_output=True, text=True)

        results = {
            'ip': server_ip,
            'reachable': ping_result.returncode == 0,
            'response_time': None
        }

        if results['reachable']:
            # Extrahiere Response-Zeit aus Ping-Output
            for line in ping_result.stdout.split('\n'):
                if 'time=' in line:
                    time_part = line.split('time=')[1].split()[0]
                    results['response_time'] = float(time_part)
                    break

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health-Check Endpoint"""
    try:
        system_info = get_system_info()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'setup_complete': is_setup_complete(),
            'system': {
                'cpu_percent': system_info.get('memory', {}).get('percent', 0),
                'memory_percent': system_info.get('memory', {}).get('percent', 0),
                'disk_percent': system_info.get('disk', {}).get('percent', 0)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Statische Assets bereitstellen"""
    return send_from_directory('/opt/jetdns/share/assets', filename)

if __name__ == '__main__':
    # Prüfe ob Setup bereits abgeschlossen wurde
    force_setup = False

    if len(sys.argv) > 1 and sys.argv[1] == '--force':
        force_setup = True
        print("WARNUNG: Setup wird mit --force erzwungen!")
        print("Dies kann zu Systeminstabilität führen!")

        # Zusätzliche Bestätigung für --force
        try:
            confirm = input("Sind Sie sicher? Geben Sie 'FORCE-SETUP' ein: ")
            if confirm != 'FORCE-SETUP':
                print("Setup abgebrochen.")
                sys.exit(1)

            # Entferne Lock-Dateien
            if SETUP_COMPLETE_FILE.exists():
                try:
                    subprocess.run(['chattr', '-i', str(SETUP_COMPLETE_FILE)], 
                                 check=False, capture_output=True)
                except:
                    pass
                SETUP_COMPLETE_FILE.unlink()

            backup_lock = CONFIG_DIR / '.jetdns_configured'
            if backup_lock.exists():
                backup_lock.unlink()

            print("Lock-Dateien entfernt. Setup wird gestartet...")

        except KeyboardInterrupt:
            print("\nSetup abgebrochen.")
            sys.exit(1)

    if is_setup_complete() and not force_setup:
        main_url = get_main_app_url()
        print("=" * 60)
        print("JetDNS Setup bereits abgeschlossen!")
        print("=" * 60)
        print(f"JetDNS ist verfügbar unter: {main_url}")
        print("")
        print("Aus Sicherheitsgründen kann das initiale Setup nicht")
        print("erneut ausgeführt werden.")
        print("")
        print("Für Systemkonfiguration verwenden Sie die Web-Oberfläche")
        print("unter 'Einstellungen' oder bearbeiten Sie direkt:")
        print(f"  {CONFIG_FILE}")
        print("")
        print("Zum erzwingen des Setup (VORSICHT!):")
        print(f"  {sys.argv[0]} --force")
        print("=" * 60)
        sys.exit(0)

    print("=" * 60)
    print("JetDNS Setup Server")
    print("=" * 60)
    print(f"Setup-Interface verfügbar unter: http://localhost:8080")
    print("Öffnen Sie diese URL in Ihrem Browser für die Konfiguration")
    print("=" * 60)

    # Starte Setup-Server auf Port 8080
    try:
        app.run(
            host='0.0.0.0', 
            port=8080, 
            debug=False,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nSetup abgebrochen.")
    except Exception as e:
        print(f"Fehler beim Starten des Setup-Servers: {e}")
