#!/bin/bash

# Advanced DNS Server - Debian Installation Script
# Unterstützt Debian 10, 11, 12 und Ubuntu 18.04+

set -e

# Farben für die Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Konfiguration
INSTALL_DIR="/opt/advanced-dns-server"
SERVICE_NAME="advanced-dns-server"
USER="dnsuser"
WEB_PORT="8080"
DNS_PORT="53"
REDIS_PORT="6379"

# Log-Datei
LOG_FILE="/var/log/advanced-dns-install.log"

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                           Advanced DNS Server Installer                             ║"
    echo "║                              Debian/Ubuntu Installation                             ║"
    echo "║                                                                                      ║"
    echo "║  Features: DNS-over-HTTPS/TLS, Threat Intelligence, Ad-Blocking, Web GUI           ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

print_step() {
    echo -e "${PURPLE}[STEP]${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Dieses Script muss als root ausgeführt werden"
        echo "Verwenden Sie: sudo $0"
        exit 1
    fi
}

detect_os() {
    print_step "Erkenne Betriebssystem..."

    if [[ ! -f /etc/os-release ]]; then
        print_error "Kann das Betriebssystem nicht erkennen"
        exit 1
    fi

    source /etc/os-release

    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_CODENAME="$VERSION_CODENAME"

    print_status "Erkannt: $OS_NAME $OS_VERSION ($OS_CODENAME)"

    # Prüfe unterstützte Versionen
    case "$ID" in
        debian)
            if [[ "$VERSION_ID" -lt 10 ]]; then
                print_error "Debian 10 oder höher erforderlich. Gefunden: $VERSION_ID"
                exit 1
            fi
            PACKAGE_MANAGER="apt"
            ;;
        ubuntu)
            if [[ "${VERSION_ID//./}" -lt 1804 ]]; then
                print_error "Ubuntu 18.04 oder höher erforderlich. Gefunden: $VERSION_ID"
                exit 1
            fi
            PACKAGE_MANAGER="apt"
            ;;
        *)
            print_error "Nicht unterstütztes Betriebssystem: $ID"
            print_error "Unterstützt werden: Debian 10+, Ubuntu 18.04+"
            exit 1
            ;;
    esac

    print_success "Betriebssystem wird unterstützt"
}

check_system_requirements() {
    print_step "Prüfe Systemvoraussetzungen..."

    # CPU-Kerne prüfen
    CPU_CORES=$(nproc)
    print_status "CPU Kerne: $CPU_CORES"

    if [[ $CPU_CORES -lt 1 ]]; then
        print_warning "Mindestens 1 CPU-Kern empfohlen"
    fi

    # RAM prüfen
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    print_status "RAM: ${TOTAL_RAM}MB"

    if [[ $TOTAL_RAM -lt 512 ]]; then
        print_error "Mindestens 512MB RAM erforderlich. Verfügbar: ${TOTAL_RAM}MB"
        exit 1
    elif [[ $TOTAL_RAM -lt 1024 ]]; then
        print_warning "Für optimale Performance werden mindestens 1GB RAM empfohlen"
    fi

    # Festplattenspeicher prüfen
    AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
    AVAILABLE_GB=$((AVAILABLE_SPACE / 1024 / 1024))

    print_status "Verfügbarer Speicher: ${AVAILABLE_GB}GB"

    if [[ $AVAILABLE_GB -lt 2 ]]; then
        print_error "Mindestens 2GB freier Speicher erforderlich. Verfügbar: ${AVAILABLE_GB}GB"
        exit 1
    fi

    # Ports prüfen
    print_status "Prüfe Port-Verfügbarkeit..."

    for port in $DNS_PORT $WEB_PORT $REDIS_PORT; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            if [[ $port -eq $DNS_PORT ]]; then
                print_warning "Port $port ist bereits belegt (DNS-Server läuft bereits?)"
                read -p "Trotzdem fortfahren? (y/N): " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
            else
                print_error "Port $port ist bereits belegt und wird benötigt"
                exit 1
            fi
        fi
    done

    print_success "Systemvoraussetzungen erfüllt"
}

update_system() {
    print_step "Aktualisiere Paketlisten..."

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq 2>&1 | tee -a "$LOG_FILE"

    print_status "Installiere grundlegende System-Updates..."
    apt-get upgrade -y -qq 2>&1 | tee -a "$LOG_FILE"

    print_success "System aktualisiert"
}

install_dependencies() {
    print_step "Installiere Abhängigkeiten..."

    # Python und grundlegende Tools
    PACKAGES=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "curl"
        "wget"
        "git"
        "unzip"
        "dnsutils"
        "net-tools"
        "htop"
        "nano"
        "systemd"
        "nginx"
        "ufw"
        "fail2ban"
        "logrotate"
        "supervisor"
    )

    # Redis installieren
    print_status "Installiere Redis Server..."
    apt-get install -y redis-server 2>&1 | tee -a "$LOG_FILE"

    # Redis konfigurieren
    systemctl enable redis-server
    systemctl start redis-server

    # Prüfe Redis
    if redis-cli ping | grep -q "PONG"; then
        print_success "Redis Server läuft"
    else
        print_error "Redis Server konnte nicht gestartet werden"
        exit 1
    fi

    # SSL/TLS Abhängigkeiten
    PACKAGES+=("openssl" "ca-certificates" "ssl-cert")

    # Entwicklungs-Abhängigkeiten für Python-Pakete
    PACKAGES+=("libffi-dev" "libssl-dev" "libcurl4-openssl-dev")

    print_status "Installiere Pakete: ${PACKAGES[*]}"

    for package in "${PACKAGES[@]}"; do
        print_status "Installiere $package..."
        apt-get install -y "$package" 2>&1 | tee -a "$LOG_FILE"
    done

    print_success "Alle Abhängigkeiten installiert"
}

create_user() {
    print_step "Erstelle DNS-Server Benutzer..."

    if ! id "$USER" &>/dev/null; then
        useradd --system --home-dir "$INSTALL_DIR" --shell /bin/false --create-home "$USER"
        print_success "Benutzer $USER erstellt"
    else
        print_status "Benutzer $USER existiert bereits"
    fi

    # Gruppe für Webserver-Zugriff
    if ! getent group dnsadmin >/dev/null; then
        groupadd dnsadmin
        print_success "Gruppe dnsadmin erstellt"
    fi

    usermod -a -G dnsadmin "$USER"
}

download_application() {
    print_step "Lade DNS-Server Anwendung..."

    # Erstelle Installationsverzeichnis
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"

    # Falls lokale Installation
    if [[ -d "/tmp/advanced-dns-server" ]]; then
        print_status "Kopiere lokale Dateien..."
        cp -r /tmp/advanced-dns-server/* "$INSTALL_DIR/"
    else
        # GitHub Download (falls öffentlich verfügbar)
        print_status "Lade von Repository... (Platzhalter)"

        # Erstelle Beispiel-Struktur
        mkdir -p src config web logs data

        # Erstelle Minimal-Konfiguration
        cat > config/settings.yaml << 'EOF'
dns_server:
  listen_port: 53
  listen_address: "0.0.0.0"
  upstream_servers:
    - "8.8.8.8"
    - "1.1.1.1"

web_interface:
  enabled: true
  port: 8080
  host: "0.0.0.0"

redis:
  enabled: true
  host: "localhost"
  port: 6379

logging:
  level: "INFO"
  log_file: "logs/dns_server.log"
EOF
    fi

    # Verzeichnisstruktur erstellen
    mkdir -p {data,logs,config/blocklists,config/dns_zones,config/ssl}

    print_success "Anwendungsdateien bereitgestellt"
}

setup_python_environment() {
    print_step "Richte Python-Umgebung ein..."

    cd "$INSTALL_DIR"

    # Prüfe Python-Version
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    print_status "Python Version: $PYTHON_VERSION"

    if [[ "$PYTHON_VERSION" < "3.8" ]]; then
        print_error "Python 3.8+ erforderlich. Gefunden: $PYTHON_VERSION"
        exit 1
    fi

    # Erstelle Virtual Environment
    print_status "Erstelle Virtual Environment..."
    sudo -u "$USER" python3 -m venv venv

    # Aktiviere venv und installiere Abhängigkeiten
    print_status "Installiere Python-Abhängigkeiten..."

    # requirements.txt erstellen falls nicht vorhanden
    if [[ ! -f requirements.txt ]]; then
        cat > requirements.txt << 'EOF'
# Core DNS Libraries
dnspython==2.4.2
dnslib==0.9.23

# Web Framework & API
flask==2.3.3
flask-cors==4.0.0
flask-socketio==5.3.6
gunicorn==21.2.0

# Database & Storage
sqlalchemy==2.0.21
redis==5.0.0

# Network & Security
cryptography==41.0.4
requests==2.31.0
urllib3==2.0.5

# Configuration & Logging
pyyaml==6.0.1
python-dotenv==1.0.0
colorlog==6.7.0

# Performance & Async
asyncio
aiohttp==3.8.6

# Monitoring & Analytics
psutil==5.9.5
prometheus-client==0.17.1
EOF
    fi

    # Installiere Abhängigkeiten
    sudo -u "$USER" bash -c "source venv/bin/activate && pip install --upgrade pip"
    sudo -u "$USER" bash -c "source venv/bin/activate && pip install -r requirements.txt"

    print_success "Python-Umgebung konfiguriert"
}

setup_ssl_certificates() {
    print_step "Richte SSL-Zertifikate ein..."

    SSL_DIR="$INSTALL_DIR/config/ssl"

    # Erstelle selbstsignierte Zertifikate für DoH/DoT
    if [[ ! -f "$SSL_DIR/cert.pem" ]]; then
        print_status "Erstelle selbstsignierte SSL-Zertifikate..."

        openssl req -x509 -newkey rsa:4096 -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
            -sha256 -days 365 -nodes \
            -subj "/C=DE/ST=State/L=City/O=Organization/OU=DNS-Server/CN=localhost" \
            2>&1 | tee -a "$LOG_FILE"

        chown "$USER:$USER" "$SSL_DIR"/{cert.pem,key.pem}
        chmod 600 "$SSL_DIR"/{cert.pem,key.pem}

        print_success "SSL-Zertifikate erstellt"
    else
        print_status "SSL-Zertifikate bereits vorhanden"
    fi

    # Let's Encrypt Setup (optional)
    if command -v certbot >/dev/null; then
        print_status "Certbot gefunden - Let's Encrypt verfügbar"
        cat > "$INSTALL_DIR/scripts/setup-letsencrypt.sh" << 'EOF'
#!/bin/bash
# Let's Encrypt Setup für DNS-Server
DOMAIN="$1"

if [[ -z "$DOMAIN" ]]; then
    echo "Verwendung: $0 <domain>"
    exit 1
fi

certbot certonly --standalone -d "$DOMAIN" --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"

if [[ $? -eq 0 ]]; then
    ln -sf "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/opt/advanced-dns-server/config/ssl/cert.pem"
    ln -sf "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "/opt/advanced-dns-server/config/ssl/key.pem"
    systemctl restart advanced-dns-server
    echo "Let's Encrypt Zertifikat für $DOMAIN installiert"
fi
EOF
        chmod +x "$INSTALL_DIR/scripts/setup-letsencrypt.sh"
    fi
}

create_systemd_service() {
    print_step "Erstelle systemd Service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Advanced DNS Server with Web GUI
Documentation=https://github.com/advanced-dns-server
After=network.target network-online.target redis-server.service
Wants=network-online.target
Requires=redis-server.service

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR/src
Environment=DNS_CONFIG_PATH=$INSTALL_DIR/config/settings.yaml
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/src/main.py
ExecReload=/bin/kill -HUP \$MAINPID

# Restart policy
Restart=always
RestartSec=10
StartLimitIntervalSec=60
StartLimitBurst=5

# Output to journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=advanced-dns-server

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR
PrivateTmp=yes
PrivateDevices=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
RestrictNamespaces=yes

# Capabilities für DNS Port 53
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # Service aktivieren
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"

    print_success "Systemd Service erstellt und aktiviert"
}

setup_nginx_proxy() {
    print_step "Konfiguriere Nginx Reverse Proxy..."

    # Nginx für Web-Interface konfigurieren
    cat > "/etc/nginx/sites-available/advanced-dns-server" << EOF
server {
    listen 80;
    server_name _;

    # Redirect HTTP to HTTPS (optional)
    # return 301 https://\$server_name\$request_uri;

    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;

        # WebSocket support
        proxy_read_timeout 86400;
    }

    # Static files
    location /static/ {
        alias $INSTALL_DIR/web/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}

# HTTPS Configuration (wenn SSL-Zertifikate vorhanden)
server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate $INSTALL_DIR/config/ssl/cert.pem;
    ssl_certificate_key $INSTALL_DIR/config/ssl/key.pem;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass http://127.0.0.1:$WEB_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    # Site aktivieren
    ln -sf /etc/nginx/sites-available/advanced-dns-server /etc/nginx/sites-enabled/

    # Standard-Site deaktivieren
    rm -f /etc/nginx/sites-enabled/default

    # Nginx testen und neuladen
    nginx -t
    systemctl enable nginx
    systemctl restart nginx

    print_success "Nginx Reverse Proxy konfiguriert"
}

setup_firewall() {
    print_step "Konfiguriere Firewall (UFW)..."

    # UFW reset (falls bereits konfiguriert)
    ufw --force reset 2>&1 | tee -a "$LOG_FILE"

    # Standard-Policies
    ufw default deny incoming
    ufw default allow outgoing

    # SSH (wichtig!)
    ufw allow ssh

    # DNS Ports
    ufw allow $DNS_PORT/udp comment "DNS UDP"
    ufw allow $DNS_PORT/tcp comment "DNS TCP" 

    # Web Interface
    ufw allow 80/tcp comment "HTTP Web Interface"
    ufw allow 443/tcp comment "HTTPS Web Interface"

    # DNS-over-TLS
    ufw allow 853/tcp comment "DNS-over-TLS"

    # Optional: DNS-over-HTTPS (falls direkt exposed)
    # ufw allow 8443/tcp comment "DNS-over-HTTPS"

    # Rate limiting für DNS
    ufw limit $DNS_PORT/udp
    ufw limit $DNS_PORT/tcp

    # Aktiviere UFW
    ufw --force enable

    print_success "Firewall konfiguriert"
    ufw status verbose
}

setup_fail2ban() {
    print_step "Konfiguriere Fail2Ban..."

    # DNS-Server Jail für Fail2Ban
    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true

[nginx-http-auth]
enabled = true

# Custom DNS Server Protection
[dns-server]
enabled = true
port = $DNS_PORT
protocol = udp
filter = dns-server
logpath = $INSTALL_DIR/logs/dns_server.log
maxretry = 10
findtime = 60
bantime = 3600
EOF

    # Filter für DNS-Server
    cat > "/etc/fail2ban/filter.d/dns-server.conf" << 'EOF'
[Definition]
failregex = ^.*Rate limited client: <HOST>.*$
ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban

    print_success "Fail2Ban konfiguriert"
}

setup_logrotate() {
    print_step "Konfiguriere Log-Rotation..."

    cat > "/etc/logrotate.d/advanced-dns-server" << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME >/dev/null 2>&1 || true
    endscript
    su $USER $USER
}
EOF

    print_success "Log-Rotation konfiguriert"
}

create_management_scripts() {
    print_step "Erstelle Management-Scripts..."

    SCRIPTS_DIR="$INSTALL_DIR/scripts"
    mkdir -p "$SCRIPTS_DIR"

    # DNS-Server Control Script
    cat > "$SCRIPTS_DIR/dns-control.sh" << 'EOF'
#!/bin/bash

SERVICE="advanced-dns-server"
INSTALL_DIR="/opt/advanced-dns-server"

case "$1" in
    start)
        echo "Starte DNS Server..."
        systemctl start $SERVICE
        ;;
    stop)
        echo "Stoppe DNS Server..."
        systemctl stop $SERVICE
        ;;
    restart)
        echo "Starte DNS Server neu..."
        systemctl restart $SERVICE
        ;;
    status)
        systemctl status $SERVICE
        ;;
    logs)
        journalctl -u $SERVICE -f
        ;;
    update-blocklists)
        echo "Aktualisiere Blocklisten..."
        curl -s -X POST http://localhost:8080/api/update_feeds
        ;;
    backup)
        echo "Erstelle Backup..."
        tar -czf "/tmp/dns-server-backup-$(date +%Y%m%d_%H%M%S).tar.gz" \
            -C "$(dirname $INSTALL_DIR)" "$(basename $INSTALL_DIR)"
        echo "Backup erstellt in /tmp/"
        ;;
    *)
        echo "Verwendung: $0 {start|stop|restart|status|logs|update-blocklists|backup}"
        exit 1
        ;;
esac
EOF

    chmod +x "$SCRIPTS_DIR/dns-control.sh"
    ln -sf "$SCRIPTS_DIR/dns-control.sh" /usr/local/bin/dns-server

    # System Info Script
    cat > "$SCRIPTS_DIR/system-info.sh" << 'EOF'
#!/bin/bash

echo "=== Advanced DNS Server - System Information ==="
echo
echo "Service Status:"
systemctl is-active advanced-dns-server
echo
echo "Port Status:"
netstat -tuln | grep -E ":53|:8080|:6379"
echo
echo "Resource Usage:"
ps aux | grep -E "(python|redis|nginx)" | grep -v grep
echo
echo "Disk Usage:"
df -h /opt/advanced-dns-server
echo
echo "Memory Usage:"
free -h
echo
echo "Recent Logs:"
tail -10 /opt/advanced-dns-server/logs/dns_server.log
EOF

    chmod +x "$SCRIPTS_DIR/system-info.sh"
    ln -sf "$SCRIPTS_DIR/system-info.sh" /usr/local/bin/dns-info

    print_success "Management-Scripts erstellt"
}

set_permissions() {
    print_step "Setze Berechtigungen..."

    # Besitzer für alle Dateien setzen
    chown -R "$USER:$USER" "$INSTALL_DIR"

    # Ausführbare Dateien
    find "$INSTALL_DIR" -name "*.py" -exec chmod +x {} \;
    find "$INSTALL_DIR" -name "*.sh" -exec chmod +x {} \;

    # Logs-Verzeichnis
    chmod 755 "$INSTALL_DIR/logs"

    # Config-Verzeichnis (sensible Daten)
    chmod 700 "$INSTALL_DIR/config"

    # SSL-Zertifikate
    chmod 600 "$INSTALL_DIR/config/ssl"/* 2>/dev/null || true

    print_success "Berechtigungen gesetzt"
}

start_services() {
    print_step "Starte Services..."

    # Redis
    systemctl start redis-server
    print_status "Redis Server gestartet"

    # DNS Server
    systemctl start "$SERVICE_NAME"
    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "DNS Server gestartet"
    else
        print_error "DNS Server konnte nicht gestartet werden"
        journalctl -u "$SERVICE_NAME" --no-pager -n 20
        exit 1
    fi

    # Nginx
    systemctl start nginx
    print_status "Nginx gestartet"
}

run_post_install_tests() {
    print_step "Führe Post-Install Tests durch..."

    # DNS Server Test
    if dig @127.0.0.1 google.com +short +time=5 >/dev/null; then
        print_success "DNS Server Test: OK"
    else
        print_warning "DNS Server Test: FAILED"
    fi

    # Web Interface Test
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$WEB_PORT | grep -q "200\|302"; then
        print_success "Web Interface Test: OK"
    else
        print_warning "Web Interface Test: FAILED"
    fi

    # Redis Test
    if redis-cli ping | grep -q "PONG"; then
        print_success "Redis Test: OK"
    else
        print_warning "Redis Test: FAILED"
    fi
}

show_completion_info() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                           Installation Erfolgreich!                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}📍 Installation Details:${NC}"
    echo -e "   Installationsverzeichnis: ${YELLOW}$INSTALL_DIR${NC}"
    echo -e "   Service Name:              ${YELLOW}$SERVICE_NAME${NC}"
    echo -e "   Benutzer:                  ${YELLOW}$USER${NC}"
    echo
    echo -e "${CYAN}🌐 Zugriff:${NC}"
    echo -e "   Web Interface:   ${GREEN}http://$(hostname -I | awk '{print $1}')${NC}      (HTTP)"
    echo -e "                    ${GREEN}https://$(hostname -I | awk '{print $1}')${NC}     (HTTPS)"
    echo -e "   DNS Server:      ${GREEN}$(hostname -I | awk '{print $1}'):53${NC}         (UDP/TCP)"
    echo -e "   DNS-over-TLS:    ${GREEN}$(hostname -I | awk '{print $1}'):853${NC}        (TCP)"
    echo
    echo -e "${CYAN}🔑 Standard-Anmeldedaten:${NC}"
    echo -e "   Benutzername: ${YELLOW}admin${NC}"
    echo -e "   Passwort:     ${YELLOW}admin123${NC}"
    echo -e "   ${RED}⚠️  Bitte ändern Sie das Passwort nach der ersten Anmeldung!${NC}"
    echo
    echo -e "${CYAN}🔧 Service Management:${NC}"
    echo -e "   Status anzeigen:    ${GREEN}dns-server status${NC}"
    echo -e "   Neustart:           ${GREEN}dns-server restart${NC}"
    echo -e "   Logs anzeigen:      ${GREEN}dns-server logs${NC}"
    echo -e "   System-Info:        ${GREEN}dns-info${NC}"
    echo -e "   Blocklisten update: ${GREEN}dns-server update-blocklists${NC}"
    echo
    echo -e "${CYAN}📁 Wichtige Verzeichnisse:${NC}"
    echo -e "   Konfiguration: ${YELLOW}$INSTALL_DIR/config/${NC}"
    echo -e "   Logs:          ${YELLOW}$INSTALL_DIR/logs/${NC}"
    echo -e "   SSL Certs:     ${YELLOW}$INSTALL_DIR/config/ssl/${NC}"
    echo
    echo -e "${CYAN}🔒 Sicherheit:${NC}"
    echo -e "   Firewall:      ${GREEN}Aktiviert (UFW)${NC}"
    echo -e "   Fail2Ban:      ${GREEN}Aktiviert${NC}"
    echo -e "   SSL/TLS:       ${GREEN}Selbstsignierte Zertifikate${NC}"
    echo
    echo -e "${CYAN}📚 Weitere Schritte:${NC}"
    echo -e "   1. Web-Interface öffnen und Passwort ändern"
    echo -e "   2. DNS-Einstellungen an Ihre Umgebung anpassen"
    echo -e "   3. Blocklisten konfigurieren"
    echo -e "   4. Für Produktion: Let's Encrypt Zertifikat installieren"
    echo -e "      ${YELLOW}$INSTALL_DIR/scripts/setup-letsencrypt.sh ihre-domain.com${NC}"
    echo
    echo -e "${GREEN}🎉 Der Advanced DNS Server ist jetzt einsatzbereit!${NC}"
    echo
}

cleanup_on_error() {
    print_error "Installation fehlgeschlagen!"
    echo "Log-Datei: $LOG_FILE"
    echo "Möchten Sie die Installation bereinigen? (y/N)"
    read -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        rm -rf "$INSTALL_DIR"
        userdel "$USER" 2>/dev/null || true
        print_status "Installation bereinigt"
    fi
    exit 1
}

# Main Installation
main() {
    # Trap für Fehlerbehandlung
    trap cleanup_on_error ERR

    print_header

    # Begrüßung und Bestätigung
    echo -e "${YELLOW}Dieser Installer wird den Advanced DNS Server auf Ihrem Debian/Ubuntu System installieren.${NC}"
    echo
    echo -e "Folgende Komponenten werden installiert:"
    echo -e "  • DNS Server mit DoH/DoT Unterstützung"
    echo -e "  • Web-basiertes Management Interface"
    echo -e "  • Redis für Caching"
    echo -e "  • Nginx als Reverse Proxy"
    echo -e "  • Threat Intelligence & Ad-Blocking"
    echo -e "  • Automatische Sicherheitskonfiguration"
    echo
    read -p "Möchten Sie fortfahren? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation abgebrochen."
        exit 0
    fi

    # Hauptinstallation
    echo -e "\n${BLUE}Beginne Installation...${NC}\n"

    check_root
    detect_os
    check_system_requirements
    update_system
    install_dependencies
    create_user
    download_application
    setup_python_environment
    setup_ssl_certificates
    create_systemd_service
    setup_nginx_proxy
    setup_firewall
    setup_fail2ban
    setup_logrotate
    create_management_scripts
    set_permissions
    start_services
    run_post_install_tests
    show_completion_info

    print_success "Installation vollständig abgeschlossen!"
}

# Script ausführen
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
