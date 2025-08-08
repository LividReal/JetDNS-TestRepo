#!/bin/bash

# JetDNS Installation Script
# Unterstützt Debian 10+, Ubuntu 18.04+

set -e

# Farben für Ausgaben
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging Funktion
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner anzeigen
show_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
     _      _   ____  _   _ ____  
    | | ___| |_|  _ \| \ | / ___| 
 _  | |/ _ \ __| | | |  \| \___ \ 
| |_| |  __/ |_| |_| | |\  |___) |
 \___/ \___|\__|____/|_| \_|____/ 

    Hochperformanter DNS-Server
    mit Web-GUI und Threat Intelligence
EOF
    echo -e "${NC}"
    echo "============================================="
    echo "JetDNS Installation wird gestartet..."
    echo "============================================="
    echo
}

# System-Informationen ermitteln
detect_system() {
    log "Erkenne Betriebssystem..."

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Kann Betriebssystem nicht erkennen!"
        exit 1
    fi

    log "Betriebssystem: $OS $VER"

    # Prüfe unterstützte Systeme
    case "$OS" in
        "Ubuntu"|"Debian GNU/Linux")
            log "Unterstütztes System erkannt."
            ;;
        *)
            error "Nicht unterstütztes Betriebssystem: $OS"
            echo "JetDNS unterstützt nur Debian und Ubuntu."
            exit 1
            ;;
    esac
}

# Root-Rechte prüfen
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Dieses Script muss als root ausgeführt werden!"
        echo "Verwenden Sie: sudo $0"
        exit 1
    fi
}

# Internetverbindung prüfen
check_internet() {
    log "Prüfe Internetverbindung..."
    if ! ping -c 1 google.com &> /dev/null; then
        error "Keine Internetverbindung verfügbar!"
        echo "Eine Internetverbindung ist für die Installation erforderlich."
        exit 1
    fi
    log "Internetverbindung OK"
}

# Installiere System-Dependencies
install_dependencies() {
    log "Installiere System-Abhängigkeiten..."

    apt-get update -q

    # Python und pip
    apt-get install -y python3 python3-pip python3-venv

    # Netzwerk-Tools
    apt-get install -y net-tools iproute2 netplan.io

    # SSL/TLS Tools
    apt-get install -y openssl

    # Build tools für Python Packages
    apt-get install -y build-essential python3-dev

    # Redis für Caching
    apt-get install -y redis-server

    # Systemd und UFW (falls nicht installiert)
    apt-get install -y systemd ufw

    log "System-Abhängigkeiten installiert"
}

# Python Virtual Environment erstellen
create_venv() {
    log "Erstelle Python Virtual Environment..."

    JETDNS_HOME="/opt/jetdns"
    mkdir -p $JETDNS_HOME

    python3 -m venv $JETDNS_HOME/venv
    source $JETDNS_HOME/venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    log "Virtual Environment erstellt in $JETDNS_HOME/venv"
}

# Installiere Python Dependencies
install_python_deps() {
    log "Installiere Python-Abhängigkeiten..."

    source /opt/jetdns/venv/bin/activate

    # Core Dependencies
    pip install flask==2.3.2
    pip install redis==4.6.0
    pip install requests==2.31.0
    pip install dnspython==2.4.0
    pip install cryptography==41.0.3
    pip install pyyaml==6.0.1
    pip install configparser==5.3.0
    pip install psutil==5.9.5
    pip install gevent==23.7.0

    # Optional Dependencies für erweiterte Features
    pip install maxminddb==2.2.0 || warn "MaxMind GeoIP nicht verfügbar"
    pip install yara-python==4.3.1 || warn "YARA nicht verfügbar"

    log "Python-Abhängigkeiten installiert"
}

# JetDNS Benutzer erstellen (übersprungen - nur Web-Interface Benutzer werden benötigt)
create_user() {
    log "Überspringe System-Benutzer-Erstellung - nur Web-Interface Benutzer werden verwendet"
    # Kein System-Benutzer wird erstellt, nur Web-Interface Benutzer im GUI
}

# Verzeichnisse und Berechtigungen einrichten
setup_directories() {
    log "Richte Verzeichnisstruktur ein..."

    # Hauptverzeichnisse
    mkdir -p /opt/jetdns/{bin,lib,share,var/{log,cache,db}}
    mkdir -p /etc/jetdns/{ssl,blocklists}
    mkdir -p /var/log/jetdns

    # Berechtigungen setzen (als root, da kein jetdns System-Benutzer vorhanden)
    chmod -R 755 /opt/jetdns
    chmod -R 755 /etc/jetdns
    chmod -R 755 /var/log/jetdns

    # Log-Rotation einrichten
    cat > /etc/logrotate.d/jetdns << EOF
/var/log/jetdns/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    postrotate
        systemctl reload jetdns 2>/dev/null || true
    endscript
}
EOF

    log "Verzeichnisstruktur eingerichtet"
}

# JetDNS Dateien kopieren
install_jetdns_files() {
    log "Installiere JetDNS Dateien..."

    JETDNS_HOME="/opt/jetdns"

    # Setup-Script kopieren
    cp setup.py $JETDNS_HOME/bin/jetdns-setup
    chmod +x $JETDNS_HOME/bin/jetdns-setup

    # Web-Interface Templates
    mkdir -p $JETDNS_HOME/share/templates
    cp setup.html $JETDNS_HOME/share/templates/
    cp base.html $JETDNS_HOME/share/templates/

    # Setup-Script kopieren
    cp jetdns-manager.py $JETDNS_HOME/bin/jetdns-manager
    chmod +x $JETDNS_HOME/bin/jetdns-manager

    # Ausführbare Dateien erstellen
    cat > /usr/local/bin/jetdns-setup << EOF
#!/bin/bash
cd /opt/jetdns
source venv/bin/activate
exec python3 bin/jetdns-setup "\$@"
EOF
    chmod +x /usr/local/bin/jetdns-setup

    cat > /usr/local/bin/jetdns << EOF
#!/bin/bash
cd /opt/jetdns
source venv/bin/activate
exec python3 bin/jetdns-manager "\$@"
EOF
    chmod +x /usr/local/bin/jetdns

    # Bash-Completion für jetdns-Manager
    cat > /etc/bash_completion.d/jetdns << 'EOF'
_jetdns_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="status backup restore restart logs config"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=($(compgen -W "--backup-name --backup-path --section --key --value --lines" -- ${cur}))
        return 0
    fi

    COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
    return 0
}
complete -F _jetdns_completions jetdns
EOF

    log "JetDNS Dateien installiert"
}

# Redis konfigurieren
configure_redis() {
    log "Konfiguriere Redis für JetDNS..."

    # Redis für JetDNS optimieren
    cat >> /etc/redis/redis.conf << EOF

# JetDNS specific configuration
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
EOF

    systemctl enable redis-server
    systemctl restart redis-server

    log "Redis konfiguriert"
}

# Firewall Basis-Konfiguration
configure_base_firewall() {
    log "Konfiguriere Basis-Firewall..."

    # UFW aktivieren falls nicht aktiv
    ufw --force enable

    # Setup-Port temporär öffnen
    ufw allow 8080/tcp comment "JetDNS Setup (temporär)"

    # SSH offen lassen
    ufw allow ssh

    log "Basis-Firewall konfiguriert"
}

# Installation abschließen
finish_installation() {
    log "Schließe Installation ab..."

    # Services aktivieren
    systemctl enable redis-server

    # Temp-Dateien aufräumen
    apt-get autoremove -y
    apt-get autoclean

    log "Installation abgeschlossen!"
}

# Zeige Setup-URL
show_setup_url() {
    echo
    echo "============================================="
    echo -e "${GREEN}Installation erfolgreich abgeschlossen!${NC}"
    echo "============================================="
    echo
    echo -e "${BLUE}Nächste Schritte:${NC}"
    echo "1. Öffnen Sie Ihren Webbrowser"
    echo "2. Besuchen Sie: http://$(hostname -I | awk '{print $1}'):8080"
    echo "3. Folgen Sie dem Setup-Assistenten"
    echo
    echo -e "${RED}WICHTIG:${NC}"
    echo "- Das initiale Setup kann nur EINMAL durchgeführt werden"
    echo "- Nach Abschluss ist es aus Sicherheitsgründen gesperrt"
    echo "- Notieren Sie sich Ihre Zugangsdaten und die finale URL"
    echo
    echo -e "${YELLOW}Setup-Server wird gestartet...${NC}"

    # Prüfe ob Setup bereits durchgeführt wurde
    if [ -f "/etc/jetdns/.setup_complete" ]; then
        echo
        error "Setup bereits abgeschlossen!"
        echo "JetDNS ist bereits konfiguriert."
        echo "Verwenden Sie die Web-Oberfläche für weitere Konfiguration."
        exit 1
    fi

    echo

    # Setup-Server starten
    cd /opt/jetdns
    source venv/bin/activate
    exec python3 bin/jetdns-setup
}

# Prüfe auf bereits vorhandene Installation
check_existing_installation() {
    log "Prüfe auf vorhandene Installation..."

    if [ -f "/etc/jetdns/.setup_complete" ]; then
        error "JetDNS ist bereits installiert und konfiguriert!"
        echo
        echo "Wenn Sie eine Neuinstallation durchführen möchten:"
        echo "1. Deinstallieren Sie JetDNS vollständig:"
        echo "   sudo /opt/jetdns/bin/uninstall.sh"
        echo "2. Führen Sie die Installation erneut durch"
        echo
        echo "Für Konfigurationsänderungen verwenden Sie die Web-Oberfläche."
        exit 1
    fi

    if [ -d "/opt/jetdns" ]; then
        warn "JetDNS-Verzeichnis existiert bereits"
        echo "Möglicherweise ist eine unvollständige Installation vorhanden."
        read -p "Soll die vorhandene Installation entfernt werden? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "Entferne vorhandene Installation..."
            rm -rf /opt/jetdns
            rm -rf /etc/jetdns
            # Kein System-Benutzer zu löschen, da keiner erstellt wurde
        else
            error "Installation abgebrochen"
            exit 1
        fi
    fi
}

# Hauptprogramm
main() {
    show_banner
    check_root
    detect_system
    check_internet
    check_existing_installation

    log "Starte JetDNS Installation..."

    install_dependencies
    create_venv
    install_python_deps
    create_user
    setup_directories
    install_jetdns_files
    configure_redis
    configure_base_firewall
    finish_installation

    show_setup_url
}

# Fehlerbehandlung
trap 'error "Installation unterbrochen!"; exit 1' ERR

# Script ausführen
main "$@"
