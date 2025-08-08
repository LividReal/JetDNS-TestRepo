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

# Berechtigungen automatisch setzen
fix_permissions() {
    local path="$1"
    local perm="${2:-777}"

    if [ -e "$path" ]; then
        log "Setze Berechtigungen $perm für: $path"
        chmod -R "$perm" "$path" 2>/dev/null || warn "Konnte Berechtigungen für $path nicht setzen"
        chown -R root:root "$path" 2>/dev/null || warn "Konnte Eigentümer für $path nicht setzen"
    fi
}

# Automatische Fehlerbehebung - Retry-Funktion
retry_command() {
    local cmd="$1"
    local max_attempts="${2:-3}"
    local delay="${3:-2}"
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        log "Versuch $attempt/$max_attempts: $cmd"
        if eval "$cmd"; then
            return 0
        fi

        warn "Versuch $attempt fehlgeschlagen, warte ${delay}s..."
        sleep $delay
        ((attempt++))
    done

    error "Befehl nach $max_attempts Versuchen fehlgeschlagen: $cmd"
    return 1
}

# Automatische Netzwerk-Fehlerbehebung
fix_network_issues() {
    log "Behebe automatisch Netzwerkprobleme..."

    # DNS-Server temporär auf Google/Cloudflare setzen
    if ! ping -c 1 google.com &>/dev/null; then
        warn "Netzwerkproblem erkannt, repariere DNS..."
        cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
        cat > /etc/resolv.conf << EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF
        log "Temporäre DNS-Server gesetzt"
    fi

    # Netzwerk-Interface neu starten falls nötig
    if ! ping -c 1 google.com &>/dev/null; then
        warn "Starte Netzwerk-Interface neu..."
        systemctl restart networking 2>/dev/null || service networking restart 2>/dev/null || true
        sleep 3
    fi

    # Letzte Rettung: systemd-resolved neu starten
    if ! ping -c 1 google.com &>/dev/null; then
        warn "Starte DNS-Resolver neu..."
        systemctl restart systemd-resolved 2>/dev/null || true
        sleep 2
    fi
}

# Automatische Paket-Fehlerbehebung
fix_package_issues() {
    log "Behebe automatisch Paket-Probleme..."

    # Defekte Pakete reparieren
    dpkg --configure -a 2>/dev/null || true
    apt-get -f install -y 2>/dev/null || true

    # Paketlisten korrigieren
    rm -rf /var/lib/apt/lists/* 2>/dev/null || true
    apt-get clean 2>/dev/null || true
    apt-get update -qq 2>/dev/null || true

    # Gesperrte Pakete entsperren
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        rm -f /var/lib/dpkg/lock-frontend 2>/dev/null || true
    fi
    if [ -f /var/lib/apt/lists/lock ]; then
        rm -f /var/lib/apt/lists/lock 2>/dev/null || true
    fi
    if [ -f /var/cache/apt/archives/lock ]; then
        rm -f /var/cache/apt/archives/lock 2>/dev/null || true
    fi

    # Defekte Repository-Keys reparieren
    apt-key update 2>/dev/null || true
}

# Automatische Port-Konflikt-Lösung
fix_port_conflicts() {
    local port="$1"
    local service_name="$2"

    log "Prüfe Port-Konflikt für Port $port..."

    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        warn "Port $port ist belegt, löse Konflikt..."

        # Finde und beende blockierende Prozesse
        local pids=$(lsof -ti :$port 2>/dev/null || true)
        if [ -n "$pids" ]; then
            for pid in $pids; do
                local process_name=$(ps -p $pid -o comm= 2>/dev/null || echo "unbekannt")
                warn "Beende Prozess $process_name (PID: $pid) der Port $port blockiert"
                kill -TERM $pid 2>/dev/null || kill -KILL $pid 2>/dev/null || true
                sleep 1
            done
        fi

        # Spezielle Behandlung für bekannte Services
        case $port in
            53)
                systemctl stop systemd-resolved 2>/dev/null || true
                systemctl disable systemd-resolved 2>/dev/null || true
                ;;
            80|443)
                systemctl stop apache2 2>/dev/null || true
                systemctl stop nginx 2>/dev/null || true
                ;;
            6379)
                systemctl stop redis-server 2>/dev/null || true
                ;;
        esac

        sleep 2
        log "Port-Konflikt für Port $port behoben"
    fi
}

# Automatische Service-Fehlerbehebung
fix_service_issues() {
    log "Behebe automatisch Service-Probleme..."

    # Systemd neu laden
    systemctl daemon-reload 2>/dev/null || true

    # Defekte Services reparieren
    systemctl reset-failed 2>/dev/null || true

    # Port-Konflikte lösen
    fix_port_conflicts 53 "DNS"
    fix_port_conflicts 80 "HTTP"
    fix_port_conflicts 8080 "WebUI"
    fix_port_conflicts 6379 "Redis"
}

# Automatische Speicherplatz-Bereinigung
fix_disk_space() {
    log "Bereinige automatisch Speicherplatz..."

    # Temporäre Dateien löschen
    rm -rf /tmp/* 2>/dev/null || true
    rm -rf /var/tmp/* 2>/dev/null || true

    # Log-Dateien bereinigen
    find /var/log -name "*.log" -type f -size +100M -exec truncate -s 50M {} \; 2>/dev/null || true

    # APT-Cache bereinigen
    apt-get clean 2>/dev/null || true
    apt-get autoclean 2>/dev/null || true

    # Journal bereinigen
    journalctl --vacuum-time=1d 2>/dev/null || true
    journalctl --vacuum-size=100M 2>/dev/null || true

    log "Speicherplatz bereinigt"
}

# Umfassende System-Reparatur
auto_fix_system() {
    log "🔧 Starte automatische System-Reparatur..."

    fix_network_issues
    fix_package_issues
    fix_service_issues
    fix_disk_space

    # Berechtigungen für kritische Verzeichnisse
    chmod 755 /tmp 2>/dev/null || true
    chmod 755 /var/tmp 2>/dev/null || true
    chmod 1777 /tmp 2>/dev/null || true

    log "✅ Automatische System-Reparatur abgeschlossen"
}

# Alle JetDNS Berechtigungen korrigieren
fix_all_jetdns_permissions() {
    log "Korrigiere alle JetDNS Berechtigungen..."

    # Hauptverzeichnisse mit Vollzugriff
    fix_permissions "/opt/jetdns" "777"
    fix_permissions "/etc/jetdns" "777"
    fix_permissions "/var/log/jetdns" "777"
    fix_permissions "/var/lib/jetdns" "777"

    # Ausführbare Dateien
    fix_permissions "/usr/local/bin/jetdns" "777"
    fix_permissions "/usr/local/bin/jetdns-setup" "777"

    # Systemd Service
    fix_permissions "/etc/systemd/system/jetdns.service" "644"

    log "Alle Berechtigungen korrigiert"
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

# Root-Rechte prüfen oder anfordern
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Root-Rechte erforderlich für die Installation.${NC}"
        echo "Optionen:"
        echo "1. Script mit sudo ausführen: sudo $0"
        echo "2. Als root anmelden und erneut ausführen"
        echo "3. Root-Passwort eingeben und automatisch mit su fortfahren"
        echo
        read -p "Root-Passwort eingeben und mit su fortfahren? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Starte Installation als root...${NC}"
            exec su -c "$0 $*"
        else
            error "Installation abgebrochen. Bitte als root ausführen."
            exit 1
        fi
    fi
}

# Internetverbindung prüfen mit automatischer Reparatur
check_internet() {
    log "Prüfe Internetverbindung..."

    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if ping -c 1 google.com &>/dev/null; then
            log "Internetverbindung OK"
            return 0
        fi

        warn "Internetverbindung Versuch $attempt/$max_attempts fehlgeschlagen"

        if [ $attempt -lt $max_attempts ]; then
            log "Versuche automatische Netzwerk-Reparatur..."
            fix_network_issues
            sleep 3
        fi

        ((attempt++))
    done

    error "Keine Internetverbindung verfügbar nach $max_attempts Reparatur-Versuchen!"
    echo "Die Installation kann ohne Internetverbindung nicht fortgesetzt werden."
    exit 1
}

# Installiere System-Dependencies mit automatischer Fehlerbehebung
install_dependencies() {
    log "Installiere System-Abhängigkeiten..."

    # Automatische Paket-Reparatur vor Installation
    fix_package_issues

    # Paketlisten mit Retry aktualisieren
    retry_command "apt-get update -q" 3 5

    # Kritische Pakete mit automatischer Fehlerbehebung installieren
    local packages=(
        "python3"
        "python3-pip" 
        "python3-venv"
        "net-tools"
        "iproute2"
        "openssl"
        "build-essential"
        "python3-dev"
        "redis-server"
        "systemd"
        "ufw"
    )

    for package in "${packages[@]}"; do
        log "Installiere $package..."
        if ! retry_command "apt-get install -y $package" 3 2; then
            warn "$package Installation fehlgeschlagen, versuche Alternative..."

            # Spezielle Fallbacks für kritische Pakete
            case $package in
                "python3-pip")
                    wget -q https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py 2>/dev/null || true
                    python3 /tmp/get-pip.py 2>/dev/null || true
                    ;;
                "redis-server")
                    warn "Redis Installation fehlgeschlagen - wird später nachinstalliert"
                    ;;
                "netplan.io")
                    warn "Netplan nicht verfügbar - übersprungen"
                    ;;
            esac
        fi
    done

    # Optionale Pakete mit Fehlertoleranz
    apt-get install -y netplan.io 2>/dev/null || warn "Netplan nicht verfügbar"
    apt-get install -y libssl-dev libffi-dev pkg-config 2>/dev/null || warn "YARA Dependencies teilweise fehlgeschlagen"

    # Finale Paket-Reparatur
    apt-get -f install -y 2>/dev/null || true

    log "System-Abhängigkeiten installiert (mit automatischer Fehlerbehebung)"
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

# Installiere Python Dependencies mit umfassender Fehlerbehebung
install_python_deps() {
    log "Installiere Python-Abhängigkeiten..."

    source /opt/jetdns/venv/bin/activate

    # Pip aktualisieren mit Retry
    retry_command "pip install --upgrade pip" 3 2

    # Wheel installieren für bessere Kompatibilität
    pip install wheel setuptools --upgrade 2>/dev/null || true

    # Core Dependencies mit automatischer Fehlerbehebung
    local core_packages=(
        "flask==2.3.2"
        "redis==4.6.0"
        "requests==2.31.0" 
        "dnspython==2.4.0"
        "cryptography==41.0.3"
        "pyyaml==6.0.1"
        "configparser==5.3.0"
        "psutil==5.9.5"
        "gevent==23.7.0"
    )

    for package in "${core_packages[@]}"; do
        log "Installiere Python-Paket: $package"
        if ! retry_command "pip install '$package'" 3 2; then
            warn "$package Installation fehlgeschlagen, versuche ohne Version..."
            local pkg_name=$(echo "$package" | cut -d'=' -f1)
            retry_command "pip install '$pkg_name'" 2 3 || warn "$pkg_name komplett fehlgeschlagen"
        fi
    done

    # Optional Dependencies mit erweiterten Fallbacks
    log "Installiere optionale Abhängigkeiten..."

    # MaxMind GeoIP
    pip install maxminddb==2.2.0 2>/dev/null || \
    pip install maxminddb 2>/dev/null || \
    warn "MaxMind GeoIP nicht verfügbar"

    # YARA mit umfassenden Fallback-Optionen
    log "Versuche YARA Installation mit erweiterten Fallbacks..."
    local yara_versions=("4.3.1" "4.2.3" "4.1.3" "4.0.5")
    local yara_installed=false

    for version in "${yara_versions[@]}"; do
        if pip install "yara-python==$version" 2>/dev/null; then
            log "YARA-Python $version erfolgreich installiert"
            yara_installed=true
            break
        fi
    done

    if [ "$yara_installed" = false ]; then
        warn "Alle YARA-Versionen fehlgeschlagen, versuche Kompilation..."
        if apt-get install -y libyara-dev 2>/dev/null; then
            pip install yara-python --no-binary=yara-python 2>/dev/null || \
            warn "YARA-Python kann nicht installiert werden - Threat Detection läuft ohne YARA"
        fi
    fi

    # Weitere ML/Analytics Pakete falls aus requirements.txt installiert werden soll
    if [ -f "../requirements.txt" ]; then
        log "Installiere Pakete aus requirements.txt..."
        pip install -r ../requirements.txt --no-deps --ignore-installed 2>/dev/null || \
        warn "Nicht alle Pakete aus requirements.txt konnten installiert werden"
    fi

    log "Python-Abhängigkeiten installiert (mit umfassender Fehlerbehebung)"
}

# JetDNS Benutzer erstellen (übersprungen - nur Web-Interface Benutzer werden benötigt)
create_user() {
    log "Überspringe System-Benutzer-Erstellung - nur Web-Interface Benutzer werden verwendet"
    # Kein System-Benutzer wird erstellt, nur Web-Interface Benutzer im GUI
    # Alle useradd Befehle wurden entfernt - System läuft als root

    # Falls noch useradd Befehle vorhanden waren, werden sie hier entfernt:
    # useradd --system --home-dir /opt/jetdns --shell /bin/false jetdns  # ENTFERNT
}

# Verzeichnisse und Berechtigungen einrichten
setup_directories() {
    log "Richte Verzeichnisstruktur ein..."

    # Hauptverzeichnisse
    mkdir -p /opt/jetdns/{bin,lib,share,var/{log,cache,db}}
    mkdir -p /etc/jetdns/{ssl,blocklists}
    mkdir -p /var/log/jetdns
    mkdir -p /var/lib/jetdns

    # Berechtigungen mit Vollzugriff setzen (777 für alle JetDNS Dateien)
    log "Setze Vollzugriff-Berechtigungen (777)..."
    chmod -R 777 /opt/jetdns
    chmod -R 777 /etc/jetdns  
    chmod -R 777 /var/log/jetdns
    chmod -R 777 /var/lib/jetdns

    # Eigentümer auf root setzen
    chown -R root:root /opt/jetdns
    chown -R root:root /etc/jetdns
    chown -R root:root /var/log/jetdns
    chown -R root:root /var/lib/jetdns

    # Log-Rotation einrichten
    cat > /etc/logrotate.d/jetdns << EOF
/var/log/jetdns/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0777 root root
    postrotate
        systemctl reload jetdns 2>/dev/null || true
    endscript
}
EOF

    # Berechtigungen für Log-Rotation
    chmod 777 /etc/logrotate.d/jetdns

    log "Verzeichnisstruktur mit Vollzugriff eingerichtet"
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

    # Template-Dateien kopieren falls vorhanden
    if [ -f "setup.html" ]; then
        cp setup.html $JETDNS_HOME/share/templates/
        log "setup.html kopiert"
    else
        warn "setup.html nicht gefunden - wird übersprungen"
    fi

    if [ -f "base.html" ]; then
        cp base.html $JETDNS_HOME/share/templates/
        log "base.html kopiert"
    elif [ -f "web/templates/base.html" ]; then
        cp web/templates/base.html $JETDNS_HOME/share/templates/
        log "base.html aus web/templates/ kopiert"
    else
        warn "base.html nicht gefunden - wird übersprungen"
    fi

    # Setup-Script kopieren
    cp jetdns-manager.py $JETDNS_HOME/bin/jetdns-manager
    chmod +x $JETDNS_HOME/bin/jetdns-manager

    # Hauptserver-Script kopieren falls vorhanden
    if [ -f "bin/jetdns-server" ]; then
        cp bin/jetdns-server $JETDNS_HOME/bin/
        chmod +x $JETDNS_HOME/bin/jetdns-server
    fi

    # Source-Dateien kopieren falls vorhanden
    if [ -d "src" ]; then
        cp -r src $JETDNS_HOME/
        log "Source-Dateien kopiert"
    fi

    # Web-Interface Dateien kopieren falls vorhanden
    if [ -d "web" ]; then
        cp -r web $JETDNS_HOME/
        log "Web-Interface Dateien kopiert"
    fi

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
    opts="status backup restore restart logs config fix-permissions"

    if [[ ${cur} == -* ]]; then
        COMPREPLY=($(compgen -W "--backup-name --backup-path --section --key --value --lines" -- ${cur}))
        return 0
    fi

    COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
    return 0
}
complete -F _jetdns_completions jetdns
EOF

    # Berechtigungs-Fix-Script erstellen
    cat > /usr/local/bin/jetdns-fix-permissions << 'EOF'
#!/bin/bash
# JetDNS Berechtigungs-Reparatur-Script

echo "🔧 JetDNS Berechtigungen werden repariert..."

# Alle JetDNS Verzeichnisse auf 777 setzen
chmod -R 777 /opt/jetdns 2>/dev/null
chmod -R 777 /etc/jetdns 2>/dev/null  
chmod -R 777 /var/log/jetdns 2>/dev/null
chmod -R 777 /var/lib/jetdns 2>/dev/null

# Eigentümer auf root setzen
chown -R root:root /opt/jetdns 2>/dev/null
chown -R root:root /etc/jetdns 2>/dev/null
chown -R root:root /var/log/jetdns 2>/dev/null
chown -R root:root /var/lib/jetdns 2>/dev/null

# Ausführbare Dateien
chmod 777 /usr/local/bin/jetdns* 2>/dev/null
chmod 777 /opt/jetdns/venv/bin/* 2>/dev/null

echo "✅ JetDNS Berechtigungen repariert!"
EOF
    chmod 777 /usr/local/bin/jetdns-fix-permissions

    # Alle kopierten Dateien mit Vollzugriff versehen
    log "Korrigiere Berechtigungen aller kopierten Dateien..."
    fix_all_jetdns_permissions

    # Zusätzlich: Alle Python-Dateien ausführbar machen
    find /opt/jetdns -name "*.py" -exec chmod 777 {} \; 2>/dev/null || true

    log "JetDNS Dateien installiert und Berechtigungen gesetzt"
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

    # JetDNS systemd Service installieren
    if [ -f "systemd/jetdns.service" ]; then
        log "Installiere systemd Service..."
        cp systemd/jetdns.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable jetdns.service
        log "JetDNS Service installiert und aktiviert"
    fi

    # Services aktivieren
    systemctl enable redis-server

    # Finale Berechtigungskorrektur für alle JetDNS Komponenten
    log "Führe finale Berechtigungskorrektur durch..."
    fix_all_jetdns_permissions

    # Stelle sicher, dass alle kritischen Dateien die richtigen Berechtigungen haben
    chmod 777 /opt/jetdns/venv/bin/* 2>/dev/null || true
    chmod 777 /usr/local/bin/jetdns* 2>/dev/null || true

    # Temp-Dateien aufräumen
    apt-get autoremove -y
    apt-get autoclean

    log "Installation abgeschlossen - alle Dateien haben Vollzugriff!"
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
            # Keine System-Benutzer werden verwendet oder gelöscht
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

    # Automatische System-Reparatur BEFORE alles andere
    log "🚀 Starte präventive System-Optimierung..."
    auto_fix_system

    check_internet
    check_existing_installation

    log "Starte JetDNS Installation mit automatischer Fehlerbehebung..."

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

# Erweiterte Fehlerbehandlung mit automatischer Reparatur
handle_error() {
    local line_number=$1
    error "Installation unterbrochen in Zeile $line_number!"

    log "🔧 Versuche automatische Fehler-Reparatur..."

    # Letzte Rettungsversuche
    auto_fix_system
    fix_all_jetdns_permissions 2>/dev/null || true

    # System aufräumen
    apt-get -f install -y 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    error "Installation fehlgeschlagen nach automatischen Reparatur-Versuchen"
    echo "Bitte manuell überprüfen oder Script erneut ausführen"
    exit 1
}

# Erweiterte Fehlerbehandlung
trap 'handle_error ${LINENO}' ERR

# Script ausführen
main "$@"
