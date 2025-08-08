#!/bin/bash

# JetDNS Deinstallations-Script
# Entfernt JetDNS vollständig vom System

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Root-Rechte prüfen
if [[ $EUID -ne 0 ]]; then
    error "Dieses Script muss als root ausgeführt werden!"
    echo "Verwenden Sie: sudo $0"
    exit 1
fi

echo "============================================="
echo "JetDNS Deinstallation"
echo "============================================="
echo
warn "ACHTUNG: Dies entfernt JetDNS vollständig vom System!"
echo "Alle Konfigurationen und Logs gehen verloren."
echo

read -p "Sind Sie sicher? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deinstallation abgebrochen."
    exit 0
fi

log "Stoppe JetDNS Services..."
systemctl stop jetdns 2>/dev/null || true
systemctl disable jetdns 2>/dev/null || true

log "Entferne Systemd Service..."
rm -f /etc/systemd/system/jetdns.service
systemctl daemon-reload

log "Entferne Firewall-Regeln..."
ufw delete allow 53/udp 2>/dev/null || true
ufw delete allow 53/tcp 2>/dev/null || true
ufw delete allow 80/tcp 2>/dev/null || true
ufw delete allow 443/tcp 2>/dev/null || true
ufw delete allow 8080/tcp 2>/dev/null || true

log "Entferne JetDNS-Dateien..."
rm -rf /opt/jetdns
rm -rf /etc/jetdns
rm -rf /var/log/jetdns
rm -f /usr/local/bin/jetdns*
rm -f /etc/logrotate.d/jetdns

log "Entferne Benutzer..."
userdel -r jetdns 2>/dev/null || true

log "Bereinige Netplan-Konfiguration..."
rm -f /etc/netplan/50-jetdns.yaml
rm -f /etc/netplan/*jetdns*

warn "Netzwerk-Konfiguration wurde NICHT automatisch zurückgesetzt!"
echo "Sie müssen die Netzwerk-Einstellungen manuell wiederherstellen."

echo
log "JetDNS wurde vollständig deinstalliert."
echo "Ein Neustart wird empfohlen."
