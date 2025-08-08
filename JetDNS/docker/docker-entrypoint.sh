#!/bin/bash
set -e

# JetDNS Docker Entrypoint

echo "🚀 JetDNS Container wird gestartet..."

# Umgebungsvariablen mit Standardwerten
DNS_PORT=${DNS_PORT:-53}
WEB_PORT=${WEB_PORT:-80}
DNS_UPSTREAM=${DNS_UPSTREAM:-"8.8.8.8,1.1.1.1,9.9.9.9"}
ENABLE_WEB=${ENABLE_WEB:-true}
ENABLE_THREAT_INTEL=${ENABLE_THREAT_INTEL:-true}
ENABLE_AD_BLOCKING=${ENABLE_AD_BLOCKING:-true}
LOG_LEVEL=${LOG_LEVEL:-INFO}

echo "📋 Konfiguration:"
echo "  DNS Port: $DNS_PORT"
echo "  Web Port: $WEB_PORT"
echo "  Upstream: $DNS_UPSTREAM"
echo "  Web Interface: $ENABLE_WEB"
echo "  Threat Intelligence: $ENABLE_THREAT_INTEL"
echo "  Ad-Blocking: $ENABLE_AD_BLOCKING"

# Konfigurationsdatei anpassen
if [ ! -f /etc/jetdns/jetdns.conf ]; then
    echo "🔧 Erstelle Standard-Konfiguration..."

    cat > /etc/jetdns/jetdns.conf << EOF
[general]
version = 1.0.0
language = de
timezone = UTC
log_level = $LOG_LEVEL

[dns]
listen_address = 0.0.0.0
listen_port = $DNS_PORT
query_timeout = 5
max_connections = 1000
worker_threads = 4

[cache]
enabled = true
max_size = 10000
ttl_min = 300
ttl_max = 3600

[upstream]
servers = $DNS_UPSTREAM
health_check_interval = 30
timeout = 5
load_balancing = true

[security]
threat_intelligence = $ENABLE_THREAT_INTEL
ad_blocking = $ENABLE_AD_BLOCKING
safe_search = true
dns_tunneling_protection = false
dnssec_validation = false
rate_limiting = true

[web]
enabled = $ENABLE_WEB
host = 0.0.0.0
port = $WEB_PORT
protocol = http

[logging]
query_logging = true
log_file = /var/log/jetdns/jetdns.log
max_log_size = 10MB
log_retention_days = 7

[performance]
connection_pool_size = 100
statistics_collection = true
real_time_updates = true
EOF
else
    echo "✅ Bestehende Konfiguration gefunden"
fi

# Redis starten falls nicht läuft
if ! pgrep redis-server > /dev/null; then
    echo "🔴 Starte Redis Server..."
    redis-server --daemonize yes --save 60 1 --loglevel warning
fi

# Berechtigungen prüfen (keine spezifischen Benutzer da Container-Umgebung)
chmod -R 755 /etc/jetdns /var/log/jetdns /var/lib/jetdns

# Erste Threat Intelligence Update (async)
if [ "$ENABLE_THREAT_INTEL" = "true" ]; then
    echo "🛡️  Initialisiere Threat Intelligence (im Hintergrund)..."
    cd /opt/jetdns && python3 -c 'import asyncio; from src.management.threat_intelligence import ThreatIntelligenceManager; ti = ThreatIntelligenceManager(); asyncio.run(ti.update_threat_feeds(["ad_blocking"]))' &
fi

# Warten auf Abhängigkeiten
echo "⏳ Warte auf Services..."
sleep 2

# Ausführung an ursprünglichen Befehl weitergeben
if [ "$1" = "supervisord" ]; then
    echo "🎯 Starte JetDNS via Supervisor..."
    exec "$@"
elif [ "$1" = "jetdns-server" ]; then
    echo "🎯 Starte JetDNS Server direkt..."
    exec bash -c "cd /opt/jetdns && python3 bin/jetdns-server"
else
    echo "🎯 Führe benutzerdefinierten Befehl aus: $@"
    exec "$@"
fi
