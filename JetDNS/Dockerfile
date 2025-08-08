# JetDNS Docker Image
FROM python:3.11-slim

LABEL maintainer="JetDNS Team"
LABEL description="JetDNS - Hochperformanter DNS Server mit Web-GUI"
LABEL version="1.0.0"

# System Updates und Dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    redis-server \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Kein System-Benutzer erforderlich - läuft als Container-Benutzer
# Arbeitsverzeichnis
WORKDIR /opt/jetdns

# Python Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# JetDNS Code kopieren
COPY src/ src/
COPY web/ web/
COPY bin/ bin/
COPY systemd/ systemd/

# Verzeichnisse erstellen
RUN mkdir -p /etc/jetdns /var/log/jetdns /var/lib/jetdns

# Berechtigungen setzen (für Container-Umgebung angepasst)
RUN chmod -R 755 /opt/jetdns /etc/jetdns /var/log/jetdns /var/lib/jetdns

# Konfigurationsdateien
COPY docker/jetdns.conf /etc/jetdns/jetdns.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/jetdns.conf

# Ports freigeben
EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

# Health Check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD dig @127.0.0.1 google.com || exit 1

# Volumes
VOLUME ["/etc/jetdns", "/var/log/jetdns", "/var/lib/jetdns"]

# Start Script
COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["supervisord", "-n"]
