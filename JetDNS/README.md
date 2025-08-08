# JetDNS

Ein hochperformanter DNS-Server mit Web-GUI, Threat Intelligence, Ad-Blocking und Enterprise-Features für Debian/Ubuntu Linux.

## 🚀 Features

### DNS Server Kern
- **Multi-Protokoll**: UDP, TCP, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT)
- **Hochperformant**: Async/Await Architektur mit Multi-Tier Caching
- **Load Balancing**: Intelligente Upstream-Server Verteilung
- **Health Monitoring**: Automatische Upstream-Server Überwachung

### Sicherheits-Features
- **🛡️ Threat Intelligence**: Echtzeit-Bedrohungsanalyse aus mehreren Quellen
- **🚫 Ad-Blocking**: Pi-Hole kompatible Blocklisten
- **🔍 DGA Detection**: Erkennung von Domain Generation Algorithms
- **🕵️ DNS Tunneling**: Schutz vor DNS-basierten Datenexfiltrations-Attacken
- **🆕 Newly Seen Domains**: OpenDNS-style Erkennung verdächtiger neuer Domains

### Content-Filterung
- **20+ Kategorien**: Malware, Phishing, Adult Content, Social Media, Gaming, etc.
- **Zeit-basierte Regeln**: Blockierung nach Zeitplänen (z.B. Arbeitszeit)
- **Safe Search**: Automatische Aktivierung für Google, Bing, YouTube
- **Custom Rules**: Wildcard-, RegEx- und Exact-Match Regeln

### Web-Management Interface
- **📊 Real-time Dashboard**: Live-Statistiken mit WebSocket-Updates
- **🖥️ Moderne UI**: Responsive Bootstrap 5 Design
- **⚙️ Vollständige Konfiguration**: Alle Features über GUI steuerbar
- **📈 Analytics**: Umfassende DNS-Query Analyse und Reporting

### Enterprise-Features
- **🌍 GeoDNS**: Standortbasierte DNS-Antworten
- **🔐 DNSSEC**: Validierung und Signing
- **🏢 Authoritative DNS**: Eigene DNS-Zonen hosten
- **📡 API**: RESTful API für Automatisierung
- **📋 SIEM Integration**: Export zu Splunk, Elasticsearch, etc.

## 📋 Systemvoraussetzungen

### Unterstützte Betriebssysteme
- **Debian**: 10, 11, 12 (Bullseye, Bookworm)
- **Ubuntu**: 18.04, 20.04, 22.04, 23.04+ (LTS und aktuelle Versionen)

### Minimum Hardware
- **RAM**: 512 MB (1 GB empfohlen)
- **CPU**: 1 Kern (2+ Kerne empfohlen)
- **Festplatte**: 2 GB frei (5 GB+ empfohlen)
- **Netzwerk**: Internetverbindung für Threat Intelligence Updates

### Erforderliche Ports
- **53/UDP+TCP**: DNS Server
- **80/TCP**: Web Interface (HTTP)
- **443/TCP**: Web Interface (HTTPS)
- **853/TCP**: DNS-over-TLS (optional)
- **6379/TCP**: Redis (intern)

## ⚡ Schnellinstallation

### Ein-Kommando Installation
