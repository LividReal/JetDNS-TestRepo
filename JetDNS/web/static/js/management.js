// JetDNS Security Management Interface
class JetDNSManager {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.currentSection = 'dashboard';
        this.refreshInterval = null;

        this.initializeSocket();
        this.initializeCharts();
        this.startAutoRefresh();

        // Event Listeners
        this.setupEventListeners();
    }

    initializeSocket() {
        this.socket = io();

        this.socket.on('connect', () => {
            console.log('Socket verbunden');
            this.refreshData();
        });

        this.socket.on('threat_detected', (data) => {
            this.handleNewThreat(data);
        });

        this.socket.on('stats_update', (data) => {
            this.updateStats(data);
        });

        this.socket.on('log_entry', (data) => {
            this.addLogEntry(data);
        });
    }

    setupEventListeners() {
        // Confidence threshold slider
        const confidenceSlider = document.getElementById('confidenceThreshold');
        if (confidenceSlider) {
            confidenceSlider.addEventListener('input', (e) => {
                document.getElementById('confidenceValue').textContent = e.target.value;
            });
        }

        // Similarity threshold slider
        const similaritySlider = document.getElementById('similarityThreshold');
        if (similaritySlider) {
            similaritySlider.addEventListener('input', (e) => {
                document.getElementById('similarityValue').textContent = e.target.value;
            });
        }
    }

    initializeCharts() {
        // Threat Timeline Chart
        const threatCtx = document.getElementById('threatChart');
        if (threatCtx) {
            this.charts.threat = new Chart(threatCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Bedrohungen',
                        data: [],
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        // Threat Type Pie Chart
        const threatTypeCtx = document.getElementById('threatTypeChart');
        if (threatTypeCtx) {
            this.charts.threatType = new Chart(threatTypeCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Typosquatting', 'DGA', 'Phishing', 'Malware'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            '#e74c3c',
                            '#f39c12',
                            '#9b59b6',
                            '#34495e'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }

        // Detection Rate Chart
        const detectionCtx = document.getElementById('detectionRateChart');
        if (detectionCtx) {
            this.charts.detection = new Chart(detectionCtx, {
                type: 'bar',
                data: {
                    labels: ['DGA', 'Zero-Day', 'Anomaly'],
                    datasets: [{
                        label: 'Genauigkeit (%)',
                        data: [95, 87, 92],
                        backgroundColor: [
                            'rgba(39, 174, 96, 0.8)',
                            'rgba(52, 152, 219, 0.8)',
                            'rgba(155, 89, 182, 0.8)'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
        }

        // Analytics Chart
        const analyticsCtx = document.getElementById('analyticsChart');
        if (analyticsCtx) {
            this.charts.analytics = new Chart(analyticsCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Blockierte Anfragen',
                            data: [],
                            borderColor: '#e74c3c',
                            backgroundColor: 'rgba(231, 76, 60, 0.1)'
                        },
                        {
                            label: 'Erlaubte Anfragen',
                            data: [],
                            borderColor: '#27ae60',
                            backgroundColor: 'rgba(39, 174, 96, 0.1)'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    interaction: {
                        intersect: false
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }

    async refreshData() {
        try {
            // Dashboard-Statistiken laden
            const statsResponse = await fetch('/api/security/stats');
            const stats = await statsResponse.json();
            this.updateDashboardStats(stats);

            // Chart-Daten laden
            const chartResponse = await fetch('/api/security/chart-data');
            const chartData = await chartResponse.json();
            this.updateCharts(chartData);

            // Aktuelle Bedrohungen laden
            const threatsResponse = await fetch('/api/security/recent-threats');
            const threats = await threatsResponse.json();
            this.updateRecentThreats(threats);

            // Brand Protection Daten laden
            if (this.currentSection === 'brand-protection') {
                await this.loadBrandProtectionData();
            }

            // Traffic Control Daten laden
            if (this.currentSection === 'traffic-control') {
                await this.loadTrafficControlData();
            }

        } catch (error) {
            console.error('Fehler beim Laden der Daten:', error);
            this.showAlert('Fehler beim Laden der Daten', 'danger');
        }
    }

    updateDashboardStats(stats) {
        document.getElementById('total-threats').textContent = stats.totalThreats || 0;
        document.getElementById('blocked-queries').textContent = stats.blockedQueries || 0;
        document.getElementById('protected-brands').textContent = stats.protectedBrands || 0;
        document.getElementById('ml-accuracy').textContent = `${stats.mlAccuracy || 0}%`;
    }

    updateCharts(data) {
        // Threat Timeline Chart
        if (this.charts.threat && data.threatTimeline) {
            this.charts.threat.data.labels = data.threatTimeline.labels;
            this.charts.threat.data.datasets[0].data = data.threatTimeline.data;
            this.charts.threat.update();
        }

        // Threat Type Chart
        if (this.charts.threatType && data.threatTypes) {
            this.charts.threatType.data.datasets[0].data = data.threatTypes;
            this.charts.threatType.update();
        }

        // Analytics Chart
        if (this.charts.analytics && data.analytics) {
            this.charts.analytics.data.labels = data.analytics.labels;
            this.charts.analytics.data.datasets[0].data = data.analytics.blocked;
            this.charts.analytics.data.datasets[1].data = data.analytics.allowed;
            this.charts.analytics.update();
        }
    }

    updateRecentThreats(threats) {
        const container = document.getElementById('recent-threats');
        if (!container || !threats.length) {
            container.innerHTML = '<p class="text-muted">Keine aktuellen Bedrohungen</p>';
            return;
        }

        container.innerHTML = threats.map(threat => `
            <div class="threat-item threat-${threat.severity}">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            ${threat.domain}
                        </h6>
                        <p class="mb-1">
                            <strong>Typ:</strong> ${threat.threatType}<br>
                            <strong>Marke:</strong> ${threat.brand}<br>
                            <strong>Konfidenz:</strong> ${(threat.confidence * 100).toFixed(1)}%
                        </p>
                        <small class="text-muted">
                            <i class="fas fa-clock me-1"></i>
                            ${new Date(threat.firstDetected * 1000).toLocaleString('de-DE')}
                        </small>
                    </div>
                    <div>
                        <span class="badge bg-${this.getSeverityColor(threat.severity)} mb-2">
                            ${threat.severity.toUpperCase()}
                        </span>
                        <br>
                        <button class="btn btn-sm btn-outline-danger" onclick="blockThreat('${threat.threatId}')">
                            <i class="fas fa-ban me-1"></i>Blockieren
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    async loadBrandProtectionData() {
        try {
            const response = await fetch('/api/brand-protection/data');
            const data = await response.json();

            // Geschützte Marken
            const brandsList = document.getElementById('protected-brands-list');
            if (brandsList && data.brands) {
                brandsList.innerHTML = data.brands.map(brand => `
                    <div class="mb-2 p-2 border rounded">
                        <div class="d-flex justify-content-between">
                            <div>
                                <strong>${brand.name}</strong>
                                <div class="text-muted small">
                                    Domains: ${brand.primaryDomains.join(', ')}
                                </div>
                            </div>
                            <div>
                                <span class="badge bg-${brand.active ? 'success' : 'secondary'}">
                                    ${brand.active ? 'Aktiv' : 'Inaktiv'}
                                </span>
                            </div>
                        </div>
                    </div>
                `).join('');
            }

            // Typosquatting Erkennungen
            const detectionsList = document.getElementById('typosquatting-detections');
            if (detectionsList && data.detections) {
                detectionsList.innerHTML = data.detections.map(detection => `
                    <div class="mb-2 p-2 border rounded bg-light">
                        <div class="fw-bold text-danger">${detection.suspiciousDomain}</div>
                        <div class="small">
                            Ziel: ${detection.targetBrand}<br>
                            Ähnlichkeit: ${(detection.similarityScore * 100).toFixed(1)}%<br>
                            Anfragen: ${detection.queryCount}
                        </div>
                    </div>
                `).join('');
            }

        } catch (error) {
            console.error('Fehler beim Laden der Brand Protection Daten:', error);
        }
    }

    async loadTrafficControlData() {
        try {
            const response = await fetch('/api/traffic-control/rules');
            const rules = await response.json();

            const tableBody = document.getElementById('traffic-rules');
            if (tableBody && rules) {
                tableBody.innerHTML = rules.map(rule => `
                    <tr>
                        <td>${rule.name}</td>
                        <td>${rule.source}</td>
                        <td>${rule.destination}</td>
                        <td>
                            <span class="badge bg-${rule.action === 'block' ? 'danger' : 'success'}">
                                ${rule.action}
                            </span>
                        </td>
                        <td>
                            <span class="badge bg-${rule.enabled ? 'success' : 'secondary'}">
                                ${rule.enabled ? 'Aktiv' : 'Inaktiv'}
                            </span>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-outline-primary me-1" onclick="editTrafficRule('${rule.id}')">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger" onclick="deleteTrafficRule('${rule.id}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    </tr>
                `).join('');
            }

        } catch (error) {
            console.error('Fehler beim Laden der Traffic Control Daten:', error);
        }
    }

    handleNewThreat(threat) {
        // Statistiken aktualisieren
        const totalThreats = document.getElementById('total-threats');
        if (totalThreats) {
            totalThreats.textContent = parseInt(totalThreats.textContent) + 1;
        }

        // Neue Bedrohung zur Liste hinzufügen
        this.addThreatToList(threat);

        // Toast-Benachrichtigung
        this.showAlert(`Neue Bedrohung erkannt: ${threat.domain}`, 'warning');
    }

    addThreatToList(threat) {
        const container = document.getElementById('recent-threats');
        if (!container) return;

        const threatElement = document.createElement('div');
        threatElement.className = `threat-item threat-${threat.severity}`;
        threatElement.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="mb-1">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        ${threat.domain}
                    </h6>
                    <p class="mb-1">
                        <strong>Typ:</strong> ${threat.threatType}<br>
                        <strong>Marke:</strong> ${threat.brand}<br>
                        <strong>Konfidenz:</strong> ${(threat.confidence * 100).toFixed(1)}%
                    </p>
                    <small class="text-muted">
                        <i class="fas fa-clock me-1"></i>
                        ${new Date().toLocaleString('de-DE')} (NEU)
                    </small>
                </div>
                <div>
                    <span class="badge bg-${this.getSeverityColor(threat.severity)} mb-2">
                        ${threat.severity.toUpperCase()}
                    </span>
                    <br>
                    <button class="btn btn-sm btn-outline-danger" onclick="blockThreat('${threat.threatId}')">
                        <i class="fas fa-ban me-1"></i>Blockieren
                    </button>
                </div>
            </div>
        `;

        container.insertBefore(threatElement, container.firstChild);
    }

    addLogEntry(logData) {
        const logContainer = document.getElementById('log-container');
        if (!logContainer) return;

        const logEntry = document.createElement('div');
        logEntry.className = 'mb-1';
        logEntry.innerHTML = `
            <span class="text-muted">[${new Date(logData.timestamp).toLocaleTimeString('de-DE')}]</span>
            <span class="badge bg-${this.getLogLevelColor(logData.level)} me-2">${logData.level}</span>
            ${logData.message}
        `;

        logContainer.insertBefore(logEntry, logContainer.firstChild);

        // Nur die letzten 100 Einträge behalten
        while (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }

    getSeverityColor(severity) {
        const colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success'
        };
        return colors[severity] || 'secondary';
    }

    getLogLevelColor(level) {
        const colors = {
            'ERROR': 'danger',
            'WARNING': 'warning',
            'INFO': 'info',
            'DEBUG': 'secondary'
        };
        return colors[level] || 'secondary';
    }

    showAlert(message, type = 'info') {
        // Toast-Benachrichtigung erstellen
        const toastContainer = document.getElementById('toast-container') || this.createToastContainer();

        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Nach 5 Sekunden automatisch entfernen
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 5000);
    }

    createToastContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '1080';
        document.body.appendChild(container);
        return container;
    }

    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.refreshData();
            }
        }, 30000); // Alle 30 Sekunden aktualisieren
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }
}

// Navigation Functions
function showSection(sectionName) {
    // Alle Sections verstecken
    document.querySelectorAll('[id$="-section"]').forEach(section => {
        section.style.display = 'none';
    });

    // Gewählte Section anzeigen
    document.getElementById(`${sectionName}-section`).style.display = 'block';

    // Aktive Navigation aktualisieren
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });

    event.target.classList.add('active');
    window.jetdnsManager.currentSection = sectionName;

    // Spezielle Daten für Section laden
    if (sectionName === 'brand-protection') {
        window.jetdnsManager.loadBrandProtectionData();
    } else if (sectionName === 'traffic-control') {
        window.jetdnsManager.loadTrafficControlData();
    }
}

function showDashboard() { showSection('dashboard'); }
function showThreatDetection() { showSection('threat-detection'); }
function showTrafficControl() { showSection('traffic-control'); }
function showBrandProtection() { showSection('brand-protection'); }
function showAnalytics() { showSection('analytics'); }
function showLogs() { showSection('logs'); }

// API Functions
async function blockThreat(threatId) {
    try {
        const response = await fetch(`/api/security/block-threat/${threatId}`, {
            method: 'POST'
        });

        if (response.ok) {
            window.jetdnsManager.showAlert('Bedrohung erfolgreich blockiert', 'success');
            window.jetdnsManager.refreshData();
        } else {
            throw new Error('Fehler beim Blockieren');
        }
    } catch (error) {
        window.jetdnsManager.showAlert('Fehler beim Blockieren der Bedrohung', 'danger');
    }
}

async function retrainModels() {
    try {
        window.jetdnsManager.showAlert('Modelle werden neu trainiert...', 'info');

        const response = await fetch('/api/ml/retrain', {
            method: 'POST'
        });

        if (response.ok) {
            window.jetdnsManager.showAlert('Modelle erfolgreich neu trainiert', 'success');
        } else {
            throw new Error('Fehler beim Training');
        }
    } catch (error) {
        window.jetdnsManager.showAlert('Fehler beim Neu-Training der Modelle', 'danger');
    }
}

function addTrafficRule() {
    // Modal für neue Traffic-Regel öffnen
    window.jetdnsManager.showAlert('Traffic-Regel Funktion wird implementiert...', 'info');
}

function editTrafficRule(ruleId) {
    window.jetdnsManager.showAlert(`Traffic-Regel ${ruleId} wird bearbeitet...`, 'info');
}

function deleteTrafficRule(ruleId) {
    if (confirm('Sind Sie sicher, dass Sie diese Regel löschen möchten?')) {
        window.jetdnsManager.showAlert(`Traffic-Regel ${ruleId} gelöscht`, 'success');
    }
}

function refreshData() {
    window.jetdnsManager.refreshData();
}

function showSettings() {
    const modal = new bootstrap.Modal(document.getElementById('settingsModal'));
    modal.show();
}

async function saveSettings() {
    const form = document.getElementById('settingsForm');
    const formData = new FormData(form);

    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            window.jetdnsManager.showAlert('Einstellungen gespeichert', 'success');
            bootstrap.Modal.getInstance(document.getElementById('settingsModal')).hide();
        } else {
            throw new Error('Fehler beim Speichern');
        }
    } catch (error) {
        window.jetdnsManager.showAlert('Fehler beim Speichern der Einstellungen', 'danger');
    }
}

function clearLogs() {
    if (confirm('Sind Sie sicher, dass Sie alle Logs löschen möchten?')) {
        document.getElementById('log-container').innerHTML = '';
        window.jetdnsManager.showAlert('Logs gelöscht', 'success');
    }
}

function logout() {
    if (confirm('Möchten Sie sich wirklich abmelden?')) {
        window.location.href = '/logout';
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    window.jetdnsManager = new JetDNSManager();
});
