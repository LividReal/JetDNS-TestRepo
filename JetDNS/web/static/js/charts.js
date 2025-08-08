// JetDNS Charts - Specialized Chart Functions
class JetDNSCharts {
    constructor() {
        this.charts = new Map();
        this.defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom'
                }
            },
            elements: {
                arc: {
                    borderWidth: 2
                },
                line: {
                    tension: 0.4
                },
                point: {
                    radius: 4,
                    hoverRadius: 6
                }
            }
        };
    }

    createThreatTimelineChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels || [],
                datasets: [{
                    label: 'Bedrohungen erkannt',
                    data: data.threats || [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Blockierte Anfragen',
                    data: data.blocked || [],
                    borderColor: '#f39c12',
                    backgroundColor: 'rgba(243, 156, 18, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                ...this.defaultOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });

        this.charts.set(canvasId, chart);
        return chart;
    }

    createThreatDistributionChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Typosquatting', 'DGA', 'Phishing', 'Malware', 'Zero-Day'],
                datasets: [{
                    data: data || [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#9b59b6',
                        '#34495e',
                        '#e67e22'
                    ],
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                ...this.defaultOptions,
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });

        this.charts.set(canvasId, chart);
        return chart;
    }

    createMLPerformanceChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const chart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Präzision', 'Recall', 'F1-Score', 'Genauigkeit', 'Geschwindigkeit'],
                datasets: [{
                    label: 'DGA Detector',
                    data: data.dga || [95, 92, 93, 95, 88],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    pointBackgroundColor: '#3498db'
                }, {
                    label: 'Zero-Day Detector',
                    data: data.zeroday || [87, 89, 88, 87, 92],
                    borderColor: '#27ae60',
                    backgroundColor: 'rgba(39, 174, 96, 0.2)',
                    pointBackgroundColor: '#27ae60'
                }, {
                    label: 'Anomaly Detector',
                    data: data.anomaly || [92, 90, 91, 92, 85],
                    borderColor: '#9b59b6',
                    backgroundColor: 'rgba(155, 89, 182, 0.2)',
                    pointBackgroundColor: '#9b59b6'
                }]
            },
            options: {
                ...this.defaultOptions,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            stepSize: 20
                        },
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    }
                }
            }
        });

        this.charts.set(canvasId, chart);
        return chart;
    }

    createNetworkTrafficChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels || [],
                datasets: [{
                    label: 'Eingehend',
                    data: data.incoming || [],
                    backgroundColor: 'rgba(52, 152, 219, 0.8)',
                    borderColor: '#3498db',
                    borderWidth: 1
                }, {
                    label: 'Ausgehend',
                    data: data.outgoing || [],
                    backgroundColor: 'rgba(39, 174, 96, 0.8)',
                    borderColor: '#27ae60',
                    borderWidth: 1
                }, {
                    label: 'Blockiert',
                    data: data.blocked || [],
                    backgroundColor: 'rgba(231, 76, 60, 0.8)',
                    borderColor: '#e74c3c',
                    borderWidth: 1
                }]
            },
            options: {
                ...this.defaultOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: false,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });

        this.charts.set(canvasId, chart);
        return chart;
    }

    createHeatmapChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        // Custom heatmap implementation using Chart.js scatter plot
        const heatmapData = [];

        if (data && data.matrix) {
            data.matrix.forEach((row, y) => {
                row.forEach((value, x) => {
                    heatmapData.push({
                        x: x,
                        y: y,
                        v: value
                    });
                });
            });
        }

        const chart = new Chart(ctx, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Bedrohungsintensität',
                    data: heatmapData,
                    backgroundColor: function(context) {
                        const value = context.parsed.v || 0;
                        const intensity = Math.min(value / 100, 1);
                        return `rgba(231, 76, 60, ${intensity})`;
                    },
                    pointRadius: function(context) {
                        const value = context.parsed.v || 0;
                        return Math.max(3, Math.min(15, value / 10));
                    }
                }]
            },
            options: {
                ...this.defaultOptions,
                scales: {
                    x: {
                        type: 'linear',
                        position: 'bottom',
                        title: {
                            display: true,
                            text: 'Zeit (Stunden)'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Bedrohungstyp'
                        }
                    }
                }
            }
        });

        this.charts.set(canvasId, chart);
        return chart;
    }

    updateChart(canvasId, newData) {
        const chart = this.charts.get(canvasId);
        if (!chart) return;

        if (newData.labels) {
            chart.data.labels = newData.labels;
        }

        if (newData.datasets) {
            newData.datasets.forEach((dataset, index) => {
                if (chart.data.datasets[index]) {
                    chart.data.datasets[index].data = dataset.data;
                }
            });
        } else if (newData.data) {
            chart.data.datasets[0].data = newData.data;
        }

        chart.update('none'); // Smooth animation
    }

    destroyChart(canvasId) {
        const chart = this.charts.get(canvasId);
        if (chart) {
            chart.destroy();
            this.charts.delete(canvasId);
        }
    }

    destroyAllCharts() {
        this.charts.forEach((chart, id) => {
            chart.destroy();
        });
        this.charts.clear();
    }

    getChart(canvasId) {
        return this.charts.get(canvasId);
    }

    // Real-time data streaming
    startRealTimeUpdate(canvasId, dataSource, interval = 5000) {
        const chart = this.charts.get(canvasId);
        if (!chart) return;

        const updateInterval = setInterval(async () => {
            try {
                const response = await fetch(dataSource);
                const data = await response.json();
                this.updateChart(canvasId, data);
            } catch (error) {
                console.error('Error updating chart data:', error);
            }
        }, interval);

        // Store interval for cleanup
        chart.updateInterval = updateInterval;

        return updateInterval;
    }

    stopRealTimeUpdate(canvasId) {
        const chart = this.charts.get(canvasId);
        if (chart && chart.updateInterval) {
            clearInterval(chart.updateInterval);
            delete chart.updateInterval;
        }
    }

    // Export chart as image
    exportChart(canvasId, filename = 'chart.png') {
        const chart = this.charts.get(canvasId);
        if (!chart) return;

        const url = chart.toBase64Image();
        const link = document.createElement('a');
        link.download = filename;
        link.href = url;
        link.click();
    }

    // Resize all charts (useful for responsive layouts)
    resizeAll() {
        this.charts.forEach(chart => {
            chart.resize();
        });
    }
}

// Global instance
window.jetdnsCharts = new JetDNSCharts();

// Auto-resize on window resize
window.addEventListener('resize', () => {
    if (window.jetdnsCharts) {
        window.jetdnsCharts.resizeAll();
    }
});
