// Forensic Log Analyzer - Frontend JavaScript

let currentAnalysisId = null;
let currentAnalysisData = null;
let severityChart = null;
let iocChart = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeUpload();
    initializeTabs();
    initializeSearch();
    initializeFilters();
});

// File Upload Functionality
function initializeUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');

    // Browse button click
    browseBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        fileInput.click();
    });

    // File input change
    fileInput.addEventListener('change', function() {
        if (this.files.length > 0) {
            handleFileUpload(this.files[0]);
        }
    });

    // Drag and drop
    dropZone.addEventListener('click', function() {
        fileInput.click();
    });

    dropZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.classList.add('drag-over');
    });

    dropZone.addEventListener('dragleave', function() {
        this.classList.remove('drag-over');
    });

    dropZone.addEventListener('drop', function(e) {
        e.preventDefault();
        this.classList.remove('drag-over');

        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    // New analysis button
    document.getElementById('new-analysis-btn').addEventListener('click', function() {
        resetAnalysis();
    });

    // Export buttons
    document.getElementById('export-json-btn').addEventListener('click', function() {
        exportAnalysis('json');
    });

    document.getElementById('export-iocs-btn').addEventListener('click', function() {
        exportAnalysis('iocs');
    });

    // Enrichment button
    document.getElementById('enrich-btn').addEventListener('click', function() {
        enrichAnalysis();
    });
}

// Handle file upload
function handleFileUpload(file) {
    const formData = new FormData();
    formData.append('file', file);

    // Add custom patterns if provided
    const customPatternsInput = document.getElementById('custom-patterns');
    if (customPatternsInput && customPatternsInput.value.trim()) {
        try {
            JSON.parse(customPatternsInput.value);  // Validate JSON
            formData.append('custom_patterns', customPatternsInput.value);
        } catch (e) {
            showStatus('Invalid JSON in custom patterns. Using defaults.', 'error');
        }
    }

    showLoading();
    hideStatus();

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();

        if (data.success) {
            currentAnalysisId = data.analysis_id;
            loadAnalysis(currentAnalysisId);
            showStatus('File analyzed successfully!', 'success');
        } else {
            showStatus('Error: ' + data.error, 'error');
        }
    })
    .catch(error => {
        hideLoading();
        showStatus('Upload failed: ' + error.message, 'error');
    });
}

// Load analysis results
function loadAnalysis(analysisId) {
    fetch(`/analyze/${analysisId}`)
        .then(response => response.json())
        .then(data => {
            currentAnalysisData = data;
            displayResults(data);
        })
        .catch(error => {
            showStatus('Failed to load analysis: ' + error.message, 'error');
        });
}

// Display analysis results
function displayResults(data) {
    document.getElementById('upload-section').style.display = 'none';
    document.getElementById('results-section').style.display = 'block';

    displayOverview(data);
    displayTimeline(data.analysis.timeline);
    displayIOCs(data.analysis.iocs);
    displayAnomalies(data.analysis.anomalies);

    // Create charts
    createCharts(data);

    // Setup timeline filters
    setupTimelineFilters();
}

// Display overview tab
function displayOverview(data) {
    const stats = data.analysis.statistics;

    // File information
    const fileInfo = document.getElementById('file-info');
    fileInfo.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Filename:</span>
            <span class="stat-value">${data.filename}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Format:</span>
            <span class="stat-value">${data.parsed_data.format}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Upload Time:</span>
            <span class="stat-value">${new Date(data.upload_time).toLocaleString()}</span>
        </div>
    `;

    // Quick statistics
    const quickStats = document.getElementById('quick-stats');
    quickStats.innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Total Entries:</span>
            <span class="stat-value">${stats.total_entries.toLocaleString()}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Date Range:</span>
            <span class="stat-value">${formatDateRange(stats.date_range)}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">IOCs Found:</span>
            <span class="stat-value">${getTotalIOCs(stats.ioc_counts)}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Anomalies:</span>
            <span class="stat-value">${stats.anomaly_count}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Suspicious Events:</span>
            <span class="stat-value">${stats.suspicious_count}</span>
        </div>
    `;

    // Suspicious activity summary
    const suspiciousSummary = document.getElementById('suspicious-summary');
    const suspicious = data.analysis.suspicious_activity;

    if (suspicious.length === 0) {
        suspiciousSummary.innerHTML = '<p class="text-muted">No suspicious activity detected.</p>';
    } else {
        const severityBreakdown = stats.severity_breakdown || {};
        const groupedByType = groupBy(suspicious, 'type');

        let html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">';

        for (const [type, items] of Object.entries(groupedByType)) {
            const highestSeverity = getHighestSeverity(items);
            html += `
                <div class="anomaly-item severity-${highestSeverity}">
                    <div class="anomaly-header">
                        <span class="anomaly-type">${type.replace(/_/g, ' ')}</span>
                        <span class="anomaly-severity ${highestSeverity}">${items.length}</span>
                    </div>
                </div>
            `;
        }

        html += '</div>';
        suspiciousSummary.innerHTML = html;
    }
}

// Display timeline
function displayTimeline(timeline) {
    const timelineContent = document.getElementById('timeline-content');

    if (timeline.length === 0) {
        timelineContent.innerHTML = '<div class="empty-state"><p>No timeline data available.</p></div>';
        return;
    }

    let html = '';
    timeline.forEach(entry => {
        html += `
            <div class="timeline-entry">
                <div class="timeline-timestamp">${formatTimestamp(entry.timestamp)}</div>
                <div class="timeline-summary">${escapeHtml(entry.summary)}</div>
                <div class="timeline-details">${escapeHtml(entry.full_entry.substring(0, 200))}</div>
            </div>
        `;
    });

    timelineContent.innerHTML = html;

    // Timeline filter
    const filterInput = document.getElementById('timeline-filter');
    filterInput.addEventListener('input', function() {
        filterTimeline(this.value);
    });
}

// Display IOCs
function displayIOCs(iocs) {
    const iocsContent = document.getElementById('iocs-content');

    const hasIOCs = Object.values(iocs).some(arr => arr.length > 0);

    if (!hasIOCs) {
        iocsContent.innerHTML = '<div class="empty-state"><p>No IOCs extracted.</p></div>';
        return;
    }

    let html = '';

    for (const [type, values] of Object.entries(iocs)) {
        if (values.length > 0) {
            html += `
                <div class="ioc-card">
                    <h3>${type.toUpperCase()} (${values.length})</h3>
                    <div class="ioc-list">
                        ${values.map(val => `<div class="ioc-item">${escapeHtml(val)}</div>`).join('')}
                    </div>
                </div>
            `;
        }
    }

    iocsContent.innerHTML = html;
}

// Display anomalies
function displayAnomalies(anomalies) {
    const anomaliesContent = document.getElementById('anomalies-content');

    if (anomalies.length === 0) {
        anomaliesContent.innerHTML = '<div class="empty-state"><p>No anomalies detected.</p></div>';
        return;
    }

    let html = '';
    anomalies.forEach(anomaly => {
        html += `
            <div class="anomaly-item severity-${anomaly.severity}">
                <div class="anomaly-header">
                    <span class="anomaly-type">${anomaly.type.replace(/_/g, ' ')}</span>
                    <span class="anomaly-severity ${anomaly.severity}">${anomaly.severity}</span>
                </div>
                <div class="anomaly-description">${escapeHtml(anomaly.description)}</div>
                ${anomaly.details ? `<div class="anomaly-details">${JSON.stringify(anomaly.details, null, 2)}</div>` : ''}
                ${anomaly.entry ? `<div class="anomaly-details">${escapeHtml(anomaly.entry)}</div>` : ''}
            </div>
        `;
    });

    anomaliesContent.innerHTML = html;
}

// Initialize tabs
function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');

            // Remove active class from all tabs and panes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));

            // Add active class to clicked tab and corresponding pane
            this.classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        });
    });
}

// Initialize search
function initializeSearch() {
    const searchBtn = document.getElementById('search-btn');
    const searchInput = document.getElementById('search-input');

    searchBtn.addEventListener('click', function() {
        performSearch();
    });

    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch();
        }
    });
}

// Perform search
function performSearch() {
    const query = document.getElementById('search-input').value.toLowerCase();
    const searchResults = document.getElementById('search-results');

    if (!currentAnalysisData || !query) {
        searchResults.innerHTML = '<div class="empty-state"><p>Enter a search term.</p></div>';
        return;
    }

    const entries = currentAnalysisData.parsed_data.entries;
    const results = entries.filter(entry =>
        entry.raw.toLowerCase().includes(query)
    );

    if (results.length === 0) {
        searchResults.innerHTML = '<div class="empty-state"><p>No results found.</p></div>';
        return;
    }

    let html = `<p class="text-muted mb-20">Found ${results.length} results</p>`;
    results.slice(0, 100).forEach(result => {
        const highlighted = highlightText(result.raw, query);
        html += `
            <div class="search-result">
                <div class="search-result-text">${highlighted}</div>
            </div>
        `;
    });

    if (results.length > 100) {
        html += '<p class="text-muted text-center mt-20">Showing first 100 results</p>';
    }

    searchResults.innerHTML = html;
}

// Filter timeline
function filterTimeline(query) {
    const entries = document.querySelectorAll('.timeline-entry');
    const lowerQuery = query.toLowerCase();

    entries.forEach(entry => {
        const text = entry.textContent.toLowerCase();
        entry.style.display = text.includes(lowerQuery) ? 'block' : 'none';
    });
}

// Export analysis
function exportAnalysis(format) {
    if (!currentAnalysisId) return;

    window.location.href = `/export/${currentAnalysisId}?format=${format}`;
}

// Reset analysis
function resetAnalysis() {
    currentAnalysisId = null;
    currentAnalysisData = null;

    document.getElementById('upload-section').style.display = 'block';
    document.getElementById('results-section').style.display = 'none';

    hideStatus();

    // Clear file input
    document.getElementById('file-input').value = '';
}

// Utility functions
function showLoading() {
    document.getElementById('loading-overlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loading-overlay').style.display = 'none';
}

function showStatus(message, type) {
    const status = document.getElementById('upload-status');
    status.textContent = message;
    status.className = `upload-status ${type}`;
}

function hideStatus() {
    const status = document.getElementById('upload-status');
    status.style.display = 'none';
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    try {
        return new Date(timestamp).toLocaleString();
    } catch {
        return timestamp;
    }
}

function formatDateRange(range) {
    if (!range.start || !range.end) return 'N/A';
    const start = new Date(range.start).toLocaleDateString();
    const end = new Date(range.end).toLocaleDateString();
    return `${start} - ${end}`;
}

function getTotalIOCs(iocCounts) {
    return Object.values(iocCounts).reduce((sum, count) => sum + count, 0);
}

function groupBy(array, key) {
    return array.reduce((result, item) => {
        const group = item[key];
        if (!result[group]) result[group] = [];
        result[group].push(item);
        return result;
    }, {});
}

function getHighestSeverity(items) {
    const severities = items.map(item => item.severity);
    if (severities.includes('high')) return 'high';
    if (severities.includes('medium')) return 'medium';
    return 'low';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function highlightText(text, query) {
    const escaped = escapeHtml(text);
    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return escaped.replace(regex, '<span class="highlight">$1</span>');
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Initialize filters
function initializeFilters() {
    // Timeline filters will be initialized when analysis is loaded
}

// Create charts
function createCharts(data) {
    const stats = data.analysis.statistics;

    // Destroy existing charts
    if (severityChart) severityChart.destroy();
    if (iocChart) iocChart.destroy();

    // Severity Distribution Chart
    const severityBreakdown = stats.severity_breakdown || {high: 0, medium: 0, low: 0};
    const severityCtx = document.getElementById('severity-chart');
    if (severityCtx) {
        severityChart = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        severityBreakdown.high || 0,
                        severityBreakdown.medium || 0,
                        severityBreakdown.low || 0
                    ],
                    backgroundColor: [
                        '#f85149',
                        '#d29922',
                        '#3fb950'
                    ],
                    borderColor: '#21262d',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#c9d1d9',
                            font: {
                                size: 12
                            }
                        }
                    },
                    title: {
                        display: false
                    }
                }
            }
        });
    }

    // IOC Categories Chart
    const iocCounts = stats.ioc_counts || {};
    const iocLabels = [];
    const iocData = [];
    for (const [key, value] of Object.entries(iocCounts)) {
        if (value > 0) {
            iocLabels.push(key.toUpperCase());
            iocData.push(value);
        }
    }

    const iocCtx = document.getElementById('ioc-chart');
    if (iocCtx && iocData.length > 0) {
        iocChart = new Chart(iocCtx, {
            type: 'bar',
            data: {
                labels: iocLabels,
                datasets: [{
                    label: 'IOCs Found',
                    data: iocData,
                    backgroundColor: '#58a6ff',
                    borderColor: '#21262d',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#c9d1d9',
                            font: {
                                size: 10
                            }
                        },
                        grid: {
                            color: '#30363d'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#c9d1d9',
                            font: {
                                size: 10
                            }
                        },
                        grid: {
                            color: '#30363d'
                        }
                    }
                }
            }
        });
    }
}

// Enhanced timeline filtering with date and severity
function setupTimelineFilters() {
    const textFilter = document.getElementById('timeline-filter');
    const severityFilter = document.getElementById('severity-filter');
    const dateFrom = document.getElementById('date-from');
    const dateTo = document.getElementById('date-to');
    const resetBtn = document.getElementById('reset-filters');

    function applyFilters() {
        const entries = document.querySelectorAll('.timeline-entry');
        const textQuery = textFilter.value.toLowerCase();
        const severity = severityFilter.value;
        const fromDate = dateFrom.value ? new Date(dateFrom.value) : null;
        const toDate = dateTo.value ? new Date(dateTo.value) : null;

        entries.forEach(entry => {
            const text = entry.textContent.toLowerCase();
            const timestamp = entry.querySelector('.timeline-timestamp').textContent;
            const entryDate = new Date(timestamp);

            // Text filter
            const textMatch = !textQuery || text.includes(textQuery);

            // Date filter
            let dateMatch = true;
            if (fromDate && entryDate < fromDate) dateMatch = false;
            if (toDate && entryDate > toDate) dateMatch = false;

            // Severity filter (check if entry contains severity keywords)
            let severityMatch = true;
            if (severity !== 'all') {
                const hasSeverity = text.includes(severity) ||
                                   entry.classList.contains(`severity-${severity}`);
                severityMatch = hasSeverity;
            }

            entry.style.display = (textMatch && dateMatch && severityMatch) ? 'block' : 'none';
        });
    }

    textFilter.addEventListener('input', applyFilters);
    severityFilter.addEventListener('change', applyFilters);
    dateFrom.addEventListener('change', applyFilters);
    dateTo.addEventListener('change', applyFilters);

    resetBtn.addEventListener('click', function() {
        textFilter.value = '';
        severityFilter.value = 'all';
        dateFrom.value = '';
        dateTo.value = '';
        applyFilters();
    });
}

// Enrich analysis with threat intelligence
function enrichAnalysis() {
    if (!currentAnalysisId) return;

    showLoading();
    const statusEl = document.getElementById('intelligence-status');
    statusEl.innerHTML = '<p class="text-muted">Enriching data... This may take a minute...</p>';

    fetch(`/enrich/${currentAnalysisId}`)
        .then(response => response.json())
        .then(data => {
            hideLoading();

            if (data.success) {
                displayIntelligence(data);
                statusEl.style.display = 'none';
                document.getElementById('intelligence-content').style.display = 'block';
            } else {
                statusEl.innerHTML = `<p class="text-muted" style="color: var(--accent-red);">Error: ${data.error}</p>`;
            }
        })
        .catch(error => {
            hideLoading();
            statusEl.innerHTML = `<p class="text-muted" style="color: var(--accent-red);">Enrichment failed: ${error.message}</p>`;
        });
}

// Display intelligence data
function displayIntelligence(data) {
    const { geoip, threat_intel, threat_summary } = data;

    // Threat Summary
    const threatSummaryEl = document.getElementById('threat-summary');
    if (threat_summary) {
        let html = `
            <div class="stat-item">
                <span class="stat-label">Total IPs:</span>
                <span class="stat-value">${threat_summary.total_ips}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Public IPs:</span>
                <span class="stat-value">${threat_summary.public_ips}</span>
            </div>
        `;

        for (const [level, count] of Object.entries(threat_summary.threat_levels)) {
            html += `
                <div class="stat-item">
                    <span class="stat-label">${level}:</span>
                    <span class="stat-value">${count}</span>
                </div>
            `;
        }

        threatSummaryEl.innerHTML = html;
    } else {
        threatSummaryEl.innerHTML = '<p class="text-muted">No threat intelligence data available (API key not configured)</p>';
    }

    // High Risk IPs
    const highRiskEl = document.getElementById('high-risk-ips');
    if (threat_summary && threat_summary.high_risk_ips && threat_summary.high_risk_ips.length > 0) {
        let html = '';
        threat_summary.high_risk_ips.forEach(ip => {
            html += `
                <div class="anomaly-item severity-high">
                    <div class="anomaly-header">
                        <span class="anomaly-type">${ip.ip}</span>
                        <span class="anomaly-severity high">Score: ${ip.threat_score}</span>
                    </div>
                    <div class="anomaly-description">
                        ${ip.country} | Reports: ${ip.abuse_reports}
                    </div>
                </div>
            `;
        });
        highRiskEl.innerHTML = html;
    } else {
        highRiskEl.innerHTML = '<p class="text-muted">No high-risk IPs detected</p>';
    }

    // GeoIP Data
    const geoipEl = document.getElementById('geoip-content');
    if (geoip && Object.keys(geoip).length > 0) {
        let html = '<div class="iocs-grid">';
        for (const [ip, info] of Object.entries(geoip)) {
            html += `
                <div class="ioc-card">
                    <h3>${ip}</h3>
                    <div class="stat-item">
                        <span class="stat-label">Country:</span>
                        <span class="stat-value">${info.country || 'Unknown'}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">City:</span>
                        <span class="stat-value">${info.city || 'Unknown'}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">ISP:</span>
                        <span class="stat-value">${info.isp || 'Unknown'}</span>
                    </div>
                </div>
            `;
        }
        html += '</div>';
        geoipEl.innerHTML = html;
    } else {
        geoipEl.innerHTML = '<p class="text-muted">No GeoIP data available</p>';
    }
}
