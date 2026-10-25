// Initial state settings
let activeAlerts = [...sampleAlerts];
let currentFilter = 'all';
let selectedAlert = null;
let notifications = [];

// DOM Elements
const threatBody = document.getElementById('threat-feed-body');
const activeAlertsCount = document.getElementById('active-alerts-count');
const criticalAlertBadge = document.getElementById('critical-alert-badge');
const alertDrawer = document.getElementById('alertDrawer');
const packetsSecEl = document.getElementById('packets-sec');
const flowsSecEl = document.getElementById('flows-sec');
const notifPopover = document.getElementById('notif-popover');
const notifBadge = document.getElementById('notif-badge');
const notifList = document.getElementById('notif-list');

// Metric fluctuations
setInterval(() => {
    if (packetsSecEl) {
        let currentPackets = parseInt(packetsSecEl.innerText.replace(/,/g, ''));
        let delta = Math.floor(Math.random() * 200) - 100;
        packetsSecEl.innerText = (currentPackets + delta).toLocaleString();
    }
    if (flowsSecEl) {
        let currentFlows = parseInt(flowsSecEl.innerText.replace(/,/g, ''));
        let delta = Math.floor(Math.random() * 20) - 10;
        flowsSecEl.innerText = (currentFlows + delta).toLocaleString();
    }
}, 3000);

// On startup
window.addEventListener('DOMContentLoaded', () => {
    updateAlertMetrics();
    renderThreatFeed();
    initializeChart();
    initializeFilterButtons();
    
    // Add default notifications
    addNotification('System started in preview mode.', 'info');
    addNotification('Loaded static sample dataset.', 'success');
});

// Navigation Handling
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetSection = link.getAttribute('data-target');
        
        // Update sidebar links
        document.querySelectorAll('.nav-link').forEach(l => {
            l.classList.remove('bg-secondary-container', 'text-on-secondary-container', 'border-l-4', 'border-primary');
            l.classList.add('text-on-surface-variant');
        });
        link.classList.add('bg-secondary-container', 'text-on-secondary-container', 'border-l-4', 'border-primary');
        link.classList.remove('text-on-surface-variant');
        
        // Show sections
        showSection(targetSection);
    });
});

function showSection(sectionId) {
    document.querySelectorAll('.view-section').forEach(section => {
        section.classList.add('hidden');
    });
    const target = document.getElementById(sectionId);
    if (target) {
        target.classList.remove('hidden');
    }
    
    // Bottom threat table shows on dashboard view, hide or display correctly
    const tableSection = document.getElementById('threat-table-section');
    if (tableSection) {
        if (sectionId === 'view-dashboard') {
            tableSection.classList.remove('hidden');
        } else {
            tableSection.classList.add('hidden');
        }
    }
}

// Render Threat Table Rows
function renderThreatFeed() {
    if (!threatBody) return;
    threatBody.innerHTML = '';
    
    const filtered = activeAlerts.filter(alert => {
        if (currentFilter === 'all') return true;
        if (currentFilter === 'adversarial') return alert.is_adversarial_test;
        return true;
    });
    
    if (filtered.length === 0) {
        threatBody.innerHTML = `
            <tr>
                <td class="px-lg py-md text-center text-on-surface-variant font-body-sm" colspan="8">
                    No active threat alerts matching current filters.
                </td>
            </tr>
        `;
        return;
    }
    
    filtered.forEach(alert => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-surface-container-high/50 cursor-pointer border-b border-outline-variant/30 text-body-sm transition-all';
        tr.onclick = () => openDrawer(alert);
        
        const dateObj = new Date(alert.timestamp);
        const timestampFormatted = dateObj.toLocaleTimeString('en-US', { timeZone: 'UTC' });
        const scoreClass = alert.anomaly_score >= 0.7 ? 'text-error font-bold' : 'text-on-surface-variant';
        const riskClass = alert.risk_score >= 70 ? 'bg-error-container text-on-error-container font-bold' : 'bg-surface-container-high text-on-surface';
        
        tr.innerHTML = `
            <td class="px-lg py-md font-data-mono">${timestampFormatted}</td>
            <td class="px-lg py-md font-data-mono">${alert.src_ip}</td>
            <td class="px-lg py-md font-data-mono">${alert.dst_ip}</td>
            <td class="px-lg py-md font-bold">${alert.attack_type_guess}</td>
            <td class="px-lg py-md font-data-mono ${scoreClass}">${alert.anomaly_score.toFixed(3)}</td>
            <td class="px-lg py-md">
                <span class="px-2 py-0.5 rounded-sm text-xs ${riskClass}">${alert.risk_score}</span>
            </td>
            <td class="px-lg py-md text-primary font-data-mono">${alert.mitre_technique}</td>
            <td class="px-lg py-md">
                ${alert.is_adversarial_test ? 
                    '<span class="bg-tertiary-fixed text-on-tertiary-fixed-variant px-1.5 py-0.5 rounded-sm text-[10px] font-bold">ADVERSARIAL</span>' : 
                    '<span class="bg-primary-fixed text-primary px-1.5 py-0.5 rounded-sm text-[10px] font-bold">LIVE_TRAFFIC</span>'
                }
            </td>
        `;
        threatBody.appendChild(tr);
    });
}

function updateAlertMetrics() {
    if (activeAlertsCount) {
        activeAlertsCount.innerText = activeAlerts.length;
    }
    const hasHighRisk = activeAlerts.some(a => a.risk_score >= 80);
    if (criticalAlertBadge) {
        if (hasHighRisk) {
            criticalAlertBadge.classList.remove('hidden');
        } else {
            criticalAlertBadge.classList.add('hidden');
        }
    }
}

// Drawer Controls
function openDrawer(alert) {
    selectedAlert = alert;
    
    document.getElementById('drawer-title').textContent = alert.attack_type_guess;
    document.getElementById('drawer-anomaly').textContent = Number(alert.anomaly_score).toFixed(3);
    const riskProbability = alert.risk_probability ?? alert.confidence;
    document.getElementById('drawer-confidence').textContent = `${Math.round(riskProbability * 100)}%`;
    document.getElementById('drawer-src').textContent = alert.src_ip ?? 'N/A';
    document.getElementById('drawer-dst').textContent = alert.dst_ip ?? 'N/A';
    document.getElementById('drawer-mitre').textContent = alert.mitre_technique ?? 'N/A';
    
    // 3-Pillar Fusion Data
    const pillarScores = alert.pillar_scores ?? {};
    const networkScore = alert.network_score ?? pillarScores.network;
    const identityScore = alert.identity_score ?? pillarScores.identity;
    const hostScore = alert.host_score ?? pillarScores.host;
    document.getElementById('fusion-network').textContent = formatPillarScore(networkScore);
    document.getElementById('fusion-identity').textContent = formatPillarScore(identityScore);
    document.getElementById('fusion-host').textContent = formatPillarScore(hostScore);
    document.getElementById('fusion-combined').textContent = `${Math.round(riskProbability * 100)}%`;

    // Set explanations
    const explanationTitle = document.getElementById('drawer-explanation-title');
    const explanationDesc = document.getElementById('drawer-explanation-desc');
    
    if (alert.explanation && alert.explanation.length > 0) {
        explanationTitle.textContent = alert.explanation[0].split(':')[0] || 'Trigger Signature';
        explanationDesc.textContent = alert.explanation[0].split(':').slice(1).join(':') || alert.explanation[0];
    } else {
        explanationTitle.textContent = 'Classifier Trigger';
        explanationDesc.textContent = 'Threat score exceeded default confidence margin thresholds.';
    }

    renderHostMappings(alert);
    renderHostShapFeatures(alert.host_shap_features);
    
    if (alertDrawer) {
        alertDrawer.classList.remove('translate-x-full');
    }
}

function formatPillarScore(score) {
    if (score === undefined || score === null || score === '') return 'N/A';
    const value = Number(score);
    return Number.isFinite(value) ? value.toFixed(3) : 'N/A';
}

function renderHostMappings(alert) {
    const container = document.getElementById('drawer-host-mappings');
    container.replaceChildren();
    const mappings = Array.isArray(alert.host_attack_mappings) ? alert.host_attack_mappings : [];

    if (mappings.length === 0) {
        const empty = document.createElement('p');
        empty.textContent = alert.host_mapping_status
            ? `No technique candidates (${alert.host_mapping_status}).`
            : 'No host mapping supplied.';
        container.appendChild(empty);
    }

    for (const mapping of mappings) {
        const card = document.createElement('article');
        card.className = 'bg-surface-container-highest/30 p-md border border-outline-variant space-y-xs';

        const heading = document.createElement('p');
        heading.className = 'font-bold text-on-surface';
        heading.textContent = `${mapping.technique_id ?? 'ATT&CK'} — ${mapping.mitre_technique ?? mapping.attack_type ?? 'Candidate'}`;
        card.appendChild(heading);

        if (mapping.mitre_tactic || mapping.severity) {
            const details = document.createElement('p');
            details.textContent = [mapping.mitre_tactic, mapping.severity].filter(Boolean).join(' · ');
            card.appendChild(details);
        }

        const evidence = Array.isArray(mapping.evidence) ? mapping.evidence : [];
        for (const item of evidence) {
            const line = document.createElement('p');
            line.textContent = `Evidence: ${item}`;
            card.appendChild(line);
        }

        const completeness = document.createElement('p');
        completeness.textContent = mapping.evidence_complete
            ? 'Required evidence complete'
            : 'Candidate evidence is incomplete';
        card.appendChild(completeness);
        container.appendChild(card);
    }

    const rationale = Array.isArray(alert.host_explanation) ? alert.host_explanation : [];
    for (const item of rationale) {
        const line = document.createElement('p');
        line.textContent = item;
        container.appendChild(line);
    }
}

function renderHostShapFeatures(features) {
    const container = document.getElementById('drawer-host-shap');
    container.replaceChildren();
    const items = Array.isArray(features) ? features : [];

    if (items.length === 0) {
        const empty = document.createElement('li');
        empty.textContent = 'No host feature explanation supplied.';
        container.appendChild(empty);
        return;
    }

    for (const item of items) {
        const line = document.createElement('li');
        const contribution = Number(item.shap_value);
        const formatted = Number.isFinite(contribution) ? contribution.toFixed(5) : 'N/A';
        line.textContent = `${item.feature ?? 'Feature'}: ${formatted} (${item.direction ?? 'direction unavailable'})`;
        container.appendChild(line);
    }
}

function closeDrawer() {
    if (alertDrawer) {
        alertDrawer.classList.add('translate-x-full');
    }
    selectedAlert = null;
}

// Filters Implementation
function initializeFilterButtons() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.remove('bg-primary', 'text-background');
            });
            btn.classList.add('bg-primary', 'text-background');
            currentFilter = btn.getAttribute('data-filter');
            renderThreatFeed();
        });
    });
}

// Search Logic
function handleSearch() {
    const query = document.getElementById('global-search').value.toLowerCase().trim();
    if (query === '') {
        activeAlerts = [...sampleAlerts];
    } else {
        activeAlerts = sampleAlerts.filter(a => 
            a.src_ip.includes(query) || 
            a.dst_ip.includes(query) || 
            a.attack_type_guess.toLowerCase().includes(query) || 
            a.mitre_technique.toLowerCase().includes(query)
        );
    }
    renderThreatFeed();
    updateAlertMetrics();
}

// Trigger Simulated Scan
function triggerScan() {
    const modal = document.getElementById('scan-modal');
    const bar = document.getElementById('scan-progress-bar');
    const label = document.getElementById('scan-step');
    
    if (!modal || !bar || !label) return;
    
    modal.classList.remove('hidden');
    bar.style.width = '0%';
    
    const steps = [
        { progress: 20, text: 'Mapping ingress packet signatures...' },
        { progress: 50, text: 'Querying GNN temporal tree edges...' },
        { progress: 85, text: 'Running drift classification matrix...' },
        { progress: 100, text: 'Scan complete!' }
    ];
    
    let currentStep = 0;
    const interval = setInterval(() => {
        if (currentStep < steps.length) {
            bar.style.width = `${steps[currentStep].progress}%`;
            label.innerText = steps[currentStep].text;
            currentStep++;
        } else {
            clearInterval(interval);
            setTimeout(() => {
                modal.classList.add('hidden');
                triggerNotification('Threat vigilance scan completed. No new anomalies found.', 'success');
            }, 600);
        }
    }, 700);
}

// Notifications popover
function toggleNotifications() {
    if (notifPopover) {
        notifPopover.classList.toggle('hidden');
    }
}

function addNotification(msg, type = 'info') {
    notifications.unshift({ msg, type, time: new Date() });
    updateNotificationsUI();
}

function clearNotifs() {
    notifications = [];
    updateNotificationsUI();
}

function updateNotificationsUI() {
    if (!notifList || !notifBadge) return;
    
    notifList.innerHTML = '';
    
    if (notifications.length === 0) {
        notifList.innerHTML = '<span class="text-xs text-on-surface-variant/70 italic block py-md text-center">No new updates.</span>';
        notifBadge.classList.add('hidden');
        return;
    }
    
    notifBadge.classList.remove('hidden');
    
    notifications.forEach(n => {
        const item = document.createElement('div');
        item.className = 'p-sm border-b border-outline-variant/20 flex flex-col gap-xs';
        
        let colorClass = 'text-primary';
        if (n.type === 'success') colorClass = 'text-green-600';
        if (n.type === 'error') colorClass = 'text-error';
        
        item.innerHTML = `
            <span class="text-xs text-on-surface leading-tight">${n.msg}</span>
            <span class="text-[9px] text-on-surface-variant font-data-mono">${n.time.toLocaleTimeString()}</span>
        `;
        notifList.appendChild(item);
    });
}

// Modals Handling
function toggleSignOutModal(show) {
    const modal = document.getElementById('signout-modal');
    if (modal) {
        if (show) modal.classList.remove('hidden');
        else modal.classList.add('hidden');
    }
}

function performSignOut() {
    toggleSignOutModal(false);
    triggerNotification('Preview session terminated.', 'info');
}

function toggleSupportModal(show) {
    const modal = document.getElementById('support-modal');
    if (modal) {
        if (show) modal.classList.remove('hidden');
        else modal.classList.add('hidden');
    }
}

function submitSupportTicket() {
    const topic = document.getElementById('support-topic').value;
    const desc = document.getElementById('support-desc').value;
    
    if (!desc.trim()) {
        alert('Please specify issue details.');
        return;
    }
    
    toggleSupportModal(false);
    document.getElementById('support-desc').value = '';
    triggerNotification(`Support ticket submitted on: ${topic}`, 'success');
}

// Drawer Actions
function isolateSelectedHost() {
    if (!selectedAlert) return;
    const host = selectedAlert.src_ip;
    closeDrawer();
    triggerNotification(`Host isolation sequence triggered for: ${host}`, 'error');
    addNotification(`ISOLATED IP: ${host}`, 'error');
}

function assignCase() {
    if (!selectedAlert) return;
    closeDrawer();
    triggerNotification(`Alert ${selectedAlert.alert_id.substring(0,8)} assigned to current case file.`, 'success');
}

// Toast System
function triggerNotification(msg, type = 'success') {
    const toast = document.getElementById('toast-alert');
    const toastMsg = document.getElementById('toast-msg');
    const toastIcon = document.getElementById('toast-icon');
    
    if (!toast || !toastMsg || !toastIcon) return;
    
    toastMsg.innerText = msg;
    
    if (type === 'error') {
        toastIcon.innerText = 'error';
        toastIcon.className = 'material-symbols-outlined text-error';
    } else if (type === 'info') {
        toastIcon.innerText = 'info';
        toastIcon.className = 'material-symbols-outlined text-primary';
    } else {
        toastIcon.innerText = 'check_circle';
        toastIcon.className = 'material-symbols-outlined text-green-600';
    }
    
    toast.classList.remove('hidden');
    setTimeout(() => {
        toast.classList.add('hidden');
    }, 4000);
}

// Chart.js Configuration
let threatTimelineChart = null;

function initializeChart() {
    const ctx = document.getElementById('anomalyChart');
    if (!ctx) return;
    
    // Sort sample alerts chronologically
    const sorted = [...sampleAlerts].sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
    const labels = sorted.map(a => new Date(a.timestamp).toLocaleTimeString());
    const dataPoints = sorted.map(a => a.anomaly_score);
    const backgroundColors = sorted.map(a => a.anomaly_score >= 0.70 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(2, 132, 199, 0.8)');
    
    threatTimelineChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Anomaly Score',
                data: dataPoints,
                backgroundColor: backgroundColors,
                borderColor: 'rgba(15, 23, 42, 0.08)',
                borderWidth: 1,
                barThickness: 32
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        afterBody: function(items) {
                            const index = items[0].dataIndex;
                            const alertItem = sorted[index];
                            return [
                                `Classification: ${alertItem.attack_type_guess}`,
                                `Confidence: ${Math.round(alertItem.confidence * 100)}%`,
                                `Risk Level: ${alertItem.risk_score}`
                            ];
                        }
                    }
                }
            },
            scales: {
                y: {
                    min: 0.0,
                    max: 1.0,
                    grid: {
                        color: 'rgba(15, 23, 42, 0.05)'
                    },
                    ticks: {
                        color: '#475569',
                        font: {
                            family: 'JetBrains Mono',
                            size: 11
                        }
                    }
                },
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#475569',
                        font: {
                            family: 'JetBrains Mono',
                            size: 10
                        }
                    }
                }
            }
        }
    });
}

function deployHarnessSimulation(techniqueName) {
    const displayName = techniqueName.replace(/_/g, ' ').toUpperCase();
    triggerNotification(`Simulating adversarial run for ${displayName}...`, 'info');
    
    // Simulate loading the evaluation series data dynamically
    setTimeout(() => {
        // Formulate intermediate steps anomaly scores based on real harness evaluations
        let anomalyScores = [];
        let labels = [];
        let count = 0;
        
        if (techniqueName === 'mimicry_attack' || techniqueName === 'feature_padding_attack') {
            count = 21;
            // High initial score declining toward benign target
            for (let i = 0; i < count; i++) {
                let score = 0.85 - (i * 0.032);
                anomalyScores.push(score);
                labels.push(`Step ${i}`);
            }
        } else {
            count = 10;
            // Low distributed drip scores below detection threshold
            for (let i = 0; i < count; i++) {
                anomalyScores.push(0.167);
                labels.push(`Split ${i}`);
            }
        }
        
        // Update Chart data series
        if (threatTimelineChart) {
            threatTimelineChart.data.labels = labels;
            threatTimelineChart.data.datasets[0].data = anomalyScores;
            threatTimelineChart.data.datasets[0].backgroundColor = anomalyScores.map(val => val >= 0.50 ? 'rgba(239, 68, 68, 0.8)' : 'rgba(2, 132, 199, 0.8)');
            threatTimelineChart.update();
        }
        
        // Append a simulated adversarial alert to the active alert feed logs
        const mockAdversarialAlert = {
            "alert_id": "9fa" + Math.random().toString(36).substring(2, 11),
            "timestamp": new Date().toISOString(),
            "src_ip": "192.168.1.105",
            "dst_ip": "10.0.0.42",
            "anomaly_score": anomalyScores[0],
            "confidence": 1.0 - anomalyScores[0],
            "risk_score": Math.round(anomalyScores[0] * 100),
            "attack_type_guess": displayName,
            "mitre_technique": techniqueName === 'slow_drip_attack' ? 'T1046' : 'T1059.001',
            "explanation": [
                `Evasion verification: Score calculated dynamically using evaluation steps against Autoencoder baseline.`
            ],
            "model_source": "autoencoder-v2-256",
            "is_adversarial_test": true
        };
        
        activeAlerts.unshift(mockAdversarialAlert);
        updateAlertMetrics();
        renderThreatFeed();
        
        // Navigate user back to the live dashboard view to show the threat timeline update
        showSection('view-dashboard');
        
        triggerNotification(`${displayName} simulation complete! Results loaded into Live Timeline chart.`, 'success');
    }, 1200);
}
