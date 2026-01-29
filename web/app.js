// API base URL - relative path via HAProxy
const API_BASE = '/api';
const AUTH_BASE = '';
let authToken = localStorage.getItem('token') || '';

// Helper function to convert UTC time to Turkey time (UTC+3) and format message
function formatRetryAfterMessage(retryAfter) {
    if (!retryAfter) {
        return 'Lütfen 1 saat sonra tekrar deneyin.';
    }

    try {
        // Parse UTC time from retryAfter string
        // Format: "2025-11-06 14:44:05 UTC" or "2025-11-06 14:44:05 UTC: see ..."
        const utcMatch = retryAfter.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
        if (utcMatch) {
            const utcString = utcMatch[1] + ' UTC';
            const utcDate = new Date(utcString);

            // Convert to Turkey time (UTC+3)
            const turkeyDate = new Date(utcDate.getTime() + (3 * 60 * 60 * 1000));

            // Format dates
            const utcFormatted = utcDate.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
            const turkeyFormatted = turkeyDate.toISOString().replace('T', ' ').substring(0, 19) + ' TR';

            return `Tekrar deneme: ${utcFormatted} / ${turkeyFormatted}`;
        }

        // If parsing fails, return original
        return `Tekrar deneme: ${retryAfter}`;
    } catch (error) {
        // If any error, return original
        return `Tekrar deneme: ${retryAfter}`;
    }
}

function setAuthUI() {
    const loggedIn = !!authToken;
    document.getElementById('auth-status').textContent = loggedIn ? 'Oturum: Açık' : 'Oturum: Kapalı';
    document.getElementById('loginBtn').classList.toggle('d-none', loggedIn);
    document.getElementById('logoutBtn').classList.toggle('d-none', !loggedIn);
    const selfPasswordBtn = document.getElementById('changeSelfPasswordBtn');
    if (selfPasswordBtn) {
        selfPasswordBtn.classList.toggle('d-none', !loggedIn);
    }
}

function showLoginModal() { window.location.href = 'login.html'; }

async function login() { window.location.href = 'login.html'; }

function logout() {
    authToken = '';
    localStorage.removeItem('token');
    setAuthUI();
    window.location.href = 'login.html';
}

// Show section
function showSection(section) {
    if (!authToken && section !== 'login') {
        showLoginModal();
        return;
    }
    document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));

    const sectionEl = document.getElementById(`${section}-section`);
    if (sectionEl) sectionEl.style.display = 'block';

    // Highlight sidebar
    const link = document.querySelector(`a[onclick="showSection('${section}')"]`);
    if (link) link.classList.add('active');

    if (section === 'stats') {
        initCharts();
        loadStats();
        startStatsInterval();
    } else {
        stopStatsInterval();
    }

    if (section === 'ingress') {
        loadIngressRules();
    } else if (section === 'portforward') {
        loadPortForwardRules();
    } else if (section === 'ssl') {
        loadSSLCertificates();
    } else if (section === 'users') {
        loadMembers();
    } else if (section === 'security') {
        loadBans();
        loadWhitelist();
        loadWafRules();
    }
}

// --- Stats & Dashboard ---
let statsInterval = null;
let trafficChart = null;
let protocolChart = null;
let chartData = {
    labels: [],
    reqRate: [],
    connRate: []
};

function initCharts() {
    if (trafficChart || protocolChart) return;

    // Traffic Chart (Line)
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'İstek/sn',
                data: [],
                borderColor: '#10b981', // Emerald 500
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4,
                fill: true
            }, {
                label: 'Bağlantı/sn',
                data: [],
                borderColor: '#3b82f6', // Blue 500
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#94a3b8' } }
            },
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' }, beginAtZero: true }
            },
            animation: { duration: 0 }
        }
    });

    // Protocol Chart (Doughnut)
    const ctxProtocol = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: ['HTTP', 'HTTPS (SSL)', 'TCP'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#f59e0b', '#10b981', '#6366f1'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#94a3b8' }, position: 'bottom' }
            }
        }
    });
}

function startStatsInterval() {
    if (statsInterval) clearInterval(statsInterval);
    statsInterval = setInterval(loadStats, 2000);
}

function stopStatsInterval() {
    if (statsInterval) {
        clearInterval(statsInterval);
        statsInterval = null;
    }
}

async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/ha_stats`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        if (!response.ok) return;
        const csvText = await response.text();
        const stats = parseStatsCSV(csvText);
        updateDashboard(stats);
    } catch (e) {
        console.error("Stats load failed", e);
    }
}

function parseStatsCSV(csv) {
    const lines = csv.trim().split('\n');
    // Remove '# ' from header if present
    if (lines[0].startsWith('# ')) lines[0] = lines[0].substring(2);

    const headers = lines[0].split(',');
    const data = [];

    for (let i = 1; i < lines.length; i++) {
        const row = lines[i].split(',');
        const obj = {};
        headers.forEach((h, idx) => obj[h] = row[idx]);
        data.push(obj);
    }
    return data;
}

function updateDashboard(statsData) {
    // Calculate global stats (sum of all frontends/backends)
    let activeConns = 0;
    let reqRate = 0;
    let connRate = 0;
    let errors = 0;
    let trafficIn = 0;
    let trafficOut = 0;

    // Filter relevant rows (Frontend/Backend totals)
    statsData.forEach(s => {
        if (s.svname === 'FRONTEND' || s.svname === 'BACKEND') {
            // scur: active sessions, rate: sessions/sec, req_rate: requests/sec, ereq: request errors
            activeConns += parseInt(s.scur || 0);
            reqRate += parseInt(s.req_rate || 0);
            connRate += parseInt(s.rate || 0);
            errors += parseInt(s.ereq || 0) + parseInt(s.econ || 0);
            // bin: bytes in, bout: bytes out
            trafficIn += parseInt(s.bin || 0);
            trafficOut += parseInt(s.bout || 0);
        }
    });

    // Protocol breakdown (mock approximation based on frontend names: http_frontend vs https_frontend)
    // Real HAProxy stats distinguish by proxy name (pxname).
    let httpCount = 0;
    let httpsCount = 0;
    statsData.forEach(s => {
        if (s.svname === 'FRONTEND') {
            if (s.pxname.includes('http') && !s.pxname.includes('https')) httpCount += parseInt(s.req_tot || 0);
            if (s.pxname.includes('https')) httpsCount += parseInt(s.req_tot || 0);
        }
    });

    // Update DOM
    document.getElementById('stat-active-conns').textContent = activeConns;
    document.getElementById('stat-req-rate').textContent = reqRate + " /s";
    document.getElementById('stat-errors').textContent = errors;

    // Uptime is usually in first row system stats, but CSV might not have it.
    // We'll mock uptime or calculate if pid/start time available.
    // For now simple placeholder update:
    document.getElementById('stat-uptime').textContent = formatUptime(parseInt(statsData[0]?.Uptime_sec || 0)); // Not in CSV std, but let's see. 
    // Actually HAProxy stats CSV doesn't have Uptime. We'd need 'show info'.
    // Let's use 'pid' existence as "Online".
    document.getElementById('stat-uptime').textContent = "Online";

    document.getElementById('last-updated').textContent = "Son Güncelleme: " + new Date().toLocaleTimeString();

    // Update Charts
    const now = new Date().toLocaleTimeString();

    if (chartData.labels.length > 50) {
        chartData.labels.shift();
        chartData.reqRate.shift();
        chartData.connRate.shift();
    }
    chartData.labels.push(now);
    chartData.reqRate.push(reqRate);
    chartData.connRate.push(connRate);

    if (trafficChart) {
        trafficChart.data.labels = chartData.labels;
        trafficChart.data.datasets[0].data = chartData.reqRate;
        trafficChart.data.datasets[1].data = chartData.connRate;
        trafficChart.update();
    }

    if (protocolChart) {
        // Just usingreq_tot ratio for demo
        // protocolChart.data.datasets[0].data = [httpCount, httpsCount, 0];
        // protocolChart.update();
    }
}

function formatUptime(seconds) {
    // Placeholder
    return "Running";
}

// --- Security (Guard) ---
async function loadBans() {
    const tbody = document.getElementById('ban-list-body');
    tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4">Veri yükleniyor...</td></tr>';

    try {
        const response = await fetch(`${API_BASE}/security/bans`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        if (!response.ok) throw new Error('Yüklenemedi');

        const data = await response.json();
        const bans = data.bans || [];

        if (bans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted"><i class="bi bi-shield-check fs-2 d-block mb-2"></i>Aktif yasaklama bulunmuyor.</td></tr>';
            return;
        }

        tbody.innerHTML = "";
        bans.forEach((ban, index) => {
            const row = `
                <tr>
                    <td class="ps-4 fw-bold text-muted">#${index + 1}</td>
                    <td>
                        <span class="font-monospace bg-dark bg-opacity-50 px-2 py-1 rounded text-warning">${ban.ip}</span>
                    </td>
                    <td class="text-muted small">
                        ${ban.date || '-'}
                    </td>
                    <td>
                        <span class="badge bg-danger bg-opacity-10 text-danger border border-danger border-opacity-25" title="${ban.reason || 'Bilinmiyor'}">${ban.reason || 'Şüpheli aktivite'}</span>
                    </td>
                    <td class="text-end pe-4">
                        <button class="btn btn-sm btn-outline-success" onclick="unbanIp('${ban.ip}')">
                            <i class="bi bi-unlock"></i> Kaldır
                        </button>
                    </td>
                </tr>
            `;
            tbody.innerHTML += row;
        });

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Hata: ${e.message}</td></tr>`;
    }
}

async function unbanIp(ip) {
    if (!confirm(`${ip} adresinin banını kaldırmak istediğinize emin misiniz?`)) return;

    try {
        const response = await fetch(`${API_BASE}/security/unban`, {
            method: 'POST',
            body: JSON.stringify({ ip }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            alert("Ban kaldırıldı.");
            loadBans();
        } else {
            alert("İşlem başarısız.");
        }
    } catch (e) {
        alert("Hata: " + e.message);
    }
}

function refreshBans() {
    loadBans();
}

function showManualBanModal() {
    const ip = prompt("Banlanacak IP Adresini Girin:");
    if (ip) {
        // TODO: Backend'e manuel ban ekleme de eklemek lazım.
        // Şimdilik sadece unban yapabiliyoruz API üzerinden.
        // Guard API POST /ban eklenebilir. 
        alert("Manuel ban (Web UI) henüz aktif değil. Lütfen Konsol kullanın.");
    }
}

// --- Whitelist Management ---
async function loadWhitelist() {
    const container = document.getElementById('whitelist-body');
    if (!container) return;

    container.innerHTML = '<li class="list-group-item bg-transparent text-center text-muted py-3">Yükleniyor...</li>';

    try {
        const response = await fetch(`${API_BASE}/security/whitelist`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        if (!response.ok) throw new Error('Yüklenemedi');

        const data = await response.json();
        const whitelist = data.whitelist || [];

        if (whitelist.length === 0) {
            container.innerHTML = '<li class="list-group-item bg-transparent text-center text-muted py-3"><i class="bi bi-list me-2"></i>Henüz IP eklenmemiş.</li>';
            return;
        }

        container.innerHTML = whitelist.map(ip => `
            <li class="list-group-item bg-transparent d-flex justify-content-between align-items-center">
                <span class="font-monospace text-success"><i class="bi bi-check-circle me-2"></i>${ip}</span>
                <button class="btn btn-sm btn-outline-danger" onclick="removeFromWhitelist('${ip}')" title="Kaldır">
                    <i class="bi bi-x-lg"></i>
                </button>
            </li>
        `).join('');

    } catch (e) {
        container.innerHTML = `<li class="list-group-item bg-transparent text-center text-danger py-3">Hata: ${e.message}</li>`;
    }
}

function showAddWhitelistModal() {
    document.getElementById('whitelist-ip-input').value = '';
    new window.bootstrap.Modal(document.getElementById('addWhitelistModal')).show();
}

async function confirmAddWhitelist() {
    const ip = document.getElementById('whitelist-ip-input').value.trim();
    if (!ip) {
        alert('Lütfen bir IP adresi girin.');
        return;
    }

    // Basic IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        alert('Geçersiz IP adresi formatı. Örnek: 1.2.3.4');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/security/whitelist`, {
            method: 'POST',
            body: JSON.stringify({ ip }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            // Close modal
            window.bootstrap.Modal.getInstance(document.getElementById('addWhitelistModal')).hide();
            showAlert('IP adresi whitelist\'e eklendi: ' + ip, 'success');
            loadWhitelist();
        } else {
            const err = await response.json();
            alert('Hata: ' + (err.error || 'Bilinmeyen hata'));
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function removeFromWhitelist(ip) {
    if (!confirm(`${ip} adresini whitelist'ten kaldırmak istediğinize emin misiniz?`)) return;

    try {
        const response = await fetch(`${API_BASE}/security/unwhitelist`, {
            method: 'POST',
            body: JSON.stringify({ ip }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            showAlert('IP adresi whitelist\'ten kaldırıldı: ' + ip, 'warning');
            loadWhitelist();
        } else {
            alert('İşlem başarısız.');
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

// --- WAF Rules Management ---
async function loadWafRules() {
    const tbody = document.getElementById('waf-rules-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4">Yükleniyor...</td></tr>';

    try {
        const response = await fetch(`${API_BASE}/waf/rules`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `HTTP ${response.status}`);
        }

        const data = await response.json();
        const rules = data.rules || [];

        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted"><i class="bi bi-file-earmark-x fs-2 d-block mb-2"></i>Henüz kural dosyası yok.</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => {
            const modified = new Date(rule.modified).toLocaleString('tr-TR');
            const sizeKb = (rule.size / 1024).toFixed(1);
            return `
                <tr>
                    <td class="ps-4">
                        <span class="font-monospace text-warning"><i class="bi bi-file-earmark-code me-2"></i>${rule.name}</span>
                    </td>
                    <td>
                        <span class="badge bg-info bg-opacity-10 text-info">${rule.ruleCount} kural</span>
                    </td>
                    <td class="text-muted small">${sizeKb} KB</td>
                    <td class="text-muted small">${modified}</td>
                    <td class="text-end pe-4">
                        <button class="btn btn-sm btn-outline-warning" onclick="editWafRule('${rule.name}')">
                            <i class="bi bi-pencil"></i> Düzenle
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">Hata: ${e.message}</td></tr>`;
    }
}

function showAddWafRuleModal() {
    document.getElementById('new-waf-filename').value = '';
    new window.bootstrap.Modal(document.getElementById('addWafRuleModal')).show();
}

async function createWafRule() {
    let filename = document.getElementById('new-waf-filename').value.trim();
    if (!filename) {
        alert('Lütfen bir dosya adı girin.');
        return;
    }

    // Add .conf if not present
    if (!filename.endsWith('.conf')) {
        filename += '.conf';
    }

    try {
        const response = await fetch(`${API_BASE}/waf/rules`, {
            method: 'POST',
            body: JSON.stringify({ filename, content: '# Custom WAF Rules\n# SecRule ... \n' }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            window.bootstrap.Modal.getInstance(document.getElementById('addWafRuleModal')).hide();
            showAlert('Kural dosyası oluşturuldu: ' + filename, 'success');
            loadWafRules();
            // Open editor
            setTimeout(() => editWafRule(filename), 500);
        } else {
            const err = await response.json();
            alert('Hata: ' + (err.error || 'Bilinmeyen hata'));
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function editWafRule(filename) {
    try {
        const response = await fetch(`${API_BASE}/waf/rules/${encodeURIComponent(filename)}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (!response.ok) throw new Error('Dosya yüklenemedi');

        const data = await response.json();

        document.getElementById('waf-editor-filename').value = data.filename;
        document.getElementById('waf-editor-content').value = data.content;

        new window.bootstrap.Modal(document.getElementById('wafRuleEditorModal')).show();

    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function saveWafRule() {
    const filename = document.getElementById('waf-editor-filename').value;
    const content = document.getElementById('waf-editor-content').value;

    try {
        const response = await fetch(`${API_BASE}/waf/rules/${encodeURIComponent(filename)}`, {
            method: 'PUT',
            body: JSON.stringify({ content }),
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (response.ok) {
            window.bootstrap.Modal.getInstance(document.getElementById('wafRuleEditorModal')).hide();
            showAlert('Kural dosyası kaydedildi: ' + filename, 'success');
            loadWafRules();
        } else {
            const err = await response.json();
            alert('Hata: ' + (err.error || 'Bilinmeyen hata'));
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function deleteWafRule() {
    const filename = document.getElementById('waf-editor-filename').value;

    if (!confirm(`"${filename}" dosyasını silmek istediğinize emin misiniz?\n\nBu işlem geri alınamaz!`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/waf/rules/${encodeURIComponent(filename)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (response.ok) {
            window.bootstrap.Modal.getInstance(document.getElementById('wafRuleEditorModal')).hide();
            showAlert('Kural dosyası silindi: ' + filename, 'warning');
            loadWafRules();
        } else {
            const err = await response.json();
            alert('Hata: ' + (err.error || 'Bilinmeyen hata'));
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function reloadWaf() {
    if (!confirm('SPOA (ModSecurity) servisini yeniden başlatmak istediğinize emin misiniz?\n\nBu işlem sırasında WAF koruması geçici olarak devre dışı kalabilir.')) {
        return;
    }

    try {
        showAlert('SPOA yeniden başlatılıyor...', 'info');

        const response = await fetch(`${API_BASE}/waf/reload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (response.ok) {
            showAlert('SPOA başarıyla yeniden başlatıldı!', 'success');
        } else {
            const err = await response.json();
            alert('Hata: ' + (err.error || 'Bilinmeyen hata'));
        }
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

// Global cache for rules to resolve backend names
let cachedRules = [];

// Load Ingress Rules
async function loadIngressRules() {
    try {
        const response = await fetch(`${API_BASE}/rules`, { headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {} });
        const rules = await response.json();
        cachedRules = rules; // Update global cache


        const tbody = document.getElementById('ingress-table-body');
        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">Henüz kural eklenmemiş</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => {
            const sslBadge = rule.ssl_enabled
                ? `<span class="badge bg-success">${rule.ssl_type === 'wildcard' ? 'Wildcard SSL' : 'SSL'}</span>`
                : '<span class="badge bg-secondary">HTTP</span>';
            const redirectBadge = rule.redirect_to_https ? '<span class="badge bg-warning text-dark ms-1">HTTP→HTTPS</span>' : '';
            const lbLabel = (rule.lb_mode || 'roundrobin') === 'failover' ? 'Failover' : 'Round Robin';
            const backendList = Array.isArray(rule.backends) && rule.backends.length
                ? rule.backends
                : (rule.backend_host && rule.backend_port ? [{ host: rule.backend_host, port: rule.backend_port }] : []);
            const backendSummary = backendList.length
                ? backendList.map((backend, index) => `${backend.host}:${backend.port}${(rule.lb_mode === 'failover' && index > 0) ? ' (yedek)' : ''}`).join(', ')
                : '-';

            // Traffic data placeholder (will be populated by updateTrafficStats)
            // Using data-backend to match HAProxy backend name: backend_{id}
            const trafficHtml = `<span id="traffic-stats-${rule.id}" data-backend="backend_${rule.id}" class="small text-muted">Veri bekleniyor...</span>`;

            return `
            <tr>
                <td>${rule.id}</td>
                <td>${rule.name}</td>
                <td>${rule.domain || '-'}</td>
                <td>${rule.path || '/'}</td>
                <td>
                    <div>${backendSummary}</div>
                    <small class="text-muted">${lbLabel}</small>
                </td>
                <td>${sslBadge}${redirectBadge}</td>
                <td>${trafficHtml}</td>
                <td>${rule.active ? '<span class="badge bg-success">Aktif</span>' : '<span class="badge bg-danger">Pasif</span>'}</td>
                <td>
                    ${rule.ssl_enabled ?
                    `<button class="btn btn-sm btn-warning" onclick="changeSSL('${rule.domain}', ${rule.id})" title="SSL Sertifikasını Değiştir">
                            <i class="bi bi-arrow-repeat"></i>
                        </button>` :
                    `<button class="btn btn-sm btn-info" onclick="requestSSL('${rule.domain}', ${rule.id})" title="SSL Sertifikası İste">
                            <i class="bi bi-shield-lock"></i>
                        </button>`
                }
                    <button class="btn btn-sm btn-warning" onclick="editIngressRule(${rule.id})">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteIngressRule(${rule.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `;
        }).join('');

        // Start live traffic updates if not already started
        startTrafficUpdates();

    } catch (error) {
        console.error('Error loading ingress rules:', error);
        document.getElementById('ingress-table-body').innerHTML =
            '<tr><td colspan="8" class="text-center text-danger">Hata: ' + error.message + '</td></tr>';
    }
}

// Load Port Forward Rules
async function loadPortForwardRules() {
    try {
        const response = await fetch(`${API_BASE}/port-forwarding`, { headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {} });
        const rules = await response.json();

        const tbody = document.getElementById('portforward-table-body');
        if (rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Henüz kural eklenmemiş</td></tr>';
            return;
        }

        tbody.innerHTML = rules.map(rule => `
            <tr>
                <td>${rule.id}</td>
                <td>${rule.name}</td>
                <td>${rule.frontend_port}</td>
                <td>${rule.backend_host}:${rule.backend_port}</td>
                <td>${rule.protocol.toUpperCase()}</td>
                <td>${rule.active ? '<span class="badge bg-success">Aktif</span>' : '<span class="badge bg-danger">Pasif</span>'}</td>
                <td>
                    <button class="btn btn-sm btn-warning" onclick="editPortForwardRule(${rule.id})">
                        <i class="bi bi-pencil"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deletePortForwardRule(${rule.id})">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading port forward rules:', error);
        document.getElementById('portforward-table-body').innerHTML =
            '<tr><td colspan="7" class="text-center text-danger">Hata: ' + error.message + '</td></tr>';
    }
}

function formatDateTime(value, includeTime = false) {
    if (!value) return 'Bilinmiyor';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Bilinmiyor';
    return includeTime
        ? date.toLocaleString('tr-TR')
        : date.toLocaleDateString('tr-TR');
}

async function loadSSLCertificates() {
    try {
        const response = await fetch(`${API_BASE}/ssl/certificates`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const certs = await response.json();

        const tbody = document.getElementById('ssl-table-body');
        if (!certs || certs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">Henüz sertifika yok</td></tr>';
            return;
        }

        // Update header if not already updated
        const thead = document.querySelector('#ssl-table thead tr');
        if (thead && !thead.innerHTML.includes('Otomatik Yenileme')) {
            thead.innerHTML = `
                <th>Domain</th>
                <th>Tip</th>
                <th>Takip (DNS)</th>
                <th>Bitiş Tarihi</th>
                <th>Oto. Yenileme</th>
                <th>İşlemler</th>
             `;
        }

        tbody.innerHTML = certs.map(cert => {
            const displayDomain = cert.cert_domain || cert.domain;
            const sslTypeLabel = cert.ssl_type === 'wildcard' ? 'Wildcard' : (cert.ssl_type === 'normal' ? 'Normal' : (cert.ssl_type || '-'));
            const expiresValue = cert.expires_at || cert.filesystem?.expires || null;
            const updatedValue = cert.updated_at || cert.filesystem?.modified || null;
            const dnsProvider = cert.provider || cert.dns_provider || 'manual';

            // Auto Renew Switch
            const canAutoRenew = dnsProvider !== 'manual';
            const autoRenewChecked = cert.auto_renew !== false;
            const autoRenewDisabled = !canAutoRenew ? 'disabled' : '';
            const autoRenewTitle = !canAutoRenew ? 'Bu sağlayıcı için otomatik yenileme desteklenmiyor' : 'Otomatik yenilemeyi aç/kapat';

            return `
                <tr>
                    <td>${displayDomain} ${cert.ssl_type === 'wildcard' ? '<span class="badge bg-info ms-1">Wildcard</span>' : ''}</td>
                    <td>${sslTypeLabel}</td>
                    <td>${dnsProvider}</td>
                    <td>${formatDateTime(expiresValue)}</td>
                    <td>
                        <div class="form-check form-switch" title="${autoRenewTitle}">
                            <input class="form-check-input" type="checkbox" 
                                id="ar-${displayDomain}" 
                                ${autoRenewChecked ? 'checked' : ''} 
                                ${autoRenewDisabled}
                                onchange="toggleAutoRenew('${displayDomain}', this.checked)">
                             ${!canAutoRenew ? '<i class="bi bi-exclamation-circle text-warning ms-1" title="Manuel DNS işlemi gerektirir"></i>' : ''}
                        </div>
                    </td>
                    <td>
                        <button class="btn btn-sm btn-info me-1" onclick="viewCertificate('${displayDomain}')" title="Detayları Gör">
                            <i class="bi bi-eye"></i>
                        </button>
                         <button class="btn btn-sm btn-warning me-1" onclick="manualRenew('${displayDomain}')" title="Şimdi Yenile">
                            <i class="bi bi-arrow-repeat"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteCertificate('${displayDomain}')" title="Sertifikayı Sil">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading SSL certificates:', error);
        document.getElementById('ssl-table-body').innerHTML =
            '<tr><td colspan="6" class="text-center text-danger">Hata: ' + error.message + '</td></tr>';
    }
}

// Show Add Ingress Modal
function showAddIngressModal() {
    const form = document.getElementById('addIngressForm');
    form.reset();
    document.querySelector('#addIngressForm [name="id"]').value = '';
    document.querySelector('input[name="ssl_type"][value="none"]').checked = true;
    toggleSSLSelection();

    const redirectCheckbox = document.getElementById('redirectToHttps');
    if (redirectCheckbox) {
        redirectCheckbox.checked = false;
        redirectCheckbox.disabled = true;
    }

    const lbModeSelect = document.getElementById('lbMode');
    if (lbModeSelect) {
        lbModeSelect.value = 'roundrobin';
    }

    const backendTargets = document.getElementById('backendTargets');
    if (backendTargets) {
        backendTargets.value = '';
    }

    // Add event listener for domain input to load certificates
    const domainInput = form.querySelector('[name="domain"]');
    domainInput.removeEventListener('input', domainInputChangeHandler);
    domainInput.addEventListener('input', domainInputChangeHandler);

    new bootstrap.Modal(document.getElementById('addIngressModal')).show();
}

// Handler for domain input changes
function domainInputChangeHandler() {
    const sslType = document.querySelector('input[name="ssl_type"]:checked')?.value;
    if (sslType === 'select') {
        loadAvailableCertificates();
    }
}

// Show Add SSL Certificate Modal
function showAddSSLCertModal() {
    document.getElementById('addSSLCertForm').reset();
    document.querySelector('input[name="ssl_type"][value="normal"]').checked = true;
    toggleSSLCertDNSProvider();
    new bootstrap.Modal(document.getElementById('addSSLCertModal')).show();
}

// Toggle DNS Provider for SSL Cert Modal
function toggleSSLCertDNSProvider() {
    const sslType = document.querySelector('#addSSLCertModal input[name="ssl_type"]:checked')?.value;
    const dnsGroup = document.getElementById('sslCertDNSProviderGroup');
    const dnsProvider = document.getElementById('sslCertDNSProvider');

    if (sslType === 'wildcard') {
        dnsGroup.style.display = 'block';
        dnsProvider.required = true;
        toggleSSLCertAPIKeyInput();
    } else {
        dnsGroup.style.display = 'none';
        dnsProvider.required = false;
        dnsProvider.value = '';
        const warningEl = document.getElementById('sslCertHeNetWarning');
        if (warningEl) warningEl.style.display = 'none';
    }
}

// Toggle API Key input for SSL Cert Modal
function toggleSSLCertAPIKeyInput() {
    const dnsProvider = document.getElementById('sslCertDNSProvider')?.value;
    const warningEl = document.getElementById('sslCertHeNetWarning');
    const heIds = document.getElementById('heIds');

    if (dnsProvider === 'he-net') {
        if (warningEl) warningEl.style.display = 'block';
        if (heIds) heIds.style.display = 'block';

        const helpEl = document.getElementById('sslCertDNSProviderHelp');
        if (helpEl) helpEl.textContent = 'Hurricane Electric (HE.net) için kullanıcı adı ve şifre/key gereklidir.';
    } else {
        if (warningEl) warningEl.style.display = 'none';
        if (heIds) heIds.style.display = 'none';

        const helpEl = document.getElementById('sslCertDNSProviderHelp');
        if (helpEl) helpEl.textContent = 'DNS credentials dosyasını /app/config/certbot/creds/ klasörüne eklemeniz gerekiyor';
    }
}

// Enhanced SSL request with validation and progress
async function addSSLCertificate() {
    const form = document.getElementById('addSSLCertForm');
    const formData = new FormData(form);

    const domain = formData.get('domain')?.trim();
    const email = formData.get('email')?.trim();
    const he_username = formData.get('he_username')?.trim();
    const he_password = formData.get('he_password')?.trim();

    // Validation
    if (!domain || !isValidDomain(domain)) {
        showAlert('Geçerli bir domain girin', 'warning');
        return;
    }

    if (!email || !isValidEmail(email)) {
        showAlert('Geçerli bir e-posta adresi girin', 'warning');
        return;
    }

    if (domain.startsWith('*.') && !dnsProvider) {
        showAlert('Wildcard sertifika için DNS provider seçimi gerekli', 'warning');
        return;
    }

    if (dnsProvider === 'he-net' && (!he_username || !he_password)) {
        showAlert('HE.net için kullanıcı adı ve şifre/key zorunludur', 'warning');
        return;
    }

    console.log('Starting SSL certificate request for:', domain);

    // Show initial progress
    const steps = [
        'SSL isteği hazırlanıyor',
        'Certbot container bağlantısı',
        'Domain doğrulaması',
        'Sertifika oluşturuluyor'
    ];
    showSSLSteps(0, steps);
    showSSLProgress('SSL sertifika isteği başlatılıyor...', 'info');

    // Disable form submit button
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn?.innerHTML;
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> İşleniyor...';
    }

    try {
        showSSLSteps(1, steps);
        showSSLProgress('Container\'a bağlanılıyor...', 'info');

        const res = await fetch(`${API_BASE}/ssl/request`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ domain, email, dnsProvider, he_username, he_password })
        });

        console.log('Response status:', res.status);
        showSSLSteps(2, steps);
        showSSLProgress('Sunucu yanıtı alındı, işleniyor...', 'info');

        let data;
        try {
            data = await res.json();
            console.log('Response data:', data);
        } catch (parseError) {
            console.error('JSON parse error:', parseError);
            hideSSLSteps();
            hideSSLProgress();
            throw new Error('Sunucudan geçersiz yanıt alındı');
        }

        try {
            if (res.ok && data.success) {
                console.log('SSL certificate request successful');
                showSSLSteps(3, steps);
                showSSLProgress('SSL sertifikası başarıyla oluşturuldu!', 'success');

                // Show certbot output if available
                if (data.certbot_output) {
                    console.log('Certbot Output:', data.certbot_output);
                }

                console.log('Hiding modal and showing success message');
                setTimeout(() => {
                    hideSSLSteps();
                    hideSSLProgress();
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addSSLCertModal'));
                    if (modal) {
                        modal.hide();
                    }
                    showAlert('✅ SSL sertifikası başarıyla eklendi!', 'success');
                }, 2000);

                await loadSSLCertificates();
            } else if (res.status === 202) {
                // Manual DNS challenge required
                hideSSLSteps();
                hideSSLProgress();
                await handleSSLError(data, { domain, email, dnsProvider });
            } else {
                console.log('Response not OK, status:', res.status);
                hideSSLSteps();
                hideSSLProgress();
                await handleSSLError(data, { domain, email, dnsProvider });
            }
        } catch (fetchError) {
            console.error('Fetch error:', fetchError);
            hideSSLSteps();
            hideSSLProgress();
            throw fetchError;
        }
    } catch (error) {
        console.error('SSL Certificate Error:', error);
        console.error('Error stack:', error.stack);
        hideSSLSteps();
        hideSSLProgress();
        showAlert('Hata: ' + error.message, 'danger');
    } finally {
        // Re-enable form submit button
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnText || 'Sertifika Oluştur';
        }
    }
}

// Save SSL Certificate (from SSL menu)
async function saveSSLCertificate() {
    console.log('saveSSLCertificate called');

    try {
        const form = document.getElementById('addSSLCertForm');
        if (!form) {
            alert('Form bulunamadı!');
            return;
        }

        const formData = new FormData(form);

        const domain = formData.get('domain')?.trim();
        const sslType = formData.get('ssl_type');
        const email = formData.get('email');
        const dnsProvider = formData.get('dns_provider') || null;

        console.log('Form data:', { domain, sslType, email, dnsProvider });

        if (!domain || !email) {
            alert('Domain ve e-posta gerekli');
            return;
        }

        // Note: he-net için confirm dialog kaldırıldı
        // Kullanıcı zaten modal'da uyarı mesajını görmüş durumda
        if (dnsProvider === 'he-net') {
            console.log('he-net detected, proceeding with manual DNS challenge');
        }

        const sslDomain = sslType === 'wildcard' ? (domain.startsWith('*.') ? domain : '*.' + domain) : domain;

        const he_username = formData.get('he_username')?.trim();
        const he_password = formData.get('he_password')?.trim();

        console.log('Sending SSL request:', { domain: sslDomain, email, dnsProvider });
        console.log('API_BASE:', API_BASE);
        console.log('authToken:', authToken ? 'exists' : 'missing');

        const requestBody = { domain: sslDomain, email, dnsProvider, he_username, he_password };
        console.log('Request body:', { ...requestBody, he_password: '***' }); // Log masked password

        try {
            const res = await fetch(`${API_BASE}/ssl/request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
                body: JSON.stringify(requestBody)
            });

            console.log('Response status:', res.status);
            console.log('Response ok:', res.ok);

            let data;
            try {
                data = await res.json();
            } catch (jsonError) {
                console.error('Failed to parse JSON response:', jsonError);
                throw new Error(`Server returned invalid JSON. Status: ${res.status}`);
            }
            console.log('Response data:', data);

            // Check for rate limit error first
            if (res.status === 429 || data.type === 'RATE_LIMIT') {
                const formattedMessage = data.message || formatRetryAfterMessage(data.retryAfter);
                showAlert(`⏰ Let's Encrypt Rate Limit\n\nÇok fazla başarısız deneme yapıldı.\n\n${formattedMessage}\n\nNot: Rate limit genellikle 1 saat sonra sıfırlanır.`, 'warning');
                return;
            }

            // Check for manual DNS challenge first (202 status)
            if (res.status === 202 || data.requires_manual_dns) {
                console.log('Response 202 - Manual DNS challenge required');
                console.log('data.txt_record:', data.txt_record);
                console.log('data.txt_domain:', data.txt_domain);

                // Manual DNS challenge required
                if (data.txt_record) {
                    console.log('TXT record found, preparing alert...');
                    const txtDomain = data.txt_domain || `_acme-challenge.${data.domain.replace('*.', '')}`;
                    const txtInfo = `🔐 MANUEL DNS CHALLENGE GEREKLİ!\n\n` +
                        `📋 Domain: ${data.domain}\n\n` +
                        `📝 TXT Record Name:\n   ${txtDomain}\n\n` +
                        `🔑 TXT Record Value:\n   ${data.txt_record}\n\n` +
                        `📌 Adımlar:\n` +
                        `   1. dns.he.net'e giriş yapın\n` +
                        `   2. Domain'inize (${data.domain.replace('*.', '')}) gidin\n` +
                        `   3. TXT kaydı ekleyin:\n` +
                        `      - Name: ${txtDomain}\n` +
                        `      - Value: ${data.txt_record}\n` +
                        `   4. 2-5 dakika bekleyin (DNS propagation)\n` +
                        `   5. "Tekrar Dene" butonuna basın`;

                    console.log('TXT Info prepared:', txtInfo.substring(0, 100) + '...');

                    try {
                        // Hide SSL cert modal first
                        console.log('Hiding SSL cert modal...');
                        const sslCertModal = bootstrap.Modal.getInstance(document.getElementById('addSSLCertModal'));
                        if (sslCertModal) {
                            sslCertModal.hide();
                            console.log('SSL cert modal hidden');
                        }

                        // Small delay to ensure modal is closed
                        setTimeout(async () => {
                            console.log('Showing DNS challenge modal...');

                            try {
                                // Populate DNS challenge modal
                                const baseDomain = data.domain.replace('*.', '');
                                const dnsChallengeDomainEl = document.getElementById('dnsChallengeDomain');
                                const dnsChallengeBaseDomainEl = document.getElementById('dnsChallengeBaseDomain');
                                const dnsChallengeNameEl = document.getElementById('dnsChallengeName');
                                const dnsChallengeValueEl = document.getElementById('dnsChallengeValue');
                                const dnsChallengeNameDisplayEl = document.getElementById('dnsChallengeNameDisplay');
                                const dnsChallengeValueDisplayEl = document.getElementById('dnsChallengeValueDisplay');

                                if (!dnsChallengeDomainEl || !dnsChallengeNameEl || !dnsChallengeValueEl) {
                                    console.error('DNS challenge modal elements not found!');
                                    alert(txtInfo); // Fallback to alert
                                    return;
                                }

                                dnsChallengeDomainEl.textContent = data.domain;
                                if (dnsChallengeBaseDomainEl) {
                                    dnsChallengeBaseDomainEl.textContent = baseDomain;
                                }
                                dnsChallengeNameEl.value = txtDomain;
                                dnsChallengeValueEl.value = data.txt_record;
                                if (dnsChallengeNameDisplayEl) {
                                    dnsChallengeNameDisplayEl.textContent = txtDomain;
                                }
                                if (dnsChallengeValueDisplayEl) {
                                    dnsChallengeValueDisplayEl.textContent = data.txt_record;
                                }

                                // Store retry info
                                const emailInput = document.querySelector('#addSSLCertModal input[name="email"]');
                                window.lastDNSChallengeData = {
                                    domain: data.domain,
                                    email: emailInput ? emailInput.value : '',
                                    dnsProvider: data.dns_provider || data.dnsProvider || 'he-net',
                                    txt_domain: data.txt_domain,
                                    txt_record: data.txt_record,
                                    lastTxtRecord: data.txt_record, // Store initial TXT record to detect changes
                                    session_id: data.session_id || null
                                };

                                // Show DNS challenge modal
                                const dnsModalEl = document.getElementById('dnsChallengeModal');
                                if (!dnsModalEl) {
                                    console.error('DNS challenge modal element not found!');
                                    alert(txtInfo); // Fallback to alert
                                    return;
                                }

                                const dnsModal = new bootstrap.Modal(dnsModalEl, {
                                    backdrop: 'static',
                                    keyboard: false
                                });
                                dnsModal.show();
                                console.log('DNS challenge modal shown successfully');
                            } catch (modalError) {
                                console.error('Error showing DNS challenge modal:', modalError);
                                alert(txtInfo); // Fallback to alert
                            }
                        }, 300);
                    } catch (error) {
                        console.error('Error showing DNS challenge modal:', error);
                        // Fallback: show alert
                        alert(txtInfo);
                    }
                } else {
                    console.log('No TXT record found in response');
                    alert('Manuel DNS challenge gerekli: ' + (data.message || 'TXT kaydı bilgisi alınamadı'));
                }
            } else if (res.ok) {
                console.log('Response OK, SSL certificate created successfully');

                // Show certbot output if available
                if (data.certbot_output && (data.certbot_output.stdout || data.certbot_output.stderr)) {
                    console.log('Certbot Output:', data.certbot_output);
                    const output = `Certbot Çıktısı:\n\nSTDOUT:\n${data.certbot_output.stdout || '(boş)'}\n\nSTDERR:\n${data.certbot_output.stderr || '(boş)'}`;
                    console.log(output);
                }

                console.log('Hiding modal and showing success message');
                const modal = bootstrap.Modal.getInstance(document.getElementById('addSSLCertModal'));
                if (modal) {
                    modal.hide();
                }
                alert('✅ SSL sertifikası başarıyla eklendi!');
                await loadSSLCertificates();
            } else {
                console.log('Response not OK, status:', res.status);
                // data already parsed above
                const e = data || { error: 'Hata' };
                console.log('Error response:', e);

                let errorMsg = 'Hata: ' + (e.error || res.status);

                // Show certbot output if available
                if (e.certbot_output) {
                    const output = `Certbot Çıktısı:\n\nSTDOUT:\n${e.certbot_output.stdout || '(boş)'}\n\nSTDERR:\n${e.certbot_output.stderr || '(boş)'}`;
                    if (e.certbot_output.fullOutput) {
                        errorMsg += '\n\nCertbot Detaylı Çıktı:\n' + e.certbot_output.fullOutput.substring(0, 1000);
                    } else {
                        errorMsg += '\n\n' + output;
                    }
                    console.error('Certbot Error Output:', e.certbot_output);
                }

                alert(errorMsg);
            }
        } catch (fetchError) {
            console.error('Fetch error:', fetchError);
            throw fetchError;
        }
    } catch (error) {
        console.error('SSL Certificate Error:', error);
        console.error('Error stack:', error.stack);
        alert('Hata: ' + error.message);
    }
}

// Save Ingress Rule
async function saveIngressRule() {
    const form = document.getElementById('addIngressForm');
    const formData = new FormData(form);

    const sslType = formData.get('ssl_type');
    const sslCertId = formData.get('ssl_cert_id');
    const newSslType = formData.get('new_ssl_type');
    const domain = formData.get('domain')?.trim();

    let sslEnabled = false;
    let sslTypeValue = 'none';
    let sslCert = null;
    let dnsProvider = null;

    const lbMode = (formData.get('lb_mode') || 'roundrobin').toLowerCase();
    const normalizedLbMode = ['roundrobin', 'failover'].includes(lbMode) ? lbMode : 'roundrobin';

    const backends = [];
    const primaryHost = formData.get('backend_host')?.trim();
    const primaryPortValue = formData.get('backend_port');
    const primaryPort = primaryPortValue ? parseInt(primaryPortValue, 10) : NaN;

    if (primaryHost && !Number.isNaN(primaryPort) && primaryPort > 0 && primaryPort < 65536) {
        backends.push({ host: primaryHost, port: primaryPort });
    }

    const extraTargetsRaw = formData.get('backend_targets')?.split('\n').map(line => line.trim()).filter(Boolean) || [];
    extraTargetsRaw.forEach(line => {
        const [hostPart, portPart] = line.split(':').map(part => part.trim());
        const parsedPort = portPart ? parseInt(portPart, 10) : NaN;
        if (hostPart && !Number.isNaN(parsedPort) && parsedPort > 0 && parsedPort < 65536) {
            backends.push({ host: hostPart, port: parsedPort });
        }
    });

    if (backends.length === 0) {
        alert('En az bir backend host/port kombinasyonu girilmelidir.');
        return;
    }

    const primaryBackend = backends[0];

    if (sslType === 'select' && sslCertId) {
        // Use existing certificate
        const certSelect = document.getElementById('sslCertSelect');
        const selectedOption = certSelect.options[certSelect.selectedIndex];
        sslEnabled = true;
        sslCert = selectedOption.getAttribute('data-cert-path');
        sslTypeValue = selectedOption.getAttribute('data-ssl-type');
    } else if (sslType === 'new') {
        // Request new certificate
        sslEnabled = true;
        sslTypeValue = newSslType;
        dnsProvider = formData.get('dns_provider') || null;

        // Request certificate will be handled separately
        const email = prompt('SSL sertifikası için e-posta adresi:');
        if (!email) {
            alert('E-posta gerekli, işlem iptal edildi');
            return;
        }

        const sslDomain = newSslType === 'wildcard' ? '*.' + domain : domain;

        if (dnsProvider === 'he-net') {
            if (!confirm('Hurricane Electric için manuel DNS challenge gerekir. Certbot size TXT kaydını gösterecek, bunu dns.he.net\'ten manuel olarak eklemeniz gerekecek. Devam etmek istiyor musunuz?')) {
                return;
            }
        }

        try {
            const sslRes = await fetch(`${API_BASE}/ssl/request`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
                body: JSON.stringify({
                    domain: sslDomain,
                    email,
                    dnsProvider,
                    he_username: formData.get('he_username')?.trim(), // From Ingress Modal
                    he_password: formData.get('he_password')?.trim(), // From Ingress Modal
                    assignToRuleId: formData.get('id') || null
                })
            });

            if (!sslRes.ok) {
                if (sslRes.status === 202) {
                    // Manual DNS challenge required
                    const data = await sslRes.json();
                    if (data.requires_manual_dns && data.txt_record) {
                        const txtDomain = data.txt_domain || `_acme-challenge.${data.domain.replace('*.', '')}`;
                        const txtInfo = `Manuel DNS Challenge Gerekli!\n\n` +
                            `Domain: ${data.domain}\n\n` +
                            `TXT Record Name: ${txtDomain}\n` +
                            `TXT Record Value: ${data.txt_record}\n\n` +
                            `Lütfen bu TXT kaydını dns.he.net'e ekleyin:\n` +
                            `1. dns.he.net'e giriş yapın\n` +
                            `2. Domain'inize gidin\n` +
                            `3. TXT kaydı ekleyin:\n` +
                            `   - Name: ${txtDomain}\n` +
                            `   - Value: ${data.txt_record}\n` +
                            `4. Birkaç dakika bekleyin (DNS propagation)\n` +
                            `5. Sonra tekrar "Kaydet" butonuna basın`;

                        alert(txtInfo);
                        return;
                    }
                }
                const e = await sslRes.json().catch(() => ({ error: 'Hata' }));
                alert('SSL sertifikası alınamadı: ' + (e.error || sslRes.status));
                return;
            }

            const sslResult = await sslRes.json();
            if (sslResult.certificate) {
                sslCert = sslResult.certificate.cert_path;
            }
        } catch (error) {
            alert('SSL sertifikası hatası: ' + error.message);
            return;
        }
    }

    const data = {
        name: formData.get('name')?.trim(),
        domain: domain,
        path: formData.get('path')?.trim() || null,
        backend_host: primaryBackend.host,
        backend_port: primaryBackend.port,
        ssl_enabled: sslEnabled,
        ssl_type: sslTypeValue,
        ssl_cert: sslCert,
        dns_provider: dnsProvider,
        lb_mode: normalizedLbMode,
        backends: backends,
        active: true,
        redirect_to_https: document.getElementById('redirectToHttps')?.checked || false
    };

    try {
        const id = formData.get('id');
        const url = id ? `${API_BASE}/rules/${id}` : `${API_BASE}/rules`;
        const method = id ? 'PUT' : 'POST';
        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json', ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}) },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            bootstrap.Modal.getInstance(document.getElementById('addIngressModal')).hide();
            await loadIngressRules();
            alert(id ? 'Kural güncellendi!' : 'Kural başarıyla eklendi!');
        } else {
            let error;
            try {
                error = await response.json();
            } catch (e) {
                error = { error: `HTTP ${response.status}: ${response.statusText}` };
            }
            alert('Hata: ' + error.error);
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

// Show Add Port Forward Modal
function showAddPortForwardModal() {
    document.getElementById('addPortForwardForm').reset();
    document.querySelector('#addPortForwardForm [name="id"]').value = '';
    new bootstrap.Modal(document.getElementById('addPortForwardModal')).show();
}

// Save Port Forward Rule
async function savePortForwardRule() {
    const form = document.getElementById('addPortForwardForm');
    const formData = new FormData(form);

    const data = {
        name: formData.get('name'),
        frontend_port: parseInt(formData.get('frontend_port')),
        backend_host: formData.get('backend_host'),
        backend_port: parseInt(formData.get('backend_port')),
        protocol: formData.get('protocol') || 'tcp'
    };

    try {
        const id = formData.get('id');
        const url = id ? `${API_BASE}/port-forwarding/${id}` : `${API_BASE}/port-forwarding`;
        const method = id ? 'PUT' : 'POST';
        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json', ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}) },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            bootstrap.Modal.getInstance(document.getElementById('addPortForwardModal')).hide();
            loadPortForwardRules();
            alert(id ? 'Port forwarding kuralı güncellendi!' : 'Port forwarding kuralı başarıyla eklendi!');
        } else {
            const error = await response.json();
            alert('Hata: ' + error.error);
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

// Delete Ingress Rule
async function deleteIngressRule(id) {
    if (!confirm('Bu kuralı silmek istediğinizden emin misiniz?')) return;

    try {
        const response = await fetch(`${API_BASE}/rules/${id}`, {
            method: 'DELETE',
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });

        if (response.ok) {
            loadIngressRules();
            alert('Kural başarıyla silindi!');
        } else {
            const error = await response.json();
            alert('Hata: ' + error.error);
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

// Copy to clipboard function (modern Clipboard API)
async function copyToClipboard(inputId) {
    const input = document.getElementById(inputId);
    if (!input) {
        console.error('Input element not found:', inputId);
        return;
    }

    const textToCopy = input.value;
    if (!textToCopy) {
        alert('Kopyalanacak metin bulunamadı.');
        return;
    }

    try {
        // Try modern Clipboard API first
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(textToCopy);
        } else {
            // Fallback to execCommand for older browsers
            input.select();
            input.setSelectionRange(0, 99999);
            if (!document.execCommand('copy')) {
                throw new Error('execCommand failed');
            }
        }

        // Show feedback
        const btn = input.parentElement.querySelector('button');
        if (btn) {
            const originalText = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check"></i> Kopyalandı!';
            btn.classList.add('btn-success');
            btn.classList.remove('btn-outline-secondary');
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-outline-secondary');
            }, 2000);
        }
    } catch (err) {
        console.error('Copy failed:', err);
        // Fallback: select text and show alert
        input.select();
        input.setSelectionRange(0, 99999);
        alert('Otomatik kopyalama başarısız. Metin seçildi, Ctrl+C ile kopyalayabilirsiniz.');
    }
}

// Retry DNS challenge with enhanced progress feedback
async function retryDNSChallenge() {
    if (!window.lastDNSChallengeData) {
        showAlert('Hata: Retry bilgisi bulunamadı. Lütfen tekrar deneyin.', 'danger');
        return;
    }

    const data = window.lastDNSChallengeData;
    console.log('Retrying DNS challenge with data:', data);

    // Show progress steps
    const steps = [
        'DNS kaydı kontrol ediliyor',
        'Certbot challenge doğrulanıyor',
        'Sertifika oluşturuluyor',
        'HAProxy yapılandırması güncelleniyor'
    ];
    showSSLSteps(0, steps);
    showSSLProgress('DNS challenge doğrulaması başlatılıyor...', 'info');

    // Show loading state first (before closing modal)
    const retryBtn = document.querySelector('#dnsChallengeModal .btn-primary');
    if (retryBtn) {
        retryBtn.disabled = true;
        retryBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Kontrol ediliyor...';
    }

    // Call API with retry flag
    try {
        showSSLSteps(1, steps);
        showSSLProgress('Certbot ile DNS challenge doğrulanıyor...', 'info');

        // Create AbortController for timeout (70 seconds - longer than API polling)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 70000);

        const res = await fetch(`${API_BASE}/ssl/continue`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                domain: data.domain
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        const responseData = await res.json();

        if (res.status === 200 && responseData.success) {
            // Success! Certificate obtained
            showSSLSteps(3, steps);
            showSSLProgress('SSL sertifikası başarıyla oluşturuldu!', 'success');

            setTimeout(() => {
                hideSSLSteps();
                hideSSLProgress();
                showAlert('✅ SSL sertifikası başarıyla alındı!', 'success');
            }, 2000);

            await loadSSLCertificates();
            // Close modal
            const dnsModal = bootstrap.Modal.getInstance(document.getElementById('dnsChallengeModal'));
            if (dnsModal) {
                dnsModal.hide();
            }
        } else if (res.status === 202 || (res.ok && !responseData.success)) {
            // Still waiting for DNS propagation or new challenge token
            const isNewToken = responseData.txt_record && window.lastDNSChallengeData &&
                responseData.txt_record !== window.lastDNSChallengeData.lastTxtRecord;

            if (isNewToken) {
                // New challenge token created - update the modal
                alert('⚠️ Yeni bir challenge token oluşturuldu. Lütfen DNS kaydını güncelleyin:\n\n' +
                    'TXT Record Name: ' + responseData.txt_domain + '\n' +
                    'TXT Record Value: ' + responseData.txt_record + '\n\n' +
                    'Eski kaydı silip yeni kaydı ekleyin.');

                // Update modal with new token (with null checks)
                const nameInput = document.getElementById('dnsChallengeName');
                const valueInput = document.getElementById('dnsChallengeValue');
                const nameDisplay = document.getElementById('dnsChallengeNameDisplay');
                const valueDisplay = document.getElementById('dnsChallengeValueDisplay');

                if (nameInput) nameInput.value = responseData.txt_domain;
                if (valueInput) valueInput.value = responseData.txt_record;
                if (nameDisplay) nameDisplay.textContent = responseData.txt_domain;
                if (valueDisplay) valueDisplay.textContent = responseData.txt_record;

                // Store new token
                if (responseData.txt_domain) window.lastDNSChallengeData.txt_domain = responseData.txt_domain;
                if (responseData.txt_record) {
                    window.lastDNSChallengeData.txt_record = responseData.txt_record;
                    window.lastDNSChallengeData.lastTxtRecord = responseData.txt_record;
                }

                // Show modal again
                const dnsModal = new bootstrap.Modal(document.getElementById('dnsChallengeModal'));
                dnsModal.show();
            } else {
                const txtDomain = responseData.txt_domain || (window.lastDNSChallengeData && window.lastDNSChallengeData.txt_domain) || '_acme-challenge.' + (data.domain.startsWith('*.') ? data.domain.substring(2) : data.domain);
                const txtRecord = responseData.txt_record || (window.lastDNSChallengeData && window.lastDNSChallengeData.txt_record) || 'Bilinmiyor';

                alert('⚠️ DNS kaydı henüz yayılmamış olabilir. Lütfen 2-5 dakika bekleyip tekrar deneyin.\n\n' +
                    'TXT kaydının doğru eklendiğinden emin olun:\n' +
                    'Name: ' + txtDomain + '\n' +
                    'Value: ' + txtRecord);
            }

            if (retryBtn) {
                retryBtn.disabled = false;
                retryBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Tekrar Dene';
            }
        } else if (res.status === 429 || responseData.type === 'RATE_LIMIT') {
            // Rate limit error
            hideSSLSteps();
            const formattedMessage = responseData.message || formatRetryAfterMessage(responseData.retryAfter);
            showSSLProgress(`⏰ Let's Encrypt rate limit: Çok fazla başarısız deneme. ${formattedMessage}`, 'warning');
            showAlert(`⏰ Let's Encrypt Rate Limit\n\nÇok fazla başarısız deneme yapıldı.\n\n${formattedMessage}\n\nNot: Rate limit genellikle 1 saat sonra sıfırlanır.`, 'warning');
            if (retryBtn) {
                retryBtn.disabled = true;
                retryBtn.innerHTML = '<i class="bi bi-clock"></i> Rate Limit';
            }
        } else {
            // Error
            hideSSLSteps();
            showSSLProgress('Hata: ' + (responseData.error || responseData.message || 'Bilinmeyen hata'), 'danger');
            if (retryBtn) {
                retryBtn.disabled = false;
                retryBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Tekrar Dene';
            }
        }
    } catch (error) {
        console.error('Retry error:', error);
        hideSSLSteps();

        // Handle AbortError (timeout)
        if (error.name === 'AbortError') {
            showSSLProgress('İstek zaman aşımına uğradı. Process hala çalışıyor olabilir. Lütfen birkaç dakika bekleyip tekrar deneyin.', 'warning');
        } else {
            showSSLProgress('Hata: ' + error.message, 'danger');
        }

        if (retryBtn) {
            retryBtn.disabled = false;
            retryBtn.innerHTML = '<i class="bi bi-arrow-clockwise"></i> Tekrar Dene';
        }
    }
}

// Show Certbot error modal with detailed output
function showCertbotErrorModal(errorMessage, certbotOutput) {
    // Create modal if it doesn't exist
    let errorModal = document.getElementById('certbotErrorModal');
    if (!errorModal) {
        const modalHtml = `
            <div class="modal fade" id="certbotErrorModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-danger text-white">
                            <h5 class="modal-title">
                                <i class="bi bi-exclamation-triangle me-2"></i>
                                Certbot Hata Detayları
                            </h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="alert alert-danger">
                                <strong>Hata:</strong> <span id="certbotErrorMessage"></span>
                            </div>
                            <div class="mb-3">
                                <label class="form-label"><strong>Certbot Çıktısı:</strong></label>
                                <textarea id="certbotErrorOutput" class="form-control" rows="10" readonly style="font-family: monospace; font-size: 12px;"></textarea>
                            </div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                            <button type="button" class="btn btn-primary" onclick="copyErrorToClipboard()">
                                <i class="bi bi-clipboard"></i> Hata Detaylarını Kopyala
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        errorModal = document.getElementById('certbotErrorModal');
    }

    // Populate modal content
    document.getElementById('certbotErrorMessage').textContent = errorMessage;
    const outputText = `STDOUT:
${certbotOutput.stdout || '(boş)'}

STDERR:
${certbotOutput.stderr || '(boş)'}

FULL OUTPUT:
${certbotOutput.fullOutput || '(boş)'}`;
    document.getElementById('certbotErrorOutput').value = outputText;

    // Show modal
    const modal = new bootstrap.Modal(errorModal);
    modal.show();
}

// Copy error details to clipboard
function copyErrorToClipboard() {
    const errorMessage = document.getElementById('certbotErrorMessage').textContent;
    const errorOutput = document.getElementById('certbotErrorOutput').value;
    const fullError = `Certbot Hata Raporu
===================

Hata Mesajı: ${errorMessage}

${errorOutput}

Tarih: ${new Date().toLocaleString('tr-TR')}`;

    navigator.clipboard.writeText(fullError).then(() => {
        showAlert('Hata detayları panoya kopyalandı', 'success');
    }).catch(err => {
        console.error('Copy failed:', err);
        showAlert('Kopyalama başarısız', 'warning');
    });
}

// Show credentials help modal
function showCredentialsHelp(provider) {
    let helpModal = document.getElementById('credentialsHelpModal');
    if (!helpModal) {
        const modalHtml = `
            <div class="modal fade" id="credentialsHelpModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header bg-warning text-dark">
                            <h5 class="modal-title">
                                <i class="bi bi-info-circle me-2"></i>
                                DNS Kimlik Bilgileri Yardımı
                            </h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div id="credentialsHelpContent"></div>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Kapat</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        helpModal = document.getElementById('credentialsHelpModal');
    }

    // Generate help content based on provider
    const helpContent = generateCredentialsHelp(provider);
    document.getElementById('credentialsHelpContent').innerHTML = helpContent;

    // Show modal
    const modal = new bootstrap.Modal(helpModal);
    modal.show();
}

// Generate credentials help content
function generateCredentialsHelp(provider) {
    const baseInstructions = `
        <div class="alert alert-info">
            <strong>Genel Bilgi:</strong> DNS kimlik bilgileri dosyası <code>/app/config/certbot/creds/</code> klasöründe olmalıdır.
        </div>
    `;

    switch (provider) {
        case 'cloudflare':
            return baseInstructions + `
                <h6>Cloudflare Ayarları:</h6>
                <ol>
                    <li>Cloudflare dashboard'a giriş yapın</li>
                    <li>My Profile > API Tokens'a gidin</li>
                    <li>"Create Token" butonuna tıklayın</li>
                    <li>"Custom token" seçin ve şu izinleri verin:
                        <ul>
                            <li>Zone:Zone:Read</li>
                            <li>Zone:DNS:Edit</li>
                        </ul>
                    </li>
                    <li>Dosya oluşturun: <code>/app/config/certbot/creds/cloudflare.ini</code></li>
                    <li>Dosya içeriği:
                        <pre>dns_cloudflare_api_token = YOUR_API_TOKEN_HERE</pre>
                    </li>
                    <li>Dosya izinlerini ayarlayın: <code>chmod 600 cloudflare.ini</code></li>
                </ol>
            `;
        case 'route53':
            return baseInstructions + `
                <h6>AWS Route53 Ayarları:</h6>
                <ol>
                    <li>AWS IAM'de yeni kullanıcı oluşturun</li>
                    <li>Route53FullAccess policy'sini ekleyin</li>
                    <li>Access Key ve Secret Key alın</li>
                    <li>Dosya oluşturun: <code>/app/config/certbot/creds/route53.ini</code></li>
                    <li>Dosya içeriği:
                        <pre>dns_route53_access_key_id = YOUR_ACCESS_KEY
dns_route53_secret_access_key = YOUR_SECRET_KEY</pre>
                    </li>
                    <li>Dosya izinlerini ayarlayın: <code>chmod 600 route53.ini</code></li>
                </ol>
            `;
        case 'digitalocean':
            return baseInstructions + `
                <h6>DigitalOcean Ayarları:</h6>
                <ol>
                    <li>DigitalOcean control panel'e giriş yapın</li>
                    <li>API > Tokens/Keys'e gidin</li>
                    <li>"Generate New Token" butonuna tıklayın</li>
                    <li>Write scope'unu seçin</li>
                    <li>Dosya oluşturun: <code>/app/config/certbot/creds/digitalocean.ini</code></li>
                    <li>Dosya içeriği:
                        <pre>dns_digitalocean_token = YOUR_API_TOKEN_HERE</pre>
                    </li>
                    <li>Dosya izinlerini ayarlayın: <code>chmod 600 digitalocean.ini</code></li>
                </ol>
            `;
        default:
            return baseInstructions + `
                <div class="alert alert-warning">
                    <strong>${provider}</strong> için özel talimatlar mevcut değil. 
                    Lütfen DNS sağlayıcınızın API dokümantasyonunu kontrol edin.
                </div>
            `;
    }
}

// Show debug output (SSH-like live view)
async function showDebugOutput() {
    if (!window.lastDNSChallengeData) {
        showAlert('Hata: DNS challenge bilgisi bulunamadı.', 'danger');
        return;
    }

    const data = window.lastDNSChallengeData;

    // Show loading state
    const debugModal = new bootstrap.Modal(document.getElementById('debugOutputModal'));
    debugModal.show();

    document.getElementById('debugCommand').textContent = 'Yükleniyor...';
    document.getElementById('debugOutput').textContent = 'Komut çalıştırılıyor...';
    document.getElementById('debugExitCode').textContent = '-';

    try {
        const res = await fetch(`${API_BASE}/ssl/debug`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                domain: data.domain,
                email: data.email,
                dnsProvider: data.dnsProvider,
                retry: false // First run to see the challenge
            })
        });

        const responseData = await res.json();

        if (res.ok && responseData.success) {
            // Show command
            document.getElementById('debugCommand').textContent = responseData.command || 'Komut bulunamadı';

            // Show full output
            const fullOutput = `=== STDOUT ===\n${responseData.stdout || '(boş)'}\n\n=== STDERR ===\n${responseData.stderr || '(boş)'}\n\n=== FULL OUTPUT ===\n${responseData.fullOutput || '(boş)'}`;
            document.getElementById('debugOutput').textContent = fullOutput;

            // Show exit code
            document.getElementById('debugExitCode').textContent = responseData.exitCode !== undefined ? responseData.exitCode : '-';

            // Color code based on exit code
            const exitCodeEl = document.getElementById('debugExitCode');
            exitCodeEl.className = 'badge ';
            if (responseData.exitCode === 0) {
                exitCodeEl.className += 'bg-success';
            } else if (responseData.exitCode === -1 || responseData.timeout) {
                exitCodeEl.className += 'bg-warning';
            } else {
                exitCodeEl.className += 'bg-danger';
            }
        } else {
            document.getElementById('debugOutput').textContent = 'Hata: ' + (responseData.error || 'Bilinmeyen hata');
        }
    } catch (error) {
        console.error('Debug error:', error);
        document.getElementById('debugOutput').textContent = 'Hata: ' + error.message;
    }
}

// Run debug command (retry mode)
async function runDebugCommand() {
    if (!window.lastDNSChallengeData) {
        alert('Hata: DNS challenge bilgisi bulunamadı.');
        return;
    }

    const data = window.lastDNSChallengeData;

    // Show loading state
    document.getElementById('debugOutput').textContent = 'Komut çalıştırılıyor (retry mode)...';
    document.getElementById('debugExitCode').textContent = '-';

    try {
        const res = await fetch(`${API_BASE}/ssl/debug`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({
                domain: data.domain,
                email: data.email,
                dnsProvider: data.dnsProvider,
                retry: true // Retry mode with yes command
            })
        });

        const responseData = await res.json();

        if (res.ok && responseData.success) {
            // Show full output
            const fullOutput = `=== STDOUT ===\n${responseData.stdout || '(boş)'}\n\n=== STDERR ===\n${responseData.stderr || '(boş)'}\n\n=== FULL OUTPUT ===\n${responseData.fullOutput || '(boş)'}`;
            document.getElementById('debugOutput').textContent = fullOutput;

            // Show exit code
            document.getElementById('debugExitCode').textContent = responseData.exitCode !== undefined ? responseData.exitCode : '-';

            // Color code based on exit code
            const exitCodeEl = document.getElementById('debugExitCode');
            exitCodeEl.className = 'badge ';
            if (responseData.exitCode === 0) {
                exitCodeEl.className += 'bg-success';
            } else if (responseData.exitCode === -1 || responseData.timeout) {
                exitCodeEl.className += 'bg-warning';
            } else {
                exitCodeEl.className += 'bg-danger';
            }
        } else {
            document.getElementById('debugOutput').textContent = 'Hata: ' + (responseData.error || 'Bilinmeyen hata');
        }
    } catch (error) {
        console.error('Debug error:', error);
        document.getElementById('debugOutput').textContent = 'Hata: ' + error.message;
    }
}

// Terminal WebSocket connection
let terminal = null;
let terminalSocket = null;
let fitAddon = null;

// Open terminal modal and connect
function openTerminal() {
    const terminalModal = new bootstrap.Modal(document.getElementById('terminalModal'));
    terminalModal.show();

    // Initialize terminal
    if (!terminal) {
        // Use xterm.js from CDN
        terminal = new window.Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Courier New, monospace',
            theme: {
                background: '#000000',
                foreground: '#00ff00',
                cursor: '#00ff00'
            }
        });

        // Use FitAddon from CDN
        if (window.FitAddon) {
            fitAddon = new window.FitAddon.FitAddon();
            terminal.loadAddon(fitAddon);
        }

        terminal.open(document.getElementById('terminal'));

        if (fitAddon) {
            fitAddon.fit();
        }

        // Handle terminal resize
        window.addEventListener('resize', () => {
            if (fitAddon) {
                fitAddon.fit();
            }
        });
    } else {
        // Clear terminal on reconnect
        terminal.clear();
    }

    // Connect WebSocket
    connectTerminal();
}

// Connect to terminal WebSocket
function connectTerminal() {
    if (terminalSocket) {
        terminalSocket.close();
    }

    // Get auth token - use the same key as the rest of the app
    const authToken = localStorage.getItem('token');
    if (!authToken) {
        terminal.write('\r\n[ERROR] Authentication token not found. Please login first.\r\n');
        terminal.write('[INFO] Redirecting to login page in 3 seconds...\r\n');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 3000);
        return;
    }

    // Determine WebSocket URL
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    const wsPort = window.location.port || (window.location.protocol === 'https:' ? 443 : 80);
    const wsUrl = `${wsProtocol}//${wsHost}:3000/ws/terminal?token=${encodeURIComponent(authToken)}`;

    terminal.write('\r\n[INFO] Connecting to Certbot container...\r\n');

    terminalSocket = new WebSocket(wsUrl);

    terminalSocket.onopen = () => {
        terminal.write('\r\n[SUCCESS] Connected to Certbot container!\r\n');
        terminal.write('[INFO] Type commands and press Enter to execute.\r\n');
        terminal.write('[INFO] Type "exit" to disconnect.\r\n\r\n');
        terminal.write('$ ');

        let commandBuffer = '';

        // Send terminal input to WebSocket (only send complete commands on Enter)
        terminal.onData((data) => {
            // Handle backspace
            if (data === '\x7f' || data === '\b') {
                if (commandBuffer.length > 0) {
                    commandBuffer = commandBuffer.slice(0, -1);
                    terminal.write('\b \b');
                }
                return;
            }

            // Handle Enter
            if (data === '\r' || data === '\n') {
                terminal.write('\r\n');
                const command = commandBuffer.trim();
                commandBuffer = '';

                if (command === 'exit' || command === 'quit') {
                    terminal.write('[INFO] Disconnecting...\r\n');
                    disconnectTerminal();
                    return;
                }

                if (command && terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
                    terminalSocket.send(command);
                } else if (!command) {
                    terminal.write('$ ');
                }
                return;
            }

            // Handle other characters
            if (data.charCodeAt(0) >= 32 && data.charCodeAt(0) <= 126) {
                commandBuffer += data;
                terminal.write(data);
            }
        });
    };

    terminalSocket.onmessage = (event) => {
        terminal.write(event.data);
    };

    terminalSocket.onerror = (error) => {
        terminal.write(`\r\n[ERROR] WebSocket error: ${error.message || 'Unknown error'}\r\n`);
    };

    terminalSocket.onclose = () => {
        terminal.write('\r\n[INFO] Connection closed.\r\n');
        terminalSocket = null;
    };
}

// Disconnect terminal
function disconnectTerminal() {
    if (terminalSocket) {
        terminalSocket.close();
        terminalSocket = null;
    }
    if (terminal) {
        terminal.clear();
    }
}

// Clear terminal
function clearTerminal() {
    if (terminal) {
        terminal.clear();
        terminal.write('\r\n$ ');
    }
}

// Delete Port Forward Rule
async function deletePortForwardRule(id) {
    if (!confirm('Bu port forwarding kuralını silmek istediğinizden emin misiniz?')) return;

    try {
        const response = await fetch(`${API_BASE}/port-forwarding/${id}`, {
            method: 'DELETE',
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });

        if (response.ok) {
            loadPortForwardRules();
            alert('Port forwarding kuralı başarıyla silindi!');
        } else {
            const error = await response.json();
            alert('Hata: ' + error.error);
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

async function viewCertificate(certDomain) {
    if (!authToken) {
        showAlert('Önce giriş yapın.', 'warning');
        return;
    }

    try {
        showSSLProgress('Sertifika detayları yükleniyor...', 'info');
        const res = await fetch(`${API_BASE}/ssl/certificates/${encodeURIComponent(certDomain)}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        hideSSLProgress();

        if (!res.ok) {
            const error = await res.json().catch(() => ({ error: res.statusText }));
            throw new Error(error.error || `Sertifika bilgisi alınamadı (${res.status})`);
        }

        const data = await res.json();
        populateCertificateDetailModal(certDomain, data);
        const detailModal = new bootstrap.Modal(document.getElementById('certificateDetailModal'));
        detailModal.show();
    } catch (error) {
        hideSSLProgress();
        console.error('Certificate detail error:', error);
        showAlert('Sertifika detayları alınamadı: ' + error.message, 'danger');
    }
}

function populateCertificateDetailModal(certDomain, data) {
    const record = data.record || {};
    const info = data.info || {};
    const metadata = info.metadata || {};

    document.getElementById('detailCertDomain').textContent = certDomain;
    document.getElementById('detailDomain').textContent = record.domain || info.baseDomain || '-';
    document.getElementById('detailType').textContent = record.ssl_type === 'wildcard' ? 'Wildcard' : (record.ssl_type || 'Bilinmiyor');
    document.getElementById('detailDNSProvider').textContent = record.dns_provider || '-';
    document.getElementById('detailEmail').textContent = record.email || '-';
    document.getElementById('detailExpires').textContent = formatDateTime(record.expires_at || info.expiresAt, true);
    document.getElementById('detailCreated').textContent = formatDateTime(record.created_at, true);
    document.getElementById('detailUpdated').textContent = formatDateTime(record.updated_at, true);
    document.getElementById('detailCertbotPath').textContent = info.certbotPath || '-';
    document.getElementById('detailHaproxyPath').textContent = info.haproxyCertPath || '-';

    document.getElementById('detailSubject').textContent = metadata.subject || '-';
    document.getElementById('detailIssuer').textContent = metadata.issuer || '-';
    document.getElementById('detailSerial').textContent = metadata.serial || '-';
    document.getElementById('detailNotBefore').textContent = metadata.notBefore || '-';
    document.getElementById('detailNotAfter').textContent = metadata.notAfter || formatDateTime(info.expiresAt, true);

    document.getElementById('detailCertificateBody').value = info.certificate || 'Sertifika içeriği bulunamadı.';
}

async function deleteCertificate(certDomain) {
    if (!authToken) {
        showAlert('Önce giriş yapın.', 'warning');
        return;
    }

    if (!confirm(`${certDomain} sertifikasını silmek istediğinizden emin misiniz? Bu işlem geri alınamaz.`)) {
        return;
    }

    try {
        showSSLProgress('Sertifika siliniyor...', 'info');
        const res = await fetch(`${API_BASE}/ssl/certificates/${encodeURIComponent(certDomain)}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        hideSSLProgress();

        if (!res.ok) {
            const error = await res.json().catch(() => ({ error: res.statusText }));
            throw new Error(error.error || `Silme işlemi başarısız (${res.status})`);
        }

        showAlert('Sertifika başarıyla silindi.', 'success');
        await loadSSLCertificates();
        await loadIngressRules();
    } catch (error) {
        hideSSLProgress();
        console.error('Delete certificate error:', error);
        showAlert('Sertifika silinemedi: ' + error.message, 'danger');
    }
}

function copyCertificateContent() {
    const textarea = document.getElementById('detailCertificateBody');
    if (!textarea) return;

    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);

    navigator.clipboard.writeText(textarea.value)
        .then(() => showAlert('Sertifika içeriği panoya kopyalandı.', 'success'))
        .catch(err => {
            console.error('Copy failed:', err);
            showAlert('Kopyalama işlemi başarısız.', 'warning');
        });
}

// Edit functions
async function editIngressRule(id) {
    try {
        const res = await fetch(`${API_BASE}/rules/${id}`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if (!res.ok) throw new Error('Kural bulunamadı');
        const rule = await res.json();
        const form = document.getElementById('addIngressForm');
        form.reset();
        form.querySelector('[name="id"]').value = rule.id;
        form.querySelector('[name="name"]').value = rule.name;
        form.querySelector('[name="domain"]').value = rule.domain || '';
        form.querySelector('[name="path"]').value = rule.path || '';
        const backendList = Array.isArray(rule.backends) && rule.backends.length
            ? rule.backends
            : (rule.backend_host && rule.backend_port ? [{ host: rule.backend_host, port: rule.backend_port }] : []);
        const primaryBackend = backendList[0] || { host: '', port: '' };
        form.querySelector('[name="backend_host"]').value = primaryBackend.host || '';
        form.querySelector('[name="backend_port"]').value = primaryBackend.port || '';

        const lbModeSelect = document.getElementById('lbMode');
        if (lbModeSelect) {
            lbModeSelect.value = (rule.lb_mode || 'roundrobin');
        }

        const backendTargets = document.getElementById('backendTargets');
        if (backendTargets) {
            const extra = backendList.slice(1).map(item => `${item.host}:${item.port}`).join('\n');
            backendTargets.value = extra;
        }

        // Set SSL selection based on rule
        if (rule.ssl_enabled && rule.ssl_cert) {
            // Check if certificate exists in pool
            form.querySelector('input[name="ssl_type"][value="select"]').checked = true;
            toggleSSLSelection();
            // Load certificates and select the one being used
            setTimeout(async () => {
                await loadAvailableCertificates(rule.domain || '');
                const certSelect = document.getElementById('sslCertSelect');
                if (certSelect) {
                    const options = Array.from(certSelect.options);
                    let selected = options.find(opt => opt.getAttribute('data-cert-path') === rule.ssl_cert);

                    if (!selected) {
                        const certs = await loadAllCertificates();
                        const matchingCert = certs.find(c => c.cert_path === rule.ssl_cert || c.cert_domain === rule.ssl_cert?.replace('.pem', ''));
                        if (matchingCert) {
                            selected = options.find(opt => opt.value === String(matchingCert.id))
                                || options.find(opt => opt.getAttribute('data-cert-path') === matchingCert.cert_path);
                        }
                    }

                    if (selected) {
                        certSelect.value = selected.value;
                    }
                }
            }, 500);
        } else {
            form.querySelector('input[name="ssl_type"][value="none"]').checked = true;
            toggleSSLSelection();
        }

        updateRedirectAvailability();
        const redirectCheckbox = document.getElementById('redirectToHttps');
        if (redirectCheckbox) {
            redirectCheckbox.checked = !!rule.redirect_to_https && !redirectCheckbox.disabled;
        }
        new bootstrap.Modal(document.getElementById('addIngressModal')).show();
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

async function editPortForwardRule(id) {
    try {
        const res = await fetch(`${API_BASE}/port-forwarding/${id}`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if (!res.ok) throw new Error('Kural bulunamadı');
        const rule = await res.json();
        const form = document.getElementById('addPortForwardForm');
        form.reset();
        form.querySelector('[name="id"]').value = rule.id;
        form.querySelector('[name="name"]').value = rule.name;
        form.querySelector('[name="frontend_port"]').value = rule.frontend_port;
        form.querySelector('[name="backend_host"]').value = rule.backend_host;
        form.querySelector('[name="backend_port"]').value = rule.backend_port;
        form.querySelector('[name="protocol"]').value = rule.protocol || 'tcp';
        new bootstrap.Modal(document.getElementById('addPortForwardModal')).show();
    } catch (e) {
        alert('Hata: ' + e.message);
    }
}

// Load data on page load
document.addEventListener('DOMContentLoaded', () => {
    setAuthUI();
    if (!authToken) {
        showLoginModal();
    } else {
        loadIngressRules();
    }
});

// SSL request helper
async function requestSSL(domain, ruleId = null) {
    if (!authToken) return alert('Önce giriş yapın.');

    const sslType = prompt('SSL Tipi seçin:\n1 - Normal SSL (domain.com) - Webroot Challenge\n2 - Wildcard SSL (*.domain.com) - DNS Challenge\n\nNumara girin (1 veya 2):', '1');
    if (!sslType) return;

    const isWildcard = sslType === '2';
    const sslDomain = isWildcard ? '*.' + domain : domain;
    const email = prompt('Sertifika için e-posta adresi:');
    if (!email) return;

    let dnsProvider = null;
    if (isWildcard) {
        dnsProvider = prompt('DNS Provider (cloudflare, route53, digitalocean, godaddy):', 'cloudflare');
        if (!dnsProvider) return;
    }

    try {
        const res = await fetch(`${API_BASE}/ssl/request`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ domain: sslDomain, email, dnsProvider, ruleId })
        });

        if (res.ok) {
            alert('SSL sertifikası başarıyla istendi!');
            loadIngressRules();
            loadSSLCertificates();
        } else {
            const e = await res.json().catch(() => ({ error: 'Hata' }));
            alert('Hata: ' + (e.error || res.status));
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

// Change SSL certificate
async function changeSSL(domain, ruleId) {
    if (!authToken) return alert('Önce giriş yapın.');

    if (!confirm(`${domain} için SSL sertifikasını değiştirmek istediğinizden emin misiniz?`)) return;

    const email = prompt('Yeni sertifika için e-posta adresi:');
    if (!email) return;

    try {
        const res = await fetch(`${API_BASE}/ssl/certificates/${domain}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
            body: JSON.stringify({ email, force: true })
        });

        if (res.ok) {
            alert('SSL sertifikası başarıyla güncellendi!');
            loadIngressRules();
            loadSSLCertificates();
        } else {
            const e = await res.json().catch(() => ({ error: 'Hata' }));
            alert('Hata: ' + (e.error || res.status));
        }
    } catch (error) {
        alert('Hata: ' + error.message);
    }
}

// Toggle SSL Selection
function updateRedirectAvailability() {
    const checkbox = document.getElementById('redirectToHttps');
    if (!checkbox) return;
    const sslType = document.querySelector('input[name="ssl_type"]:checked')?.value;
    const isEnabled = sslType === 'select' || sslType === 'new';
    checkbox.disabled = !isEnabled;
    if (!isEnabled) {
        checkbox.checked = false;
    }
}

// Toggle SSL Selection
function toggleSSLSelection() {
    const sslType = document.querySelector('input[name="ssl_type"]:checked')?.value;
    const sslSelectGroup = document.getElementById('sslSelectGroup');
    const sslNewGroup = document.getElementById('sslNewGroup');
    const dnsGroup = document.getElementById('dnsProviderGroup');

    if (sslType === 'select') {
        sslSelectGroup.style.display = 'block';
        sslNewGroup.style.display = 'none';
        dnsGroup.style.display = 'none';
        const domainValue = document.querySelector('[name="domain"]')?.value;
        loadAvailableCertificates(domainValue);
    } else if (sslType === 'new') {
        sslSelectGroup.style.display = 'none';
        sslNewGroup.style.display = 'block';
        toggleDNSProvider();
    } else {
        sslSelectGroup.style.display = 'none';
        sslNewGroup.style.display = 'none';
        dnsGroup.style.display = 'none';
    }

    updateRedirectAvailability();
}

// Toggle DNS Provider (for new SSL)
function toggleDNSProvider() {
    const newSslType = document.querySelector('input[name="new_ssl_type"]:checked')?.value;
    const dnsGroup = document.getElementById('dnsProviderGroup');
    const dnsProvider = document.getElementById('dnsProvider');

    if (newSslType === 'wildcard') {
        dnsGroup.style.display = 'block';
        dnsProvider.required = true;
        toggleAPIKeyInput();
    } else {
        dnsGroup.style.display = 'none';
        dnsProvider.required = false;
        dnsProvider.value = '';
        const warningEl = document.getElementById('heNetWarning');
        if (warningEl) warningEl.style.display = 'none';
    }
}

// Toggle API Key input based on DNS provider
function toggleAPIKeyInput() {
    const dnsProvider = document.getElementById('dnsProvider')?.value;
    const warningEl = document.getElementById('heNetWarning');

    if (dnsProvider === 'he-net') {
        if (warningEl) warningEl.style.display = 'block';
        const helpEl = document.getElementById('dnsProviderHelp');
        if (helpEl) helpEl.textContent = 'Hurricane Electric için resmi API yoktur. Manuel DNS challenge gerekir.';
    } else {
        if (warningEl) warningEl.style.display = 'none';
        const helpEl = document.getElementById('dnsProviderHelp');
        if (helpEl) helpEl.textContent = 'DNS credentials dosyasını /app/config/certbot/creds/ klasörüne eklemeniz gerekiyor';
    }
}

// Load available certificates for domain
async function loadAvailableCertificates(domainOverride) {
    const domainInput = document.querySelector('[name="domain"]');
    const domain = domainOverride || domainInput?.value;
    const certSelect = document.getElementById('sslCertSelect');

    if (!domain) {
        certSelect.innerHTML = '<option value="">Önce domain girin</option>';
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/ssl/certificates/available/${domain}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (!response.ok) throw new Error('Sertifikalar yüklenemedi');

        const certs = await response.json();

        if (certs.length === 0) {
            certSelect.innerHTML = '<option value="">Bu domain için uygun sertifika yok</option>';
        } else {
            certSelect.innerHTML = '<option value="">Seçiniz</option>' +
                certs.map(cert =>
                    `<option value="${cert.id}" data-cert-path="${cert.cert_path}" data-ssl-type="${cert.ssl_type}">
                        ${cert.cert_domain} ${cert.ssl_type === 'wildcard' ? '(Wildcard)' : ''} - ${new Date(cert.expires_at).toLocaleDateString('tr-TR')}
                    </option>`
                ).join('');
        }
    } catch (error) {
        certSelect.innerHTML = '<option value="">Hata: ' + error.message + '</option>';
    }
}

// Load all certificates for dropdown
async function loadAllCertificates() {
    try {
        const response = await fetch(`${API_BASE}/ssl/certificates`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        if (!response.ok) throw new Error('Sertifikalar yüklenemedi');

        return await response.json();
    } catch (error) {
        console.error('Error loading certificates:', error);
        return [];
    }
}

// Enhanced DNS Challenge Modal
async function showDNSChallengeModal(data, requestData) {
    console.log('Showing DNS Challenge Modal with data:', data);

    try {
        // Extract domain information
        const domain = data.domain || requestData?.domain || '';
        const baseDomain = domain.replace('*.', '');
        const txtDomain = data.txt_domain || `_acme-challenge.${baseDomain}`;
        const txtValue = data.txt_record || data.txtValue || '';

        // Populate modal elements
        const elements = {
            dnsChallengeDomain: document.getElementById('dnsChallengeDomain'),
            dnsChallengeBaseDomain: document.getElementById('dnsChallengeBaseDomain'),
            dnsChallengeBaseDomainDisplay: document.getElementById('dnsChallengeBaseDomainDisplay'),
            dnsChallengeName: document.getElementById('dnsChallengeName'),
            dnsChallengeValue: document.getElementById('dnsChallengeValue'),
            dnsChallengeNameDisplay: document.getElementById('dnsChallengeNameDisplay'),
            dnsChallengeValueDisplay: document.getElementById('dnsChallengeValueDisplay')
        };

        // Check if all required elements exist
        const missingElements = Object.entries(elements)
            .filter(([key, element]) => !element)
            .map(([key]) => key);

        if (missingElements.length > 0) {
            console.error('Missing DNS challenge modal elements:', missingElements);
            // Fallback to alert
            const alertText = `Manuel DNS Challenge Gerekli!

Domain: ${domain}
TXT Record Name: ${txtDomain}
TXT Record Value: ${txtValue}

Lütfen bu TXT kaydını DNS sağlayıcınıza ekleyin.`;
            alert(alertText);
            return;
        }

        // Populate elements
        elements.dnsChallengeDomain.textContent = domain;
        elements.dnsChallengeBaseDomain.textContent = baseDomain;
        elements.dnsChallengeBaseDomainDisplay.textContent = baseDomain;
        elements.dnsChallengeName.value = txtDomain;
        elements.dnsChallengeValue.value = txtValue;
        if (elements.dnsChallengeNameDisplay) elements.dnsChallengeNameDisplay.textContent = txtDomain;
        if (elements.dnsChallengeValueDisplay) elements.dnsChallengeValueDisplay.textContent = txtValue;

        // Store challenge data for retry
        window.lastDNSChallengeData = {
            domain: domain,
            email: requestData?.email || '',
            dnsProvider: requestData?.dnsProvider || 'he-net',
            txt_domain: txtDomain,
            txt_record: txtValue,
            lastTxtRecord: txtValue, // Store initial TXT record to detect changes
            session_id: data.session_id || null
        };

        // Setup DNS checker
        setupDNSChecker(txtDomain, txtValue);

        // Show modal
        const modalElement = document.getElementById('dnsChallengeModal');
        if (modalElement) {
            const modal = new bootstrap.Modal(modalElement, {
                backdrop: 'static',
                keyboard: false
            });
            modal.show();
            console.log('DNS Challenge Modal shown successfully');
        } else {
            console.error('DNS Challenge Modal element not found');
            // Fallback to alert
            const alertText = `Manuel DNS Challenge Gerekli!

Domain: ${domain}
TXT Record Name: ${txtDomain}
TXT Record Value: ${txtValue}`;
            alert(alertText);
        }
    } catch (error) {
        console.error('Error showing DNS Challenge Modal:', error);
        // Fallback to alert
        const alertText = `Manuel DNS Challenge Gerekli!

Hata: ${error.message}`;
        alert(alertText);
    }
}

// Enhanced SSL error handling with detailed feedback
async function handleSSLError(data, requestData, isRetry = false) {
    const errorType = data.type || 'UNKNOWN_ERROR';

    console.log('Handling SSL error:', { errorType, data, requestData });

    switch (errorType) {
        case 'DNS_CHALLENGE':
            if (data.txtDomain && data.txtValue) {
                if (isRetry) {
                    // Update existing modal with new values
                    document.getElementById('txtDomain').textContent = data.txtDomain;
                    document.getElementById('txtValue').textContent = data.txtValue;
                    showAlert('Yeni DNS challenge token oluşturuldu. Lütfen TXT kaydını güncelleyin.', 'warning');
                } else {
                    await showDNSChallengeModal(data, requestData);
                }
            } else {
                showAlert('DNS Challenge gerekli ancak TXT record bilgisi alınamadı: ' + data.error, 'danger');
            }
            break;

        case 'CERTBOT_ERROR':
            const certbotMsg = data.error || 'Certbot işlemi başarısız';
            showAlert(`
                <strong>Certbot Hatası:</strong><br>
                ${certbotMsg}<br>
                <small class="text-muted">Detaylar için hata raporuna bakın</small>
            `, 'danger', true);

            // Show detailed error in console and optionally in modal
            if (data.stdout || data.stderr || data.certbot_output) {
                console.error('Certbot detailed output:', {
                    stdout: data.stdout || data.certbot_output?.stdout,
                    stderr: data.stderr || data.certbot_output?.stderr,
                    fullOutput: data.certbot_output?.fullOutput
                });

                // Show debug modal for detailed error
                if (data.certbot_output?.fullOutput || data.certbot_output?.stderr) {
                    setTimeout(() => {
                        showCertbotErrorModal(certbotMsg, data.certbot_output || { stdout: data.stdout, stderr: data.stderr });
                    }, 1000);
                }
            }
            break;

        case 'CREDENTIALS_NOT_FOUND':
            const provider = requestData?.dnsProvider || 'DNS provider';
            showAlert(`
                <strong>DNS Kimlik Bilgileri Bulunamadı:</strong><br>
                ${provider} için credentials dosyası bulunamadı.<br>
                <small class="text-muted">Yardım için otomatik açılacak modalı kontrol edin</small>
            `, 'warning', true);
            setTimeout(() => showCredentialsHelp(provider), 1500);
            break;

        case 'CREDENTIALS_PERMISSION_ERROR':
            showAlert(`
                <strong>Dosya İzin Hatası:</strong><br>
                DNS kimlik bilgileri dosyası okunamıyor.<br>
                <code>chmod 600 /app/config/certbot/creds/*.ini</code> komutunu çalıştırın
            `, 'warning');
            break;

        case 'DOMAIN_VALIDATION_ERROR':
            showAlert(`
                <strong>Domain Doğrulama Hatası:</strong><br>
                ${data.error || 'Geçersiz domain formatı'}<br>
                <small class="text-muted">Domain formatını kontrol edin (example.com veya *.example.com)</small>
            `, 'warning');
            break;

        case 'RATE_LIMIT_ERROR':
            showAlert(`
                <strong>Rate Limit Aşıldı:</strong><br>
                Let's Encrypt haftalık sertifika limitı aşıldı.<br>
                <small class="text-muted">Lütfen bir hafta sonra tekrar deneyin</small>
            `, 'warning');
            break;

        case 'NETWORK_ERROR':
            showAlert(`
                <strong>Ağ Bağlantı Hatası:</strong><br>
                Let's Encrypt sunucularına erişilemiyor.<br>
                <small class="text-muted">İnternet bağlantınızı ve firewall ayarlarınızı kontrol edin</small>
            `, 'danger');
            break;

        default:
            // Handle manual DNS challenge (common case)
            if (data.requires_manual_dns || data.txt_record) {
                await showDNSChallengeModal(data, requestData);
            } else {
                const errorMsg = data.error || data.message || 'Bilinmeyen hata oluştu';
                showAlert(`
                    <strong>SSL Sertifika Hatası:</strong><br>
                    ${errorMsg}<br>
                    <small class="text-muted">Hata kodu: ${data.code || 'UNKNOWN'}</small>
                `, 'danger');

                // Log additional context
                console.error('SSL Error Details:', {
                    errorType,
                    data,
                    requestData,
                    timestamp: new Date().toISOString()
                });
            }
    }
}

// Utility functions for validation
function isValidDomain(domain) {
    const domainRegex = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$/;
    return domainRegex.test(domain);
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Enhanced alert system with better error categorization
function showAlert(message, type = 'info', persistent = false) {
    // Remove existing alerts of same type (unless persistent)
    if (!persistent) {
        const existingAlerts = document.querySelectorAll(`.alert-custom.alert-${type}`);
        existingAlerts.forEach(alert => alert.remove());
    }

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show alert-custom shadow`;
    alertDiv.style.position = 'fixed';
    alertDiv.style.top = '20px';
    alertDiv.style.right = '20px';
    alertDiv.style.zIndex = '9999';
    alertDiv.style.maxWidth = '450px';
    alertDiv.style.minWidth = '300px';

    // Add appropriate icon based on type
    const iconHtml = type === 'success' ? '<i class="bi bi-check-circle-fill me-2"></i>' :
        type === 'danger' ? '<i class="bi bi-x-circle-fill me-2"></i>' :
            type === 'warning' ? '<i class="bi bi-exclamation-triangle-fill me-2"></i>' :
                type === 'info' ? '<i class="bi bi-info-circle-fill me-2"></i>' : '';

    alertDiv.innerHTML = `
        <div class="d-flex align-items-start">
            ${iconHtml}
            <div class="flex-grow-1">${message}</div>
            <button type="button" class="btn-close btn-close-white ms-2" onclick="this.parentElement.parentElement.remove()"></button>
        </div>
    `;

    document.body.appendChild(alertDiv);

    // Auto-remove after different durations based on type
    const duration = type === 'danger' ? 8000 : type === 'warning' ? 6000 : 5000;
    if (!persistent) {
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, duration);
    }
}

// Enhanced SSL Progress indicator with real-time feedback
function showSSLProgress(message, type = 'info', showSpinner = true) {
    let progressDiv = document.getElementById('ssl-progress');
    if (!progressDiv) {
        progressDiv = document.createElement('div');
        progressDiv.id = 'ssl-progress';
        progressDiv.style.position = 'fixed';
        progressDiv.style.bottom = '20px';
        progressDiv.style.right = '20px';
        progressDiv.style.zIndex = '9999';
        progressDiv.style.maxWidth = '400px';
        progressDiv.style.minWidth = '300px';
        document.body.appendChild(progressDiv);
    }

    const typeClass = type === 'error' ? 'danger' : type;
    const spinnerHtml = (showSpinner && type === 'info') ?
        '<div class="spinner-border spinner-border-sm me-2" role="status"></div>' : '';

    const iconHtml = type === 'success' ? '<i class="bi bi-check-circle me-2"></i>' :
        type === 'danger' ? '<i class="bi bi-x-circle me-2"></i>' :
            type === 'warning' ? '<i class="bi bi-exclamation-triangle me-2"></i>' : '';

    progressDiv.innerHTML = `
        <div class="alert alert-${typeClass} d-flex align-items-center shadow">
            ${spinnerHtml}${iconHtml}
            <div class="flex-grow-1">${message}</div>
            <button type="button" class="btn-close btn-close-white ms-2" onclick="hideSSLProgress()"></button>
        </div>
    `;

    // Auto-hide success/error messages after 5 seconds
    if (type === 'success' || type === 'danger') {
        setTimeout(() => {
            hideSSLProgress();
        }, 5000);
    }
}

function hideSSLProgress() {
    const progressDiv = document.getElementById('ssl-progress');
    if (progressDiv) {
        progressDiv.remove();
    }
}

// Progress steps for SSL certificate creation
function showSSLSteps(currentStep, steps) {
    let stepsDiv = document.getElementById('ssl-steps');
    if (!stepsDiv) {
        stepsDiv = document.createElement('div');
        stepsDiv.id = 'ssl-steps';
        stepsDiv.style.position = 'fixed';
        stepsDiv.style.top = '20px';
        stepsDiv.style.right = '20px';
        stepsDiv.style.zIndex = '9998';
        stepsDiv.style.maxWidth = '350px';
        document.body.appendChild(stepsDiv);
    }

    const stepsHtml = steps.map((step, index) => {
        const isActive = index === currentStep;
        const isCompleted = index < currentStep;
        const statusClass = isCompleted ? 'text-success' : isActive ? 'text-primary' : 'text-muted';
        const icon = isCompleted ? 'bi-check-circle-fill' : isActive ? 'bi-arrow-right-circle' : 'bi-circle';

        return `
            <div class="d-flex align-items-center mb-2 ${statusClass}">
                <i class="bi ${icon} me-2"></i>
                <small>${step}</small>
            </div>
        `;
    }).join('');

    stepsDiv.innerHTML = `
        <div class="card shadow-sm">
            <div class="card-header py-2">
                <h6 class="mb-0">SSL Sertifika İşlemi</h6>
            </div>
            <div class="card-body py-2">
                ${stepsHtml}
            </div>
        </div>
    `;
}

function hideSSLSteps() {
    const stepsDiv = document.getElementById('ssl-steps');
    if (stepsDiv) {
        stepsDiv.remove();
    }
}

// Enhanced DNS propagation checker with better feedback
let dnsCheckInterval = null;

function setupDNSChecker(txtDomain, txtValue) {
    const checkerDiv = document.getElementById('dns-checker');
    if (checkerDiv) {
        checkerDiv.innerHTML = `
            <div class="mt-3">
                <div class="d-flex gap-2 mb-2">
                    <button type="button" class="btn btn-outline-info btn-sm" onclick="checkDNSPropagation('${txtDomain}', '${txtValue}')">
                        <i class="bi bi-search"></i> DNS Kontrol Et
                    </button>
                    <button type="button" class="btn btn-outline-secondary btn-sm" onclick="startAutoDNSCheck('${txtDomain}', '${txtValue}')">
                        <i class="bi bi-arrow-repeat"></i> Otomatik Kontrol
                    </button>
                    <button type="button" class="btn btn-outline-danger btn-sm" onclick="stopAutoDNSCheck()" style="display: none;" id="stopDnsCheck">
                        <i class="bi bi-stop"></i> Durdur
                    </button>
                </div>
                <div id="dns-status" class="mt-2"></div>
                <div id="dns-help" class="mt-2">
                    <small class="text-muted">
                        <i class="bi bi-info-circle"></i> 
                        DNS yayılımı genellikle 2-10 dakika sürer. 
                        TXT kaydını ekledikten sonra birkaç dakika bekleyip kontrol edin.
                    </small>
                </div>
            </div>
        `;
    }
}

async function checkDNSPropagation(txtDomain, txtValue) {
    const statusDiv = document.getElementById('dns-status');
    statusDiv.innerHTML = `
        <div class="d-flex align-items-center">
            <div class="spinner-border spinner-border-sm me-2"></div>
            <span>DNS yayılımı kontrol ediliyor...</span>
        </div>
    `;

    try {
        // Use multiple DNS checkers for better reliability
        const checkers = [
            { name: 'Google DNS', url: `https://dns.google/resolve?name=${txtDomain}&type=TXT` },
            { name: 'Cloudflare DNS', url: `https://cloudflare-dns.com/dns-query?name=${txtDomain}&type=TXT`, headers: { 'Accept': 'application/dns-json' } }
        ];

        let foundCorrectRecord = false;
        let checkerResults = [];

        for (const checker of checkers) {
            try {
                const response = await fetch(checker.url, { headers: checker.headers || {} });
                const data = await response.json();

                if (data.Answer && data.Answer.length > 0) {
                    const txtRecords = data.Answer.filter(record => record.type === 16);
                    const hasCorrectValue = txtRecords.some(record => {
                        const recordData = record.data.replace(/"/g, '');
                        return recordData === txtValue || record.data.includes(txtValue);
                    });

                    checkerResults.push({
                        checker: checker.name,
                        found: hasCorrectValue,
                        records: txtRecords.map(r => r.data)
                    });

                    if (hasCorrectValue) {
                        foundCorrectRecord = true;
                    }
                } else {
                    checkerResults.push({
                        checker: checker.name,
                        found: false,
                        records: []
                    });
                }
            } catch (checkerError) {
                console.warn(`${checker.name} check failed:`, checkerError);
                checkerResults.push({
                    checker: checker.name,
                    error: checkerError.message
                });
            }
        }

        // Display results
        if (foundCorrectRecord) {
            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="bi bi-check-circle-fill me-2"></i>
                    <strong>DNS kaydı doğru şekilde yayılmış!</strong><br>
                    <small>TXT kaydı DNS sunucularında bulundu. Artık "Tekrar Dene" butonuna basabilirsiniz.</small>
                </div>
            `;

            // Enable retry button if it exists
            const retryBtn = document.querySelector('#dnsChallengeModal .btn-primary');
            if (retryBtn && retryBtn.disabled) {
                retryBtn.disabled = false;
                retryBtn.classList.add('btn-success');
                retryBtn.classList.remove('btn-primary');
                retryBtn.innerHTML = '<i class="bi bi-check-circle"></i> Tekrar Dene (Hazır)';
            }
        } else {
            const resultDetails = checkerResults.map(result => {
                if (result.error) {
                    return `<li>${result.checker}: <span class="text-warning">Hata - ${result.error}</span></li>`;
                } else if (result.found) {
                    return `<li>${result.checker}: <span class="text-success">Bulundu ✓</span></li>`;
                } else {
                    return `<li>${result.checker}: <span class="text-muted">Bulunamadı</span></li>`;
                }
            }).join('');

            statusDiv.innerHTML = `
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    <strong>DNS kaydı henüz yayılmamış</strong><br>
                    <small>TXT kaydını ekledikten sonra 2-10 dakika bekleyin.</small>
                    <details class="mt-2">
                        <summary>DNS Kontrol Sonuçları</summary>
                        <ul class="mb-0 mt-1">${resultDetails}</ul>
                    </details>
                </div>
            `;
        }
    } catch (error) {
        statusDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="bi bi-x-circle-fill me-2"></i>
                <strong>DNS kontrolü başarısız:</strong> ${error.message}<br>
                <small>Lütfen manuel olarak TXT kaydını kontrol edin.</small>
            </div>
        `;
    }
}

function startAutoDNSCheck(txtDomain, txtValue) {
    if (dnsCheckInterval) {
        clearInterval(dnsCheckInterval);
    }

    // Show/hide buttons
    const startBtn = document.querySelector('button[onclick*="startAutoDNSCheck"]');
    const stopBtn = document.getElementById('stopDnsCheck');
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = 'inline-block';

    // Initial check
    checkDNSPropagation(txtDomain, txtValue);

    // Check every 30 seconds
    dnsCheckInterval = setInterval(() => {
        checkDNSPropagation(txtDomain, txtValue);
    }, 30000);

    // Show status
    const statusDiv = document.getElementById('dns-status');
    const currentContent = statusDiv.innerHTML;
    statusDiv.innerHTML = currentContent + `
        <div class="mt-2">
            <small class="text-info">
                <i class="bi bi-arrow-repeat"></i> 
                Otomatik kontrol aktif (30 saniyede bir)
            </small>
        </div>
    `;
}

function stopAutoDNSCheck() {
    if (dnsCheckInterval) {
        clearInterval(dnsCheckInterval);
        dnsCheckInterval = null;
    }

    // Show/hide buttons
    const startBtn = document.querySelector('button[onclick*="startAutoDNSCheck"]');
    const stopBtn = document.getElementById('stopDnsCheck');
    if (startBtn) startBtn.style.display = 'inline-block';
    if (stopBtn) stopBtn.style.display = 'none';

    // Update status
    const statusDiv = document.getElementById('dns-status');
    const autoStatusEl = statusDiv.querySelector('small.text-info');
    if (autoStatusEl) {
        autoStatusEl.remove();
    }
}

function stopDNSPropagationCheck() {
    stopAutoDNSCheck();
}

// Copy button functionality
function setupCopyButtons() {
    // Add copy functionality to TXT domain and value
    const txtDomainEl = document.getElementById('txtDomain');
    const txtValueEl = document.getElementById('txtValue');

    if (txtDomainEl && !txtDomainEl.nextElementSibling?.classList.contains('copy-btn')) {
        addCopyButton(txtDomainEl, 'txtDomain');
    }

    if (txtValueEl && !txtValueEl.nextElementSibling?.classList.contains('copy-btn')) {
        addCopyButton(txtValueEl, 'txtValue');
    }
}

function addCopyButton(element, type) {
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn btn-outline-secondary btn-sm ms-2 copy-btn';
    copyBtn.innerHTML = '<i class="bi bi-clipboard"></i>';
    copyBtn.onclick = () => copyTextToClipboard(element.textContent, copyBtn);

    element.parentNode.appendChild(copyBtn);
}

async function copyTextToClipboard(text, button) {
    try {
        await navigator.clipboard.writeText(text);
        const originalHTML = button.innerHTML;
        button.innerHTML = '<i class="bi bi-check"></i>';
        button.classList.add('btn-success');
        button.classList.remove('btn-outline-secondary');

        setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('btn-success');
            button.classList.add('btn-outline-secondary');
        }, 2000);
    } catch (error) {
        showAlert('Kopyalama başarısız: ' + error.message, 'warning');
    }
}

async function loadMembers() {
    const tbody = document.getElementById('members-table-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="text-center">Yükleniyor...</td></tr>';
    try {
        const response = await fetch(`${API_BASE}/members`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (response.status === 403) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Bu işlem için yetkiniz yok</td></tr>';
            return;
        }
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Sunucu hatası (${response.status})`);
        }
        const members = await response.json();
        if (!Array.isArray(members) || members.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Henüz kullanıcı yok</td></tr>';
            return;
        }
        tbody.innerHTML = members.map(member => `
            <tr>
                <td>${member.id}</td>
                <td>${member.email}</td>
                <td>${(member.role || '').toUpperCase()}</td>
                <td>${formatDateTime(member.created_at, true)}</td>
                <td>
                    <button class="btn btn-sm btn-warning me-2" onclick="showChangePasswordModal(${member.id}, '${member.email}')">
                        <i class="bi bi-key"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteMember(${member.id}, '${member.email}')">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading members:', error);
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-danger">Hata: ${error.message}</td></tr>`;
    }
}

function showAddMemberModal() {
    const form = document.getElementById('addMemberForm');
    if (form) {
        form.reset();
    }
    new bootstrap.Modal(document.getElementById('addMemberModal')).show();
}

function showSelfPasswordModal() {
    if (!authToken) {
        showLoginModal();
        return;
    }
    const form = document.getElementById('selfPasswordForm');
    if (form) form.reset();
    new bootstrap.Modal(document.getElementById('selfPasswordModal')).show();
}

async function updateSelfPassword() {
    const form = document.getElementById('selfPasswordForm');
    const currentPassword = form.querySelector('[name="current_password"]').value;
    const newPassword = form.querySelector('[name="new_password"]').value;
    const confirmPassword = form.querySelector('[name="new_password_confirm"]').value;

    if (!newPassword || newPassword.length < 8) {
        showAlert('Yeni şifre en az 8 karakter olmalıdır', 'warning');
        return;
    }
    if (newPassword !== confirmPassword) {
        showAlert('Yeni şifre ve tekrarı eşleşmiyor', 'warning');
        return;
    }

    try {
        const response = await fetch(`${AUTH_BASE}/auth/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Şifre güncellenemedi');
        }
        showAlert('Şifreniz başarıyla güncellendi', 'success');
        bootstrap.Modal.getInstance(document.getElementById('selfPasswordModal'))?.hide();
    } catch (error) {
        console.error('Error updating self password:', error);
        showAlert(error.message, 'danger');
    }
}

async function saveMember() {
    const form = document.getElementById('addMemberForm');
    const formData = new FormData(form);
    const email = formData.get('email')?.trim();
    const password = formData.get('password');
    const confirmPassword = formData.get('password_confirm');
    const role = formData.get('role');

    if (!email) {
        showAlert('E-posta adresi gerekli', 'warning');
        return;
    }
    if (!password || password.length < 8) {
        showAlert('Şifre en az 8 karakter olmalıdır', 'warning');
        return;
    }
    if (password !== confirmPassword) {
        showAlert('Şifre ve şifre tekrarı eşleşmiyor', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/members`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ email, password, role })
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Kullanıcı oluşturulamadı');
        }

        showAlert('Kullanıcı başarıyla eklendi', 'success');
        bootstrap.Modal.getInstance(document.getElementById('addMemberModal'))?.hide();
        loadMembers();
    } catch (error) {
        console.error('Error creating member:', error);
        showAlert(error.message, 'danger');
    }
}

function showChangePasswordModal(memberId, email) {
    const form = document.getElementById('changePasswordForm');
    if (!form) return;
    form.reset();
    form.querySelector('[name="member_id"]').value = memberId;
    document.getElementById('changePasswordEmail').textContent = email;
    new bootstrap.Modal(document.getElementById('changePasswordModal')).show();
}

async function updateMemberPassword() {
    const form = document.getElementById('changePasswordForm');
    const memberId = form.querySelector('[name="member_id"]').value;
    const password = form.querySelector('[name="password"]').value;
    const confirmPassword = form.querySelector('[name="password_confirm"]').value;

    if (!password || password.length < 8) {
        showAlert('Şifre en az 8 karakter olmalıdır', 'warning');
        return;
    }
    if (password !== confirmPassword) {
        showAlert('Şifre ve şifre tekrarı eşleşmiyor', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/members/${memberId}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ password })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Şifre güncellenemedi');
        }
        showAlert('Şifre başarıyla güncellendi', 'success');
        bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'))?.hide();
    } catch (error) {
        console.error('Error updating member password:', error);
        showAlert(error.message, 'danger');
    }
}

async function deleteMember(memberId, email) {
    if (!confirm(`${email} kullanıcısını silmek istediğinize emin misiniz?`)) {
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/members/${memberId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || 'Kullanıcı silinemedi');
        }
        showAlert('Kullanıcı silindi', 'success');
        loadMembers();
    } catch (error) {
        console.error('Error deleting member:', error);
        showAlert(error.message, 'danger');
    }
}

// --- Active Connections Monitor ---
let connectionInterval = null;
let isConnectionPaused = false;
let cachedConnectionData = []; // Cache for filtering

function formatBackendName(rawName) {
    if (!rawName) return '-';
    // Handle standard pattern: backend_web_example_com
    if (rawName.startsWith('backend_web_')) {
        return rawName.replace('backend_web_', '').replace(/_/g, '.') + ' (Web)';
    }
    // Handle API/Internal
    if (rawName === 'api_backend') return 'Yönetim Paneli (API)';
    if (rawName === 'web_backend') return 'Yönetim Paneli (Web)';
    if (rawName === 'spoa') return 'ModSecurity Agent';
    // Handle generic IDs (backend_ID) - Try to resolve from cached rules
    if (rawName.startsWith('backend_')) {
        const id = rawName.replace('backend_', '');
        // Find rule with this ID
        const rule = cachedRules.find(r => r.id == id);
        if (rule) {
            return rule.domain + ' (ID: ' + id + ')';
        }
        return 'Kural ID: ' + id;
    }
    return rawName;
}

function clearConnectionFilters() {
    const srcInput = document.getElementById('conn-filter-src');
    const beInput = document.getElementById('conn-filter-be');
    if (srcInput) srcInput.value = '';
    if (beInput) beInput.value = '';
    loadConnections(); // Re-render from cache
}

function showConnectionsModal() {
    const modal = new window.bootstrap.Modal(document.getElementById('connectionsModal'));
    modal.show();

    // Reset filters
    clearConnectionFilters();

    // Start polling immediately
    isConnectionPaused = false;
    updateConnectionPauseButton();
    fetchConnections();

    if (connectionInterval) clearInterval(connectionInterval);
    connectionInterval = setInterval(() => {
        if (!isConnectionPaused) fetchConnections();
    }, 2000); // 2 seconds refresh

    // Stop polling when modal closed
    document.getElementById('connectionsModal').addEventListener('hidden.bs.modal', function () {
        if (connectionInterval) clearInterval(connectionInterval);
        connectionInterval = null;
    });
}

function toggleConnectionPause() {
    isConnectionPaused = !isConnectionPaused;
    updateConnectionPauseButton();
}

function updateConnectionPauseButton() {
    const btn = document.getElementById('btn-pause-connections');
    if (isConnectionPaused) {
        btn.innerHTML = '<i class="bi bi-play-fill me-1"></i> <span>Devam Et</span>';
        btn.classList.replace('btn-outline-warning', 'btn-outline-success');
    } else {
        btn.innerHTML = '<i class="bi bi-pause-fill me-1"></i> <span>Durdur</span>';
        btn.classList.replace('btn-outline-success', 'btn-outline-warning');
    }
}

// Fetch data from API
async function fetchConnections() {
    try {
        // Ensure we have rules for naming resolution
        if (cachedRules.length === 0) {
            try {
                const rResponse = await fetch(`${API_BASE}/rules`, { headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {} });
                if (rResponse.ok) cachedRules = await rResponse.json();
            } catch (ignore) { }
        }

        const response = await fetch(`${API_BASE}/ha_sessions`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });

        if (!response.ok) return;

        cachedConnectionData = await response.json();
        document.getElementById('connection-count-badge').textContent = `${cachedConnectionData.length} Bağlantı`;

        // Render
        loadConnections();

    } catch (e) {
        console.error("Load Connections failed", e);
    }
}

// Render Table (called by fetch or filter input)
function loadConnections() {
    const tbody = document.getElementById('connections-table-body');
    const srcInput = document.getElementById('conn-filter-src');
    const beInput = document.getElementById('conn-filter-be');

    // Safety check if inputs exist (in case modal HTML is not updated yet)
    const filterSrc = srcInput ? srcInput.value.toLowerCase() : '';
    const filterBe = beInput ? beInput.value.toLowerCase() : '';

    const filtered = cachedConnectionData.filter(s => {
        const src = (s.src || '').toLowerCase();
        const beFormatted = formatBackendName(s.be || '').toLowerCase();
        // Also search in raw backend name
        const beRaw = (s.be || '').toLowerCase();

        return src.includes(filterSrc) && (beFormatted.includes(filterBe) || beRaw.includes(filterBe));
    });

    // SORTING: Real users first, System/Internal last
    filtered.sort((a, b) => {
        const aIsSystem = (a.src || '').includes('Internal') || (a.src || '').includes('Check');
        const bIsSystem = (b.src || '').includes('Internal') || (b.src || '').includes('Check');

        if (aIsSystem && !bIsSystem) return 1;  // System goes down
        if (!aIsSystem && bIsSystem) return -1; // User goes up
        return 0;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-muted">Sonuç bulunamadı</td></tr>';
        return;
    }

    // Increased limit to 200 rows
    tbody.innerHTML = filtered.slice(0, 200).map(s => {
        const srcIp = s.src ? s.src.split(':')[0] : '-';
        const duration = s.age || '-';
        const prettyBackend = formatBackendName(s.be);

        let statusBadge = '<span class="badge bg-success bg-opacity-25 text-success">Active</span>';
        if (s.src.includes('Internal') || s.src.includes('Check')) statusBadge = '<span class="badge bg-secondary">System</span>';

        return `
            <tr>
                <td><span class="font-monospace text-info">${srcIp}</span></td>
                <td>${s.fe || '-'}</td>
                <td>
                    <div class="d-flex flex-column">
                        <span class="fw-bold text-white" style="font-size: 0.9em;">${prettyBackend}</span>
                        <span class="text-muted small" style="font-size: 0.75em;">${s.be || '-'}</span>
                    </div>
                </td>
                <td>${duration}</td>
                <td>${statusBadge}</td>
            </tr>
        `;
    }).join('');
}

// Live Traffic Updates
let trafficInterval = null;

function startTrafficUpdates() {
    if (trafficInterval) clearInterval(trafficInterval);
    updateTrafficStats(); // Initial call
    trafficInterval = setInterval(updateTrafficStats, 3000); // Update every 3 seconds
}

async function updateTrafficStats() {
    // Only update if ingress section is visible
    if (document.getElementById('ingress-section').style.display === 'none') return;

    try {
        const response = await fetch(`${API_BASE}/ha_stats`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });

        if (!response.ok) return;

        // Parse CSV
        const csv = await response.text();
        const stats = parseStatsCSV(csv);

        // Update each row matching backend name
        stats.forEach(s => {
            if (s.svname !== 'BACKEND') return;

            // Backend name is s.pxname (e.g. backend_12)
            // Find element that has data-backend matching this name
            const el = document.querySelector(`[data-backend="${s.pxname}"]`);

            if (el) {
                const statusColor = s.status === 'UP' ? 'success' : 'danger';

                el.innerHTML = `
                    <div class="d-flex flex-column" style="font-size: 0.8rem">
                        <div><i class="bi bi-arrow-down text-success"></i> ${formatBytes(s.bin)} <i class="bi bi-arrow-up text-primary"></i> ${formatBytes(s.bout)}</div>
                        <div class="mt-1">
                            <span class="badge bg-${statusColor} p-1">${s.status}</span> 
                            <span>${s.scur} conn (${s.rate}/s)</span>
                        </div>
                    </div>
                `;
            }
        });

    } catch (error) {
        console.error('Error fetching traffic stats:', error);
    }
}

function formatBytes(bytes, decimals = 1) {
    if (!bytes) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Toggle Auto Renewal
async function toggleAutoRenew(domain, enabled) {
    try {
        await fetch(`${API_BASE}/ssl/certificates/${domain}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ auto_renew: enabled })
        });
        // No alert needed for boolean toggle usually, but can log it
        console.log(`Auto renew for ${domain} set to ${enabled}`);
    } catch (error) {
        console.error('Failed to toggle auto renew:', error);
        showAlert('Otomatik yenileme durumu güncellenemedi', 'danger');
        // Revert checkbox state
        document.getElementById(`ar-${domain}`).checked = !enabled;
    }
}

// Manual Renew Trigger
async function manualRenew(domain) {
    if (!confirm(`${domain} için sertifika yenileme işlemini başlatmak istiyor musunuz?`)) return;

    // Attempt standard renew first
    showAlert('Yenileme başlatılıyor...', 'info');

    try {
        const response = await fetch(`${API_BASE}/ssl/renew/${domain}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });

        const result = await response.json();

        if (response.ok && result.success) {
            showAlert('Sertifika başarıyla yenilendi!', 'success');
            loadSSLCertificates();
        } else {
            if (result.type === 'DNS_CHALLENGE' || result.requires_manual_dns) {
                // Redirect to request flow
                const confirmManual = confirm(
                    'Bu sertifika manuel DNS doğrulaması (veya API desteklenmeyen provider) kullanıyor.\n\n' +
                    'Otomatik yenileme yapılamadı. Yeni bir sertifika talebi oluşturmak ister misiniz?'
                );

                if (confirmManual) {
                    showAlert('Lütfen "Sertifika Ekle" butonuna basarak süreci başlatın.', 'warning');
                }
            } else {
                showAlert('Yenileme başarısız: ' + (result.error || result.message), 'danger');
            }
        }
    } catch (error) {
        console.error('Renew error:', error);
        showAlert('Yenileme hatası: ' + error.message, 'danger');
    }
}



// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    setAuthUI();
    // Default to stats section (which handles auth check)
    showSection('stats');
});
