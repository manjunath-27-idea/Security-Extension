/**
 * Security Extension - Redesigned Popup Script v2.4.1
 */

let currentTabId = null;

// Theme Toggle Logic
const themeToggleBtn = document.getElementById('themeToggleBtn');
const applyTheme = (theme) => {
  document.documentElement.setAttribute('data-theme', theme);
  if (themeToggleBtn) {
    themeToggleBtn.textContent = theme === 'light' ? '🌙' : '☀️';
  }
};

chrome.storage.local.get(['theme'], (result) => {
  applyTheme(result.theme || 'dark');
});

if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    chrome.storage.local.set({ theme: newTheme });
    applyTheme(newTheme);
  });
}

// Initialize popup markup
document.getElementById('content').innerHTML = `
  <div class="score-card">
    <div class="circle-container">
      <svg>
        <circle class="circle-bg" cx="30" cy="30" r="27.5"></circle>
        <circle class="circle-progress" id="scoreRing" cx="30" cy="30" r="27.5"></circle>
      </svg>
      <span class="score-value" id="scoreNum">--</span>
    </div>
    <div class="score-details">
      <h2>Security Score</h2>
      <p id="auditLabel">Running payload audits...</p>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card critical">
      <span class="stat-val" id="statCritical">0</span>
      <span class="stat-lbl">Critical Leaks</span>
    </div>
    <div class="stat-card high">
      <span class="stat-val" id="statHigh">0</span>
      <span class="stat-lbl">High Risk</span>
    </div>
    <div class="stat-card alerts">
      <span class="stat-val" id="statAlerts">0</span>
      <span class="stat-lbl">Payload Alerts</span>
    </div>
    <div class="stat-card blocked">
      <span class="stat-val" id="statBlocked">0</span>
      <span class="stat-lbl">Blocked</span>
    </div>
  </div>

  <div class="banner" id="topFinding"></div>

  <div class="firewall-panel">
    <div class="fw-left">
      <div class="fw-title">Payload Firewall</div>
      <span class="fw-status" id="firewallStatus">Monitoring only</span>
    </div>
    <label class="switch">
      <input type="checkbox" id="firewallCheckbox">
      <span class="slider"></span>
    </label>
  </div>

  <div class="actions">
    <button class="btn btn-primary" id="dashboardBtn">
      Open Dashboard
    </button>
    <button class="btn btn-ghost" id="clearBtn">
      Clear Logs
    </button>
  </div>
`;

// Fetch active tab information
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) return;
  currentTabId = tab.id;

  const siteUrlEl = document.getElementById('siteUrl');
  if (siteUrlEl) {
    try {
      const url = new URL(tab.url);
      siteUrlEl.textContent = url.hostname;
    } catch {
      siteUrlEl.textContent = 'N/A';
    }
  }

  loadData();
});

// Listen for real-time updates from background worker
chrome.runtime.onMessage.addListener((request) => {
  if (request.action === 'securityDataUpdated') {
    if (request.tabId === currentTabId) {
      loadData();
    }
  }
});

function loadData() {
  chrome.runtime.sendMessage({ action: 'getSecurityData', tabId: currentTabId }, (response) => {
    if (chrome.runtime.lastError || !response) {
      showError('Could not load security data');
      return;
    }
    renderPopup(response);
  });
}

function renderPopup(data) {
  const { audit, payloadAlerts } = data;
  const score = audit.score;
  const grade = audit.grade;
  const gradeColor = getGradeColor(grade);

  const critical = audit.findings.filter(f => f.severity === 'critical').length;
  const high = audit.findings.filter(f => f.severity === 'high').length;
  const alertCount = payloadAlerts?.length || 0;
  const blocked = payloadAlerts?.filter(a => a.blocked).length || 0;

  // Update Score & Circle Ring
  document.getElementById('scoreNum').textContent = score;
  document.getElementById('scoreNum').style.color = gradeColor;
  
  const ring = document.getElementById('scoreRing');
  if (ring) {
    const circumference = 172.78; // 2 * PI * r
    const offset = circumference - (circumference * score) / 100;
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = gradeColor;
  }

  document.getElementById('auditLabel').textContent = audit.isSystemPage 
    ? 'Auditing inactive on system pages'
    : `Grade ${grade} — ${getGradeText(grade)}`;

  // Update stats
  document.getElementById('statCritical').textContent = critical;
  document.getElementById('statHigh').textContent = high;
  document.getElementById('statAlerts').textContent = alertCount;
  document.getElementById('statBlocked').textContent = blocked;

  // Firewall state
  chrome.storage.session.get(['firewallEnabled'], (result) => {
    const enabled = result.firewallEnabled === true;
    updateFirewallUI(enabled);
  });

  // Show top finding
  const topFinding = audit.findings[0];
  const findingEl = document.getElementById('topFinding');
  if (topFinding) {
    findingEl.style.display = 'flex';
    findingEl.className = `banner ${topFinding.severity}`;
    findingEl.innerHTML = `<span>${topFinding.title}</span>`;
  } else {
    findingEl.style.display = 'none';
  }

  // Setup Event Listeners
  document.getElementById('firewallCheckbox').addEventListener('change', toggleFirewall);
  document.getElementById('dashboardBtn').addEventListener('click', openDashboard);
  document.getElementById('clearBtn').addEventListener('click', clearData);
}

function updateFirewallUI(enabled) {
  const checkbox = document.getElementById('firewallCheckbox');
  const status = document.getElementById('firewallStatus');
  
  if (checkbox) checkbox.checked = enabled;
  if (status) {
    status.textContent = enabled ? 'Blocking critical leaks' : 'Monitoring only';
    status.style.color = enabled ? 'var(--green)' : 'var(--muted)';
  }
}

function toggleFirewall() {
  const checkbox = document.getElementById('firewallCheckbox');
  const newState = checkbox.checked;
  chrome.runtime.sendMessage({ action: 'setFirewall', tabId: currentTabId, enabled: newState });
  chrome.storage.session.set({ firewallEnabled: newState });
  updateFirewallUI(newState);
}

function openDashboard() {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
}

function clearData() {
  chrome.runtime.sendMessage({ action: 'clearData', tabId: currentTabId }, () => {
    document.getElementById('content').innerHTML =
      '<div style="text-align:center;padding:32px;color:var(--green);font-size:12px;font-weight:600;">✓ Security logs cleared</div>';
    setTimeout(() => location.reload(), 800);
  });
}

function getGradeColor(grade) {
  return { A: 'var(--green)', B: 'var(--indigo)', C: 'var(--yellow)', D: 'var(--orange)', F: 'var(--red)' }[grade] || 'var(--muted)';
}

function getGradeText(grade) {
  return { 
    A: 'Excellent protection', 
    B: 'Good, minor vulnerabilities', 
    C: 'Warning, check headers', 
    D: 'High risk detected', 
    F: 'Critical leaks present' 
  }[grade] || 'Security audit active';
}

function showError(msg) {
  document.getElementById('content').innerHTML =
    `<div style="color:var(--red);padding:24px;text-align:center;font-size:11px;font-weight:600;">${msg}</div>`;
}
