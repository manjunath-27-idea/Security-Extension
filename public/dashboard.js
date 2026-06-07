/**
 * Security Extension - Redesigned Dashboard Script v2.4.3
 */

let currentTabId = null;
let refreshInterval = null;

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const paramTabId = urlParams.get('tabId');
  
  const initDashboardForTab = (tabId) => {
    currentTabId = tabId;
    
    // Query tab details to get hostname
    if (currentTabId && currentTabId !== 'all') {
      chrome.tabs.get(currentTabId, (tab) => {
        if (!chrome.runtime.lastError && tab && tab.url) {
          const currentSiteEl = document.getElementById('currentSite');
          if (currentSiteEl) {
            try {
              currentSiteEl.textContent = new URL(tab.url).hostname;
            } catch {
              currentSiteEl.textContent = 'Unknown';
            }
          }
        }
      });
    } else if (currentTabId === 'all') {
      const currentSiteEl = document.getElementById('currentSite');
      if (currentSiteEl) {
        currentSiteEl.textContent = 'All Active Websites';
      }
    }
    loadDashboard();
  };

  if (paramTabId) {
    initDashboardForTab(parseInt(paramTabId, 10));
  } else {
    // Fallback: ask background what the activeTab is
    chrome.runtime.sendMessage({ action: 'getSecurityData' }, (response) => {
      if (response && response.tabId) {
        initDashboardForTab(response.tabId);
      } else {
        // Ultimate fallback
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const tab = tabs[0];
          if (tab) {
            initDashboardForTab(tab.id);
          }
        });
      }
    });
  }

  setupTabs();
  setupFirewallToggle();
  setupSettingsToggles();
  setupStatBoxClicks();
  setupModalClose();
  setupLocalBlocklistInput();
  setupTheme();

  const dropdown = document.getElementById('activeTabsDropdown');
  const autoFollowCb = document.getElementById('autoFollowCheckbox');

  // Load persistent Auto-Follow setting
  if (autoFollowCb) {
    chrome.storage.local.get(['autoFollowActive'], (result) => {
      const active = result.autoFollowActive !== false; // Default to true
      autoFollowCb.checked = active;
      if (active) {
        loadDashboard();
      }
    });

    autoFollowCb.addEventListener('change', () => {
      chrome.storage.local.set({ autoFollowActive: autoFollowCb.checked });
      if (autoFollowCb.checked) {
        loadDashboard(); // Will trigger auto-follow sync
      }
    });
  }

  if (dropdown) {
    dropdown.addEventListener('change', (e) => {
      const selectedValue = e.target.value;
      if (selectedValue === 'all') {
        if (autoFollowCb) {
          autoFollowCb.checked = false;
          chrome.storage.local.set({ autoFollowActive: false });
        }
        currentTabId = 'all';
        initDashboardForTab('all');
      } else {
        const selectedTabId = parseInt(selectedValue, 10);
        if (selectedTabId && selectedTabId !== currentTabId) {
          if (autoFollowCb) {
            autoFollowCb.checked = false;
            chrome.storage.local.set({ autoFollowActive: false });
          }
          initDashboardForTab(selectedTabId);
        }
      }
    });
  }

  // Handle visibility changes to refresh stats immediately
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      loadDashboard();
    }
  });

  const btnClearGlobal = document.getElementById('btnClearGlobalHistory');
  if (btnClearGlobal) {
    btnClearGlobal.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'clearGlobalHistory' }, () => {
        loadDashboard();
      });
    });
  }

  // Listen for real-time updates from background worker
  chrome.runtime.onMessage.addListener((request) => {
    if (request.action === 'securityDataUpdated') {
      loadDashboard();
    }
  });

  document.getElementById('btnClear').addEventListener('click', clearData);
  document.getElementById('btnRefresh').addEventListener('click', loadDashboard);
  refreshInterval = setInterval(loadDashboard, 10000); // Polling fallback slowed to 10s
});

function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    });
  });
}

function setupFirewallToggle() {
  const toggle = document.getElementById('firewallToggle');
  
  chrome.storage.session.get(['firewallEnabled'], (result) => {
    const enabled = result.firewallEnabled === true;
    if (toggle) toggle.checked = enabled;
    updateFirewallLabel(enabled);
  });

  if (toggle) {
    toggle.addEventListener('change', () => {
      const newState = toggle.checked;
      chrome.storage.session.set({ firewallEnabled: newState });
      chrome.runtime.sendMessage({ action: 'setFirewall', tabId: currentTabId, enabled: newState });
      updateFirewallLabel(newState);
    });
  }
}

function updateFirewallLabel(enabled) {
  const label = document.getElementById('fwLabelText');
  if (label) {
    label.textContent = enabled ? 'FIREWALL ON' : 'FIREWALL OFF';
    label.className = enabled ? 'fw-label active' : 'fw-label';
    label.style.color = enabled ? 'var(--green)' : 'var(--muted)';
  }
}

// ─── Data Loading ─────────────────────────────────────────────────────────────
let lastLoadedData = null;

function loadDashboard() {
  chrome.runtime.sendMessage({ action: 'getSecurityData', tabId: currentTabId }, (response) => {
    if (chrome.runtime.lastError || !response) {
      console.error('Failed to load:', chrome.runtime.lastError);
      return;
    }

    // Filter activeTabsList to only contain actual websites (http/https)
    const webTabs = (response.activeTabsList || []).filter(tab => {
      return tab.url.startsWith('http:') || tab.url.startsWith('https:');
    });

    // Check if Auto-Follow is active
    const autoFollowCb = document.getElementById('autoFollowCheckbox');
    if (autoFollowCb && autoFollowCb.checked) {
      const activeWebTab = webTabs.find(t => t.isActive);
      if (activeWebTab && activeWebTab.id !== currentTabId) {
        currentTabId = activeWebTab.id;
        // Reload data for the new auto-followed web tab
        chrome.runtime.sendMessage({ action: 'getSecurityData', tabId: currentTabId }, (newResponse) => {
          if (!chrome.runtime.lastError && newResponse) {
            lastLoadedData = newResponse;
            const newWebTabs = (newResponse.activeTabsList || []).filter(tab => {
              return tab.url.startsWith('http:') || tab.url.startsWith('https:');
            });
            renderAll({ ...newResponse, activeTabsList: newWebTabs });
            updateLastUpdate();
          }
        });
        return;
      }
    }

    // If currentTabId is not a web tab (e.g. closed or system page), and is not 'all', fall back
    const isWebTab = (tid) => tid === 'all' || webTabs.some(t => t.id === tid);
    if (!isWebTab(currentTabId)) {
      const activeWebTab = webTabs.find(t => t.isActive) || webTabs[0];
      if (activeWebTab) {
        currentTabId = activeWebTab.id;
        // Reload data for the fallback web tab
        chrome.runtime.sendMessage({ action: 'getSecurityData', tabId: currentTabId }, (newResponse) => {
          if (!chrome.runtime.lastError && newResponse) {
            lastLoadedData = newResponse;
            const newWebTabs = (newResponse.activeTabsList || []).filter(tab => {
              return tab.url.startsWith('http:') || tab.url.startsWith('https:');
            });
            renderAll({ ...newResponse, activeTabsList: newWebTabs });
            updateLastUpdate();
          }
        });
        return;
      }
    }

    lastLoadedData = response;
    renderAll({ ...response, activeTabsList: webTabs });
    updateLastUpdate();
  });
}

function renderAll(data) {
  renderUpdateBanner(data);
  renderActiveTabsDropdown(data.activeTabsList || [], data.tabId);
  renderOverview(data);
  renderAudit(data.audit);
  renderGlobalHistory(data.globalThreatLog || []);
  renderPayloadAlerts(data.payloadAlerts || []);
  renderTraffic(data.requests || []);
  renderHeaders(data.headers || []);
  renderTrackers(data.trackers || []);
  renderScriptScans(data.scriptScans || []);
  renderBehavioralAlerts(data.behavioralAlerts || []);
  renderLocalBlocklist(data.localBlockedDomains || [], data.blockedDomainsMetadata || {});
}

function renderUpdateBanner(data) {
  const container = document.getElementById('updateBannerContainer');
  if (!container) return;

  if (data.updateReadyToReload) {
    container.innerHTML = `
      <div class="update-banner ready-reload">
        <div class="banner-text">
          <div class="banner-title">🔄 Restart Required (v${data.updateReadyToReload.version})</div>
          <div class="banner-body">Extension files have been updated on disk. Reload now to apply updates.</div>
        </div>
        <div class="banner-actions">
          <button class="btn btn-primary" id="btnReloadExt">Restart Firewall</button>
        </div>
      </div>
    `;
    document.getElementById('btnReloadExt').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'reloadExtension' });
    });
  } else if (data.updateAvailable) {
    container.innerHTML = `
      <div class="update-banner">
        <div class="banner-text">
          <div class="banner-title">🌟 Update Available (v${data.updateAvailable.version})</div>
          <div class="banner-body">A new release is available on GitHub. Pull the latest repository files to update.</div>
        </div>
        <div class="banner-actions">
          <button class="btn btn-primary" id="btnOpenRepo" style="border: none;">Open GitHub</button>
          <button class="btn btn-ghost" id="btnReloadExt">Reload</button>
        </div>
      </div>
    `;
    document.getElementById('btnOpenRepo').addEventListener('click', () => {
      window.open(data.updateAvailable.url || 'https://github.com/manjunath-27-idea/Security-Extension', '_blank');
    });
    document.getElementById('btnReloadExt').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'reloadExtension' });
    });
  } else {
    container.innerHTML = '';
  }
}

function renderActiveTabsDropdown(activeTabs, selectedTabId) {
  const dropdown = document.getElementById('activeTabsDropdown');
  if (!dropdown) return;

  const allSelected = selectedTabId === 'all' ? 'selected' : '';
  let optionsHTML = `<option value="all" ${allSelected}>All Active Tabs</option>`;

  optionsHTML += activeTabs.map(tab => {
    const isSel = tab.id === selectedTabId ? 'selected' : '';
    const cleanTitle = tab.title.substring(0, 30);
    const countBadge = tab.threatCount > 0 ? ` (${tab.threatCount})` : '';
    return `<option value="${tab.id}" ${isSel}>${escHtml(cleanTitle)}${countBadge}</option>`;
  }).join('');

  dropdown.innerHTML = optionsHTML;
}

function formatHistoryTimestamp(item) {
  const todayStr = new Date().toLocaleDateString();
  const arrivals = item.arrivals || [{ timestamp: item.timestamp, count: item.count || 1 }];

  // Group arrivals by date
  const groups = {};
  arrivals.forEach(arr => {
    const d = new Date(arr.timestamp);
    const dateStr = d.toLocaleDateString();
    const timeStr = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    const countSuffix = arr.count > 1 ? ` (x${arr.count})` : '';

    if (!groups[dateStr]) {
      groups[dateStr] = [];
    }
    groups[dateStr].push(`${timeStr}${countSuffix}`);
  });

  const formattedGroups = Object.entries(groups).map(([dateStr, times]) => {
    if (dateStr === todayStr) {
      return times.join(', ');
    } else {
      return `${dateStr} (${times.join(', ')})`;
    }
  });

  const display = formattedGroups.slice(-3).join('; ') + (formattedGroups.length > 3 ? ' ...' : '');
  const tooltip = Object.entries(groups).map(([dateStr, times]) => `${dateStr}: ${times.join(', ')}`).join('\n');

  return { display, tooltip };
}

function renderGlobalHistory(historyLog) {
  const container = document.getElementById('globalHistoryContent');
  if (!container) return;

  if (historyLog.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div>No global events captured yet</div>
        <div style="font-size:11px;margin-top:6px;color:var(--muted)">All blocked trackers, insecure requests, leaks, and spoofed fingerprints will be archived here.</div>
      </div>
    `;
    return;
  }

  const tableHTML = `
    <table class="data-table" style="width: 100%; border-collapse: collapse; margin-top: 10px;">
      <thead>
        <tr style="border-bottom: 2px solid var(--border); text-align: left; font-size: 12px; color: var(--muted);">
          <th style="padding: 12px 16px;">Timestamp</th>
          <th style="padding: 12px 16px;">Origin / Domain</th>
          <th style="padding: 12px 16px;">Threat Detected</th>
          <th style="padding: 12px 16px;">Category</th>
          <th style="padding: 12px 16px;">Details</th>
          <th style="padding: 12px 16px; text-align: right;">Action</th>
        </tr>
      </thead>
      <tbody>
        ${historyLog.slice().reverse().map(item => {
          const { display, tooltip } = formatHistoryTimestamp(item);

          let catClass = 'medium';
          if (item.category.toLowerCase().includes('critical') || item.category.toLowerCase().includes('malware')) {
            catClass = 'critical';
          } else if (item.category.toLowerCase().includes('insecure') || item.category.toLowerCase().includes('leak')) {
            catClass = 'high';
          } else if (item.category.toLowerCase().includes('behavior') || item.category.toLowerCase().includes('tracker')) {
            catClass = 'alerts';
          }

          let actionClass = 'warned-badge';
          if (item.action.toLowerCase() === 'blocked' || item.action.toLowerCase() === 'poisoned') {
            actionClass = 'blocked-badge';
          }

          return `
            <tr style="border-bottom: 1px solid var(--border); font-size: 13px;">
              <td style="padding: 12px 16px; color: var(--muted); font-size: 11px;" title="${escHtml(tooltip)}">
                ${escHtml(display)}
              </td>
              <td style="padding: 12px 16px; color: var(--text); font-weight: 600;">
                ${escHtml(item.domain)}
              </td>
              <td style="padding: 12px 16px; color: var(--text);">
                ${escHtml(item.label)}
              </td>
              <td style="padding: 12px 16px;">
                <span class="sev-badge ${catClass}">${escHtml(item.category)}</span>
              </td>
              <td style="padding: 12px 16px; color: var(--muted); font-family: var(--mono); font-size: 11px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escHtml(item.url)}">
                ${escHtml(item.url)}
              </td>
              <td style="padding: 12px 16px; text-align: right;">
                <span class="${actionClass}">${escHtml(item.action.toUpperCase())}</span>
              </td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;

  container.innerHTML = tableHTML;
}

// ─── Overview ─────────────────────────────────────────────────────────────────
function renderOverview(data) {
  const { audit } = data;
  const score = audit.score;
  const grade = audit.grade;
  const color = getGradeColor(grade);

  document.getElementById('scoreValue').textContent = score;
  document.getElementById('scoreValue').style.color = color;
  document.getElementById('gradeValue').textContent = grade;
  document.getElementById('gradeValue').style.color = color;

  // Score Ring SVG
  const ring = document.getElementById('scoreRing');
  if (ring) {
    const circumference = 345.57; // 2 * PI * r (r=55)
    const offset = circumference - (circumference * score) / 100;
    ring.style.strokeDashoffset = offset;
    ring.style.stroke = color;
  }

  // Stats
  document.getElementById('ovReqs').textContent = audit.stats.totalRequests;
  document.getElementById('ovSecure').textContent = audit.stats.secureRequests;
  document.getElementById('ovHttp').textContent = audit.stats.httpRequests;
  document.getElementById('ovAlerts').textContent = audit.stats.payloadAlerts;
  document.getElementById('ovBlocked').textContent = audit.stats.blockedRequests;
  document.getElementById('ovTrackers').textContent = audit.stats.trackersDetected;
  document.getElementById('ovHdrsOk').textContent = audit.stats.headersPresent;
  document.getElementById('ovHdrsMissing').textContent = audit.stats.headersMissing;

  // Finding badges
  const critical = audit.findings.filter(f => f.severity === 'critical').length;
  const high = audit.findings.filter(f => f.severity === 'high').length;
  const medium = audit.findings.filter(f => f.severity === 'medium').length;

  document.getElementById('ovCritical').textContent = critical;
  document.getElementById('ovHigh').textContent = high;
  document.getElementById('ovMedium').textContent = medium;

  // Tab badge for payload alerts
  const alertBadge = document.getElementById('payloadBadge');
  if (alertBadge) {
    alertBadge.textContent = audit.stats.payloadAlerts > 0 ? audit.stats.payloadAlerts : '';
    alertBadge.style.display = audit.stats.payloadAlerts > 0 ? 'inline' : 'none';
  }
}



// ─── Audit & Suggestions ──────────────────────────────────────────────────────
function renderAudit(audit) {
  const container = document.getElementById('auditContent');
  if (!audit) { container.innerHTML = '<p style="color:var(--muted);text-align:center;padding:32px">No audit data</p>'; return; }

  let emptyFindings = "No security findings detected for this site";
  let emptySuggestions = "System checks green — no immediate suggestions";

  if (audit.isSystemPage) {
    emptyFindings = "Shield auditing is inactive on local and system pages (chrome://, chrome-extension://, file://). Visit a remote website to run security audits.";
    emptySuggestions = "Local resources are run within the secure sandbox environment. No recommendations needed.";
  }

  const findingsHTML = audit.findings.length === 0
    ? `<div class="empty-state">${emptyFindings}</div>`
    : audit.findings.map(f => `
      <div class="audit-finding sev-${f.severity}">
        <div class="af-header">
          <span class="af-title">${f.title}</span>
          <span class="sev-badge ${f.severity}">${f.severity.toUpperCase()}</span>
          ${f.blocked ? '<span class="blocked-badge">BLOCKED</span>' : ''}
        </div>
        <div class="af-category">${f.category}</div>
        ${f.detail ? `<div class="af-detail">${escHtml(f.detail)}</div>` : ''}
      </div>
    `).join('');

  const suggestionsHTML = audit.suggestions.length === 0
    ? `<div class="empty-state">${emptySuggestions}</div>`
    : audit.suggestions.map(s => `
      <div class="suggestion-card pri-${s.priority}">
        <div class="sug-header">
          <span class="sug-title">${s.title}</span>
          <span class="sev-badge ${s.priority}">${s.priority.toUpperCase()}</span>
        </div>
        <ul class="sug-steps">
          ${s.steps.map(step => `<li>${escHtml(step)}</li>`).join('')}
        </ul>
      </div>
    `).join('');

  container.innerHTML = `
    <div class="audit-section-title">🔍 Security Findings (${audit.findings.length})</div>
    <div class="audit-findings">${findingsHTML}</div>
    <div class="audit-section-title" style="margin-top:28px">💡 Recommendations (${audit.suggestions.length})</div>
    <div class="suggestions">${suggestionsHTML}</div>
  `;
}

// ─── Payload Alerts ───────────────────────────────────────────────────────────
function renderPayloadAlerts(alerts) {
  const container = document.getElementById('payloadContent');
  if (alerts.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div>No payload alerts — no sensitive keys or PII found in outgoing requests</div>
        <div style="font-size:11px;margin-top:6px;color:var(--muted)">The fetch/XHR deep inspector is active in document context</div>
      </div>`;
    return;
  }

  container.innerHTML = alerts.slice().reverse().map(a => {
    const hasCritical = a.findings.some(f => f.severity === 'critical');
    return `
      <div class="payload-alert ${hasCritical ? 'critical' : 'high'}">
        <div class="pa-header">
          <span class="pa-url">${escHtml(a.url?.substring(0, 100) || 'unknown')}</span>
          <span class="pa-time">${new Date(a.timestamp).toLocaleTimeString()}</span>
          ${a.blocked 
            ? '<span class="blocked-badge">BLOCKED</span>'
            : '<span class="warned-badge">DETECTED</span>'}
        </div>
        <div class="pa-findings">
          ${a.findings.map(f => `
            <div class="pa-finding">
              <span class="sev-badge ${f.severity}">${f.severity}</span>
              <strong>${f.label}</strong>
              <span style="color:var(--muted);font-size:11px;margin-left:4px;">${f.desc}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }).join('');
}

// ─── Traffic ──────────────────────────────────────────────────────────────────
function renderTraffic(requests) {
  const container = document.getElementById('trafficContent');
  if (requests.length === 0) {
    container.innerHTML = '<div class="empty-state">No requests captured yet</div>';
    return;
  }
  container.innerHTML = requests.slice(-50).reverse().map(req => `
    <div class="traffic-item ${req.threat}">
      <div class="ti-header">
        <span class="ti-time">${formatTime(req.timestamp)}</span>
        <span class="ti-type">${req.type}</span>
        <span class="ti-method">${req.method}</span>
      </div>
      <div class="ti-url">${escHtml(req.url.substring(0, 120))}</div>
      <div class="ti-meta"><span>${escHtml(req.domain)}</span></div>
    </div>
  `).join('');
}

// ─── Headers ─────────────────────────────────────────────────────────────────
function renderHeaders(headers) {
  const container = document.getElementById('headersContent');
  if (headers.length === 0) {
    container.innerHTML = '<div class="empty-state">No headers analyzed yet</div>';
    return;
  }
  const present = headers.filter(h => h.status === 'present').length;
  const missing = headers.filter(h => h.status === 'missing').length;

  // Group headers by domain
  const grouped = {};
  headers.forEach(h => {
    const domain = h.domain || 'Unknown';
    if (!grouped[domain]) grouped[domain] = [];
    grouped[domain].push(h);
  });

  let html = `
    <div class="hdr-summary">
      <span class="hdr-sum-badge present">${present} Present</span>
      <span class="hdr-sum-badge missing">${missing} Missing</span>
    </div>
  `;

  Object.entries(grouped).forEach(([domain, domainHeaders]) => {
    html += `
      <div class="hdr-domain-section" style="margin-top: 20px; margin-bottom: 12px;">
        <div style="font-size: 11px; font-weight: 800; text-transform: uppercase; color: var(--indigo); letter-spacing: 0.8px; margin-bottom: 10px;">
          Domain: ${escHtml(domain)}
        </div>
        ${domainHeaders.map(h => `
          <div class="header-item ${h.status}">
            <div class="hi-top">
              <span class="hi-name">${h.name}</span>
              <span class="sev-badge ${h.status === 'present' ? 'ok' : h.severity}">${h.status.toUpperCase()}</span>
            </div>
            <div class="hi-desc">${h.description || ''}</div>
            ${h.value ? `<div class="hi-value">${escHtml(h.value.substring(0, 140))}</div>` : ''}
            ${h.status === 'missing' && h.suggestion ? `<div class="hi-suggestion">${escHtml(h.suggestion)}</div>` : ''}
          </div>
        `).join('')}
      </div>
    `;
  });

  container.innerHTML = html;
}

// ─── Trackers ─────────────────────────────────────────────────────────────────
function renderTrackers(trackers) {
  const container = document.getElementById('trackersContent');
  if (trackers.length === 0) {
    container.innerHTML = '<div class="empty-state">No known trackers detected on this site</div>';
    return;
  }
  container.innerHTML = trackers.map(t => `
    <div class="tracker-item ${t.riskLevel}">
      <div class="trk-header">
        <span class="trk-name">${escHtml(t.name)}</span>
        <span class="trk-cat">${escHtml(t.category)}</span>
        <span class="sev-badge ${t.riskLevel === 'high' ? 'critical' : t.riskLevel}">${t.riskLevel.toUpperCase()} RISK</span>
      </div>
      <div class="trk-domain">${escHtml(t.domain)} • ${t.requests} requests • Source: ${escHtml(t.sourceUrl || 'Direct Access')}</div>
      <div class="trk-data">${(t.dataCollected || []).map(d => escHtml(d)).join(' · ')}</div>
    </div>
  `).join('');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function getGradeColor(g) {
  return { A: 'var(--green)', B: 'var(--indigo)', C: 'var(--yellow)', D: 'var(--orange)', F: 'var(--red)' }[g] || 'var(--muted)';
}

function getCategoryEmoji(c) {
  return { analytics: '📊', advertising: '📢', social: '👥', tracking: '🎯' }[c] || '🔍';
}

function formatTime(ts) {
  try { return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }); }
  catch { return '--:--:--'; }
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function updateLastUpdate() {
  const el = document.getElementById('lastUpdate');
  if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

function clearData() {
  chrome.runtime.sendMessage({ action: 'clearData', tabId: currentTabId }, () => {
    loadDashboard();
  });
}

// ─── Stat Box Click Interactions ──────────────────────────────────────────────
function setupStatBoxClicks() {
  const modal = document.getElementById('statModal');
  const title = document.getElementById('modalTitle');
  const linksContainer = document.getElementById('modalLinks');

  const showModal = (modalTitle, urls) => {
    title.textContent = modalTitle;
    linksContainer.innerHTML = '';
    
    if (!urls || urls.length === 0) {
      linksContainer.innerHTML = '<div class="modal-link-empty">No matching records found.</div>';
    } else {
      const uniqueUrls = [...new Set(urls)].filter(Boolean);
      if (uniqueUrls.length === 0) {
        linksContainer.innerHTML = '<div class="modal-link-empty">No matching records found.</div>';
      } else {
        uniqueUrls.forEach(url => {
          const a = document.createElement('a');
          a.className = 'modal-link-item';
          a.href = url.startsWith('http') ? url : `https://${url}`;
          a.target = '_blank';
          a.textContent = url;
          linksContainer.appendChild(a);
        });
      }
    }
    
    modal.classList.add('active');
  };

  document.getElementById('ovReqs').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const urls = lastLoadedData.requests.map(r => r.url);
    showModal('All Network Requests', urls);
  });

  document.getElementById('ovSecure').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const urls = lastLoadedData.requests.filter(r => r.secure).map(r => r.url);
    showModal('Secure (HTTPS) Connections', urls);
  });

  document.getElementById('ovHttp').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const urls = lastLoadedData.requests.filter(r => !r.secure).map(r => r.url);
    showModal('Insecure HTTP Connections', urls);
  });

  document.getElementById('ovAlerts').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const urls = lastLoadedData.payloadAlerts.map(a => a.url);
    showModal('PII / Key Leak Payloads', urls);
  });

  document.getElementById('ovBlocked').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const urls = lastLoadedData.payloadAlerts.filter(a => a.blocked).map(a => a.url);
    showModal('Neutralized/Redacted Leaks', urls);
  });

  document.getElementById('ovTrackers').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const domains = lastLoadedData.trackers.map(t => t.domain);
    showModal('Detected Tracker Domains', domains);
  });

  document.getElementById('ovHdrsOk').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const presentHeaders = lastLoadedData.headers.filter(h => h.status === 'present');
    const displayList = presentHeaders.map(h => `${h.domain || 'Active Site'} : ${h.name}`);
    showModal('Configured Security Headers', displayList);
  });

  document.getElementById('ovHdrsMissing').parentElement.addEventListener('click', () => {
    if (!lastLoadedData) return;
    const missingHeaders = lastLoadedData.headers.filter(h => h.status === 'missing');
    const displayList = missingHeaders.map(h => `${h.domain || 'Active Site'} : ${h.name}`);
    showModal('Missing Security Headers', displayList);
  });
}

function setupModalClose() {
  const modal = document.getElementById('statModal');
  const closeBtn = document.getElementById('modalClose');

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      modal.classList.remove('active');
    });
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.remove('active');
      }
    });
  }
}

// Chatbot functionality removed

function setupSettingsToggles() {
  const dbgToggle = document.getElementById('debuggerToggle');
  const heuToggle = document.getElementById('heuristicsToggle');

  chrome.runtime.sendMessage({ action: 'getSettings' }, (settings) => {
    if (!settings) return;
    if (dbgToggle) {
      dbgToggle.checked = settings.debuggerEnabled === true;
      updateSettingsLabel('dbgLabelText', settings.debuggerEnabled === true, 'DEEP SCAN ON', 'DEEP SCAN OFF');
    }
    if (heuToggle) {
      heuToggle.checked = settings.heuristicsEnabled === true;
      updateSettingsLabel('heuLabelText', settings.heuristicsEnabled === true, 'BEHAVIOR SHIELD ON', 'BEHAVIOR SHIELD OFF');
    }
  });

  const saveSettings = () => {
    const debuggerEnabled = dbgToggle ? dbgToggle.checked : false;
    const heuristicsEnabled = heuToggle ? heuToggle.checked : true;

    chrome.runtime.sendMessage({
      action: 'setSettings',
      settings: { debuggerEnabled, heuristicsEnabled }
    });

    updateSettingsLabel('dbgLabelText', debuggerEnabled, 'DEEP SCAN ON', 'DEEP SCAN OFF');
    updateSettingsLabel('heuLabelText', heuristicsEnabled, 'BEHAVIOR SHIELD ON', 'BEHAVIOR SHIELD OFF');
  };

  if (dbgToggle) dbgToggle.addEventListener('change', saveSettings);
  if (heuToggle) heuToggle.addEventListener('change', saveSettings);
}

function updateSettingsLabel(id, enabled, textOn, textOff) {
  const label = document.getElementById(id);
  if (label) {
    label.textContent = enabled ? textOn : textOff;
    label.className = enabled ? 'fw-label active' : 'fw-label';
    label.style.color = enabled ? 'var(--indigo)' : 'var(--muted)';
  }
}

// ─── Script Scans & Behavioral Protection Renderers ──────────────────────────
function renderScriptScans(scans) {
  const container = document.getElementById('scansContent');
  const badge = document.getElementById('scansBadge');
  if (!container) return;

  if (badge) {
    badge.textContent = scans.length > 0 ? scans.length : '';
    badge.style.display = scans.length > 0 ? 'inline' : 'none';
  }

  if (scans.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        No script scans registered. Turn on DEEP SCAN in the topbar and reload tabs to begin debugging network JS elements.
      </div>`;
    return;
  }

  container.innerHTML = scans.slice().reverse().map(scan => `
    <div class="tracker-item high" style="border-left-color: var(--blue);">
      <div class="trk-header">
        <span class="trk-name" style="font-family: var(--mono); font-size: 12px; word-break: break-all;">${escHtml(scan.url)}</span>
        <span class="sev-badge critical" style="background: rgba(59, 130, 246, 0.12); color: #93c5fd; border-color: rgba(59, 130, 246, 0.25);">${scan.findings.length} Issue(s)</span>
      </div>
      <div class="trk-domain" style="margin-top: 8px;">Scanned at ${new Date(scan.timestamp).toLocaleTimeString()}</div>
      <div class="pa-findings" style="margin-top: 10px; display: flex; flex-direction: column; gap: 8px;">
        ${scan.findings.map(f => `
          <div class="pa-finding" style="font-size: 12px;">
            <span class="sev-badge ${f.severity}">${f.severity}</span>
            <strong>${escHtml(f.label)}</strong>
            <span style="color:var(--muted);font-size:11px;margin-left:4px;">${escHtml(f.desc)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

function renderBehavioralAlerts(alerts) {
  const container = document.getElementById('behavioralContent');
  const badge = document.getElementById('behavioralBadge');
  if (!container) return;

  if (badge) {
    badge.textContent = alerts.length > 0 ? alerts.length : '';
    badge.style.display = alerts.length > 0 ? 'inline' : 'none';
  }

  if (alerts.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        No behavioral heuristics triggered yet. The Behavior Shield is active.
      </div>`;
    return;
  }

  container.innerHTML = alerts.slice().reverse().map(alert => {
    const isWasm = alert.type.includes('WASM');
    const borderCol = isWasm ? 'var(--yellow)' : 'var(--orange)';
    const bgCol = isWasm ? 'rgba(245, 158, 11, 0.1)' : 'rgba(249, 115, 22, 0.1)';
    const textCol = isWasm ? '#fcd34d' : '#fdba74';
    
    return `
      <div class="tracker-item" style="border-left: 3px solid ${borderCol};">
        <div class="trk-header">
          <span class="trk-name" style="color: ${borderCol}; font-weight: 700;">${escHtml(alert.type)}</span>
          <span class="sev-badge" style="background: ${bgCol}; color: ${textCol}; border: 1px solid ${borderCol};">MITIGATED</span>
        </div>
        <div class="trk-domain" style="margin-top: 8px;">Timestamp: ${new Date(alert.timestamp).toLocaleTimeString()}</div>
        <div class="trk-data" style="margin-top: 6px; font-family: var(--mono); font-size: 11px;">
          ${escHtml(alert.desc)}
        </div>
      </div>
    `;
  }).join('');
}

function setupLocalBlocklistInput() {
  const addBlockBtn = document.getElementById('addBlockBtn');
  const addBlockInput = document.getElementById('addBlockInput');
  if (addBlockBtn && addBlockInput) {
    addBlockBtn.addEventListener('click', () => {
      const domain = addBlockInput.value.trim();
      if (!domain) return;
      chrome.runtime.sendMessage({ action: 'addLocalBlockDomain', domain }, (res) => {
        if (res && res.success) {
          addBlockInput.value = '';
          loadDashboard();
        }
      });
    });
    addBlockInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        addBlockBtn.click();
      }
    });
  }
}

function renderLocalBlocklist(domains, metadata = {}) {
  const container = document.getElementById('localBlocklistContent');
  if (!container) return;

  if (domains.length === 0) {
    container.innerHTML = `
      <div class="empty-state">No custom blocked domains added yet. Trackers detected will be automatically logged and blocked here.</div>
    `;
    return;
  }

  let html = `
    <table class="data-table" style="width: 100%; border-collapse: collapse; margin-top: 10px;">
      <thead>
        <tr style="border-bottom: 2px solid var(--border); text-align: left; font-size: 12px; color: var(--muted);">
          <th style="padding: 12px 16px;">Blocked Domain</th>
          <th style="padding: 12px 16px;">First Found On (Source)</th>
          <th style="padding: 12px 16px; width: 100px; text-align: right;">Action</th>
        </tr>
      </thead>
      <tbody>
  `;

  domains.forEach(domain => {
    const meta = metadata[domain] || {};
    const source = meta.sourceUrl || 'Auto / Default Block';
    html += `
      <tr style="border-bottom: 1px solid var(--border); font-size: 13px;">
        <td style="padding: 12px 16px; color: var(--text); font-family: var(--mono); font-weight: 500;">${escHtml(domain)}</td>
        <td style="padding: 12px 16px; color: var(--muted);">${escHtml(source)}</td>
        <td style="padding: 12px 16px; text-align: right;">
          <button class="btn btn-ghost remove-block-btn" data-domain="${escHtml(domain)}" style="padding: 4px 10px; font-size: 11px; color: var(--red); border: 1px solid rgba(239, 68, 68, 0.2); background: rgba(239, 68, 68, 0.05); border-radius: 6px; cursor: pointer; transition: all 0.2s;">
            Remove
          </button>
        </td>
      </tr>
    `;
  });

  html += `
      </tbody>
    </table>
  `;

  container.innerHTML = html;

  // Bind click listeners to remove buttons
  container.querySelectorAll('.remove-block-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const domain = e.target.dataset.domain;
      chrome.runtime.sendMessage({ action: 'removeLocalBlockDomain', domain }, (res) => {
        if (res && res.success) {
          loadDashboard();
        }
      });
    });
  });
}

function setupTheme() {
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
}
