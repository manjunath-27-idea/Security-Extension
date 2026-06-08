/**
 * Security Extension - Content Script (ISOLATED world)
 * Bridges events from the MAIN world injector → background service worker.
 * Also handles firewall mode toggle and page-level DOM analysis.
 */

// ─── Bridge: MAIN world → background ─────────────────────────────────────────

window.addEventListener('__secext_payload_alert', (event) => {
  const detail = event.detail;
  chrome.runtime.sendMessage({
    action: 'payloadAlert',
    data: detail,
  }).catch(() => {});
});

window.addEventListener('__secext_behavioral_alert', (event) => {
  const detail = event.detail;
  chrome.runtime.sendMessage({
    action: 'behavioralAlert',
    data: detail,
  }).catch(() => {});
});

// ─── Settings / Firewall Mode Sync ───────────────────────────────────────────
let extensionSettings = { heuristicsEnabled: true, debuggerEnabled: false };

function syncSettingsToPage(settings) {
  extensionSettings = settings;
  window.dispatchEvent(new CustomEvent('__secext_sync_settings', {
    detail: settings
  }));
}

// Get initial settings
chrome.runtime.sendMessage({ action: 'getSettings' }, (response) => {
  if (response) {
    syncSettingsToPage(response);
  }
});

if (chrome.storage?.session) {
  chrome.storage.session.get(['firewallEnabled'], (result) => {
    window.__secext_firewall = result.firewallEnabled === true;
    window.dispatchEvent(new CustomEvent('__secext_set_firewall', {
      detail: { enabled: result.firewallEnabled === true }
    }));
  });
} else {
  chrome.runtime.sendMessage({ action: 'getFirewallState' }, (response) => {
    if (response) {
      window.__secext_firewall = response.enabled === true;
      window.dispatchEvent(new CustomEvent('__secext_set_firewall', {
        detail: { enabled: response.enabled === true }
      }));
    }
  });
}

chrome.runtime.onMessage.addListener((request) => {
  if (request.action === 'syncSettings') {
    syncSettingsToPage(request.settings);
  }
  if (request.action === 'setFirewall') {
    window.__secext_firewall = request.enabled;
    window.dispatchEvent(new CustomEvent('__secext_set_firewall', {
      detail: { enabled: request.enabled }
    }));
  }
  if (request.action === 'showThreatToast') {
    showSecurityToast(request.count, request.type);
  }
  if (request.action === 'showUpdateToast') {
    showUpdateToastNotification(request.updateType, request.version);
  }
});

// ─── Page Analysis ───────────────────────────────────────────────────────────

function analyzePage() {
  const pageData = {
    hasHTTPS: window.location.protocol === 'https:',
    hasMixedContent: checkMixedContent(),
    insecureElements: findInsecureElements(),
    formTargets: analyzeFormTargets(),
    passwordFormsOnHTTP: checkPasswordFormsOnHTTP(),
    externalScripts: getExternalScripts(),
    iframes: getIframes(),
  };

  chrome.runtime.sendMessage({ action: 'pageAnalysis', data: pageData }).catch(() => {});
}

function checkMixedContent() {
  return [...document.querySelectorAll('img,script,link[rel="stylesheet"],iframe')]
    .some(el => (el.src || el.href || '').startsWith('http://'));
}

function findInsecureElements() {
  const insecure = { images: [], scripts: [], stylesheets: [], iframes: [] };
  document.querySelectorAll('img[src^="http://"]').forEach(el => insecure.images.push(el.src));
  document.querySelectorAll('script[src^="http://"]').forEach(el => insecure.scripts.push(el.src));
  document.querySelectorAll('link[rel="stylesheet"][href^="http://"]').forEach(el => insecure.stylesheets.push(el.href));
  document.querySelectorAll('iframe[src^="http://"]').forEach(el => insecure.iframes.push(el.src));
  return insecure;
}

function analyzeFormTargets() {
  return [...document.querySelectorAll('form')].map(form => ({
    action: form.getAttribute('action') || window.location.href,
    method: (form.getAttribute('method') || 'GET').toUpperCase(),
    isSecure: !form.getAttribute('action') || 
              form.getAttribute('action').startsWith('https://') || 
              form.getAttribute('action').startsWith('/'),
    hasPassword: !!form.querySelector('input[type="password"]'),
    hasEmail: !!form.querySelector('input[type="email"]'),
    hasCreditCard: !![...form.querySelectorAll('input')].find(i =>
      /card|cvv|ccnum|credit/i.test(i.name + i.id + i.placeholder)
    ),
  }));
}

function checkPasswordFormsOnHTTP() {
  if (window.location.protocol === 'https:') return false;
  return !!document.querySelector('input[type="password"]');
}

function getExternalScripts() {
  return [...document.querySelectorAll('script[src]')]
    .map(s => s.src)
    .filter(src => {
      try {
        return new URL(src).hostname !== window.location.hostname;
      } catch { return false; }
    });
}

function getIframes() {
  return [...document.querySelectorAll('iframe[src]')]
    .map(i => ({ src: i.src, sandbox: i.getAttribute('sandbox') }));
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', analyzePage);
} else {
  analyzePage();
}

// Watch for dynamic DOM additions with a debounce to prevent CPU spikes and lag
let analysisTimeout = null;
const observer = new MutationObserver(() => {
  if (analysisTimeout) clearTimeout(analysisTimeout);
  analysisTimeout = setTimeout(analyzePage, 800);
});
observer.observe(document.documentElement, { childList: true, subtree: true });

console.log('[Security Extension] Content script active');

// ─── Active Security Toast Notification ──────────────────────────────────────
let toastTimeout = null;
let toastEl = null;

function showSecurityToast(count, lastThreatType) {
  if (!document.getElementById('__secext_toast_styles')) {
    const style = document.createElement('style');
    style.id = '__secext_toast_styles';
    style.textContent = `
      .__secext_toast_container, .__secext_toast_container * {
        box-sizing: border-box !important;
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.4 !important;
        letter-spacing: normal !important;
        text-transform: none !important;
        text-align: left !important;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
      }
      .__secext_toast_container {
        position: fixed !important;
        bottom: 24px !important;
        right: 24px !important;
        z-index: 2147483647 !important;
        background: rgba(13, 11, 23, 0.92) !important;
        backdrop-filter: blur(16px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.15) !important;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.45), 0 0 20px rgba(99, 102, 241, 0.15) !important;
        color: #f1f1f5 !important;
        padding: 14px 18px !important;
        border-radius: 16px !important;
        display: flex !important;
        align-items: center !important;
        gap: 14px !important;
        min-width: 320px !important;
        max-width: 420px !important;
        transform: translateY(120px) scale(0.95) !important;
        opacity: 0 !important;
        transition: transform 0.45s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.35s ease !important;
        pointer-events: none !important;
      }
      .__secext_toast_container.show {
        transform: translateY(0) scale(1) !important;
        opacity: 1 !important;
        pointer-events: auto !important;
      }
      .__secext_toast_icon {
        width: 36px !important;
        height: 36px !important;
        border-radius: 10px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        color: white !important;
        font-size: 18px !important;
        flex-shrink: 0 !important;
      }
      .__secext_toast_icon.tracker {
        background: linear-gradient(135deg, #3182ce 0%, #319795 100%) !important;
        box-shadow: 0 4px 12px rgba(49, 130, 206, 0.35) !important;
      }
      .__secext_toast_icon.malware {
        background: linear-gradient(135deg, #e53e3e 0%, #805ad5 100%) !important;
        box-shadow: 0 4px 12px rgba(229, 62, 62, 0.35) !important;
      }
      .__secext_toast_icon.leak {
        background: linear-gradient(135deg, #b7791f 0%, #e53e3e 100%) !important;
        box-shadow: 0 4px 12px rgba(183, 121, 31, 0.35) !important;
      }
      .__secext_toast_icon.download {
        background: linear-gradient(135deg, #dd6b20 0%, #d69e2e 100%) !important;
        box-shadow: 0 4px 12px rgba(221, 107, 32, 0.35) !important;
      }
      .__secext_toast_icon.behavior {
        background: linear-gradient(135deg, #805ad5 0%, #319795 100%) !important;
        box-shadow: 0 4px 12px rgba(128, 90, 213, 0.35) !important;
      }
      .__secext_toast_icon.script {
        background: linear-gradient(135deg, #4a5568 0%, #718096 100%) !important;
        box-shadow: 0 4px 12px rgba(74, 85, 104, 0.35) !important;
      }
      .__secext_toast_icon.default {
        background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%) !important;
        box-shadow: 0 4px 12px rgba(99, 102, 241, 0.35) !important;
      }
      .__secext_toast_body {
        flex: 1 !important;
        min-width: 0 !important;
        display: flex !important;
        flex-direction: column !important;
      }
      .__secext_toast_title {
        font-weight: 700 !important;
        color: #ffffff !important;
        margin-bottom: 2px !important;
        font-size: 13.5px !important;
        letter-spacing: -0.2px !important;
      }
      .__secext_toast_desc {
        color: #a0aec0 !important;
        font-size: 11px !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
      }
      .__secext_toast_badge {
        background: #e53e3e !important;
        color: white !important;
        font-size: 11px !important;
        font-weight: 700 !important;
        padding: 3px 8px !important;
        border-radius: 9999px !important;
        flex-shrink: 0 !important;
        box-shadow: 0 2px 8px rgba(229, 62, 62, 0.3) !important;
      }
    `;
    document.head.appendChild(style);
  }

  if (!toastEl) {
    toastEl = document.createElement('div');
    toastEl.className = '__secext_toast_container';
    document.body.appendChild(toastEl);
  }

  // Determine threat category visual styles
  let icon = '🛡️';
  let gradientClass = 'default';
  let title = 'Shield Active Protection';
  const typeLower = lastThreatType.toLowerCase();

  if (typeLower.includes('tracker') || typeLower.includes('analytics')) {
    icon = '👁️';
    gradientClass = 'tracker';
    title = 'Privacy Tracker Blocked';
  } else if (typeLower.includes('malware') || typeLower.includes('dnr') || typeLower.includes('miner')) {
    icon = '🚨';
    gradientClass = 'malware';
    title = 'Malware Domain Blocked';
  } else if (typeLower.includes('payload') || typeLower.includes('leak') || typeLower.includes('critical')) {
    icon = '🔑';
    gradientClass = 'leak';
    title = 'Data Leak Prevented';
  } else if (typeLower.includes('download')) {
    icon = '📥';
    gradientClass = 'download';
    title = 'Malicious Download Blocked';
  } else if (typeLower.includes('fingerprint') || typeLower.includes('behavior')) {
    icon = '👤';
    gradientClass = 'behavior';
    title = 'Fingerprint Attempt Spoofed';
  } else if (typeLower.includes('script') || typeLower.includes('packet')) {
    icon = '⚙️';
    gradientClass = 'script';
    title = 'Suspicious Script Audited';
  }

  toastEl.innerHTML = `
    <div class="__secext_toast_icon ${gradientClass}">${icon}</div>
    <div class="__secext_toast_body">
      <div class="__secext_toast_title">${title}</div>
      <div class="__secext_toast_desc">${lastThreatType}</div>
    </div>
    <div class="__secext_toast_badge">${count}</div>
  `;

  if (toastTimeout) clearTimeout(toastTimeout);

  // Trigger reflow to make transition work
  toastEl.getBoundingClientRect();
  toastEl.classList.add('show');

  toastTimeout = setTimeout(() => {
    toastEl.classList.remove('show');
  }, 5000);
}

// Capture anchor clicks and send userIntentNavigate message to background
window.addEventListener('click', (e) => {
  const anchor = e.target.closest('a');
  if (anchor && anchor.href) {
    try {
      const clickedHost = new URL(anchor.href, window.location.href).hostname;
      if (clickedHost && clickedHost !== window.location.hostname) {
        chrome.runtime.sendMessage({
          action: 'userIntentNavigate',
          host: clickedHost,
          timestamp: Date.now()
        }).catch(() => {});
      }
    } catch (err) {}
  }
}, { capture: true, passive: true });

let updateToastEl = null;
function showUpdateToastNotification(type, version) {
  if (!document.getElementById('__secext_update_toast_styles')) {
    const style = document.createElement('style');
    style.id = '__secext_update_toast_styles';
    style.textContent = `
      .__secext_update_toast_container, .__secext_update_toast_container * {
        box-sizing: border-box !important;
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.4 !important;
        font-family: system-ui, -apple-system, sans-serif !important;
      }
      .__secext_update_toast_container {
        position: fixed !important;
        bottom: 24px !important;
        left: 24px !important;
        z-index: 2147483647 !important;
        background: rgba(13, 11, 23, 0.94) !important;
        backdrop-filter: blur(20px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-top: 1px solid rgba(255, 255, 255, 0.15) !important;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.5), 0 0 24px rgba(99, 102, 241, 0.15) !important;
        color: #f1f1f5 !important;
        padding: 16px 20px !important;
        border-radius: 16px !important;
        display: flex !important;
        flex-direction: column !important;
        gap: 12px !important;
        width: 320px !important;
        transform: translateX(-120%) scale(0.95) !important;
        opacity: 0 !important;
        transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease !important;
      }
      .__secext_update_toast_container.show {
        transform: translateX(0) scale(1) !important;
        opacity: 1 !important;
      }
      .__secext_update_toast_header {
        display: flex !important;
        align-items: center !important;
        gap: 10px !important;
      }
      .__secext_update_toast_icon {
        font-size: 20px !important;
      }
      .__secext_update_toast_title {
        font-weight: 800 !important;
        color: #ffffff !important;
        font-size: 13.5px !important;
        letter-spacing: -0.2px !important;
      }
      .__secext_update_toast_body {
        color: #a0aec0 !important;
        font-size: 11.5px !important;
        line-height: 1.4 !important;
      }
      .__secext_update_toast_actions {
        display: flex !important;
        gap: 8px !important;
      }
      .__secext_update_btn {
        padding: 8px 14px !important;
        border-radius: 8px !important;
        border: none !important;
        font-size: 11px !important;
        font-weight: 700 !important;
        cursor: pointer !important;
        transition: background 0.15s, transform 0.1s !important;
      }
      .__secext_update_btn:active {
        transform: scale(0.97) !important;
      }
      .__secext_update_btn_primary {
        background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%) !important;
        color: white !important;
        box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3) !important;
      }
      .__secext_update_btn_primary:hover {
        filter: brightness(1.1) !important;
      }
      .__secext_update_btn_ghost {
        background: rgba(255, 255, 255, 0.04) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        color: #a1a0b0 !important;
      }
      .__secext_update_btn_ghost:hover {
        background: rgba(255, 255, 255, 0.08) !important;
        color: white !important;
      }
    `;
    document.head.appendChild(style);
  }

  if (!updateToastEl) {
    updateToastEl = document.createElement('div');
    updateToastEl.className = '__secext_update_toast_container';
    document.body.appendChild(updateToastEl);
  }

  const isReload = type === 'reload';
  const icon = isReload ? '🔄' : '🌟';
  const title = isReload ? 'Restart Required' : `Update Available (v${version})`;
  const desc = isReload
    ? 'Extension files updated on disk. Click below to restart and apply.'
    : 'A new version is available on GitHub. Pull the files to update.';

  const actionButtonHtml = isReload
    ? `<button class="__secext_update_btn __secext_update_btn_primary" id="__secext_btn_restart">Restart Firewall</button>`
    : `
      <button class="__secext_update_btn __secext_update_btn_primary" id="__secext_btn_github">Open GitHub</button>
      <button class="__secext_update_btn __secext_update_btn_ghost" id="__secext_btn_reload">Reload</button>
    `;

  updateToastEl.innerHTML = `
    <div class="__secext_update_toast_header">
      <span class="__secext_update_toast_icon">${icon}</span>
      <span class="__secext_update_toast_title">${title}</span>
    </div>
    <div class="__secext_update_toast_body">${desc}</div>
    <div class="__secext_update_toast_actions">
      ${actionButtonHtml}
    </div>
  `;

  if (isReload) {
    document.getElementById('__secext_btn_restart').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'reloadExtension' }).catch(() => {});
    });
  } else {
    document.getElementById('__secext_btn_github').addEventListener('click', () => {
      window.open('https://github.com/manjunath-27-idea/Security-Extension', '_blank');
    });
    document.getElementById('__secext_btn_reload').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'reloadExtension' }).catch(() => {});
    });
  }

  updateToastEl.getBoundingClientRect();
  updateToastEl.classList.add('show');
}
