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

  incrementAndShow(detail.blocked ? 'Payload Leak Sanitized' : 'Payload Leak Detected');
});

window.addEventListener('__secext_behavioral_alert', (event) => {
  const detail = event.detail;
  chrome.runtime.sendMessage({
    action: 'behavioralAlert',
    data: detail,
  }).catch(() => {});

  incrementAndShow(detail.type || 'Behavioral Threat Poisoned');
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
  if (request.action === 'incrementThreatCount') {
    incrementAndShow(request.type);
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

// Watch for dynamic DOM additions
const observer = new MutationObserver(() => analyzePage());
observer.observe(document.documentElement, { childList: true, subtree: true });

console.log('[Security Extension] Content script active');

// ─── Active Security Toast Notification ──────────────────────────────────────
let pageThreatCount = 0;
let toastTimeout = null;
let toastEl = null;

function showSecurityToast(count, lastThreatType) {
  if (!document.getElementById('__secext_toast_styles')) {
    const style = document.createElement('style');
    style.id = '__secext_toast_styles';
    style.textContent = `
      .__secext_toast_container {
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        background: rgba(9, 8, 15, 0.95);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(99, 102, 241, 0.35);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.6), 0 0 20px rgba(99, 102, 241, 0.2);
        color: #f1f1f5;
        padding: 12px 18px;
        border-radius: 12px;
        font-family: 'Plus Jakarta Sans', system-ui, sans-serif;
        font-size: 12.5px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 280px;
        max-width: 380px;
        transform: translateY(100px);
        opacity: 0;
        transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease;
        pointer-events: none;
      }
      .__secext_toast_container.show {
        transform: translateY(0);
        opacity: 1;
        pointer-events: auto;
      }
      .__secext_toast_icon {
        width: 30px;
        height: 30px;
        background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 15px;
        flex-shrink: 0;
        box-shadow: 0 0 10px rgba(99, 102, 241, 0.4);
      }
      .__secext_toast_body {
        flex: 1;
        min-width: 0;
      }
      .__secext_toast_title {
        font-weight: 800;
        color: white;
        margin-bottom: 1px;
        font-size: 13px;
        letter-spacing: -0.1px;
      }
      .__secext_toast_desc {
        color: #a1a0b0;
        font-size: 10.5px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .__secext_toast_badge {
        background: #ef4444;
        color: white;
        font-size: 10px;
        font-weight: 700;
        padding: 2px 7px;
        border-radius: 20px;
        flex-shrink: 0;
        box-shadow: 0 0 8px rgba(239, 68, 68, 0.3);
      }
    `;
    document.head.appendChild(style);
  }

  if (!toastEl) {
    toastEl = document.createElement('div');
    toastEl.className = '__secext_toast_container';
    document.body.appendChild(toastEl);
  }

  toastEl.innerHTML = `
    <div class="__secext_toast_icon">🛡️</div>
    <div class="__secext_toast_body">
      <div class="__secext_toast_title">Shield Active Protection</div>
      <div class="__secext_toast_desc">Blocked: ${lastThreatType}</div>
    </div>
    <div class="__secext_toast_badge">${count}</div>
  `;

  if (toastTimeout) clearTimeout(toastTimeout);

  toastEl.getBoundingClientRect();
  toastEl.classList.add('show');

  toastTimeout = setTimeout(() => {
    toastEl.classList.remove('show');
  }, 5000);
}

function incrementAndShow(type) {
  pageThreatCount++;
  showSecurityToast(pageThreatCount, type);
}
