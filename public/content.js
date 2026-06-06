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
