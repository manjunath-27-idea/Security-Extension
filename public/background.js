/**
 * Security Extension - Background Service Worker v2.3.0
 * 
 * Persistent & Robust for Manifest V3:
 *  - Persists state in chrome.storage.session to survive Service Worker idle terminations.
 *  - Handles payload alerts from injector (crypto keys, seed phrases, PII).
 *  - Firewall mode toggle (blocks critical leaks via XHR/fetch abort).
 *  - Full Audit Engine with scoring + suggestions.
 *  - Exposes storage session access level to content scripts.
 */

// ─── Set Storage Access Level ────────────────────────────────────────────────
if (chrome.storage?.session) {
  chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }).catch(() => {});
}

// ─── Serializable State Store ────────────────────────────────────────────────
const securityData = {
  requests: {},       // tabId → [{...}]
  headers: {},        // tabId → { domain: {headerName: status} }
  trackers: {},       // tabId → { domain: trackerInfo }
  payloadAlerts: {},   // tabId → [{...}]
  pageData: {},       // tabId → pageAnalysis
  scriptScans: {},    // tabId → [{...}]
  behavioralAlerts: {}, // tabId → [{...}]
  settings: {
    debuggerEnabled: false,
    heuristicsEnabled: true,
  },
  activeTab: null,
};

// Helper to save state
function saveState() {
  if (chrome.storage?.session) {
    chrome.storage.session.set({ securityData }).catch(() => {});
  }
}

// Load state at startup
const stateLoaded = new Promise((resolve) => {
  if (chrome.storage?.session) {
    chrome.storage.session.get(['securityData'], (result) => {
      if (result?.securityData) {
        Object.assign(securityData, result.securityData);
      }
      resolve();
    });
  } else {
    resolve();
  }
});

// ─── Known Trackers ──────────────────────────────────────────────────────────
const TRACKER_DOMAINS = {
  'google-analytics.com': { name: 'Google Analytics', category: 'analytics', risk: 'medium' },
  'analytics.google.com': { name: 'Google Analytics', category: 'analytics', risk: 'medium' },
  'facebook.com': { name: 'Facebook Pixel', category: 'social', risk: 'high' },
  'connect.facebook.net': { name: 'Facebook Pixel', category: 'social', risk: 'high' },
  'doubleclick.net': { name: 'DoubleClick', category: 'advertising', risk: 'high' },
  'ads.doubleclick.net': { name: 'DoubleClick', category: 'advertising', risk: 'high' },
  'hotjar.com': { name: 'Hotjar', category: 'analytics', risk: 'medium' },
  'twitter.com': { name: 'Twitter Pixel', category: 'social', risk: 'low' },
  'platform.twitter.com': { name: 'Twitter/X', category: 'social', risk: 'low' },
  'linkedin.com': { name: 'LinkedIn', category: 'social', risk: 'medium' },
  'snap.com': { name: 'Snapchat', category: 'social', risk: 'medium' },
  'tiktok.com': { name: 'TikTok', category: 'social', risk: 'high' },
  'pinterest.com': { name: 'Pinterest', category: 'social', risk: 'medium' },
  'segment.com': { name: 'Segment', category: 'analytics', risk: 'medium' },
  'mixpanel.com': { name: 'Mixpanel', category: 'analytics', risk: 'medium' },
  'amplitude.com': { name: 'Amplitude', category: 'analytics', risk: 'medium' },
  'intercom.io': { name: 'Intercom', category: 'analytics', risk: 'low' },
  'drift.com': { name: 'Drift', category: 'analytics', risk: 'low' },
  'zendesk.com': { name: 'Zendesk', category: 'analytics', risk: 'low' },
  'mouseflow.com': { name: 'Mouseflow', category: 'analytics', risk: 'medium' },
  'fullstory.com': { name: 'FullStory', category: 'analytics', risk: 'high' },
  'heap.io': { name: 'Heap Analytics', category: 'analytics', risk: 'medium' },
  'crazyegg.com': { name: 'Crazy Egg', category: 'analytics', risk: 'medium' },
  'scorecardresearch.com': { name: 'Scorecard Research', category: 'tracking', risk: 'high' },
  'outbrain.com': { name: 'Outbrain', category: 'advertising', risk: 'high' },
  'taboola.com': { name: 'Taboola', category: 'advertising', risk: 'high' },
};

// ─── Security Headers ─────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'content-security-policy': {
    name: 'Content-Security-Policy',
    severity: 'critical',
    description: 'Prevents XSS attacks by controlling which resources can load',
    suggestion: 'Add CSP header: Content-Security-Policy: default-src \'self\'',
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security',
    severity: 'critical',
    description: 'Forces HTTPS — prevents protocol downgrade attacks',
    suggestion: 'Add: Strict-Transport-Security: max-age=63072000; includeSubDomains',
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'high',
    description: 'Prevents clickjacking by blocking framing of your page',
    suggestion: 'Add: X-Frame-Options: DENY  (or SAMEORIGIN)',
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'high',
    description: 'Prevents MIME-type sniffing attacks',
    suggestion: 'Add: X-Content-Type-Options: nosniff',
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'medium',
    description: 'Controls how much referrer info is shared with third parties',
    suggestion: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'medium',
    description: 'Restricts which browser features/APIs the page can use',
    suggestion: 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'low',
    description: 'Legacy XSS filter (superseded by CSP but still checked by scanners)',
    suggestion: 'Add: X-XSS-Protection: 1; mode=block',
  },
  'cache-control': {
    name: 'Cache-Control (sensitive pages)',
    severity: 'low',
    description: 'Sensitive pages should use no-store to prevent caching private data',
    suggestion: 'For auth pages: Cache-Control: no-store, no-cache, must-revalidate',
  },
};

// ─── Audit Engine ─────────────────────────────────────────────────────────────
function generateAudit(tabId) {
  const requests = securityData.requests[tabId] || [];
  const headersMap = securityData.headers[tabId] || {};
  const trackers = securityData.trackers[tabId] || {};
  const payloadAlerts = securityData.payloadAlerts[tabId] || [];
  const page = securityData.pageData[tabId] || {};

  const findings = [];
  const suggestions = [];
  let score = 100;

  // ── 1. Payload / Data Leak Findings ──
  const criticalAlerts = payloadAlerts.filter(a => a.findings.some(f => f.severity === 'critical'));
  const highAlerts = payloadAlerts.filter(a => a.findings.some(f => f.severity === 'high'));

  if (criticalAlerts.length > 0) {
    score -= criticalAlerts.length * 30;
    findings.push({
      id: 'payload-critical',
      category: 'Payload Inspection',
      severity: 'critical',
      icon: '🔑',
      title: `${criticalAlerts.length} Critical Data Leak(s) Detected`,
      detail: criticalAlerts.map(a => `${a.findings.map(f => f.label).join(', ')} → ${a.url}`).join('\n'),
      blocked: criticalAlerts.some(a => a.blocked),
    });
    suggestions.push({
      priority: 'critical',
      icon: '🔑',
      title: 'Potential Crypto / PII Data Exfiltration',
      steps: [
        'Enable Firewall Mode to automatically block these requests.',
        'Verify you are not on a phishing or compromised site.',
        'Never paste seed phrases, private keys, or SSNs into web forms.',
        'Use a hardware wallet for crypto key storage.',
        'Audit extensions installed in your browser — remove unfamiliar ones.',
      ],
    });
  }

  if (highAlerts.length > 0) {
    score -= highAlerts.length * 10;
    findings.push({
      id: 'payload-high',
      category: 'Payload Inspection',
      severity: 'high',
      icon: '🗝️',
      title: `${highAlerts.length} Sensitive Token(s) in Outgoing Requests`,
      detail: 'API keys or wallet addresses detected in request payloads.',
      blocked: false,
    });
    suggestions.push({
      priority: 'high',
      icon: '🗝️',
      title: 'API Keys Detected in Outgoing Payloads',
      steps: [
        'Rotate any exposed API keys immediately.',
        'Use environment variables or server-side proxies — never embed keys in frontend JS.',
        'Check if this site is a phishing clone of a legitimate service.',
      ],
    });
  }

  // ── 2. HTTP (non-HTTPS) Connections ──
  const httpRequests = requests.filter(r => !r.secure);
  if (httpRequests.length > 0) {
    score -= httpRequests.length * 5;
    findings.push({
      id: 'http-requests',
      category: 'Transport Security',
      severity: 'critical',
      icon: '🔓',
      title: `${httpRequests.length} Unencrypted HTTP Request(s)`,
      detail: `Plain HTTP used: ${httpRequests.slice(0, 3).map(r => r.domain).join(', ')}`,
    });
    suggestions.push({
      priority: 'critical',
      icon: '🔒',
      title: 'Enable HTTPS Everywhere',
      steps: [
        'This page (or its resources) uses plain HTTP — data is readable by anyone on the network.',
        'Enable HSTS on the server: Strict-Transport-Security: max-age=63072000',
        'Use a browser extension like "HTTPS Everywhere" as a client-side fallback.',
        'On public Wi-Fi, use a VPN when sites use HTTP.',
      ],
    });
  }

  // ── 3. Missing Security Headers ──
  const flatHeaders = [];
  Object.values(headersMap).forEach(domainHeaders => {
    Object.entries(domainHeaders).forEach(([name, status]) => {
      if (!flatHeaders.find(h => h.name === name)) flatHeaders.push({ name, ...status });
    });
  });

  const missingCritical = flatHeaders.filter(h => h.status === 'missing' && h.severity === 'critical');
  const missingHigh = flatHeaders.filter(h => h.status === 'missing' && h.severity === 'high');
  const missingMedium = flatHeaders.filter(h => h.status === 'missing' && h.severity === 'medium');

  missingCritical.forEach(h => {
    score -= 15;
    findings.push({
      id: `header-missing-${h.name}`,
      category: 'Security Headers',
      severity: 'critical',
      icon: '🛑',
      title: `Missing Critical Header: ${h.name}`,
      detail: h.description,
    });
    const headerConfig = Object.values(SECURITY_HEADERS).find(s => s.name === h.name);
    if (headerConfig) {
      suggestions.push({
        priority: 'critical',
        icon: '🛑',
        title: `Add ${h.name}`,
        steps: [headerConfig.suggestion, headerConfig.description],
      });
    }
  });

  missingHigh.forEach(h => {
    score -= 8;
    findings.push({
      id: `header-missing-high-${h.name}`,
      category: 'Security Headers',
      severity: 'high',
      icon: '⚠️',
      title: `Missing Header: ${h.name}`,
      detail: h.description,
    });
  });

  if (missingMedium.length > 0) {
    score -= missingMedium.length * 3;
    findings.push({
      id: 'headers-missing-medium',
      category: 'Security Headers',
      severity: 'medium',
      icon: '📋',
      title: `${missingMedium.length} Recommended Header(s) Missing`,
      detail: missingMedium.map(h => h.name).join(', '),
    });
  }

  // ── 4. High-Risk Trackers ──
  const trackerArray = Object.values(trackers);
  const highRisk = trackerArray.filter(t => t.riskLevel === 'high');
  const mediumRisk = trackerArray.filter(t => t.riskLevel === 'medium');

  if (highRisk.length > 0) {
    score -= highRisk.length * 8;
    findings.push({
      id: 'trackers-high',
      category: 'Privacy',
      severity: 'high',
      icon: '👁️',
      title: `${highRisk.length} High-Risk Tracker(s) Active`,
      detail: highRisk.map(t => `${t.name} (${t.requests} requests)`).join(', '),
    });
    suggestions.push({
      priority: 'high',
      icon: '🛡️',
      title: 'Block High-Risk Trackers',
      steps: [
        `Detected: ${highRisk.map(t => t.name).join(', ')}`,
        'Install uBlock Origin or Privacy Badger to block trackers automatically.',
        'Use Firefox with Enhanced Tracking Protection enabled.',
        'Consider a DNS-level blocker like NextDNS or Pi-hole for network-wide protection.',
      ],
    });
  }

  if (mediumRisk.length > 0) {
    score -= mediumRisk.length * 3;
  }

  // ── 5. Mixed Content ──
  if (page.hasMixedContent) {
    score -= 10;
    findings.push({
      id: 'mixed-content',
      category: 'Mixed Content',
      severity: 'high',
      icon: '🔀',
      title: 'Mixed Content Detected (HTTPS + HTTP resources)',
      detail: 'This HTTPS page loads resources over HTTP, weakening its security.',
    });
    suggestions.push({
      priority: 'high',
      icon: '🔀',
      title: 'Fix Mixed Content',
      steps: [
        'Update all resource URLs to HTTPS (images, scripts, stylesheets).',
        'Use protocol-relative URLs (//example.com/resource) as a fallback.',
        'Check your CSP report-uri to identify which resources are mixed.',
      ],
    });
  }

  // ── 6. Password Forms on HTTP ──
  if (page.passwordFormsOnHTTP) {
    score -= 25;
    findings.push({
      id: 'password-on-http',
      category: 'Form Security',
      severity: 'critical',
      icon: '🔐',
      title: 'Password Form on HTTP Page!',
      detail: 'Credentials entered here are transmitted in plaintext.',
    });
    suggestions.push({
      priority: 'critical',
      icon: '🔐',
      title: 'CRITICAL: Do Not Enter Passwords on HTTP Sites',
      steps: [
        'This page is HTTP — your password will be sent in plaintext over the network.',
        'Do not submit any credentials on this page.',
        'Contact the site owner to upgrade to HTTPS.',
        'Use a password manager that flags HTTP login pages.',
      ],
    });
  }

  // ── 7. Insecure Iframes ──
  const insecureIframes = (page.insecureElements?.iframes || []);
  if (insecureIframes.length > 0) {
    score -= 5;
    findings.push({
      id: 'insecure-iframes',
      category: 'Iframe Security',
      severity: 'medium',
      icon: '🖼️',
      title: `${insecureIframes.length} Insecure iframe(s) on page`,
      detail: 'Iframes from HTTP sources may load malicious content.',
    });
  }

  // ── 8. External Scripts ──
  const externalScripts = page.externalScripts || [];
  if (externalScripts.length > 5) {
    score -= 5;
    findings.push({
      id: 'many-external-scripts',
      category: 'Supply Chain',
      severity: 'medium',
      icon: '📦',
      title: `${externalScripts.length} External Scripts Loaded`,
      detail: 'Many third-party scripts increase your attack surface (supply chain attacks).',
    });
    suggestions.push({
      priority: 'medium',
      icon: '📦',
      title: 'Reduce Third-Party Script Exposure',
      steps: [
        `${externalScripts.length} external scripts detected on this page.`,
        'Each external script is a potential supply chain attack vector.',
        'Implement Subresource Integrity (SRI) on all external scripts and stylesheets.',
        'Consider self-hosting critical libraries instead of loading from CDNs.',
        'Use a Content Security Policy to whitelist approved script sources.',
      ],
    });
  }

  // ── 9. Debugger Script Scans ──
  const scriptScans = securityData.scriptScans[tabId] || [];
  if (scriptScans.length > 0) {
    const criticalScripts = scriptScans.filter(s => s.findings.some(f => f.severity === 'critical'));
    const highScripts = scriptScans.filter(s => s.findings.some(f => f.severity === 'high'));
    
    if (criticalScripts.length > 0) {
      score -= criticalScripts.length * 20;
      findings.push({
        id: 'script-critical',
        category: 'Deep Packet Scan',
        severity: 'critical',
        icon: '🛡️',
        title: `${criticalScripts.length} Critical Script Vulnerabilities`,
        detail: criticalScripts.map(s => `${s.url} → ${s.findings.map(f => f.label).join(', ')}`).join('\n'),
      });
    }
    
    if (highScripts.length > 0) {
      score -= highScripts.length * 10;
      findings.push({
        id: 'script-high',
        category: 'Deep Packet Scan',
        severity: 'high',
        icon: '⚠️',
        title: `${highScripts.length} Suspicious Script File(s)`,
        detail: highScripts.map(s => `${s.url} → ${s.findings.map(f => f.label).join(', ')}`).join('\n'),
      });
    }
  }

  // ── 10. Behavioral Fingerprinting / WASM Heuristics ──
  const behavioralAlerts = securityData.behavioralAlerts[tabId] || [];
  if (behavioralAlerts.length > 0) {
    const fingerprintAlerts = behavioralAlerts.filter(a => a.type.includes('Fingerprinting'));
    const wasmAlerts = behavioralAlerts.filter(a => a.type.includes('WASM'));

    if (fingerprintAlerts.length > 0) {
      score -= fingerprintAlerts.length * 15;
      findings.push({
        id: 'behavior-fingerprint',
        category: 'Behavioral Protection',
        severity: 'high',
        icon: '👤',
        title: `Fingerprinting Attempt Blocked & Poisoned`,
        detail: fingerprintAlerts.map(a => `${a.type}: ${a.desc}`).join('\n'),
      });
      suggestions.push({
        priority: 'high',
        icon: '👤',
        title: 'Active Fingerprinting Heuristics Shielded',
        steps: [
          'The extension successfully detected background canvas/audio reads.',
          'Subtle pixel noise has been injected into the returned canvas buffers, spoiling the hash for trackers.',
          'Keep Behavioral Protection toggled ON to defend against zero-day fingerprints.'
        ]
      });
    }

    if (wasmAlerts.length > 0) {
      score -= 5;
      findings.push({
        id: 'behavior-wasm',
        category: 'Behavioral Protection',
        severity: 'medium',
        icon: '⚙️',
        title: `WebAssembly Exec Loaded`,
        detail: 'Dynamic WASM execution was loaded on this page (indicator of miners/complex scripts).',
      });
    }
  }

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    grade: getGrade(score),
    findings,
    suggestions,
    stats: {
      totalRequests: requests.length,
      secureRequests: requests.filter(r => r.secure).length,
      httpRequests: httpRequests.length,
      blockedRequests: payloadAlerts.filter(a => a.blocked).length,
      payloadAlerts: payloadAlerts.length,
      trackersDetected: trackerArray.length,
      headersPresent: flatHeaders.filter(h => h.status === 'present').length,
      headersMissing: flatHeaders.filter(h => h.status === 'missing').length,
    },
  };
}

function getGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// ─── Tab Listeners ────────────────────────────────────────────────────────────
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  await stateLoaded;
  securityData.activeTab = activeInfo.tabId;
  chrome.storage.session.set({ activeTab: activeInfo.tabId });
  saveState();
});

// ─── Network Listeners ────────────────────────────────────────────────────────
function getDomain(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.hostname;
  } catch {
    return null;
  }
}

function checkTracker(domain) {
  for (const [d, info] of Object.entries(TRACKER_DOMAINS)) {
    if (domain.includes(d)) return info;
  }
  return null;
}

chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    await stateLoaded;
    if (details.tabId === -1) return;
    const domain = getDomain(details.url);
    if (!domain) return;

    const headers = {};
    (details.responseHeaders || []).forEach(h => {
      headers[h.name.toLowerCase()] = h.value;
    });

    const headerStatus = {};
    Object.entries(SECURITY_HEADERS).forEach(([key, info]) => {
      const val = headers[key];
      headerStatus[info.name] = val
        ? { name: info.name, status: 'present', value: val, severity: info.severity, description: info.description, suggestion: info.suggestion }
        : { name: info.name, status: 'missing', severity: info.severity, description: info.description, suggestion: info.suggestion };
    });

    if (!securityData.headers[details.tabId]) {
      securityData.headers[details.tabId] = {};
    }
    const existing = securityData.headers[details.tabId];
    securityData.headers[details.tabId] = { ...existing, [domain]: headerStatus };

    // Tracker check
    const tracker = checkTracker(domain);
    if (tracker) {
      if (!securityData.trackers[details.tabId]) {
        securityData.trackers[details.tabId] = {};
      }
      const trackers = securityData.trackers[details.tabId];
      if (!trackers[domain]) {
        trackers[domain] = {
          id: `tracker-${domain}`,
          name: tracker.name,
          domain,
          category: tracker.category,
          requests: 0,
          riskLevel: tracker.risk,
          dataCollected: getTrackerData(tracker.name),
        };
      }
      trackers[domain].requests++;
    }
    saveState();
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    await stateLoaded;
    if (details.tabId === -1) return;
    const domain = getDomain(details.url);
    if (!domain) return;

    const isSecure = details.url.startsWith('https');
    const tracker = checkTracker(domain);
    const threat = !isSecure ? 'critical' : tracker ? 'warning' : 'none';

    if (!securityData.requests[details.tabId]) {
      securityData.requests[details.tabId] = [];
    }
    const reqs = securityData.requests[details.tabId];
    reqs.push({
      id: `req-${details.requestId}`,
      url: details.url,
      domain,
      method: details.method,
      type: details.type,
      secure: isSecure,
      threat,
      timestamp: new Date().toISOString(),
      size: 0,
      status: 0,
    });
    if (reqs.length > 100) reqs.shift();
    saveState();
  },
  { urls: ['<all_urls>'] }
);

// ─── Message Handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = request.tabId || sender?.tab?.id;

  // Handle async state loading before processing message actions
  stateLoaded.then(() => {
    if (request.action === 'payloadAlert') {
      if (!tabId) return;
      if (!securityData.payloadAlerts[tabId]) {
        securityData.payloadAlerts[tabId] = [];
      }
      const alerts = securityData.payloadAlerts[tabId];
      alerts.push(request.data);
      if (alerts.length > 200) alerts.shift();

      // Show notification for critical leaks
      const hasCritical = request.data.findings?.some(f => f.severity === 'critical');
      if (hasCritical) {
        chrome.notifications?.create({
          type: 'basic',
          iconUrl: 'images/icon-48.png',
          title: '🚨 Security Alert',
          message: `Sensitive data detected in outgoing request to ${getDomain(request.data.url) || 'unknown'}`,
          priority: 2,
        });
      }
      saveState();
      sendResponse({ success: true });
      return;
    }

    if (request.action === 'pageAnalysis') {
      if (!tabId) return;
      securityData.pageData[tabId] = request.data;
      saveState();
      sendResponse({ success: true });
      return;
    }

    if (request.action === 'getSecurityData') {
      const getResponse = (isSystemPage = false) => {
        const requests = securityData.requests[tabId] || [];
        const headersMap = securityData.headers[tabId] || {};
        const trackers = securityData.trackers[tabId] || {};
        const payloadAlerts = securityData.payloadAlerts[tabId] || [];

        const flatHeaders = [];
        Object.entries(headersMap).forEach(([domain, dh]) => {
          Object.values(dh).forEach(h => {
            flatHeaders.push({ ...h, domain });
          });
        });

        let audit = generateAudit(tabId);

        if (isSystemPage) {
          audit = {
            score: 100,
            grade: 'A',
            findings: [],
            suggestions: [],
            stats: {
              totalRequests: 0,
              secureRequests: 0,
              httpRequests: 0,
              blockedRequests: 0,
              payloadAlerts: 0,
              trackersDetected: 0,
              headersPresent: 0,
              headersMissing: 0,
            },
            isSystemPage: true,
          };
        }

        // Determine active site domain for default fallback headers
        let defaultDomain = 'Active Tab';
        if (requests.length > 0) {
          defaultDomain = requests[0].domain || 'Active Tab';
        }
        const finalHeaders = flatHeaders.length > 0 
          ? flatHeaders 
          : (isSystemPage ? [] : getDefaultHeaders().map(h => ({ ...h, domain: defaultDomain })));

        return {
          requests: isSystemPage ? [] : requests,
          headers: finalHeaders,
          trackers: isSystemPage ? [] : Object.values(trackers),
          payloadAlerts: isSystemPage ? [] : payloadAlerts,
          scriptScans: isSystemPage ? [] : (securityData.scriptScans[tabId] || []),
          behavioralAlerts: isSystemPage ? [] : (securityData.behavioralAlerts[tabId] || []),
          audit,
          tabId,
        };
      };

      if (tabId && tabId !== -1) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError || !tab) {
            sendResponse(getResponse(false));
            return;
          }
          let isSystem = false;
          if (tab.url) {
            try {
              const u = new URL(tab.url);
              if (u.protocol !== 'http:' && u.protocol !== 'https:') {
                isSystem = true;
              }
            } catch {
              isSystem = true;
            }
          }
          sendResponse(getResponse(isSystem));
        });
      } else {
        sendResponse(getResponse(false));
      }
      return;
    }

    if (request.action === 'getFirewallState') {
      chrome.storage.session.get(['firewallEnabled'], (result) => {
        sendResponse({ enabled: result?.firewallEnabled === true });
      });
      return;
    }

    if (request.action === 'getSettings') {
      sendResponse(securityData.settings || { debuggerEnabled: false, heuristicsEnabled: true });
      return;
    }

    if (request.action === 'setSettings') {
      securityData.settings = { ...securityData.settings, ...request.settings };
      saveState();

      if (securityData.settings.debuggerEnabled) {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) attachDebugger(tabs[0].id);
        });
      } else {
        detachAllDebuggers();
      }

      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          chrome.tabs.sendMessage(tab.id, { action: 'syncSettings', settings: securityData.settings }).catch(() => {});
        });
      });

      sendResponse({ success: true });
      return;
    }

    if (request.action === 'behavioralAlert') {
      if (!tabId) return;
      if (!securityData.behavioralAlerts[tabId]) {
        securityData.behavioralAlerts[tabId] = [];
      }
      const alerts = securityData.behavioralAlerts[tabId];
      alerts.push(request.data);
      if (alerts.length > 100) alerts.shift();
      saveState();
      sendResponse({ success: true });
      return;
    }

    if (request.action === 'clearData') {
      delete securityData.requests[tabId];
      delete securityData.headers[tabId];
      delete securityData.trackers[tabId];
      delete securityData.payloadAlerts[tabId];
      delete securityData.pageData[tabId];
      delete securityData.scriptScans[tabId];
      delete securityData.behavioralAlerts[tabId];
      saveState();
      sendResponse({ success: true });
      return;
    }

    if (request.action === 'setFirewall') {
      chrome.storage.session.set({ firewallEnabled: request.enabled });
      if (tabId) {
        chrome.tabs.sendMessage(tabId, { action: 'setFirewall', enabled: request.enabled }).catch(() => {});
      }
      sendResponse({ success: true });
      return;
    }
  });

  return true; // Keep the message channel open for asynchronous responses
});

// ─── Tab Cleanup ──────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener(async (tabId) => {
  await stateLoaded;
  delete securityData.requests[tabId];
  delete securityData.headers[tabId];
  delete securityData.trackers[tabId];
  delete securityData.payloadAlerts[tabId];
  delete securityData.pageData[tabId];
  delete securityData.scriptScans[tabId];
  delete securityData.behavioralAlerts[tabId];
  detachDebugger(tabId);
  saveState();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────


function getDefaultHeaders() {
  return Object.values(SECURITY_HEADERS).map(h => ({
    name: h.name, status: 'missing', severity: h.severity,
    description: h.description, suggestion: h.suggestion,
  }));
}

function getTrackerData(name) {
  const map = {
    'Google Analytics': ['Page views', 'User ID', 'Session duration', 'Device info', 'Click events'],
    'Facebook Pixel': ['User behavior', 'Conversion tracking', 'Audience data', 'Purchase events'],
    'DoubleClick': ['Ad impressions', 'Click tracking', 'User profile', 'Cross-site tracking'],
    'Hotjar': ['Mouse movements', 'Keystroke logging', 'Scroll depth', 'Session recordings'],
    'FullStory': ['Full session replay', 'All interactions', 'Rage clicks', 'Dead clicks'],
    'TikTok': ['User interactions', 'Video engagement', 'Purchase intent'],
    'Scorecard Research': ['Browser fingerprint', 'Visit frequency', 'Cross-site profile'],
  };
  return map[name] || ['User behavior', 'Engagement metrics'];
}

// ─── Instant Downloads Interceptor ───────────────────────────────────────────
function isSuspiciousDownload(filename, url) {
  if (!filename) return false;
  const ext = filename.split('.').pop().toLowerCase();
  
  // Highly suspicious script/installer/executable extensions
  const SUSPICIOUS_EXTENSIONS = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'scr', 'jar', 'pif', 'com', 'reg'];
  if (SUSPICIOUS_EXTENSIONS.includes(ext)) return true;

  // Suspicious keywords in URL
  const lowUrl = (url || '').toLowerCase();
  const SUSPICIOUS_KEYWORDS = ['malware', 'exploit', 'bypass', 'hack', 'virus', 'trojan', 'ransomware', 'stealer', 'keylogger'];
  if (SUSPICIOUS_KEYWORDS.some(k => lowUrl.includes(k))) return true;

  return false;
}

if (chrome.downloads) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    chrome.storage.session.get(['firewallEnabled'], (result) => {
      if (result.firewallEnabled !== true) return;

      const filename = downloadItem.filename || '';
      const url = downloadItem.url || '';
      
      if (isSuspiciousDownload(filename, url)) {
        chrome.downloads.pause(downloadItem.id, () => {
          console.warn('[Shield Firewall] Suspicious download PAUSED:', filename);
          const cleanName = filename.replace(/^.*[\\\/]/, '');

          chrome.notifications?.create({
            type: 'basic',
            iconUrl: 'images/icon-48.png',
            title: '⚠️ Suspicious Download Paused',
            message: `The file "${cleanName || 'unknown'}" is suspicious and was paused by Shield Firewall.`,
            buttons: [
              { title: 'Resume' },
              { title: 'Discard/Cancel' }
            ]
          }, (notificationId) => {
            if (!securityData.pausedDownloads) {
              securityData.pausedDownloads = {};
            }
            securityData.pausedDownloads[notificationId] = downloadItem.id;
            saveState();
          });
        });
      }
    });
  });

  if (chrome.notifications?.onButtonClicked) {
    chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
      if (securityData.pausedDownloads && securityData.pausedDownloads[notificationId]) {
        const downloadId = securityData.pausedDownloads[notificationId];
        if (buttonIndex === 0) {
          chrome.downloads.resume(downloadId, () => {
            console.log('[Shield Firewall] Download resumed by user:', downloadId);
          });
        } else {
          chrome.downloads.cancel(downloadId, () => {
            console.log('[Shield Firewall] Download canceled by user:', downloadId);
          });
        }
        delete securityData.pausedDownloads[notificationId];
        saveState();
      }
    });
  }
}

console.log('[Security Extension] Background worker v2.3.0 initialized');

// ─── Declarative Net Request Dynamic Rules ───────────────────────────────────
function setupDeclarativeRules() {
  if (!chrome.declarativeNetRequest) return;

  const defaultBlockDomains = [
    'malicious-tracker-test.com',
    'bad-adserver.net',
    'coinhive.com',
    'miner.c3pool.com',
    'urlhaus-test.malware-cnc.biz'
  ];

  chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
    const removeRuleIds = existingRules.map(r => r.id);
    const addRules = defaultBlockDomains.map((domain, index) => ({
      id: index + 1000,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: domain,
        resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'xmlhttprequest']
      }
    }));

    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds,
      addRules
    }, () => {
      if (chrome.runtime.lastError) {
        console.error('[Shield DNR] Error setting rules:', chrome.runtime.lastError);
      } else {
        console.log('[Shield DNR] Dynamic threat rules active:', defaultBlockDomains.length);
      }
    });
  });
}

if (chrome.declarativeNetRequest?.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request.tabId;
    if (tabId === -1) return;

    const domain = getDomain(info.request.url) || 'Blocked Threat';
    
    if (!securityData.trackers[tabId]) {
      securityData.trackers[tabId] = {};
    }
    const trackers = securityData.trackers[tabId];
    if (!trackers[domain]) {
      trackers[domain] = {
        id: `dnr-${domain}`,
        name: 'DNR Blocked Threat',
        domain,
        category: 'malware',
        requests: 0,
        riskLevel: 'critical',
        dataCollected: ['DNR Blocked domain request'],
      };
    }
    trackers[domain].requests++;

    if (!securityData.requests[tabId]) {
      securityData.requests[tabId] = [];
    }
    const reqs = securityData.requests[tabId];
    reqs.push({
      id: `dnr-req-${Date.now()}`,
      url: info.request.url,
      domain,
      method: info.request.method,
      type: info.request.type,
      secure: info.request.url.startsWith('https'),
      threat: 'critical',
      timestamp: new Date().toISOString(),
      size: 0,
      status: 'BLOCKED',
    });
    if (reqs.length > 100) reqs.shift();
    saveState();
  });
}

// ─── Debugger API Attachment & Events ─────────────────────────────────────────
const attachedTabs = new Set();

function attachDebugger(tabId) {
  if (!securityData.settings.debuggerEnabled) return;
  if (tabId === -1 || !tabId) return;
  if (attachedTabs.has(tabId)) return;

  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    if (tab.url && (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://'))) {
      return;
    }

    chrome.debugger.attach({ tabId }, '1.3', () => {
      if (chrome.runtime.lastError) {
        console.warn('[Shield Debugger] Attach failed for tab', tabId, ':', chrome.runtime.lastError.message);
        return;
      }
      attachedTabs.add(tabId);
      console.log('[Shield Debugger] Attached to tab:', tabId);

      chrome.debugger.sendCommand({ tabId }, 'Debugger.enable', {}, () => {
        if (chrome.runtime.lastError) {
          console.warn('[Shield Debugger] Debugger.enable failed for tab', tabId, ':', chrome.runtime.lastError.message);
        }
      });
    });
  });
}

function detachDebugger(tabId) {
  if (attachedTabs.has(tabId)) {
    chrome.debugger.detach({ tabId }, () => {
      attachedTabs.delete(tabId);
      console.log('[Shield Debugger] Detached from tab:', tabId);
    });
  }
}

function detachAllDebuggers() {
  for (const tabId of attachedTabs) {
    detachDebugger(tabId);
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    if (securityData.settings.debuggerEnabled) {
      detachDebugger(tabId);
      attachDebugger(tabId);
    }
  }
});

chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId;
  if (!tabId) return;

  if (method === 'Debugger.scriptParsed') {
    const { scriptId, url } = params;
    if (!url || url.startsWith('chrome-extension://') || url.startsWith('chrome://')) return;

    chrome.debugger.sendCommand(source, 'Debugger.getScriptSource', { scriptId }, (result) => {
      if (chrome.runtime.lastError || !result || !result.scriptSource) return;
      const code = result.scriptSource;

      const findings = analyzeScriptCode(code);
      if (findings.length > 0) {
        if (!securityData.scriptScans[tabId]) {
          securityData.scriptScans[tabId] = [];
        }
        const scans = securityData.scriptScans[tabId];
        
        if (!scans.some(s => s.url === url)) {
          scans.push({
            url,
            findings,
            timestamp: Date.now(),
          });
          if (scans.length > 50) scans.shift();
          saveState();

          const hasCritical = findings.some(f => f.severity === 'critical');
          if (hasCritical) {
            chrome.notifications?.create({
              type: 'basic',
              iconUrl: 'images/icon-48.png',
              title: '🛡️ Deep Packet Scan Alert',
              message: `Suspicious code block in script: ${url.substring(0, 50)}...`,
              priority: 1,
            });
          }
        }
      }
    });
  }
});

function analyzeScriptCode(code) {
  const findings = [];

  if (/\beval\s*\(/g.test(code)) {
    findings.push({
      label: 'Dangerous eval() Exec',
      desc: 'Dynamic code execution (eval) found, commonly used to execute disguised payload injections.',
      severity: 'high',
    });
  }

  if (/\bnew\s+Function\s*\(/g.test(code)) {
    findings.push({
      label: 'Dynamic Constructor',
      desc: 'Use of new Function() executes text scripts in page runtime.',
      severity: 'medium',
    });
  }

  const hexPattern = /\\x[0-9a-fA-F]{2}/g;
  const hexCount = (code.match(hexPattern) || []).length;
  if (hexCount > 150) {
    findings.push({
      label: 'Heavy Hex Obfuscation',
      desc: 'High concentration of hex-escaped chars, suggesting payload encapsulation.',
      severity: 'high',
    });
  }

  if (code.includes('chrome.storage') || code.includes('localStorage.getItem')) {
    if (code.includes('token') || code.includes('key') || code.includes('mnemonic')) {
      findings.push({
        label: 'Sensitive Storage Query',
        desc: 'Script attempts to access local storage keys querying tokens/mnemonic strings.',
        severity: 'critical',
      });
    }
  }

  return findings;
}

// ─── Initialize Threat Protection ────────────────────────────────────────────
stateLoaded.then(() => {
  setupDeclarativeRules();
  if (securityData.settings?.debuggerEnabled) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) attachDebugger(tabs[0].id);
    });
  }
});
