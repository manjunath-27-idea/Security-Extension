# Shield Sandbox Firewall v2.5.2

A professional, high-performance Chrome security extension designed to perform deep packet inspection, prevent PII/secret exfiltration, override behavioral fingerprinting vectors, and block trackers natively using browser-level filtering rules.

## 🚀 Key Features

* **Native Blocklist Rules Engine**: Utilizes Chrome's native `declarativeNetRequest` API to perform lightning-fast, C++ level dropping of malicious domains, merging default rules with custom user-blocked items.
* **Deep Script Scanner**: Hooks Chrome's native `debugger` API to scan parsed script sources on the fly for dynamic execution (`eval`), dynamic constructors (`new Function`), storage harvesting, and hex obfuscation.
* **Behavioral Fingerprint Shields**: Automatically monitors main-world execution via `injector.js`. Alters Canvas and Audio outputs dynamically if queried without genuine user interaction, poisoning fingerprint hashes without visual distortion.
* **Mixed Content & Security Auditing**: Analyzes page headers, insecure HTTP resource loads, password form transmissions, and external script counts, producing a grading score from A to F.
* **Suspicious Download Interceptor**: Automatically monitors and pauses high-risk executable downloads, triggering a system-level confirm/discard notification.
* **Premium Glassmorphic UI**: Includes tailored light/dark themes with fluid gradient background pulses, synchronized circular progress gauges, and real-time update push notifications.

---

## 🛡️ Security Capabilities & Performance Characteristics

This extension implements several core security modules designed to run in parallel with zero-to-low overhead:

### 1. DNR - Declarative Net Request (Native Firewall)
* **Abbreviation**: **DNR** / **NFW** (Native Firewall)
* **How it performs**: Operates directly at Chrome's native C++ network filtering layer. By compiling static blocklists and custom user domains into dynamic dynamic rules, it discards requests to tracking systems and malware nodes prior to DNS resolution or TCP handshakes, introducing 0ms of javascript execution delay.

### 2. DPI - Deep Packet Inspection (PII/Secret Leak Protection)
* **Abbreviation**: **DPI** / **PII** (Personally Identifiable Information)
* **How it performs**: Monkey-patches main-world API hooks for `fetch()` and `XMLHttpRequest.send()`. Evaluates payload bodies dynamically for seed phrases (BIP39), EVM private keys, wallet address formats, and key/tokens. When the **Payload Firewall (PF)** is switched on, matching requests are immediately aborted.

### 3. DPS - Deep Packet Script Scan (Debugger JS Parser)
* **Abbreviation**: **DPS** / **SDP** (Script Debugger Parser)
* **How it performs**: Connects Chrome's native `debugger` protocol to analyze scripts parse-by-parse. Scans for dynamic code strings (`eval`), constructor calls (`new Function`), storage credentials harvesting, and hex obfuscation. Runs completely asynchronously to prevent webpage rendering blocks.

### 4. BPS - Behavioral Protection Shield (Fingerprint Poisoning)
* **Abbreviation**: **BPS** / **FSP** (Fingerprinting Spoofing Protection)
* **How it performs**: Intercepts DOM canvas buffer calls (`getImageData`, `toDataURL`) and `AudioContext` sweeps. Injects random pixel noise into query results when triggered in the background without user gesture flags. This poisons tracker fingerprint hashes without causing visual or audio distortions.

### 5. SDI - Suspicious Download Interceptor (File Shield)
* **Abbreviation**: **SDI** / **FSD** (File Shield Downloads)
* **How it performs**: Hooks into `chrome.downloads.onCreated` to check incoming file names and target URLs. Executables and installers (like `.exe`, `.msi`, `.bat`, `.ps1`) are instantly paused. The system alerts the user via native OS notifications containing action buttons to Resume/Cancel.

### 6. MHA - Mixed Content & Security Headers Audit
* **Abbreviation**: **MHA** / **SHA** (Security Headers Audit)
* **How it performs**: Inspects incoming HTTP headers (CSP, HSTS, X-Frame-Options) and scans web layouts for unencrypted frame loads or logins on plain HTTP. Grades sites from A to F and renders immediate remediation guidelines.

---

## 🏛️ Extension Architecture & Data Flow

Shield Sandbox Firewall operates across four execution environments to balance deep threat mitigation, low-overhead native network filtering, and sandboxed UI rendering under Manifest V3:

```text
┌──────────────────────────────────────────────────────────────────┐
│                      PAGE MAIN WORLD (webpage)                   │
│  [injector.js]                                                   │
│    ├── Patches prototypes (Canvas, AudioContext, WebAssembly)    │
│    └── Dispatches CustomEvents on detection / exfiltration       │
└────────────────────────────────.─────────────────────────────────┘
                                 │ CustomEvents
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                     ISOLATED WORLD (extension)                   │
│  [content.js]                                                    │
│    ├── Listens for CustomEvents and relays via runtime messages  │
│    └── Injects and renders visual glassmorphic threat toasts     │
└────────────────────────────────.─────────────────────────────────┘
                                 │ chrome.runtime.sendMessage
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                   EXTENSION BACKGROUND WORKER                    │
│  [background.js]                                                 │
│    ├── Survives sw idle cycles via chrome.storage.session        │
│    ├── Compiles local blocks into native declarativeNetRequest    │
│    ├── Connects Chrome Debugger API to audit parsed script sources│
│    └── Aggregates authority scoring & threat counters            │
└───────────────────────.──────────────────.───────────────────────┘
                        │                  │
  securityDataUpdated   │                  │ securityDataUpdated
                        ▼                  ▼
┌───────────────────────────┐      ┌───────────────────────────┐
│       POPUP UI CARD       │      │   CONTROL CENTER DASHBOARD│
│  [popup.js/html]          │      │  [dashboard.js/html]      │
│    └── Real-time status   │      │    └── Settings & logs    │
└───────────────────────────┘      └───────────────────────────┘
```

### Module Breakdown:
1. **Main-World Injector (`injector.js`)**: Injected directly into the website's execution thread before the page loads (`document_start`). This permits monkey-patching native JS functions to poison device fingerprinting contexts and track user gestures.
2. **Sync Bridge Content Script (`content.js`)**: Runs in a secure isolated world, acting as a translator between the webpage and the background worker. Relays main-world alerts to the service worker and dynamically injects isolated CSS-scoped threat notifications in the webpage.
3. **Persistent Orchestrator (`background.js`)**: The main service worker. Intercepts web requests, compiles dynamic DNR C++ blocking rules, runs script source vulnerability checks via Chrome's Debugger API, and maintains security scores.
4. **Synchronized UIs (`dashboard.js` & `popup.js`)**: Pull data dynamically from the background store and auto-reload their elements on message update prompts (`securityDataUpdated`) to keep counts matching and responsive.

---

## 📅 Version History & Release Logs

### v2.5.2 (Current) — Defense-Aware Security Scoring
* **Defense-Aware Mitigation Scale**: Transitioned the security scoring engine to respect active firewall blocks and browser shielding. Critical payload exfiltration leaks drop deductions from `-30` to `-5` when blocked, high-risk exfiltrations drop from `-10` to `-2`, and programmatically blocked trackers drop from `-8`/`-3` to `-1`/`-0.5`. Poisoned fingerprint attempts drop deductions from `-15` to `-2`. This keeps security grades representative of actual user protection.

### v2.5.1 — In-Page Toasts & Threat Log Deduplication
* **Bottom-Left Page-Level Update Toasts**: Injected warning toasts inside browser pages when an update or reload is ready, replacing OS-level desktop notification clutter with interactive restart elements.
* **Threat Log Arrivals Deduplication**: Grouped identical threats under a single site threat entry. When threat events occur within the same minute, the count is incremented (e.g. `14:08 (x2)`). When multiple events occur on the same date, they are displayed grouped together, displaying only the times and suppressing redundant date text.

### v2.5.0 — Popup & Redirect Blocker
* **Dynamic Popup Tab Prevention**: Automatically intercepts `chrome.tabs.onCreated` and `chrome.tabs.onUpdated` in the background worker. Compares opening popup URLs against the parent tab's registered user-initiated click events. If no match is found, the unsolicited popup is automatically closed, and a warning is logged.
* **Location Hijack Rollback**: Detects unauthorized current-tab redirects to external adware domains (like `xm.com`). Instantly rolls back the navigation to the previous page if the transition lacks verified user intent (click records) and the target is not whitelisted.
* **Main-World window.open Overrides**: Patched `window.open` inside the page main-world context (`injector.js`) to reject window creation scripts that attempt to redirect or spawn popups to external hosts.
* **OAuth & Payments Whitelisting**: Maintained a strict default whitelist of common payment gateways and single sign-on (SSO) authentication providers to guarantee seamless logins.

### v2.4.7 — UI Styling & Clear Button Redesign
* **Redesigned Clear Buttons**: Styled all "Clear" buttons (Dashboard header, Global Threat History, and Extension Popup logs) in cohesive red styling (`var(--red)`) across both dark and light modes.
* **Inline Style Cleanup**: Refactored the inline color styles on the threat history clear button into centralized CSS rules.

### v2.4.6 — Native Notification Audit
* **Clean Desktop Notification Tray**: Removed OS/system-level notifications (`chrome.notifications.create`) for DoubleClick tracker blocks, request firewalls, critical payload leaks, script debugger parses, remote update alarms, local reload requests, and reload success callbacks.
* **In-App Notification Focus**: Relayed these alerts to webpage toasts (inside Chrome browser pages) and dashboard inline banners to prevent OS desktop clutter.
* **Urgent Download Alerts**: Preserved native desktop notifications exclusively for **Suspicious Download Paused** events.

### v2.4.5 — Real-time Sync & "All Active Tabs" Aggregated View
* **Aggregated View**: Implemented the "All Active Tabs" option in the dropdown selector, combining metrics, sorting requests, averaging security scores, and prefixing findings with domain labels.
* **Real-time Active Tab Sync**: Added listeners for tab updates and window focus transitions to keep the background's active tab state fully accurate.
* **Immediate Visibility Refresh**: Added document `visibilitychange` hooks to immediately query and sync the dashboard when the tab gains focus.
* **Persistent Auto-Follow Settings**: Saved the AUTO-FOLLOW checkbox choice locally.

### v2.4.4 — Parallel Tab Tracking & Global Threat History Log
* **Global History Log**: Implemented `addToGlobalLog()` to archive security events historically across all tabs.
* **Inspecting Tab dropdown**: Integrated tab selectors to switch dashboard contexts in real-time.

### v2.4.3 — Native System Notifications on Block
* **Firewall Blocks System Notifications**: Intercepts blocked domains and displays a native Chrome push notification showing the threat categorization and blocked host.
* **DoubleClick Disabled Notification**: Detects DoubleClick ad/analytics trackers and creates a dedicated system alert signifying when tracking has been disabled on the tab.
* **Notification Anti-Spam Cache**: Built an in-memory decay buffer to prevent multiple simultaneous blocking events on a single page from spamming the system tray.

### v2.4.2 — Premium Styling & Source Context Tracking
* **Typography & UI Polish**: Upgraded all text elements to `Inter`. Tailored harmonious dark/light color variables, premium shadows, and translucent top/sidebars.
* **Animated Elements**: Implemented dynamic keyframe background pulses in the Control Center dashboard and subtle animated glow overlays in the popup.
* **Source/Origin Context**: Modified `recordTracker` and webRequest listeners to capture and log request initiators (`details.initiator`), displaying exactly *which site* requested a tracker domain.
* **Detailed Domain Tables**: Appended "First Found On (Source)" columns to the blocked domains table and dashboard trackers list.
* **Real-time Sync Fixes**: Hardened active tab tracking to ignore internal extension pages and implemented dynamic query parameters (`?tabId=`) for popup-to-dashboard navigation.

### v2.4.1 — Authoritative Threat Counting & UI Refreshes
* **Centralized Count Engine**: Added `getTabThreatCount()` in `background.js` to unify calculations across trackers, payload leaks, script scans, and behavioral alerts.
* **Synchronized UI Messaging**: Replaced old polling calls with a push-based model (`saveStateAndNotify`) broadcasting `securityDataUpdated` and `showThreatToast` events instantly.
* **Dynamic Toasts**: Integrated page-level visual alerts that color-code by category (malware, tracker, leak, download) and dismiss automatically.

### v2.4.0 — Core Architecture Implementation
* **Dynamic Rule Compilation**: Integrated programmatic DNR rule adjustments for custom local blocked domains.
* **Main-World Hooking**: Structured MAIN-world injection for interactions and prototype overrides.
* **Audit Core**: Developed the header and mixed-content grading logic with active notification capabilities.

---

## 🛠️ Project Structure

```text
Security-Extension/
├── public/
│   ├── background.js     # Persistent service worker (DNR, debugger, state)
│   ├── content.js        # Content sync bridge & page toast overlays
│   ├── injector.js       # Main-world Canvas, Audio, & WASM override hooks
│   ├── dashboard.html    # Control Center dashboard UI
│   ├── dashboard.js      # Dashboard render loops & user settings controls
│   ├── popup.html        # Compact browser action popup
│   ├── popup.js          # Popup metrics & state toggles
│   ├── manifest.json     # MV3 permissions and script mappings
│   └── images/           # Chrome branding assets
└── README.md             # Project documentation (this file)
```

---

## 📦 Local Installation & Development

1. Clone or download the repository to your local machine.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top-right switch).
4. Click **Load unpacked** (top-left button) and select the `public` directory.
5. Pin the extension to access the popup dashboard and monitor security events in real-time.
