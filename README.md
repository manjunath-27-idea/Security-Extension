# Shield Sandbox Firewall v2.4.2

A professional, high-performance Chrome security extension designed to perform deep packet inspection, prevent PII/secret exfiltration, override behavioral fingerprinting vectors, and block trackers natively using browser-level filtering rules.

## 🚀 Key Features

* **Native Blocklist Rules Engine**: Utilizes Chrome's native `declarativeNetRequest` API to perform lightning-fast, C++ level dropping of malicious domains, merging default rules with custom user-blocked items.
* **Deep Script Scanner**: Hooks Chrome's native `debugger` API to scan parsed script sources on the fly for dynamic execution (`eval`), dynamic constructors (`new Function`), storage harvesting, and hex obfuscation.
* **Behavioral Fingerprint Shields**: Automatically monitors main-world execution via `injector.js`. Alters Canvas and Audio outputs dynamically if queried without genuine user interaction, poisoning fingerprint hashes without visual distortion.
* **Mixed Content & Security Auditing**: Analyzes page headers, insecure HTTP resource loads, password form transmissions, and external script counts, producing a grading score from A to F.
* **Suspicious Download Interceptor**: Automatically monitors and pauses high-risk executable downloads, triggering a system-level confirm/discard notification.
* **Premium Glassmorphic UI**: Includes tailored light/dark themes with fluid gradient background pulses, synchronized circular progress gauges, and real-time update push notifications.

---

## 📅 Version History & Release Logs

### v2.4.2 (Current) — Premium Styling & Source Context Tracking
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
