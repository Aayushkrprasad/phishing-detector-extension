# 🔐 Phishing Detector Pro v3.6 (Enterprise Cyber Suite)

An enterprise-grade, real-time AI & Heuristic Chrome Extension for phishing, typosquatting, credential harvesting, clipboard hijacking, social engineering text inspection, and Threat Intelligence.

---

## 🚀 Advanced Capabilities & Architecture

### 0. 🌟 Ultra-Simple User Experience (Simple vs. Advanced Mode)
- **Simple Mode (Default)**: Designed for non-technical users with a clear, jargon-free **Pulsing Security Shield** (🟢 Secure / 🟡 Caution / 🔴 Danger), simple plain-English summaries, and a single **Master Real-time Shield** toggle.
- **Advanced Mode**: 1-click toggle to unlock deep threat telemetry, Shannon Entropy meters, Levenshtein edit distance calculations, forensic logs, and interactive labs.

### 1. 🛡️ In-Page Active Defense (Zero-Trust Browsing)
- **Automatic High-Risk Page Warning Toast**: Instant on-screen security alert when landing on dangerous or typosquatted sites.
- **Hover Link Shield**: Real-time mouse hover listener with floating security badge (🟢 Verified / 🟡 Caution / 🔴 Phishing Risk) showing destination threat score before clicking.
- **In-Page Credential Guard**: Prevents credential harvesting by alerting before passwords or credit card numbers are typed on unencrypted HTTP or high-risk domains.
- **Fake OAuth & Window Modal Detector**: Detects DOM elements simulating browser login windows (e.g., fake "Sign in with Google" / "Sign in with Microsoft" dialogs).
- **Crypto Clipboard Hijacking (Clipjacking) Sentinel**: Detects and alerts if malicious page scripts attempt to replace copied Bitcoin, Ethereum, or Solana wallet addresses.
- **Cross-Domain Webhook Exfiltration Interceptor**: Flags forms attempting to exfiltrate submitted form data directly to unauthorized external endpoints (e.g. Discord webhooks or Telegram bots).

### 2. 🤖 AI Code & Prompt Injection Security Sentinel (NEW)
- **Live In-Page AI Protection**: Observes streaming code responses on ChatGPT, Claude, Gemini, and GitHub.
- **AI Package Hallucination / Slopsquatting**: Detects hallucinated packages (e.g. `pip install sys` which exploits Python built-ins with malicious supply-chain packages).
- **Remote Pipe & Shell Interception**: Flags `curl ... | bash`, `irm ... | iex`, reverse shells (`/bin/sh -i`, netcat sockets), and credential exfiltration webhooks (Discord/Telegram).
- **In-Page Alert Badges & Safe Copy Guard**: Alerts users before copying or executing dangerous AI code.

### 3. 🎓 Academic Thesis Clone & Journal Hijacking Guard (NEW)
- **Google Scholar In-Page Shield**: Scans search results on `scholar.google.com` to distinguish verified publishers from predatory clone mirrors.
- **DOI Authority Cross-Referencing**: Extracts Digital Object Identifiers (`10.xxxx/...`) and validates whether the hosting domain matches official publishers (IEEE, Springer, Nature, Elsevier, ACM, arXiv) or an unauthorized paper-mill clone.
- **Paper Mill & Predatory Fee Flagging**: Identifies fraudulent publication fee demands on hijacked academic journals.

### 4. 📧 Email & SMS Social Engineering Text & File Analyzer (NEW)
- Dedicated Text Analyzer tab in the Popup and Security Lab with **Direct File Upload Support** (`.eml`, `.txt`, `.pdf`, `.msg`, `.log`).
- **Drag-and-Drop / 1-Click Upload**: Extracts text and email headers (Subject, From, Body) directly from saved email files or suspicious documents.
- Evaluates content for psychological panic triggers, artificial urgency, fake account suspension warnings, gift card/lottery scams, OTP theft demands, and suspicious embedded URLs.

### 5. 🔍 Instant Multi-Vector Inspector (In-Popup Scanner)
- 5-tab popup interface (**Live Tab**, **URL Scanner**, **Text Analyzer**, **AI Code Guard**, and **Scholar Guard**).
- Computes mathematical Shannon Entropy, checks against 50+ canonical global brand permutations, inspects TLD risk, and generates full forensic threat audits.
- **1-Click Copy & PDF Audit Export**: Copy structured forensic summaries or print PDF audit reports.

### 6. 🧪 Interactive Threat Simulator & Security Lab (`sandbox.html`)
A dedicated interactive cybersecurity testbed with 9 hands-on attack modules:
1. 🎯 **Typosquatting & Levenshtein Matrix**: Computes dynamic 1-edit distance against top enterprise domains with explanatory threat analysis.
2. 🎲 **Shannon Entropy & DGA Generator**: Measures information disorder and simulates botnet algorithmic domain generation.
3. 🔤 **IDN Homoglyph & Punycode Resolver**: De-obfuscates Cyrillic/Greek Unicode lookalikes and `xn--` punycode strings.
4. 🖼️ **Quishing (QR Code Phishing) Analyzer**: Safely inspects and decodes QR codes inside the sandbox without exposing mobile devices.
5. 🔐 **Credential & Form Hijack Simulator**: Interactive demonstration of real-time form interception and defensive guard banners.
6. 📧 **Email & SMS Social Engineering Inspector**: Evaluates text message content and extracts embedded threat vectors.
7. ⚡ **Live Threat Payload Sandbox**: Test custom URLs and payloads with real-time heuristic scoring.
8. 🤖 **AI Code & Prompt Poisoning Simulator**: Test AI hallucinations, shell pipes, and exfiltration scripts.
9. 🎓 **Academic Thesis & Journal Hijack Simulator**: Compare authentic IEEE/Nature DOIs vs unauthorized clone mirrors.

### 7. 📊 Security Analytics, Rule Backup & STIX 2.1 / IOC Compliance
- Real-time KPI summary cards (Total Scans, Phishing Blocked, Safe Domain Rate %).
- **JSON Security Rules Import/Export**: Backup Whitelist/Blacklist rules or import external threat list bundles (`trusted.html`).
- **Export Security Audit Reports** in **CSV**, **JSON**, and standardized **STIX 2.1 IOC** (Indicators of Compromise) for SOC teams.

---

## 📁 Project Structure

```
phishing-detector-extension/
├── manifest.json            # Manifest V3 configuration & web accessible resources
├── heuristics.js            # Core mathematical heuristics (Levenshtein, Entropy, Homoglyphs)
├── service-worker.js        # Background monitoring, auto-blocking, badge status
├── content.js               # In-page Hover Link Shield, Credential Guard, Clipjacking Sentinel
├── content.css              # Floating badges, banners, and toast alert styles
├── popup.html               # Multi-tab Popup (Live Tab Inspector & Instant URL Scanner)
├── popup.css                # Cyber dark-mode UI & interactive gauge animations
├── popup.js                 # Popup controller & quick scanner logic
├── sandbox.html             # Interactive Cyber Threat Simulator & Security Lab
├── sandbox.css              # Cyber defense lab styles & visual meters
├── sandbox.js               # Attack simulators, QR analyzer & STIX 2.1 export
├── history.html             # Security Analytics & Forensic Log Dashboard
├── history.js               # History charts, search filtering, CSV/JSON export
├── trusted.html             # Whitelist & Blacklist rules manager
├── trusted.js               # Rules manager logic
├── warning.html             # High-risk auto-block intercept screen
└── warning.js               # Intercept navigation controller
```

---

## 🛠️ Installation & Setup

1. Open Google Chrome, Brave, or Microsoft Edge.
2. Navigate to `chrome://extensions`.
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked**.
5. Select the `phishing-detector-extension` folder.

---

## 🧪 Testing Scenarios & Demo Workflows

1. **Instant URL Scanner**:
   - Click the extension icon and select the **URL Scanner** tab.
   - Click test pills (e.g. `paypa1.com`, `g00gle-security.xyz`, `chase-bank.update-auth.tk`) to see instant risk calculations.
2. **Interactive Security Lab**:
   - Click **Lab** in the popup footer or open `sandbox.html`.
   - Test Levenshtein distance, generate random DGA strings, decode Punycode homoglyphs, and inspect QR codes safely.
3. **In-Page Hover Link Shield**:
   - Hover over links on search results or webmail to observe real-time safety badges.
4. **Credential Guard**:
   - Focus on password input fields on HTTP or unverified test domains to see the Credential Guard banner.
5. **Security Analytics & STIX Export**:
   - Click **Analytics** to view forensic logs and export STIX 2.1 IOC packages for enterprise threat feeds.

---

## 👨‍💻 Author
Aayush Prasad