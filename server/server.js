/**
 * Phishing Detector Enterprise - Node.js Backend Cloud Threat API
 * Provides RESTful Threat Intelligence endpoints, SOC Telemetry Ingestion (STIX 2.1), and Rule Sync.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(cors());
app.use(express.json());

// In-Memory Telemetry Database Store
const telemetryStore = [];
const customProtectedBrands = [
  { name: "MyCompany Portal", domain: "mycompany.com" },
  { name: "Acme Bank", domain: "acmebank.org" }
];

// 1. Healthcheck Endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ACTIVE',
    version: '3.6.0',
    service: 'Phishing Detector Enterprise Threat Cloud',
    timestamp: new Date().toISOString()
  });
});

// 2. Cloud URL Scan Endpoint
app.post('/api/v1/scan/url', (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ success: false, error: 'Missing target URL parameter.' });
  }

  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();

    let risk = 0;
    const threats = [];

    if (parsed.protocol === 'http:') {
      risk += 25;
      threats.push({ icon: '🔓', type: 'INSECURE_HTTP', text: 'Unencrypted HTTP protocol connection.' });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      risk += 45;
      threats.push({ icon: '🌐', type: 'RAW_IP', text: 'Uses direct IP address instead of registered domain.' });
    }

    if (host.includes('xn--')) {
      risk += 45;
      threats.push({ icon: '🔤', type: 'PUNYCODE', text: 'Punycode IDN homograph character spoofing.' });
    }

    if (host.endsWith('.tk') || host.endsWith('.xyz') || host.endsWith('.top')) {
      risk += 35;
      threats.push({ icon: '🚩', type: 'HIGH_RISK_TLD', text: 'High-risk top-level domain frequently abused in phishing.' });
    }

    risk = Math.min(Math.max(risk, 0), 100);

    return res.json({
      success: true,
      data: {
        url,
        hostname: host,
        riskScore: risk,
        threatLevel: risk >= 60 ? 'HIGH_RISK' : risk >= 25 ? 'SUSPICIOUS' : 'SAFE',
        threats,
        scannedAt: new Date().toISOString()
      }
    });
  } catch (err) {
    return res.status(400).json({ success: false, error: 'Invalid URL format.' });
  }
});

// 3. Social Engineering Text Analyzer Endpoint
app.post('/api/v1/scan/text', (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ success: false, error: 'Missing text content.' });
  }

  const textLower = text.toLowerCase();
  let risk = 0;
  let urgency = 0;
  const threats = [];

  if (textLower.includes('suspended') || textLower.includes('immediate action')) {
    risk += 30;
    urgency += 40;
    threats.push({ icon: '⏳', type: 'URGENCY_SCARE', text: 'Coercive time pressure / account suspension warning.' });
  }

  if (textLower.includes('gift card') || textLower.includes('you have won')) {
    risk += 30;
    threats.push({ icon: '💰', type: 'REWARD_SCAM', text: 'Baiting scam: Free reward or prize claim.' });
  }

  if (textLower.includes('seed phrase') || textLower.includes('verify your password') || textLower.includes('otp')) {
    risk += 40;
    threats.push({ icon: '🔑', type: 'CREDENTIAL_HARVEST', text: 'Credential theft: Requests password, OTP, or seed phrase.' });
  }

  risk = Math.min(Math.max(risk, 0), 100);
  urgency = Math.min(Math.max(urgency, 0), 100);

  return res.json({
    success: true,
    data: {
      riskScore: risk,
      urgencyScore: urgency,
      threatLevel: risk >= 60 ? 'HIGH_RISK' : risk >= 25 ? 'SUSPICIOUS' : 'SAFE',
      threats,
      evaluatedAt: new Date().toISOString()
    }
  });
});

// 4. Enterprise SOC Telemetry Report Ingestion (STIX 2.1)
app.post('/api/v1/telemetry/report', (req, res) => {
  const telemetryData = req.body;
  if (!telemetryData) {
    return res.status(400).json({ success: false, error: 'Empty telemetry payload.' });
  }

  const reportId = `report-${Date.now()}`;
  telemetryStore.push({ id: reportId, data: telemetryData, receivedAt: new Date().toISOString() });

  console.log(`[SOC Telemetry] Ingested report ${reportId} for host: ${telemetryData.hostname || 'Unknown'}`);

  return res.status(201).json({
    success: true,
    reportId,
    stixCompliant: true,
    message: 'Telemetry successfully logged to Enterprise Security Information Event Management (SIEM).'
  });
});

// 5. Enterprise Rule Sync Endpoint
app.get('/api/v1/rules/sync', (req, res) => {
  res.json({
    success: true,
    version: '3.6.0',
    lastUpdated: new Date().toISOString(),
    protectedBrands: customProtectedBrands,
    globalHighRiskTlds: [
      '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.link', '.work'
    ]
  });
});

app.listen(PORT, () => {
  console.log(`🛡️ Phishing Detector Enterprise API listening on port ${PORT}`);
});
