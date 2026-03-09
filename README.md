<div align="center">

# 🔑 KeySentinel

### Universal API Key Validator for Security Researchers & Bug Bounty Hunters

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)]()
[![React](https://img.shields.io/badge/React-18-61dafb.svg?logo=react)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5-646cff.svg?logo=vite)](https://vite.dev)
[![Author](https://img.shields.io/badge/by-PratikKaran23-purple.svg)](https://github.com/PratikKaran23)

**Validate 17+ API key types with live API checks — built for recon, bug bounty, and security research.**

[Features](#features) · [Supported Providers](#supported-providers) · [Setup](#setup) · [Security](#security) · [Disclaimer](#disclaimer)

</div>

---

## Overview

KeySentinel is a professional, browser-based tool that validates API keys found during security engagements. It performs both **format checks** (regex pattern matching) and **live API validation** (hitting the actual provider endpoint) to confirm whether a key is active, and extracts useful recon data — account info, scopes, plan tier, ARN, expiry, and more.

No backend required. Keys are validated in-memory only and are never stored, logged, or sent anywhere except the respective API provider.

---

## Features

- 🔍 **Dual Validation** — format check + live API ping for every key type
- 📊 **Rich Metadata** — extracts account info, scopes, plan tier, ARN, org, expiry
- 🗂️ **17 Providers** across 6 categories — AI, Cloud, Payments, Messaging, Auth, E-Commerce
- 🔎 **Search & Filter** — find key types instantly by name or category
- 🕑 **Session History** — log of all checks with timestamps and results
- 🔐 **JWT Decoder** — full header/payload decode with expiry status
- 🔴 **Stripe LIVE/TEST detection** — flags production keys explicitly
- ⚡ **AWS STS** — uses `GetCallerIdentity` with proper AWS4-HMAC-SHA256 signing — returns Account ID + ARN with zero permissions required
- 🛡️ **XSS-safe** — all API response content sanitized before rendering

---

## Supported Providers

| # | Provider | Category | What it returns |
|---|---|---|---|
| 1 | **Anthropic / Claude** | AI / ML | Plan tier, RPM, TPM limits |
| 2 | **OpenAI** | AI / ML | Account info, available models |
| 3 | **Google AI (Gemini)** | AI / ML | Available models list |
| 4 | **HuggingFace** | AI / ML | Username, account type, orgs |
| 5 | **GitHub Token** | DevOps / Cloud | Username, name, plan, scopes, private repo count |
| 6 | **AWS Access Key** | DevOps / Cloud | Account ID, ARN, User ID via STS |
| 7 | **GitLab Token** | DevOps / Cloud | Username, email, admin status |
| 8 | **NPM Token** | DevOps / Cloud | Username |
| 9 | **Firebase / GCP** | DevOps / Cloud | Key type, enabled services |
| 10 | **Databricks Token** | DevOps / Cloud | Workspace clusters count |
| 11 | **Stripe** | Payments | Account ID, business name, country, LIVE vs TEST mode |
| 12 | **Slack** | Messaging | Team name, username, workspace URL |
| 13 | **Telegram Bot** | Messaging | Bot name, username, bot ID |
| 14 | **Twilio** | Messaging | Account name, status, account type |
| 15 | **SendGrid** | Messaging | Username, account type |
| 16 | **Mailgun** | Messaging | Verified domains list |
| 17 | **Discord Bot** | Messaging | Username, bot ID, verified status |
| 18 | **JWT Token** | Auth / Identity | Algorithm, all claims, issuer, subject, expiry status |
| 19 | **Shopify Admin API** | E-Commerce | Shop name, email, plan, currency |

---

## Setup

### Prerequisites
- Node.js v18+

### Run locally

```bash
git clone https://github.com/PratikKaran23/claude-api-inspector.git
cd claude-api-inspector
npm install
npm run dev
# Opens at http://localhost:3000
```

### Build for production

```bash
npm run build
npm run preview
```

---

## Security

| Measure | Detail |
|---|---|
| Format validation | Regex check before any network request fires |
| Input sanitization | Control chars stripped from all inputs |
| Output sanitization | All API response content HTML-escaped (XSS prevention) |
| No persistence | Keys stored in React state only — never written to disk or localStorage |
| No telemetry | Zero analytics, tracking, or third-party requests |
| CORS-safe | Uses `anthropic-dangerous-direct-browser-access` only for Anthropic |

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.**

Use KeySentinel only on API keys from systems you own or have **explicit written permission** to test. Unauthorized access to API keys or accounts may violate the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, or equivalent laws in your jurisdiction.

Always follow responsible disclosure practices and your bug bounty program's rules of engagement before testing any key you discover during recon.

---

## Author

<div>
  <strong>Pratik Karan</strong> — Security Consultant @ Prescient Security<br/>
  OSCP · OSWE · BSCP<br/>
  HackerOne: <a href="https://hackerone.com/bloody_eye"><code>bloody_eye</code></a> · 
  GitHub: <a href="https://github.com/PratikKaran23">PratikKaran23</a>
</div>

---

## License

[MIT](LICENSE) © 2025 PratikKaran23
