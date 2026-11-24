# 🛡️ Secure Student Data Analytics System

A professional, zero-transmission web application designed for academic performance analytics with privacy preservation, client-side PII masking, and AES-256-GCM authenticated encryption.

Developed as a college mini project under the subject **Secure Data Science**.

🔗 **GitHub Repository:** https://github.com/amsharaiman3-maker/SECURE-DATA-SCIENHCE.git

---

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Key Security Architecture](#key-security-architecture)
3. [Features](#features)
4. [Technology Stack](#technology-stack)
5. [Local Setup & Testing](#local-setup--testing)
6. [Vercel Deployment](#vercel-deployment)
7. [Cryptographic Specifications](#cryptographic-specifications)
8. [License](#license)

---

## 🎯 Project Overview

Educational institutions frequently analyze student datasets to track academic performance, subject pass rates, and attendance compliance. However, these datasets contain sensitive Personally Identifiable Information (PII) including student names, phone numbers, home email addresses, and enrollment IDs.

The **Secure Student Data Analytics System** solves this privacy risk by executing all data parsing, statistical analytics, visualization, and encryption strictly inside the local web browser memory enclave via HTML5 and Web Crypto API. **Zero student records are transmitted over the network.**

---

## 🛡️ Key Security Architecture

- **Zero-Transmission Runtime:** Uploaded CSV spreadsheets are parsed locally via HTML5 `FileReader`. No backend database or server endpoint receives student records.
- **Automated PII Masking:**
  - **Names:** Redacted to initials and masked tokens (e.g. `Aarav Sharma` $\rightarrow$ `A**** S*****`).
  - **Emails:** Anonymized preserving domain (e.g. `diya.patel@example.edu` $\rightarrow$ `d***l@example.edu`).
  - **Phone Numbers:** Masked preserving only the final four digits (e.g. `+91-9876543210` $\rightarrow$ `+91-******3210`).
  - **Student IDs:** Masked preserving prefix and sequence tail (e.g. `STU2024001` $\rightarrow$ `STU****001`).
- **AES-256-GCM Hardware-Accelerated Encryption:**
  - Key derivation using **PBKDF2-HMAC-SHA256** with **100,000 iterations**.
  - Random 12-byte cryptographically secure initialization vector (IV) via `crypto.getRandomValues`.
  - Authenticated Galois/Counter Mode (GCM) ensuring both confidentiality and ciphertext integrity.
- **Privacy Dashboard & Role-Based Access Simulation:**
  - Demo authentication simulation emphasizing defense-in-depth principles.
  - Granular toggle between masked privacy view and officer view with explicit privacy warnings.

---

## ✨ Features

- 🔐 **Demo Authentication Flow:** Role-based access control with session state management.
- 📂 **Drag-and-Drop CSV Ingestion:** Automatic schema validation, numeric constraint checking, and file size protection ($< 10\text{ MB}$).
- 👥 **Sample Dataset Loader:** Includes 25 synthetic student records with marks and attendance data.
- 📊 **Executive Analytics KPIs:** Total students, average marks, attendance rate, and distinction counts.
- 📈 **Interactive Canvas Charts:**
  - **Academic Performance Donut Chart:** Categorizes students into Distinctions ($\ge 85\%$), First Class ($70-84\%$), Second Class ($50-69\%$), and Academic Intervention ($< 50\%$).
  - **Attendance Compliance Bar Chart:** Monitors regulatory attendance ($\ge 85\%$, $75-84\%$, and Shortage $< 75\%$).
- 🔍 **Search & Multi-Tier Filtering:** Fast ledger search across names, IDs, scores, and compliance status.
- 📥 **Dual Secure Export Options:**
  1. Anonymized CSV export for downstream privacy-compliant research.
  2. Encrypted `.enc.json` package protected by passphrases using AES-256-GCM.

---

## 💻 Technology Stack

- **HTML5:** Semantic architecture, accessible forms, canvas elements.
- **CSS3:** Custom enterprise navy/blue theme, responsive flexbox & grid, custom scrollbars, animations.
- **Vanilla JavaScript (ES6+):** Zero external dependencies, pure native DOM manipulation.
- **Web Crypto API (`window.crypto.subtle`):** Browser-native cryptographic operations.
- **Vercel:** Static edge hosting with zero-config deployment.

---

## 🚀 Local Setup & Testing

No package managers, build steps, or runtime dependencies are required.

```bash
# 1. Clone repository
git clone https://github.com/amsharaiman3-maker/SECURE-DATA-SCIENHCE.git
cd SECURE-DATA-SCIENHCE

# 2. Run with any local HTTP server (or double-click index.html)
# Using Python 3:
python -m http.server 8000

# Using Node:
npx serve .
```

Open [http://localhost:8000](http://localhost:8000) in your web browser.

---

## 🌐 Vercel Deployment

This project is 100% static and optimized for instant Vercel deployment:

1. Push this project to GitHub repository `SECURE-DATA-SCIENHCE`.
2. Go to [vercel.com](https://vercel.com) $\rightarrow$ **Add New...** $\rightarrow$ **Project**.
3. Import **`amsharaiman3-maker/SECURE-DATA-SCIENHCE`**.
4. Framework Preset: **Other** (Static Site).
5. Output Directory: `./` (Root).
6. Click **Deploy**. Done!

---

## 🔒 Cryptographic Specifications

| Parameter | Specification | Standard |
|---|---|---|
| **Cipher Algorithm** | AES-GCM (Galois/Counter Mode) | NIST SP 800-38D |
| **Key Length** | 256 bits | High Security |
| **Key Derivation Function** | PBKDF2 with HMAC-SHA-256 | RFC 2898 / NIST SP 800-132 |
| **KDF Iterations** | 100,000 rounds | OWASP Recommended |
| **Salt Length** | 128 bits (16 bytes) | CSPRNG |
| **Nonce / IV Length** | 96 bits (12 bytes) | Standard for AES-GCM |
| **Auth Tag Length** | 128 bits | Cryptographic Integrity |

---

## 📄 License
MIT License — Academic & Educational Use Only.
