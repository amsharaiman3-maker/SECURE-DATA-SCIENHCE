# COLLEGE MINI PROJECT REPORT

## SUBJECT: SECURE DATA SCIENCE
### TITLE: SECURE STUDENT DATA ANALYTICS SYSTEM
**Academic Year:** 2024–2025  
**Domain:** Secure Data Science, Client-Side Cryptography, and Privacy-Preserving Analytics  
**Repository:** https://github.com/amsharaiman3-maker/SECURE-DATA-SCIENHCE.git  

---

## 1. ABSTRACT

In contemporary educational institutions, academic performance tracking and student evaluation require managing large volumes of demographic and examination records. Traditional analytics platforms frequently store or transmit unencrypted Personally Identifiable Information (PII) over networks to cloud servers, exposing institutions to data breaches, unauthorized surveillance, and regulatory non-compliance with FERPA and GDPR.

The **Secure Student Data Analytics System** introduces a zero-knowledge, client-side data science architecture. Using the W3C Web Crypto API, HTML5 FileReader, and hardware-accelerated AES-256-GCM authenticated encryption, the system computes cohort statistics, detects performance anomalies, renders interactive visualizations, and masks sensitive student identities completely within the browser sandbox without transmitting records to any external backend server.

---

## 2. PROBLEM STATEMENT

Academic analytics datasets often combine educational metrics (marks, percentage, attendance compliance) with sensitive personal identifiers (student names, residential phone numbers, email addresses, institutional roll numbers).

Key security vulnerabilities identified in traditional systems:
1. **Network Sniffing & In-Transit Interception:** Unencrypted CSV uploads over insecure channels.
2. **Database Leakage:** Centralized server-side storage of unmasked student personal profiles.
3. **Identity Correlation Attacks:** Third-party analytics services linking student attendance shortages with personal identities.
4. **Lack of Cryptographic Confidentiality:** Datasets shared between academic advisors are often stored in cleartext spreadsheets.

---

## 3. OBJECTIVES

1. Implement a **Zero-Transmission Architecture** where CSV ingestion and data parsing execute entirely in client-side memory.
2. Develop an **Automated PII Cleansing & Masking Engine** that redacts names, email addresses, contact numbers, and student IDs.
3. Construct an **Academic Statistical Engine** that calculates average marks, attendance distributions, distinction rates, and identifies students requiring academic intervention.
4. Render lightweight **Interactive Canvas Visualizations** (performance tiers donut chart and attendance compliance bar chart) without external third-party tracking scripts.
5. Provide **Hardware-Accelerated AES-256-GCM Authenticated Encryption** for secure dataset exports using PBKDF2 key derivation.
6. Design an enterprise-grade dark navy and blue user interface compliant with WCAG accessibility and responsive standards.

---

## 4. SYSTEM ARCHITECTURE & DATA FLOW

```
+---------------------------------------------------------------------------------+
|                                 USER BROWSER RUNTIME                            |
|                                                                                 |
|  [ Student CSV Dataset ]                                                        |
|           |                                                                     |
|           v                                                                     |
|  [ HTML5 FileReader ] ---> (In-Memory String Stream - No Server Network Calls)   |
|           |                                                                     |
|           +----------------------------------+                                  |
|           |                                  |                                  |
|           v                                  v                                  |
|  [ PII Masking Engine ]             [ Analytics Computation Engine ]            |
|  - Regex Name Masking               - Mean Marks & Attendance Calculations      |
|  - Email Anonymization              - Performance Tier Classification           |
|  - Phone Number Redaction           - Correlation & Risk Identification         |
|  - ID Pseudonymization                       |                                  |
|           |                                  v                                  |
|           v                         [ HTML5 Canvas Visualizer ]                 |
|  [ Student Ledger Table ]           - Donut Performance Classification          |
|  - Filter by Academic Tier          - Bar Attendance Compliance                 |
|  - Real-time PII Toggle                      |                                  |
|           |                                  |                                  |
|           +-----------------+----------------+                                  |
|                             |                                                   |
|                             v                                                   |
|                [ W3C Web Crypto API Enclave ]                                   |
|                - Passphrase Hash (PBKDF2-SHA256, 100K Rounds)                   |
|                - CSPRNG IV Generation (96-bit Salt/IV)                          |
|                - AES-256-GCM Authenticated Encryption                           |
|                             |                                                   |
|                             v                                                   |
|           [ Downloadable Encrypted Package: .enc.json ]                         |
+---------------------------------------------------------------------------------+
```

---

## 5. METHODOLOGY & IMPLEMENTATION

### 5.1 Client-Side Data Ingestion & Validation
The system uses the HTML5 `FileReader` API. File size is validated ($< 10\text{ MB}$), and the MIME/extension format is verified. The CSV parser splits data into records while preserving commas enclosed within quotation marks.

### 5.2 Automated PII Redaction Algorithms
- **Names:** Tokenized into distinct name parts; initials are preserved while subsequent characters are converted to asterisks.
- **Emails:** The local-part is masked keeping the initial and terminal character, while maintaining the educational domain.
- **Telephone Numbers:** All digits except the final 4 are masked with `******`.
- **Student IDs:** Intermediate characters are masked (e.g., `STU****001`).

### 5.3 Performance Classification & Compliance Logic
Students are categorized into standard academic tiers:
- **Distinction:** $\text{Marks} \ge 85\%$
- **First Class:** $70\% \le \text{Marks} < 85\%$
- **Second Class:** $50\% \le \text{Marks} < 70\%$
- **Needs Intervention:** $\text{Marks} < 50\%$

Attendance compliance is evaluated against the statutory university threshold of $75\%$.

### 5.4 Cryptographic Pipeline (AES-256-GCM)
```javascript
// Key Derivation
const baseKey = await crypto.subtle.importKey('raw', passphraseBuffer, 'PBKDF2', false, ['deriveKey']);
const aesKey = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);

// Authenticated Encryption
const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintextBuffer);
```

---

## 6. EXPERIMENTAL RESULTS & VERIFICATION

| Verification Metric | Expected Outcome | Observed Result | Status |
|---|---|---|---|
| In-browser CSV Parsing | Process 25 records without server transmission | 25 records loaded in $< 20\text{ms}$ | **PASSED** |
| PII Masking Accuracy | Redact all 4 sensitive fields | Names, phones, emails, IDs sanitized | **PASSED** |
| Statistics Accuracy | Mean marks and attendance calculated correctly | Cohort average verified against ground truth | **PASSED** |
| Canvas Rendering | Render donut and bar charts | HTML5 Canvas charts rendered with legends | **PASSED** |
| AES-256-GCM Encryption | Generate authenticated cipher package | 100,000 round PBKDF2 + AES-GCM output generated | **PASSED** |
| Static Bundle Size | Total package size $< 10\text{ MB}$ | Total project footprint: $\approx 85\text{ KB}$ | **PASSED** |

---

## 7. CONCLUSION & FUTURE SCOPE

The **Secure Student Data Analytics System** demonstrates how modern web standards and client-side cryptography can empower institutions with rich analytical insights without compromising student privacy.

**Future Enhancements:**
- Integration of Differential Privacy ($\varepsilon$-DP) noise mechanisms for statistical queries.
- Homomorphic encryption primitives for multi-institutional aggregated benchmarks.
- Biometric WebAuthn passkey authentication for session unlock.

---

## 8. REFERENCES
1. W3C Recommendation: *Web Cryptography API*, World Wide Web Consortium, 2017.
2. NIST Special Publication 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*.
3. Family Educational Rights and Privacy Act (FERPA), 34 CFR Part 99.
4. General Data Protection Regulation (GDPR), Regulation (EU) 2016/679, Article 5 & Article 32.
