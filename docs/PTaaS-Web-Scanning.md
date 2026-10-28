# PTaaS Web Security Scanning

`lory scan` connects developer workstations directly to Lorikeet Security's **Penetration Testing as a Service (PTaaS)** platform, performing real-time passive and active vulnerability audits against live URLs.

---

## 1. Running a Web Security Scan

To scan any live web application or API:

```bash
# Scan a live domain or staging endpoint
lory scan https://example.com

# Output structured JSON for automation
lory scan https://api.example.com --format=json
```

When a URL (beginning with `http://` or `https://`, or containing a common TLD like `.com`, `.org`, `.net`, `.io`) is supplied to `lory scan`, it automatically activates the PTaaS Web Security Scanner instead of local file review.

---

## 2. Platform Audit Protocol

The scan is executed through the Lorikeet Security platform audit API:
```text
POST https://lorikeetsecurity.com/ptaas/tools/scan-api.php
Content-Type: application/json
Authorization: Bearer <Talon_Access_Token>

{
  "target": "https://example.com"
}
```

### Response Payload Structure
```json
{
  "target": "https://example.com",
  "score": 88,
  "status": "PASSED",
  "scan_id": "scan_8f29d41b",
  "summary": "Application demonstrates strong transport and cookie security posture.",
  "checks": [
    {
      "name": "Strict-Transport-Security (HSTS)",
      "passed": true,
      "severity": "high",
      "description": "max-age=31536000; includeSubDomains; preload configured correctly."
    },
    {
      "name": "Content-Security-Policy (CSP)",
      "passed": true,
      "severity": "high",
      "description": "Restricts script-src, object-src, and default-src."
    },
    {
      "name": "Cookie Security Flags",
      "passed": true,
      "severity": "medium",
      "description": "All session cookies enforce Secure, HttpOnly, and SameSite=Lax."
    },
    {
      "name": "Server Version Disclosure",
      "passed": false,
      "severity": "low",
      "description": "Server header exposes nginx/1.24.0. Recommend removing banner."
    }
  ]
}
```

---

## 3. Audited Security Controls

The PTaaS engine checks across key web security dimensions:

### 1. HTTP Security Headers
- **Content-Security-Policy (CSP)**: Validates protection against Cross-Site Scripting (XSS) and data injection.
- **Strict-Transport-Security (HSTS)**: Checks for `max-age` (minimum 1 year recommended), `includeSubDomains`, and `preload`.
- **X-Frame-Options / frame-ancestors**: Verifies clickjacking mitigation.
- **X-Content-Type-Options**: Ensures `nosniff` is enforced.
- **Referrer-Policy**: Ensures sensitive path parameters are not leaked in referrers.
- **Permissions-Policy**: Restricts access to sensitive browser APIs (camera, geolocation, microphone).

### 2. Transport Layer Security (TLS/SSL)
- Certificate validity, expiration date, and issuer chain.
- Insecure protocol rejection (TLS 1.0 and TLS 1.1 disabled; TLS 1.2 and TLS 1.3 enforced).
- Strong cipher suite negotiation and Forward Secrecy.

### 3. Cookie & Session Security
- `Secure` flag on all HTTPS cookies.
- `HttpOnly` flag preventing client-side script theft of session identifiers.
- `SameSite` attribute (`Strict` or `Lax`) defending against Cross-Site Request Forgery (CSRF).

### 4. Information Leakage & Fingerprinting
- `Server` and `X-Powered-By` banner suppression.
- Publicly accessible debug, `.git`, `.env`, or configuration files.
- CORS policy review (prevention of wildcard `Access-Control-Allow-Origin: *` with credentials).

---

## 4. Security Scoring & Trust Badge Qualification

The platform computes an overall posture score from **0 to 100**:

| Score Range | Status | Assessment | Trust Badge Eligibility |
| :---: | :---: | :--- | :---: |
| **85 – 100** | **VERIFIED** | Outstanding security controls; passes all high/critical audits. | ✅ Eligible |
| **70 – 84** | **PASSED** | Acceptable posture; minor low-severity recommendations. | ✅ Eligible |
| **< 70** | **AUDITED** | Remediation required for key controls before qualification. | ❌ Ineligible |

When your application achieves a qualifying score of 70+, `lory` automatically displays a prompt to generate your verified trust badge:

```text
[Lorikeet Trust Badge] Assessment complete (88/100). Run `lory badge example.com` to generate your verified footer badge.
```
