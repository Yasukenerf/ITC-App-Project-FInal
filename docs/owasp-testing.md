# OWASP Top 10 testing (Assessment Evidence)

This project is a defensive, educational web application. The goal is to **test** for common OWASP Top 10 risks and capture evidence (screenshots / scan outputs), not to create exploitable code.

## Tools used
- OWASP ZAP Baseline (DAST) via GitHub Actions (`.github/workflows/ci.yml`)
- Bandit (SAST)
- pip-audit (dependency scanning)

## Three OWASP risks we explicitly address and test

### A01:2021 – Broken Access Control
**Control implemented**: Role-Based Access Control (admin vs user) and MFA gate for protected routes.
**Where**: `src/backend/app/middleware/authz.py` and admin routes under `/app/admin/...`.
**How to evidence**: Attempt to open `/app/admin/quarantine` as a normal user (should be blocked) and capture screenshot/log.

### A07:2021 – Identification and Authentication Failures
**Control implemented**: TOTP-based 2FA + rate limiting on the login endpoint.
**Where**: `src/backend/app/controllers/auth.py` and limiter config in `src/backend/app/__init__.py`.
**How to evidence**: Show 2FA login flow and demonstrate rate-limit after repeated bad logins.

### A05:2021 – Security Misconfiguration
**Control implemented**: Security headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.).
**Where**: `src/backend/app/__init__.py` (after-request hook).
**How to evidence**: Run OWASP ZAP baseline and attach the report; show that missing headers are reduced.

## ZAP Baseline expectations
ZAP baseline is a passive scan. You may still see informational alerts (e.g., cookie flags in HTTP dev mode). For deployment, enable HTTPS and set `SESSION_COOKIE_SECURE=1`.
