# Secure Phishing Email Detector (DevSecOps)

This repository is a refactor of the team's original Tkinter phishing detector into a **professional full‑stack** structure (backend + frontend + DB + DevSecOps).

## What this includes (Assessment minimums)
- **Authentication** (login) + **RBAC** (user/admin)
- **2FA (TOTP)** via Google/Microsoft Authenticator
- **Database** (SQLite) to store users, analyses, audit logs
- **Advanced, explainable phishing analysis engine**
  - weighted scoring + evidence breakdown
  - URL heuristics (IP domains, @ tricks, excessive subdomains, punycode, shorteners, suspicious tokens)
  - header signals (Reply-To mismatch, SPF/DKIM/DMARC fail tokens when present)
  - attachment name risk checks (dangerous extensions, double-extension trick)
- **Quarantine** (admin-only)
- **Export** analysis history as CSV

## Project structure (matches Assessment 3 repo structure)
```
src/
  backend/
    app/
      controllers/    # routes
      middleware/     # RBAC + 2FA guards
      services/       # phishing analyzer
      models.py       # DB models
      utils/          # security helpers
    server.py         # entry point
    requirements.txt
  frontend/
    templates/        # HTML templates
    static/           # CSS
tests/                # pytest tests
docs/                 # report artifacts (scan results/screenshots)
ci-cd/                # pipeline notes
.github/workflows/ci.yml
```

## Run locally (Windows/macOS/Linux)

### 1) Backend
```bash
cd src/backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python server.py
```
Then open:
- `http://127.0.0.1:5000/login`

### 2) Demo accounts (already created)
On first run, the app seeds two demo accounts:

- **Admin**: `admin` / `Admin@123`
- **User**: `user` / `User@123`

You can override these via environment variables:
- `DEMO_ADMIN_PASSWORD`
- `DEMO_USER_PASSWORD`

Registration is also enabled for assessment demos at:
- `http://127.0.0.1:5000/register`

### 3) Enable 2FA
After login:
- Click **2FA Setup** → enable → scan QR code → verify code.

## Admin capabilities (RBAC)
When logged in as **admin**, the navbar shows:
- **Admin Overview** (recent analyses + audit logs)
- **Quarantine** (flagged emails)
- **Incident Response** (simulated IR workflow recorded in audit log)

## Security tooling (DevSecOps)
Suggested tools to run in CI/CD:
- **Bandit** (SAST)
- **pip-audit** (dependency scanning)
- **OWASP ZAP** (DAST) against the running web app

See `ci-cd/github-actions.yml`.

## Ethical note
This project is for educational purposes only. Do not use it against real users or systems.
