# DevSecOps pipeline (Assessment Evidence)

The CI pipeline is implemented using **GitHub Actions** in `.github/workflows/ci.yml`.

## Stages
1. **Build / Install** – Install Python and dependencies.
2. **SAST** – Bandit scans `src/backend/app` and outputs `docs/security-results/bandit-report.txt`.
3. **Dependency Scan** – pip-audit checks `src/backend/requirements.txt` and outputs `docs/security-results/pip-audit.txt`.
4. **Tests** – Pytest runs the unit tests in `/tests`.
5. **DAST** – OWASP ZAP Baseline runs against the locally started Flask server (`http://localhost:5000`) and uploads a ZAP artifact.

## Required evidence for your report
- Screenshot of a successful GitHub Actions run
- Bandit report file
- pip-audit report file
- ZAP report artifact (downloaded from Actions)
