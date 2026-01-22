# Architecture

## High level
- **Frontend**: server-side rendered HTML templates (minimal UI) under `/frontend`
- **Backend**: Flask API + security + DB under `/backend/app`
- **Database**: SQLite (demo), can be swapped to Postgres/MySQL

## Layered structure
- `controllers/`: route handlers
- `middleware/`: RBAC and MFA enforcement
- `services/`: business logic (phishing analysis)
- `models/`: persistence models (users, analyses, audit logs)

