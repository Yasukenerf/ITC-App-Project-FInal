# Threat Model (Starter)

## Assets
- User accounts (password hashes)
- 2FA secrets
- Email content submitted for analysis
- Audit logs

## Entry points
- Login endpoint
- Analyze endpoint (user input)
- Admin quarantine actions

## Example threats (STRIDE)
- Spoofing: credential stuffing -> mitigate rate limiting (future work)
- Tampering: malicious input -> server-side validation, escaping
- Repudiation: dispute actions -> audit logging
- Information disclosure: data leakage -> avoid printing emails to logs
- Denial of service: large payloads -> request size limits
- Elevation of privilege: bypass RBAC -> enforce decorators
