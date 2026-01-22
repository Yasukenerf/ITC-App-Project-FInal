from __future__ import annotations

from functools import wraps

from flask import abort, session
from flask_login import current_user


def require_role(*roles: str):
    """RBAC: require current_user.role in roles."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_mfa(fn):
    """Require successful MFA verification for this session."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if current_user.totp_secret and not session.get("mfa_ok"):
            abort(403)
        return fn(*args, **kwargs)

    return wrapper
