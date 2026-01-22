from __future__ import annotations

import os

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"

# Flask-Limiter instance (init_app happens in create_app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


def create_app() -> Flask:
    # Repo layout (Assessment 3 required):
    #   /src/backend/app (this file after restructuring)
    #   /src/frontend/...
    # When running pre-restructure (older zip), this still works because we compute
    # the repo root by walking up until we find README.md.

    def find_repo_root(start: str) -> str:
        cur = os.path.abspath(start)
        for _ in range(6):
            if os.path.exists(os.path.join(cur, "README.md")):
                return cur
            cur = os.path.dirname(cur)
        # Fallback: previous behaviour (2 levels up from backend/app)
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    base_dir = find_repo_root(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, "src", "frontend", "templates")
    static_dir = os.path.join(base_dir, "src", "frontend", "static")

    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

    # Rate limiting to reduce brute-force attacks (OWASP A07 style control).
    limiter.init_app(app)

    # In production, load from environment/secret manager.
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

    db_path = os.environ.get("DATABASE_URL")
    if not db_path:
        db_file = os.path.join(base_dir, "src", "backend", "instance", "app.db")
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        db_path = f"sqlite:///{db_file}"

    # Safer cookie defaults (good for OWASP/DAST scans)
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    # Only set Secure if behind HTTPS (local dev will be HTTP)
    app.config.setdefault("SESSION_COOKIE_SECURE", os.environ.get("SESSION_COOKIE_SECURE", "0") == "1")

    app.config["SQLALCHEMY_DATABASE_URI"] = db_path
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    login_manager.init_app(app)

    # Blueprints
    from .controllers.auth import auth_bp
    from .controllers.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.after_request
    def set_security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
        )
        return resp

    with app.app_context():
        from .models import AuditLog, EmailAnalysis, User

        db.create_all()

        # Seed demo accounts (useful for marking + live demo). These are created
        # only if they do not already exist.
        if not User.query.filter_by(username="admin").first():
            u = User(username="admin", role="admin")
            u.set_password(os.environ.get("DEMO_ADMIN_PASSWORD", "Admin@123"))
            db.session.add(u)
            db.session.commit()

        if not User.query.filter_by(username="user").first():
            u = User(username="user", role="user")
            u.set_password(os.environ.get("DEMO_USER_PASSWORD", "User@123"))
            db.session.add(u)
            db.session.commit()

    return app
