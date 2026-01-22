from __future__ import annotations

import qrcode
from io import BytesIO

from flask import Blueprint, flash, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_user, logout_user

from .. import db, limiter
from ..models import AuditLog, User
from ..utils.security import generate_totp_secret, totp_uri, verify_totp


auth_bp = Blueprint("auth", __name__)


def _audit(event: str, detail: str | None = None, ip: str | None = None, user_id: int | None = None):
    log = AuditLog(event=event, detail=detail, ip_address=ip, user_id=user_id)
    db.session.add(log)
    db.session.commit()


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    # For assessment demo: open registration.
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "user").strip()

        if not username or not password:
            flash("Username and password required.", "danger")
            return render_template("register.html")

        if role not in {"user", "admin"}:
            role = "user"

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("register.html")

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        _audit("user_registered", f"username={username} role={role}", request.remote_addr, user.id)
        flash("Account created. Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            _audit("login_failed", f"username={username}", request.remote_addr)
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        login_user(user)
        session["mfa_ok"] = False
        _audit("login_success", f"username={username}", request.remote_addr, user.id)

        # If user has MFA configured, require verification.
        if user.totp_secret:
            return redirect(url_for("auth.mfa"))
        return redirect(url_for("dashboard.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    if current_user.is_authenticated:
        _audit("logout", None, request.remote_addr, current_user.id)
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    if not current_user.totp_secret:
        return redirect(url_for("dashboard.dashboard"))

    if request.method == "POST":
        token = (request.form.get("token") or "").strip().replace(" ", "")
        if verify_totp(current_user.totp_secret, token):
            session["mfa_ok"] = True
            _audit("mfa_verified", None, request.remote_addr, current_user.id)
            return redirect(url_for("dashboard.dashboard"))
        _audit("mfa_failed", None, request.remote_addr, current_user.id)
        flash("Invalid 2FA code.", "danger")

    return render_template("mfa.html")


@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        # Generate and save secret
        secret = generate_totp_secret()
        current_user.totp_secret = secret
        db.session.commit()
        session["mfa_ok"] = False
        _audit("mfa_enabled", None, request.remote_addr, current_user.id)
        flash("2FA enabled. Scan the QR code and verify.", "success")
        return redirect(url_for("auth.mfa_qr"))

    return render_template("mfa_setup.html")


@auth_bp.route("/mfa/qr")
def mfa_qr():
    if not current_user.is_authenticated or not current_user.totp_secret:
        return redirect(url_for("dashboard.dashboard"))

    uri = totp_uri(current_user.username, current_user.totp_secret)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
