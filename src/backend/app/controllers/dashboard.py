from __future__ import annotations

import json

from flask import Blueprint, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required

from .. import db
from ..middleware.authz import require_mfa, require_role
from ..models import AuditLog, EmailAnalysis
from ..services.phishing_analyzer import PhishingAnalyzer


dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/app")

analyzer = PhishingAnalyzer()


def _audit(event: str, detail: str | None = None, ip: str | None = None):
    log = AuditLog(event=event, detail=detail, ip_address=ip, user_id=(current_user.id if current_user.is_authenticated else None))
    db.session.add(log)
    db.session.commit()


@dashboard_bp.route("/dashboard")
@login_required
@require_mfa
def dashboard():
    # Show user's recent analyses
    items = (
        EmailAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(EmailAnalysis.created_at.desc())
        .limit(20)
        .all()
    )
    return render_template("dashboard.html", items=items)


@dashboard_bp.route("/analyze", methods=["GET", "POST"])
@login_required
@require_mfa
def analyze():
    if request.method == "POST":
        email_text = (request.form.get("email_text") or "").strip()
        if not email_text:
            flash("Paste an email to analyze.", "danger")
            return render_template("analyze.html")

        result = analyzer.analyze(email_text)
        record = EmailAnalysis(
            user_id=current_user.id,
            email_text=email_text,
            risk_score=result.score,
            risk_level=result.level,
            details_json=json.dumps(
                {
                    "keywords": result.keywords,
                    "urls": result.urls,
                    "sensitive": result.sensitive,
                    "header_issues": result.header_issues,
                    "attachment_issues": result.attachment_issues,
                    "breakdown": result.breakdown,
                },
                ensure_ascii=False,
            ),
        )
        db.session.add(record)
        db.session.commit()
        _audit("email_analyzed", f"analysis_id={record.id} score={result.score}", request.remote_addr)

        return redirect(url_for("dashboard.result", analysis_id=record.id))

    return render_template("analyze.html")


@dashboard_bp.route("/result/<int:analysis_id>")
@login_required
@require_mfa
def result(analysis_id: int):
    record = EmailAnalysis.query.filter_by(id=analysis_id, user_id=current_user.id).first_or_404()
    details = json.loads(record.details_json)
    return render_template("result.html", record=record, details=details)


@dashboard_bp.route("/export/csv")
@login_required
@require_mfa
def export_csv():
    # Export last 100 analyses for the current user
    items = (
        EmailAnalysis.query.filter_by(user_id=current_user.id)
        .order_by(EmailAnalysis.created_at.desc())
        .limit(100)
        .all()
    )

    import csv
    import io
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id",
        "created_at",
        "risk_score",
        "risk_level",
        "quarantined",
        "keyword_count",
        "url_count",
        "sensitive_count",
    ])

    for it in items:
        try:
            d = json.loads(it.details_json or "{}")
        except Exception:
            d = {}
        writer.writerow(
            [
                it.id,
                it.created_at.isoformat(),
                it.risk_score,
                it.risk_level,
                it.quarantined,
                len(d.get("keywords") or []),
                len(d.get("urls") or []),
                len(d.get("sensitive") or []),
            ]
        )

    data = buf.getvalue().encode("utf-8")
    return send_file(
        io.BytesIO(data),
        mimetype="text/csv",
        as_attachment=True,
        download_name="analysis_export.csv",
    )


@dashboard_bp.route("/admin/quarantine")
@login_required
@require_mfa
@require_role("admin")
def quarantine_list():
    items = EmailAnalysis.query.filter_by(quarantined=True).order_by(EmailAnalysis.created_at.desc()).limit(50).all()
    return render_template("admin_quarantine.html", items=items)


@dashboard_bp.route("/admin/quarantine/<int:analysis_id>", methods=["POST"])
@login_required
@require_mfa
@require_role("admin")
def quarantine_set(analysis_id: int):
    reason = (request.form.get("reason") or "Flagged by admin").strip()
    rec = EmailAnalysis.query.get_or_404(analysis_id)
    rec.quarantined = True
    rec.quarantine_reason = reason
    db.session.commit()
    _audit("email_quarantined", f"analysis_id={analysis_id} reason={reason}", request.remote_addr)
    flash("Email moved to quarantine.", "success")
    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/admin/incident", methods=["GET", "POST"])
@login_required
@require_mfa
@require_role("admin")
def incident_response():
    """Simple incident-response simulation for the assignment demo.

    This does not perform any offensive actions. It just records an "incident"
    in the audit log and shows recommended response steps (containment,
    eradication, recovery, lessons learned).
    """
    if request.method == "POST":
        incident_type = (request.form.get("incident_type") or "phishing_campaign").strip()
        note = (request.form.get("note") or "").strip()
        _audit("incident_simulated", f"type={incident_type} note={note}", request.remote_addr)
        flash("Incident recorded in audit log. Review the response steps below.", "success")
        return redirect(url_for("dashboard.incident_response"))

    return render_template("admin_incident.html")


@dashboard_bp.route("/admin/overview")
@login_required
@require_mfa
@require_role("admin")
def admin_overview():
    """Admin overview: see recent analyses and audit events."""

    analyses = EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).limit(50).all()
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(50).all()
    return render_template("admin_overview.html", analyses=analyses, logs=logs)
