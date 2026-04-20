"""
BASTION — OWASP Web Application Security Auditor
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 1.0.0

Passive web application auditor: HTTP security headers, cookie security,
content analysis, OWASP Top 10 mapping, and graded security reports.
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from datetime import datetime
from urllib.parse import urlparse
import os
import uuid
import threading
import logging
import json
import io
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
sio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Models ───────────────────────────────────────────────────────
class AuditJob(db.Model):
    __tablename__ = "audit_jobs"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = db.Column(db.String(500))
    hostname = db.Column(db.String(200))
    status = db.Column(db.String(30), default="pending")
    overall_grade = db.Column(db.String(5))
    overall_score = db.Column(db.Integer)
    header_grade = db.Column(db.String(5))
    header_score = db.Column(db.Integer)
    finding_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    owasp_categories = db.Column(db.Integer, default=0)
    https = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "target_url": self.target_url, "hostname": self.hostname,
            "status": self.status, "overall_grade": self.overall_grade,
            "overall_score": self.overall_score, "header_grade": self.header_grade,
            "finding_count": self.finding_count, "critical_count": self.critical_count,
            "owasp_categories": self.owasp_categories, "https": self.https,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AuditFinding(db.Model):
    __tablename__ = "audit_findings"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    audit_id = db.Column(db.String(36), db.ForeignKey("audit_jobs.id"))
    module = db.Column(db.String(50))   # headers | cookies | content | owasp
    category = db.Column(db.String(100))
    issue = db.Column(db.String(300))
    severity = db.Column(db.String(20))
    owasp = db.Column(db.String(50))
    description = db.Column(db.Text)
    fix = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id, "audit_id": self.audit_id, "module": self.module,
            "category": self.category, "issue": self.issue, "severity": self.severity,
            "owasp": self.owasp, "description": self.description, "fix": self.fix,
        }


# ─── Routes — Pages ───────────────────────────────────────────────
@app.route("/")
def dashboard():
    audits = AuditJob.query.order_by(AuditJob.created_at.desc()).limit(20).all()
    total_audits = AuditJob.query.count()
    completed = AuditJob.query.filter_by(status="completed").count()
    critical_findings = db.session.query(db.func.sum(AuditJob.critical_count)).scalar() or 0
    return render_template("index.html",
        audits=audits, total_audits=total_audits,
        completed=completed, critical_findings=critical_findings)


@app.route("/audit/<audit_id>")
def audit_detail(audit_id):
    audit = AuditJob.query.get_or_404(audit_id)
    findings = AuditFinding.query.filter_by(audit_id=audit_id).all()
    from core.owasp_checker import categorize
    owasp_data = categorize([f.to_dict() for f in findings])
    findings_by_sev = sorted(findings, key=lambda f: _sev_order(f.severity))
    return render_template("audit_detail.html", audit=audit,
                            findings=findings_by_sev, owasp_data=owasp_data)


@app.route("/reports")
def reports_page():
    audits = AuditJob.query.filter_by(status="completed").order_by(
        AuditJob.completed_at.desc()
    ).all()
    return render_template("reports.html", audits=audits)


# ─── Routes — API ─────────────────────────────────────────────────
@app.route("/api/audit", methods=["POST"])
def start_audit():
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "url is required"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return jsonify({"error": "Invalid URL"}), 400

    audit = AuditJob(target_url=url, hostname=hostname, status="running",
                     started_at=datetime.utcnow())
    db.session.add(audit)
    db.session.commit()

    thread = threading.Thread(target=_run_audit, args=(audit.id, url),
                              daemon=True)
    thread.start()

    return jsonify({"audit_id": audit.id, "status": "running"}), 202


@app.route("/api/audit/<audit_id>")
def get_audit(audit_id):
    audit = AuditJob.query.get_or_404(audit_id)
    findings = AuditFinding.query.filter_by(audit_id=audit_id).all()
    return jsonify({
        "audit": audit.to_dict(),
        "findings": [f.to_dict() for f in findings],
    })


@app.route("/api/report/<audit_id>/json")
def download_report(audit_id):
    audit = AuditJob.query.get_or_404(audit_id)
    findings = AuditFinding.query.filter_by(audit_id=audit_id).all()
    from core.owasp_checker import categorize
    owasp = categorize([f.to_dict() for f in findings])
    report = {
        "report_generated": datetime.utcnow().isoformat(),
        "audit_id": audit.id,
        "target": audit.target_url,
        "status": audit.status,
        "overall_grade": audit.overall_grade,
        "overall_score": audit.overall_score,
        "https": audit.https,
        "owasp_categories_flagged": audit.owasp_categories,
        "findings": [f.to_dict() for f in findings],
        "owasp_summary": [
            {"id": c["id"], "name": c["name"], "finding_count": len(c["findings"]),
             "max_severity": c["max_severity"]}
            for c in owasp["categories"]
        ],
    }
    return send_file(
        io.BytesIO(json.dumps(report, indent=2).encode()),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"audit_report_{audit_id[:8]}.json",
    )


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "1.0.0",
                    "timestamp": datetime.utcnow().isoformat()})


@sio.on("connect")
def on_connect():
    logger.info("Client connected")


# ─── Audit Runner ─────────────────────────────────────────────────
def _run_audit(audit_id: str, url: str):
    from proxy.http_client import fetch
    from core.header_analyzer import analyze as analyze_headers
    from core.cookie_analyzer import analyze as analyze_cookies
    from core.content_analyzer import analyze as analyze_content
    from core.owasp_checker import overall_owasp_score, categorize

    timeout = app.config.get("AUDIT_TIMEOUT", 15)
    all_findings = []

    try:
        response = fetch(url, timeout=timeout)
        error = response.get("error")

        with app.app_context():
            audit = AuditJob.query.get(audit_id)

            if error:
                audit.status = "failed"
                db.session.commit()
                return

            audit.https = response.get("https", False)

            # HTTPS check
            if not audit.https:
                all_findings.append({
                    "module": "transport",
                    "category": "Cryptographic Failures",
                    "issue": "Site not served over HTTPS",
                    "severity": "CRITICAL",
                    "owasp": "A02:2021",
                    "description": "All traffic is transmitted in cleartext, exposing credentials and data.",
                    "fix": "Enable HTTPS with a valid TLS certificate.",
                })

            # Header analysis
            header_result = analyze_headers(response["headers"])
            audit.header_grade = header_result["grade"]
            audit.header_score = header_result["score"]
            for f in header_result["findings"]:
                all_findings.append({
                    "module": "headers",
                    "category": f.get("category", "Headers"),
                    "issue": f.get("issue") or f"Missing {f.get('header')}",
                    "severity": f["severity"],
                    "owasp": f.get("owasp", ""),
                    "description": f["description"],
                    "fix": f["fix"],
                })

            # Cookie analysis
            cookie_result = analyze_cookies(response["set_cookie_headers"])
            for f in cookie_result["findings"]:
                all_findings.append({
                    "module": "cookies",
                    "category": "Cookie Security",
                    "issue": f["issue"],
                    "severity": f["severity"],
                    "owasp": f.get("owasp", ""),
                    "description": f["description"],
                    "fix": f["fix"],
                })

            # Content analysis
            if response.get("html"):
                content_result = analyze_content(response["html"], url)
                for f in content_result["findings"]:
                    all_findings.append({
                        "module": "content",
                        "category": f.get("category", "Content"),
                        "issue": f["issue"],
                        "severity": f["severity"],
                        "owasp": f.get("owasp", ""),
                        "description": f["description"],
                        "fix": f["fix"],
                    })

            # Persist findings
            for f in all_findings:
                finding = AuditFinding(
                    audit_id=audit_id,
                    module=f.get("module", ""),
                    category=f.get("category", ""),
                    issue=f["issue"],
                    severity=f["severity"],
                    owasp=f.get("owasp", ""),
                    description=f.get("description", ""),
                    fix=f.get("fix", ""),
                )
                db.session.add(finding)

            # OWASP mapping
            owasp_data = categorize(all_findings)
            score_data = overall_owasp_score(all_findings)

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in all_findings:
                sev = f.get("severity", "INFO")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            audit.status = "completed"
            audit.completed_at = datetime.utcnow()
            audit.overall_grade = score_data["grade"]
            audit.overall_score = score_data["score"]
            audit.finding_count = len(all_findings)
            audit.critical_count = sev_counts["CRITICAL"]
            audit.owasp_categories = owasp_data["covered_categories"]
            db.session.commit()

            sio.emit("audit_complete", {
                "audit_id": audit_id,
                "grade": score_data["grade"],
                "score": score_data["score"],
            })

    except Exception as e:
        logger.exception("Audit failed for %s: %s", url, e)
        with app.app_context():
            audit = AuditJob.query.get(audit_id)
            if audit:
                audit.status = "failed"
                db.session.commit()


def _sev_order(severity: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 5)


def create_app():
    with app.app_context():
        os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)
        db.create_all()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5008))
    sio.run(app, host="0.0.0.0", port=port, debug=False)
