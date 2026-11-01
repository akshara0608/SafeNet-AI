"""
SafeNet AI Backend - Flask Application
"""

import csv
import io
import os
import sys
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request, send_from_directory

# Add project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

# Import SafeNet analyzer, threat store and integrations
from analyze_url import analyze
from threat_store import (
    clear_scans, init_db, list_scans, record_scan, threat_summary
)
from integrations import (
    get_webhook_config, notify_scan, save_webhook_config, send_test_alert
)
from user_settings import get_settings, reset_settings, save_settings

app = Flask(__name__)

init_db()


@app.route("/")
def home():
    # Serve the dashboard from the same origin as the API (no CORS needed)
    return send_from_directory(FRONTEND_DIR, "mainindex.html")


@app.route("/report")
def report_page():
    # Printable report; reads ?days= and calls /api/reports
    return send_from_directory(FRONTEND_DIR, "report.html")


@app.route("/api/health")
def health():
    return jsonify(
        {"message": "SafeNet AI Backend is running", "status": "success"}
    )


@app.route("/api/analyze", methods=["POST"])
def analyze_url():
    try:
        # Get JSON data safely
        data = request.get_json(silent=True)

        # Check if URL exists
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400

        # Check URL is a string
        if not isinstance(data["url"], str):
            return jsonify({"error": "URL must be a string"}), 400

        url = data["url"].strip()

        # Check for empty URL
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400

        # Analyze URL using SafeNet
        result = analyze(url, get_settings())

        # Save scan for threat intelligence (never fail the analysis on it)
        try:
            record_scan(result)
        except Exception as e:
            app.logger.warning("Could not record scan: %s", e)

        # Webhook alert for high-risk scans (runs in background)
        try:
            notify_scan(result)
        except Exception as e:
            app.logger.warning("Could not send webhook alert: %s", e)

        return jsonify(result), 200

    except Exception as e:
        # In production, you might want to log this error internally
        return jsonify({"error": str(e)}), 500


@app.route("/api/threats")
def threats():
    try:
        return jsonify(threat_summary()), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# REPORTS
# ============================================================

def _report_days():
    """
    Read ?days= (1-3650). Missing or "all" means every scan.
    """

    raw = request.args.get("days", "all")

    if raw == "all":
        return None

    days = int(raw)

    if not 1 <= days <= 3650:
        raise ValueError("days must be between 1 and 3650")

    return days


REPORT_FIELDS = [
    "scanned_at", "url", "host", "classification",
    "phishing_probability", "risk_score", "risk_level", "https",
]


@app.route("/api/reports")
def report():
    try:
        days = _report_days()
    except ValueError:
        return jsonify({"error": "days must be 'all' or 1-3650"}), 400

    try:
        scans = list_scans(days)

        return jsonify({
            "period_days": days,
            "generated_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ),
            "summary": threat_summary(days=days),
            "scans": [
                {**{k: s[k] for k in REPORT_FIELDS},
                 "indicators": s["indicators"]}
                for s in scans
            ],
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reports/csv")
def report_csv():
    try:
        days = _report_days()
    except ValueError:
        return jsonify({"error": "days must be 'all' or 1-3650"}), 400

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(REPORT_FIELDS + ["indicators"])

    for s in list_scans(days):
        writer.writerow(
            [s[k] for k in REPORT_FIELDS] + ["; ".join(s["indicators"])]
        )

    name = f"safenet-report-{'all' if days is None else str(days) + 'd'}.csv"

    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}"},
    )


# ============================================================
# INTEGRATIONS
# ============================================================

@app.route("/api/integrations")
def integrations():
    return jsonify({
        "webhook": get_webhook_config(),
        "api": {
            "analyze": "/api/analyze",
            "threats": "/api/threats",
            "reports": "/api/reports",
        },
    }), 200


@app.route("/api/integrations/webhook", methods=["PUT"])
def update_webhook():
    data = request.get_json(silent=True) or {}

    try:
        config = save_webhook_config(
            data.get("url", ""),
            data.get("enabled", False),
            data.get("min_level", "High"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(config), 200


@app.route("/api/integrations/webhook/test", methods=["POST"])
def test_webhook():
    try:
        status = send_test_alert()
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"status": status, "webhook": get_webhook_config()}), 200


# ============================================================
# SETTINGS
# ============================================================

@app.route("/api/settings")
def settings():
    return jsonify(get_settings()), 200


@app.route("/api/settings", methods=["PUT"])
def update_settings():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    try:
        return jsonify(save_settings(data)), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/settings/reset", methods=["POST"])
def restore_settings():
    return jsonify(reset_settings()), 200


@app.route("/api/scans", methods=["DELETE"])
def delete_scans():
    return jsonify({"deleted": clear_scans()}), 200


if __name__ == "__main__":
    print("\n===================================")
    print("        SAFENET AI BACKEND         ")
    print("===================================")
    print("Server running at:")
    print("http://127.0.0.1:5000")
    print("===================================\n")

    app.run(host="127.0.0.1", port=5000, debug=True)
