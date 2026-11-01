"""
SafeNet-AI Integrations

Webhook alerts:
    POST a JSON message to a user-configured URL whenever a scan
    reaches the chosen risk level. The payload carries "text" (Slack)
    and "content" (Discord) so incoming webhooks of either work as-is,
    plus a structured "safenet" object for custom receivers.
"""

import json
import threading
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from threat_store import get_setting, set_setting


LEVEL_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

DEFAULT_WEBHOOK = {
    "url": "",
    "enabled": False,
    "min_level": "High",
    "last_status": None,
    "last_sent_at": None,
}


# ============================================================
# CONFIGURATION
# ============================================================

def get_webhook_config():
    return {**DEFAULT_WEBHOOK, **get_setting("webhook", {})}


def save_webhook_config(url, enabled, min_level):
    """
    Validate and store webhook settings. Raises ValueError on bad input.
    """

    url = (url or "").strip()

    if url:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Webhook URL must be an http(s) URL")

    if enabled and not url:
        raise ValueError("Set a webhook URL before enabling alerts")

    if min_level not in LEVEL_RANK:
        raise ValueError(
            "min_level must be one of: " + ", ".join(LEVEL_RANK)
        )

    config = get_webhook_config()
    config.update(url=url, enabled=bool(enabled), min_level=min_level)
    set_setting("webhook", config)

    return config


def _record_status(status):
    config = get_webhook_config()
    config["last_status"] = status
    config["last_sent_at"] = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )
    set_setting("webhook", config)


# ============================================================
# DELIVERY
# ============================================================

def build_payload(result, test=False):
    prefix = "[TEST] " if test else ""

    text = (
        f"{prefix}SafeNet-AI alert: {result['risk_level']} risk "
        f"({result['risk_score']:.0f}/100)\n"
        f"URL: {result['url']}\n"
        f"Model: {result['classification']}, "
        f"phishing probability {result['phishing_probability']}%"
    )

    if result.get("recommendations"):
        text += f"\nAdvice: {result['recommendations'][0]}"

    return {
        "text": text,
        "content": text,
        "safenet": {
            "test": test,
            "url": result["url"],
            "classification": result["classification"],
            "phishing_probability": result["phishing_probability"],
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "indicators": result.get("indicators", []),
        },
    }


def send_webhook(url, payload, timeout=5):
    """
    POST payload as JSON. Returns a short status string, never raises.
    """

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SafeNet-AI-Webhook/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return f"Delivered (HTTP {response.status})"

    except Exception as e:
        return f"Failed: {e}"


def notify_scan(result):
    """
    Send an alert for this scan if webhooks are enabled and the scan
    meets the minimum risk level. Runs in the background so the scan
    response is not delayed.
    """

    config = get_webhook_config()

    if not (config["enabled"] and config["url"]):
        return

    if LEVEL_RANK.get(result["risk_level"], 0) < LEVEL_RANK[config["min_level"]]:
        return

    def deliver():
        _record_status(send_webhook(config["url"], build_payload(result)))

    threading.Thread(target=deliver, daemon=True).start()


def send_test_alert():
    """
    Send a sample alert synchronously and return the status.
    """

    config = get_webhook_config()

    if not config["url"]:
        raise ValueError("Set a webhook URL first")

    sample = {
        "url": "http://secure-login-verify-account-update.xyz/login.php",
        "classification": "Phishing",
        "phishing_probability": 100.0,
        "risk_score": 100.0,
        "risk_level": "Critical",
        "indicators": ["Random Forest detected strong phishing characteristics."],
        "recommendations": ["Do not open or interact with this URL."],
    }

    status = send_webhook(config["url"], build_payload(sample, test=True))
    _record_status(status)

    return status
