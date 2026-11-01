"""
SafeNet-AI User Settings

Detection settings edited from the dashboard:
1. HTTP penalty and risk level cutoffs (used by risk_engine)
2. Trusted and blocked domain lists
"""

import re

from risk_engine import DEFAULT_SETTINGS
from threat_store import get_setting, set_setting


MAX_DOMAINS = 500

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)


def get_settings():
    return {**DEFAULT_SETTINGS, **get_setting("detection", {})}


def _clean_domain(raw):
    """
    Accept "example.com", "https://www.example.com/path" or "*.example.com"
    and return "example.com". Raises ValueError.
    """

    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0]
    d = d.removeprefix("*.").removeprefix("www.").rstrip(".")

    if not DOMAIN_RE.match(d):
        raise ValueError(f"Not a valid domain: {raw.strip()}")

    return d


def _clean_domain_list(value, name):
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")

    domains = []

    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} entries must be strings")

        if item.strip():
            d = _clean_domain(item)

            if d not in domains:
                domains.append(d)

    if len(domains) > MAX_DOMAINS:
        raise ValueError(f"{name} can hold at most {MAX_DOMAINS} domains")

    return domains


def _int_in(data, key, low, high):
    value = data.get(key, DEFAULT_SETTINGS[key])

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")

    if not low <= value <= high or value != int(value):
        raise ValueError(f"{key} must be a whole number from {low} to {high}")

    return int(value)


def save_settings(data):
    """
    Validate and store detection settings. Raises ValueError on bad input.
    """

    settings = {
        "http_penalty": _int_in(data, "http_penalty", 0, 50),
        "low_max": _int_in(data, "low_max", 1, 98),
        "medium_max": _int_in(data, "medium_max", 2, 98),
        "high_max": _int_in(data, "high_max", 3, 99),
        "trusted_domains": _clean_domain_list(
            data.get("trusted_domains", []), "trusted_domains"
        ),
        "blocked_domains": _clean_domain_list(
            data.get("blocked_domains", []), "blocked_domains"
        ),
    }

    if not settings["low_max"] < settings["medium_max"] < settings["high_max"]:
        raise ValueError("Cutoffs must increase: Low < Medium < High")

    set_setting("detection", settings)

    return settings


def reset_settings():
    set_setting("detection", {})

    return get_settings()
