"""
SafeNet-AI Risk Engine

Combines:
1. Random Forest phishing probability
2. HTTPS security signal
3. Risk scoring
4. Risk severity
5. Security indicators
6. Security recommendations
"""

from urllib.parse import urlparse

from check_https import check_https


# ============================================================
# DEFAULT SETTINGS (editable from the dashboard Settings view)
# ============================================================

DEFAULT_SETTINGS = {
    # Points added when the URL does not use HTTPS
    "http_penalty": 10,

    # Upper bound (inclusive) of each risk level; above high_max is Critical
    "low_max": 30,
    "medium_max": 50,
    "high_max": 75,

    # Max model probability counted for popular domains (reputation.py)
    "reputation_cap": 10,

    # Points added for URL patterns the hostname-only model cannot see
    "pattern_points": {
        "has_suspicious_keyword": 15,
        "has_at_symbol_in_authority": 15,
        "is_shortened_url": 10,
        "has_port": 5,
        "is_free_hosting": 15,
        "deep_subdomains": 10,
    },

    # Domain lists (a domain also matches its subdomains)
    "trusted_domains": [],
    "blocked_domains": [],
}


# ============================================================
# RISK SCORE CALCULATION
# ============================================================

def calculate_risk(ml_phishing_probability, is_https, settings=None,
                   pattern_points=0):
    """
    Calculate final SafeNet risk score.

    ML phishing probability:
        0 - 100

    HTTPS:
        Small security adjustment only.

    Returns:
        risk_score
        risk_level
        https
    """

    settings = {**DEFAULT_SETTINGS, **(settings or {})}

    # --------------------------------------------------------
    # Start with ML probability
    # --------------------------------------------------------

    risk_score = float(ml_phishing_probability)

    # --------------------------------------------------------
    # HTTPS is a security signal.
    # It is NOT part of the ML classifier.
    # --------------------------------------------------------

    if not is_https:
        risk_score += settings["http_penalty"]

    # --------------------------------------------------------
    # URL pattern signals (path keywords, @, shorteners, ports)
    # --------------------------------------------------------

    risk_score += pattern_points

    # --------------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------------

    risk_score = min(max(risk_score, 0), 100)

    # --------------------------------------------------------
    # Determine severity
    # --------------------------------------------------------

    if risk_score <= settings["low_max"]:
        risk_level = "Low"

    elif risk_score <= settings["medium_max"]:
        risk_level = "Medium"

    elif risk_score <= settings["high_max"]:
        risk_level = "High"

    else:
        risk_level = "Critical"

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "https": is_https
    }


# ============================================================
# URL PATTERN SIGNALS
# ============================================================

PATTERN_MESSAGES = {
    "has_suspicious_keyword":
        "URL contains words often used in phishing (login, verify, account...).",
    "has_at_symbol_in_authority":
        "URL uses @ before the host, which can disguise the real site.",
    "is_shortened_url":
        "URL shortener hides the real destination.",
    "has_port":
        "URL uses an explicit port number.",
    "is_free_hosting":
        "Site is hosted on a free hosting platform often used for phishing.",
    "deep_subdomains":
        "Hostname has three or more subdomain levels.",
}


def pattern_signals(url_features, settings):
    """
    Return (points, messages) for URL patterns found in the full-URL
    features from fast_feature_extractor.extract_fast_features.
    """

    if not url_features:
        return 0, []

    points = 0
    messages = []

    found = dict(url_features)
    found["deep_subdomains"] = int(url_features.get("subdomain_depth", 0) >= 3)

    for key, value in settings["pattern_points"].items():
        if found.get(key, 0):
            points += value
            messages.append(PATTERN_MESSAGES[key])

    return points, messages


# ============================================================
# DOMAIN LISTS
# ============================================================

def domain_list_match(url, settings):
    """
    Return "blocked", "trusted" or None for the URL's host.
    Blocked wins if a host is on both lists.
    """

    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").rstrip(".").lower()

    def on_list(domains):
        return any(
            host == d or host.endswith("." + d)
            for d in domains
        )

    if on_list(settings.get("blocked_domains", [])):
        return "blocked"

    if on_list(settings.get("trusted_domains", [])):
        return "trusted"

    return None


# ============================================================
# INDICATORS
# ============================================================

def generate_indicators(
    ml_phishing_probability,
    is_https,
    risk_level
):
    """
    Generate human-readable security indicators.
    """

    indicators = []

    # --------------------------------------------------------
    # ML indicator
    # --------------------------------------------------------

    if ml_phishing_probability >= 75:

        indicators.append(
            "Random Forest detected strong phishing characteristics."
        )

    elif ml_phishing_probability >= 50:

        indicators.append(
            "URL contains characteristics associated with phishing."
        )

    elif ml_phishing_probability >= 25:

        indicators.append(
            "URL has some suspicious characteristics."
        )

    else:

        indicators.append(
            "No strong phishing characteristics detected by the model."
        )

    # --------------------------------------------------------
    # HTTPS indicator
    # --------------------------------------------------------

    if is_https:

        indicators.append(
            "HTTPS connection detected."
        )

    else:

        indicators.append(
            "URL does not use HTTPS."
        )

    # --------------------------------------------------------
    # Overall risk
    # --------------------------------------------------------

    if risk_level in ("High", "Critical"):

        indicators.append(
            "High-risk URL: verify the website before entering sensitive information."
        )

    return indicators


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(
    ml_phishing_probability,
    is_https,
    risk_level
):
    """
    Generate security recommendations.
    """

    recommendations = []

    # --------------------------------------------------------
    # Critical / High risk
    # --------------------------------------------------------

    if risk_level == "Critical":

        recommendations.append(
            "Do not open or interact with this URL."
        )

        recommendations.append(
            "Do not enter passwords, OTPs, banking details, or personal information."
        )

        recommendations.append(
            "Verify the website through its official domain."
        )

    elif risk_level == "High":

        recommendations.append(
            "Avoid entering sensitive information on this website."
        )

        recommendations.append(
            "Verify the domain before continuing."
        )

    elif risk_level == "Medium":

        recommendations.append(
            "Proceed with caution and verify the website domain."
        )

    else:

        recommendations.append(
            "No major phishing indicators were detected."
        )

    # --------------------------------------------------------
    # HTTP recommendation
    # --------------------------------------------------------

    if not is_https:

        recommendations.append(
            "Prefer an HTTPS version of the website when available."
        )

    # --------------------------------------------------------
    # Strong ML warning
    # --------------------------------------------------------

    if ml_phishing_probability >= 75:

        recommendations.append(
            "The Random Forest model gives this URL a high phishing probability."
        )

    return recommendations


# ============================================================
# COMPLETE URL ANALYSIS
# ============================================================

def analyze_url(ml_phishing_probability, url, settings=None, url_features=None,
                reputation=None):
    """
    Combine ML prediction with HTTPS analysis,
    risk scoring, indicators and recommendations.
    """

    settings = {**DEFAULT_SETTINGS, **(settings or {})}

    # --------------------------------------------------------
    # Check protocol / HTTPS
    # --------------------------------------------------------

    https_result = check_https(url)

    is_https = https_result["is_https"]

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    points, pattern_messages = pattern_signals(url_features, settings)

    # --------------------------------------------------------
    # Popular domains: cap the model's contribution
    # --------------------------------------------------------

    model_score = float(ml_phishing_probability)

    if reputation:
        model_score = min(model_score, float(settings["reputation_cap"]))

    risk_result = calculate_risk(
        model_score,
        is_https,
        settings,
        points
    )

    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    # --------------------------------------------------------
    # Domain lists override the score
    # --------------------------------------------------------

    list_match = domain_list_match(url, settings)

    if list_match == "blocked":
        risk_score = 100.0
        risk_level = "Critical"

    elif list_match == "trusted":
        risk_score = min(risk_score, float(settings["low_max"]))
        risk_level = "Low"

    # --------------------------------------------------------
    # Generate indicators
    # --------------------------------------------------------

    indicators = generate_indicators(
        model_score,
        is_https,
        risk_level
    )

    # --------------------------------------------------------
    # Generate recommendations
    # --------------------------------------------------------

    recommendations = generate_recommendations(
        model_score,
        is_https,
        risk_level
    )

    # Pattern messages go right after the model indicator
    indicators[1:1] = pattern_messages

    if reputation:
        indicators.insert(
            0,
            f"Popular domain: {reputation['domain']} is #{reputation['rank']:,} "
            f"on the {reputation['list']} "
            f"(model score {float(ml_phishing_probability):.0f}% capped at "
            f"{model_score:.0f})."
        )

    if list_match == "blocked":
        indicators.insert(0, "Domain is on your blocked list.")

    elif list_match == "trusted":
        indicators.insert(0, "Domain is on your trusted list.")
        recommendations = [
            "This domain is on your trusted list. "
            "Check the address is spelled exactly right."
        ]

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "url": url,

        "protocol": https_result["protocol"],

        "https": is_https,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "indicators": indicators,

        "recommendations": recommendations,

        "list_match": list_match,

        "reputation": reputation
    }


# ============================================================
# TEST RISK ENGINE
# ============================================================

if __name__ == "__main__":

    test_cases = [

        ("https://www.google.com", 22.09),

        ("http://www.google.com", 22.09),

        ("https://suspicious-example.com/login", 80.0),

        ("http://suspicious-example.com/login", 80.0)
    ]

    print("\n" + "=" * 60)
    print("           SAFENET AI RISK ENGINE")
    print("=" * 60)

    for url, ml_probability in test_cases:

        result = analyze_url(
            ml_probability,
            url
        )

        print("\nURL:", result["url"])

        print(
            "Protocol:",
            result["protocol"]
        )

        print(
            "HTTPS:",
            result["https"]
        )

        print(
            "ML Phishing Probability:",
            ml_probability,
            "%"
        )

        print(
            "Final Risk Score:",
            result["risk_score"],
            "/ 100"
        )

        print(
            "Risk Level:",
            result["risk_level"]
        )

        print("\nIndicators:")

        for indicator in result["indicators"]:
            print(" -", indicator)

        print("\nRecommendations:")

        for recommendation in result["recommendations"]:
            print(" -", recommendation)

        print("-" * 60)
