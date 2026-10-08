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

from check_https import check_https


# ============================================================
# RISK SCORE CALCULATION
# ============================================================

def calculate_risk(ml_phishing_probability, is_https):
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

    # --------------------------------------------------------
    # Start with ML probability
    # --------------------------------------------------------

    risk_score = float(ml_phishing_probability)

    # --------------------------------------------------------
    # HTTPS is a security signal.
    # It is NOT part of the ML classifier.
    # --------------------------------------------------------

    if not is_https:
        risk_score += 10

    # --------------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------------

    risk_score = min(max(risk_score, 0), 100)

    # --------------------------------------------------------
    # Determine severity
    # --------------------------------------------------------

    if risk_score <= 30:
        risk_level = "Low"

    elif risk_score <= 50:
        risk_level = "Medium"

    elif risk_score <= 75:
        risk_level = "High"

    else:
        risk_level = "Critical"

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "https": is_https
    }


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

def analyze_url(ml_phishing_probability, url):
    """
    Combine ML prediction with HTTPS analysis,
    risk scoring, indicators and recommendations.
    """

    # --------------------------------------------------------
    # Check protocol / HTTPS
    # --------------------------------------------------------

    https_result = check_https(url)

    is_https = https_result["is_https"]

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    risk_result = calculate_risk(
        ml_phishing_probability,
        is_https
    )

    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    # --------------------------------------------------------
    # Generate indicators
    # --------------------------------------------------------

    indicators = generate_indicators(
        ml_phishing_probability,
        is_https,
        risk_level
    )

    # --------------------------------------------------------
    # Generate recommendations
    # --------------------------------------------------------

    recommendations = generate_recommendations(
        ml_phishing_probability,
        is_https,
        risk_level
    )

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

        "recommendations": recommendations
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