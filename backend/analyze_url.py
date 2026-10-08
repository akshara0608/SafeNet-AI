"""
SafeNet-AI URL Security Analyzer
Integrates Random Forest ML Classification with Multi-Layer Risk Engine
"""

import os
import sys

# Add ml folder and project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(PROJECT_ROOT, "ml")

for p in (PROJECT_ROOT, ML_DIR):
    if p not in sys.path:
        sys.path.append(p)

from predict import predict_url
from risk_engine import analyze_url as calculate_final_risk


def analyze(url: str) -> dict:
    """
    Complete SafeNet URL Security Analysis.

    Pipeline:
    1. Random Forest URL classification.
    2. HTTPS security analysis.
    3. Risk score and severity calculation.
    4. Security indicators and recommendations.
    """

    if not url or not isinstance(url, str):
        return {
            "error": "Invalid URL provided",
            "url": str(url)
        }

    url = url.strip()

    # Step 1: Random Forest prediction
    ml_result = predict_url(url)

    phishing_prob = float(ml_result["phishing_probability"])
    legitimate_prob = float(ml_result["legitimate_probability"])
    classification = str(ml_result["prediction"])

    # Step 2: Risk Engine
    risk_result = calculate_final_risk(
        phishing_prob,
        url
    )

    # Step 3: Final SafeNet response
    return {
        "url": str(url),

        "classification": classification,
        "is_phishing": bool(ml_result["is_phishing"]),

        "phishing_probability": phishing_prob,
        "legitimate_probability": legitimate_prob,

        "https": bool(risk_result["https"]),
        "protocol": str(risk_result["protocol"]),

        "risk_score": float(risk_result["risk_score"]),
        "risk_level": str(risk_result["risk_level"]),

        "indicators": [
            str(item)
            for item in risk_result["indicators"]
        ],

        "recommendations": [
            str(item)
            for item in risk_result["recommendations"]
        ],

        "features": {
            str(key): float(value)
            for key, value in ml_result.get("features", {}).items()
        }
    }


# ==================================================
# CLI TEST RUNNER
# ==================================================

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://www.google.com",
        "https://www.youtube.com",
        "http://suspicious-banking-update.xyz/login.php"
    ]

    print("\n" + "=" * 55)
    print("      SAFENET-AI: RANDOM FOREST ANALYSIS TEST")
    print("=" * 55)

    for url in test_urls:
        result = analyze(url)
        tag = "[PHISHING]" if result["is_phishing"] else "[LEGITIMATE]"

        print(f"\nURL             : {result['url']}")
        print(f"Classification  : {tag} {result['classification']}")
        print(f"Phishing Prob   : {result['phishing_probability']}%")
        print(f"Legitimate Prob : {result['legitimate_probability']}%")
        print(f"Protocol / HTTPS: {result['protocol']} (HTTPS={result['https']})")
        print(f"Risk Score      : {result['risk_score']}/100 [{result['risk_level']}]")
        print("-" * 55)