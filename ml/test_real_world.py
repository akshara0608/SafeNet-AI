"""
SafeNet AI - Real World URL Validation

Tests the current Random Forest model against:
- Known legitimate URLs
- HTTP versions of legitimate websites
- Suspicious/phishing-style URLs

No WHOIS, DNS, SSL, or internet requests are used.
"""

import os
import sys

# ============================================================
# PATH CONFIGURATION
# ============================================================

current_dir = os.path.dirname(os.path.abspath(__file__))

if current_dir not in sys.path:
    sys.path.append(current_dir)

from predict import SafeNetRFPredictor


# ============================================================
# TEST DATA
# ============================================================

legitimate_urls = [

    # HTTPS legitimate
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.github.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.in",
    "https://www.wikipedia.org",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.facebook.com",

    # HTTP legitimate
    "http://www.google.com",
    "http://www.youtube.com",
    "http://www.github.com",
    "http://www.microsoft.com",
    "http://www.apple.com",
    "http://www.amazon.in",
    "http://www.wikipedia.org",
    "http://www.linkedin.com",
    "http://www.instagram.com",
    "http://www.facebook.com",
]


phishing_urls = [

    # Suspicious login pages
    "http://secure-login-verify-account.xyz/login.php",
    "http://verify-your-account-security.xyz/login",
    "http://paypal-login-security.xyz/signin.php",
    "http://account-verification-update.xyz/login.php",
    "http://secure-bank-login.xyz/verify.php",

    # Suspicious domains
    "http://google-account-security.xyz/login",
    "http://youtube-security-verification.xyz/login.php",
    "http://microsoft-account-verify.xyz/signin",
    "http://amazon-payment-update.xyz/login.php",
    "http://apple-id-verification.xyz/account/login",

    # IP-based URLs
    "http://192.168.1.100/login",
    "http://45.123.45.67/secure/login.php",
    "http://103.45.67.89/account/verify",

    # Suspicious URL structures
    "http://login.verify-account-update.com/secure/login.php",
    "http://secure.account.validation.xyz/user/login",
    "http://payment-confirmation-security.xyz/update",
    "http://password-reset-confirm-account.xyz/reset.php",
    "http://signin-security-check.xyz/auth/login",
    "http://verify-user-information.xyz/account.php",
    "http://banking-security-alert.xyz/confirm/login.php",
]


# ============================================================
# TEST FUNCTION
# ============================================================

def test_urls(predictor, urls, expected_label):

    results = []

    for url in urls:

        try:

            result = predictor.predict(url)

            predicted_label = (
                "Phishing"
                if result["is_phishing"]
                else "Legitimate"
            )

            correct = predicted_label == expected_label

            results.append({
                "url": url,
                "expected": expected_label,
                "predicted": predicted_label,
                "phishing_probability":
                    result["phishing_probability"],
                "legitimate_probability":
                    result["legitimate_probability"],
                "correct": correct
            })

        except Exception as e:

            results.append({
                "url": url,
                "expected": expected_label,
                "predicted": "ERROR",
                "phishing_probability": 0,
                "legitimate_probability": 0,
                "correct": False,
                "error": str(e)
            })

    return results


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("\n====================================================")
    print("        SAFENET AI REAL-WORLD VALIDATION")
    print("====================================================")

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    try:

        predictor = SafeNetRFPredictor()

    except Exception as e:

        print("\nERROR loading model:")
        print(e)

        sys.exit(1)

    print(
        f"\nModel: {predictor.model_type}"
    )

    print(
        f"Features: {len(predictor.features)}"
    )

    # --------------------------------------------------------
    # Test legitimate URLs
    # --------------------------------------------------------

    print("\n----------------------------------------------------")
    print("TESTING LEGITIMATE URLS")
    print("----------------------------------------------------")

    legitimate_results = test_urls(
        predictor,
        legitimate_urls,
        "Legitimate"
    )

    for result in legitimate_results:

        status = (
            "PASS"
            if result["correct"]
            else "FAIL"
        )

        print(
            f"\n[{status}] {result['url']}"
        )

        print(
            f"Expected : {result['expected']}"
        )

        print(
            f"Predicted: {result['predicted']}"
        )

        print(
            f"Phishing : "
            f"{result['phishing_probability']}%"
        )

        print(
            f"Legitimate: "
            f"{result['legitimate_probability']}%"
        )

    # --------------------------------------------------------
    # Test phishing URLs
    # --------------------------------------------------------

    print("\n----------------------------------------------------")
    print("TESTING PHISHING URLS")
    print("----------------------------------------------------")

    phishing_results = test_urls(
        predictor,
        phishing_urls,
        "Phishing"
    )

    for result in phishing_results:

        status = (
            "PASS"
            if result["correct"]
            else "FAIL"
        )

        print(
            f"\n[{status}] {result['url']}"
        )

        print(
            f"Expected : {result['expected']}"
        )

        print(
            f"Predicted: {result['predicted']}"
        )

        print(
            f"Phishing : "
            f"{result['phishing_probability']}%"
        )

        print(
            f"Legitimate: "
            f"{result['legitimate_probability']}%"
        )

    # ========================================================
    # CALCULATE RESULTS
    # ========================================================

    all_results = (
        legitimate_results +
        phishing_results
    )

    total = len(all_results)

    correct = sum(
        1
        for result in all_results
        if result["correct"]
    )

    incorrect = total - correct

    accuracy = (
        (correct / total) * 100
        if total > 0
        else 0
    )

    # --------------------------------------------------------
    # Legitimate statistics
    # --------------------------------------------------------

    legitimate_total = len(
        legitimate_results
    )

    legitimate_correct = sum(
        1
        for result in legitimate_results
        if result["correct"]
    )

    legitimate_false_positives = (
        legitimate_total -
        legitimate_correct
    )

    legitimate_accuracy = (
        legitimate_correct /
        legitimate_total *
        100
        if legitimate_total > 0
        else 0
    )

    # --------------------------------------------------------
    # Phishing statistics
    # --------------------------------------------------------

    phishing_total = len(
        phishing_results
    )

    phishing_correct = sum(
        1
        for result in phishing_results
        if result["correct"]
    )

    phishing_false_negatives = (
        phishing_total -
        phishing_correct
    )

    phishing_accuracy = (
        phishing_correct /
        phishing_total *
        100
        if phishing_total > 0
        else 0
    )

    # ========================================================
    # FINAL REPORT
    # ========================================================

    print("\n\n====================================================")
    print("                 FINAL RESULTS")
    print("====================================================")

    print(
        f"\nTotal URLs Tested       : {total}"
    )

    print(
        f"Correct Predictions     : {correct}"
    )

    print(
        f"Incorrect Predictions   : {incorrect}"
    )

    print(
        f"Overall Accuracy        : "
        f"{accuracy:.2f}%"
    )

    print("\n----------------------------------------------------")

    print(
        f"Legitimate URLs Tested  : "
        f"{legitimate_total}"
    )

    print(
        f"Legitimate Correct      : "
        f"{legitimate_correct}"
    )

    print(
        f"False Positives         : "
        f"{legitimate_false_positives}"
    )

    print(
        f"Legitimate Accuracy     : "
        f"{legitimate_accuracy:.2f}%"
    )

    print("\n----------------------------------------------------")

    print(
        f"Phishing URLs Tested    : "
        f"{phishing_total}"
    )

    print(
        f"Phishing Correct        : "
        f"{phishing_correct}"
    )

    print(
        f"False Negatives         : "
        f"{phishing_false_negatives}"
    )

    print(
        f"Phishing Detection Rate : "
        f"{phishing_accuracy:.2f}%"
    )

    print("\n====================================================")
    print("              VALIDATION COMPLETE")
    print("====================================================")