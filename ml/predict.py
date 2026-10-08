"""
SafeNet-AI Model Inference Module

Model: Random Forest Classifier

Uses the same 17 fast URL-based features that were used during training.

No WHOIS, DNS, SSL, or internet requests are required.

Dataset convention:
    0 = Phishing
    1 = Legitimate
"""

import os
import sys
import joblib
import pandas as pd


# ============================================================
# PATH CONFIGURATION
# ============================================================

current_dir = os.path.dirname(os.path.abspath(__file__))

if current_dir not in sys.path:
    sys.path.append(current_dir)


# ============================================================
# IMPORT FAST FEATURE EXTRACTOR
# ============================================================

# IMPORTANT:
# This must be the SAME extractor used during training.
from fast_feature_extractor import extract_fast_features


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = os.path.join(
    current_dir,
    "model",
    "safenet_model_v2.pkl"
)


# ============================================================
# RANDOM FOREST PREDICTOR
# ============================================================

class SafeNetRFPredictor:
    """
    Random Forest-based URL safety predictor.

    Model features:
        1.  url_length
        2.  hostname_length
        3.  has_ip_address
        4.  subdomain_depth
        5.  digit_count
        6.  letter_count
        7.  dot_count
        8.  slash_count
        9.  hyphen_count
        10. underscore_count
        11. equals_count
        12. question_mark_count
        13. ampersand_count
        14. at_count
        15. percent_count
        16. special_char_count
        17. entropy

    No is_https feature is used.
    """

    def __init__(self, model_path: str = MODEL_PATH):

        # ----------------------------------------------------
        # Check model exists
        # ----------------------------------------------------

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model file not found at {model_path}. "
                "Please run ml/train.py first."
            )

        # ----------------------------------------------------
        # Load trained Random Forest model
        # ----------------------------------------------------

        model_payload = joblib.load(model_path)

        self.model = model_payload["model"]

        # Feature order saved during training
        self.features = model_payload["features"]

        # Model type
        self.model_type = model_payload.get(
            "model_type",
            "RandomForestClassifier"
        )

        # Classes learned by the model
        self.classes = list(self.model.classes_)

    # ========================================================
    # PREDICT URL
    # ========================================================

    def predict(self, url: str) -> dict:
        """
        Extract fast URL features and predict whether
        the URL is Phishing or Legitimate.

        Dataset convention:
            0 = Phishing
            1 = Legitimate
        """

        # ----------------------------------------------------
        # 1. Extract the SAME 17 features used during training
        # ----------------------------------------------------

        extracted = extract_fast_features(url)

        # ----------------------------------------------------
        # 2. Convert extracted features into DataFrame
        # ----------------------------------------------------

        feature_df = pd.DataFrame([extracted])

        # ----------------------------------------------------
        # 3. Check for missing features
        # ----------------------------------------------------

        missing_features = [
            feature
            for feature in self.features
            if feature not in feature_df.columns
        ]

        if missing_features:
            raise ValueError(
                "Missing features required by model: "
                f"{missing_features}"
            )

        # ----------------------------------------------------
        # 4. Arrange features in EXACT training order
        # ----------------------------------------------------

        feature_df = feature_df[self.features]

        # ----------------------------------------------------
        # 5. Make prediction
        # ----------------------------------------------------

        pred_label = self.model.predict(feature_df)[0]

        # ----------------------------------------------------
        # 6. Get prediction probabilities
        # ----------------------------------------------------

        probabilities = self.model.predict_proba(feature_df)[0]

        # ----------------------------------------------------
        # 7. Map probabilities to class labels
        # ----------------------------------------------------

        class_prob_map = dict(
            zip(
                self.classes,
                probabilities
            )
        )

        # ----------------------------------------------------
        # Dataset convention:
        #
        # 0 = Phishing
        # 1 = Legitimate
        # ----------------------------------------------------

        phishing_prob = float(
            class_prob_map.get(0, 0.0) * 100
        )

        legitimate_prob = float(
            class_prob_map.get(1, 0.0) * 100
        )

        # ----------------------------------------------------
        # 8. Determine final classification
        # ----------------------------------------------------

        is_phishing = bool(pred_label == 0)

        classification = (
            "Phishing"
            if is_phishing
            else "Legitimate"
        )

        # ----------------------------------------------------
        # 9. Return prediction result
        # ----------------------------------------------------

        return {
            "url": url,

            "prediction": classification,

            "is_phishing": is_phishing,

            "phishing_probability": round(
                phishing_prob,
                2
            ),

            "legitimate_probability": round(
                legitimate_prob,
                2
            ),

            "features": extracted
        }


# ============================================================
# SINGLETON PREDICTOR
# ============================================================

_predictor_instance = None


def get_predictor() -> SafeNetRFPredictor:
    """
    Return a single shared predictor instance.
    """

    global _predictor_instance

    if _predictor_instance is None:
        _predictor_instance = SafeNetRFPredictor()

    return _predictor_instance


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def predict_url(url: str) -> dict:
    """
    Predict whether a URL is phishing or legitimate.
    """

    predictor = get_predictor()

    return predictor.predict(url)


# ============================================================
# TEST RUNNER
# ============================================================

if __name__ == "__main__":

    print("\n==============================================")
    print("     SAFENET RANDOM FOREST INFERENCE TEST")
    print("==============================================")

    # --------------------------------------------------------
    # Test URLs
    # --------------------------------------------------------

    test_urls = [

        # Known legitimate website
        "https://www.google.com",

        # Same website but HTTP
        "http://www.google.com",

        # Known legitimate website
        "https://www.youtube.com",

        # Suspicious URL
        "http://suspicious-login-verify-account-update.xyz/login.php"
    ]

    # --------------------------------------------------------
    # Load predictor
    # --------------------------------------------------------

    try:

        predictor = SafeNetRFPredictor()

    except Exception as e:

        print("\nERROR loading model")
        print(f"Reason: {e}")

        sys.exit(1)

    # --------------------------------------------------------
    # Model information
    # --------------------------------------------------------

    print(
        f"\nLoaded Model : "
        f"{predictor.model_type}"
    )

    print(
        f"Features ({len(predictor.features)}):"
    )

    for i, feature in enumerate(
        predictor.features,
        start=1
    ):
        print(
            f" {i:2}. {feature}"
        )

    print("\n==============================================")

    # --------------------------------------------------------
    # Test every URL
    # --------------------------------------------------------

    for url in test_urls:

        try:

            result = predictor.predict(url)

            # ------------------------------------------------
            # Status tag
            # ------------------------------------------------

            status_tag = (
                "[PHISHING]"
                if result["is_phishing"]
                else "[LEGITIMATE]"
            )

            # ------------------------------------------------
            # Print URL
            # ------------------------------------------------

            print(
                f"\nURL: {result['url']}"
            )

            # ------------------------------------------------
            # Print classification
            # ------------------------------------------------

            print(
                f"Result: {status_tag} "
                f"{result['prediction']}"
            )

            # ------------------------------------------------
            # Print probabilities
            # ------------------------------------------------

            print(
                f"Phishing Probability   : "
                f"{result['phishing_probability']}%"
            )

            print(
                f"Legitimate Probability : "
                f"{result['legitimate_probability']}%"
            )

            print("-" * 46)

        except Exception as e:

            print(
                f"\nERROR analyzing URL: {url}"
            )

            print(
                f"Reason: {e}"
            )

            print("-" * 46)