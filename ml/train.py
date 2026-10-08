"""
SafeNet-AI
Fast Random Forest Training Pipeline

IMPORTANT:
This training pipeline uses ONLY URL-based features.

It does NOT perform:
- WHOIS requests
- DNS requests
- SSL certificate requests
- Internet/network requests

Therefore the complete PhiUSIIL dataset can be processed locally.
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PATH CONFIGURATION
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from fast_feature_extractor import extract_fast_features


DATASET_PATH = os.path.join(
    CURRENT_DIR,
    "dataset",
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_DIR = os.path.join(
    CURRENT_DIR,
    "model"
)

# V2 MODEL
MODEL_PATH = os.path.join(
    MODEL_DIR,
    "safenet_model_v2.pkl"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# SETTINGS
# ============================================================

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ============================================================
# FEATURES
# ============================================================

EXPECTED_FEATURES = [
    "url_length",
    "hostname_length",
    "has_ip_address",
    "subdomain_depth",
    "digit_count",
    "letter_count",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "underscore_count",
    "equals_count",
    "question_mark_count",
    "ampersand_count",
    "at_count",
    "percent_count",
    "special_char_count",
    "entropy"
]


# ============================================================
# RANDOM FOREST PARAMETERS
# ============================================================

RF_PARAMS = {
    "n_estimators": 200,
    "criterion": "gini",
    "max_depth": None,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "bootstrap": True,
    "oob_score": True,
    "class_weight": "balanced",
    "n_jobs": -1,
    "random_state": RANDOM_STATE
}


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("\n" + "=" * 65)
    print("STEP 1: LOADING DATASET")
    print("=" * 65)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found:\n{DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows   : {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    # --------------------------------------------------------
    # Remove duplicate rows
    # --------------------------------------------------------

    before = len(df)

    df = df.drop_duplicates()

    removed = before - len(df)

    print(f"Duplicates removed: {removed:,}")
    print(f"Final rows: {len(df):,}")

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    required_columns = [
        "URL",
        "label"
    ]

    for column in required_columns:

        if column not in df.columns:

            raise ValueError(
                f"Required column '{column}' not found in dataset."
            )

    return df


# ============================================================
# FAST FEATURE EXTRACTION
# ============================================================

def extract_features_from_dataset(df):

    print("\n" + "=" * 65)
    print("STEP 2: FAST URL FEATURE EXTRACTION")
    print("=" * 65)

    print("\nIMPORTANT:")
    print("No WHOIS requests")
    print("No DNS requests")
    print("No SSL requests")
    print("No internet requests")

    print(
        f"\nExtracting URL features from "
        f"{len(df):,} URLs..."
    )

    feature_records = []

    total = len(df)

    for index, url in enumerate(
        df["URL"],
        start=1
    ):

        feature_records.append(
            extract_fast_features(url)
        )

        # Progress every 10,000 URLs
        if index % 10000 == 0 or index == total:

            percent = (
                index / total
            ) * 100

            print(
                f"Processed: {index:,}/{total:,} "
                f"({percent:.1f}%)"
            )

    # --------------------------------------------------------
    # Create feature DataFrame
    # --------------------------------------------------------

    X = pd.DataFrame(
        feature_records
    )

    y = df["label"].astype(int)

    # --------------------------------------------------------
    # Ensure correct feature order
    # --------------------------------------------------------

    X = X[EXPECTED_FEATURES]

    # --------------------------------------------------------
    # Handle invalid values
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(0)

    print("\nFeature extraction completed.")

    print(
        f"Feature matrix: {X.shape}"
    )

    print("\nFeatures used:")

    for number, feature in enumerate(
        EXPECTED_FEATURES,
        start=1
    ):

        print(
            f"{number:2d}. {feature}"
        )

    # ========================================================
    # LABEL DISTRIBUTION
    # ========================================================

    print("\nClass distribution:")

    counts = y.value_counts()

    for label, count in counts.items():

        percentage = (
            count / len(y)
        ) * 100

        if label == 0:
            name = "Phishing"
        else:
            name = "Legitimate"

        print(
            f"  {label} = {name:<12} "
            f"{count:,} ({percentage:.2f}%)"
        )

    return X, y


# ============================================================
# TRAIN RANDOM FOREST
# ============================================================

def train_random_forest(
    X_train,
    y_train
):

    print("\n" + "=" * 65)
    print("STEP 3: RANDOM FOREST TRAINING")
    print("=" * 65)

    print("\nRandom Forest parameters:")

    for key, value in RF_PARAMS.items():

        print(
            f"  {key}: {value}"
        )

    print("\nTraining model...")
    print("Using all available CPU cores.")

    model = RandomForestClassifier(
        **RF_PARAMS
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "\nRandom Forest training completed!"
    )

    if hasattr(
        model,
        "oob_score_"
    ):

        print(
            f"OOB Score: "
            f"{model.oob_score_ * 100:.2f}%"
        )

    return model


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print("\n" + "=" * 65)
    print("STEP 4: MODEL EVALUATION")
    print("=" * 65)

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    y_pred = model.predict(
        X_test
    )

    y_probability = model.predict_proba(
        X_test
    )[:, 1]

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        y_probability
    )

    # --------------------------------------------------------
    # Performance
    # --------------------------------------------------------

    print("\n--- PERFORMANCE ---")

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC   : {roc_auc:.6f}"
    )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("\n--- CONFUSION MATRIX ---")

    print(
        f"True Phishing        : {cm[0, 0]:,}"
    )

    print(
        f"Phishing → Legitimate: {cm[0, 1]:,}"
    )

    print(
        f"Legitimate → Phishing: {cm[1, 0]:,}"
    )

    print(
        f"True Legitimate      : {cm[1, 1]:,}"
    )

    # ========================================================
    # CLASSIFICATION REPORT
    # ========================================================

    print(
        "\n--- CLASSIFICATION REPORT ---"
    )

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Phishing",
                "Legitimate"
            ],
            zero_division=0
        )
    )

    # ========================================================
    # FEATURE IMPORTANCE
    # ========================================================

    print(
        "--- FEATURE IMPORTANCE ---"
    )

    importance_df = pd.DataFrame({

        "Feature": EXPECTED_FEATURES,

        "Importance":
            model.feature_importances_
    })

    importance_df = (
        importance_df
        .sort_values(
            by="Importance",
            ascending=False
        )
        .reset_index(drop=True)
    )

    for _, row in importance_df.iterrows():

        percentage = (
            row["Importance"] * 100
        )

        print(
            f"{row['Feature']:<25}"
            f": {percentage:6.2f}%"
        )

    # --------------------------------------------------------
    # Return metrics
    # --------------------------------------------------------

    return {

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1_score":
            f1,

        "roc_auc":
            roc_auc,

        "oob_score":
            getattr(
                model,
                "oob_score_",
                None
            )
    }


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model,
    metrics
):

    print("\n" + "=" * 65)
    print("STEP 5: SAVING MODEL")
    print("=" * 65)

    model_payload = {

        "model":
            model,

        "features":
            EXPECTED_FEATURES,

        "model_type":
            "RandomForestClassifier",

        "parameters":
            RF_PARAMS,

        "metrics":
            metrics,

        "version":
            "V2",

        "protocol_independent_features":
            True
    }

    # IMPORTANT:
    # Use MODEL_PATH, not MODEL_SAVE_PATH
    joblib.dump(
        model_payload,
        MODEL_PATH
    )

    print(
        "\nModel saved successfully!"
    )

    print(
        f"Location:\n{MODEL_PATH}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("\n" + "#" * 65)

    print(
        "      SAFENET-AI: FAST RANDOM FOREST TRAINING V2"
    )

    print("#" * 65)

    print(
        "\nModel output:"
    )

    print(
        MODEL_PATH
    )

    # --------------------------------------------------------
    # 1. Load dataset
    # --------------------------------------------------------

    df = load_dataset()

    # --------------------------------------------------------
    # 2. Extract features
    # --------------------------------------------------------

    X, y = extract_features_from_dataset(
        df
    )

    # --------------------------------------------------------
    # 3. Train / Test Split
    # --------------------------------------------------------

    print("\n" + "=" * 65)
    print("STEP 3A: TRAIN / TEST SPLIT")
    print("=" * 65)

    X_train, X_test, y_train, y_test = train_test_split(

        X,
        y,

        test_size=TEST_SIZE,

        random_state=RANDOM_STATE,

        stratify=y
    )

    print(
        f"Training samples: {len(X_train):,}"
    )

    print(
        f"Testing samples : {len(X_test):,}"
    )

    # --------------------------------------------------------
    # 4. Train
    # --------------------------------------------------------

    model = train_random_forest(
        X_train,
        y_train
    )

    # --------------------------------------------------------
    # 5. Evaluate
    # --------------------------------------------------------

    metrics = evaluate_model(
        model,
        X_test,
        y_test
    )

    # --------------------------------------------------------
    # 6. Save
    # --------------------------------------------------------

    save_model(
        model,
        metrics
    )

    # --------------------------------------------------------
    # Final message
    # --------------------------------------------------------

    print("\n" + "#" * 65)

    print(
        "      TRAINING COMPLETED SUCCESSFULLY"
    )

    print("#" * 65)

    print(
        f"\nV2 model saved at:"
    )

    print(
        MODEL_PATH
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()