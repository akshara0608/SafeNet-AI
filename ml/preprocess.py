"""
SafeNet-AI Data Preprocessing Module
Specialized for Tree-Based Models (Random Forest)
"""

import pandas as pd
import numpy as np


def clean_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean the feature matrix for Random Forest training and inference.
    
    Random Forest handles non-linear relationships and is scale-invariant,
    so no feature scaling (StandardScaler/MinMaxScaler) is required.
    However, numerical values must be finite and free of NaNs.
    
    Operations:
    1. Replace infinite values (+/- inf) with NaN.
    2. Convert all columns to numeric types.
    3. Replace sentinel error values (-1 from WHOIS/SSL failures) with NaN.
    4. Impute missing values (NaN) with column medians (or 0.0 if empty).
    """
    cleaned_df = df.copy()

    # Replace infinities
    cleaned_df = cleaned_df.replace([np.inf, -np.inf, float("inf"), float("-inf")], np.nan)

    # Convert everything to numeric
    cleaned_df = cleaned_df.apply(pd.to_numeric, errors="coerce")

    # Replace sentinel -1 values (e.g., unavailable WHOIS or SSL info) with NaN
    cleaned_df = cleaned_df.replace(-1, np.nan)

    # Impute missing values with column median safely without empty slice warnings
    for col in cleaned_df.columns:
        valid_vals = cleaned_df[col].dropna()
        if len(valid_vals) > 0:
            median_val = float(valid_vals.median())
        else:
            median_val = 0.0

        if pd.isna(median_val):
            median_val = 0.0

        cleaned_df[col] = cleaned_df[col].fillna(median_val)

    return cleaned_df


def validate_features(df: pd.DataFrame, expected_features: list[str]) -> pd.DataFrame:
    """
    Validate that all required features exist and align the DataFrame
    to the exact feature order expected by the Random Forest model.
    """
    missing = [feat for feat in expected_features if feat not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    return df[expected_features]
