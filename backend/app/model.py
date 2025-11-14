# backend/app/model.py
"""
Model utilities: load model+scaler and produce predictions, anomaly scores and confidences.
"""

import os
import joblib
import numpy as np
import pandas as pd
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")

DEFAULT_MODEL = "isolation_forest"

def _model_path_for_name(name):
    return os.path.join(MODELS_DIR, f"{name}.joblib")

def _load_model_and_scaler(model_name=DEFAULT_MODEL):
    model_path = _model_path_for_name(model_name)
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found: {model_path}")
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler not found: {SCALER_PATH}")
    model = joblib.load(model_path)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler

def _prepare_features(df):
    feature_columns = ["pkt_count", "byte_count"]
    optional_features = ["pkt_rate", "byte_rate", "unique_src_ports",
                         "unique_dst_ports", "duration", "avg_payload_size"]
    for feat in optional_features:
        if feat in df.columns:
            feature_columns.append(feat)
    missing = [c for c in ["pkt_count", "byte_count"] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")
    X = df[feature_columns].fillna(0).replace([np.inf, -np.inf], 0)
    return X, feature_columns

def predict_scores_and_confidence(df, model_name=None):
    """
    Predict using a named model and return:
      - preds: array (1 normal, -1 anomaly)
      - anomaly_scores: higher == more anomalous
      - confidences: 0-100 normalized confidence (higher => more confident anomaly)
      - inference_time (seconds) for prediction step (not including scaling)
    """
    if isinstance(df, list):
        df = pd.DataFrame(df)
    elif not isinstance(df, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame or list of dicts")

    model_to_use = model_name if model_name else DEFAULT_MODEL
    model, scaler = _load_model_and_scaler(model_to_use)

    X, feat_cols = _prepare_features(df)
    X_scaled = scaler.transform(X)

    t0 = time.time()
    preds = model.predict(X_scaled)
    t1 = time.time()
    inference_time = t1 - t0

    # try to get decision function; convert so higher = more anomalous
    try:
        raw_scores = model.decision_function(X_scaled)
        anomaly_scores = raw_scores.max() - raw_scores
    except Exception:
        # fallback: use negative of predictions (anomaly -> 1)
        anomaly_scores = (-preds).astype(float)

    anomaly_scores = np.array(anomaly_scores, dtype=float)

    # Normalize confidence: map anomaly_scores to 0-100
    s_min = anomaly_scores.min() if anomaly_scores.size > 0 else 0.0
    s_max = anomaly_scores.max() if anomaly_scores.size > 0 else 0.0
    if s_max != s_min:
        normalized = 100.0 * (anomaly_scores - s_min) / (s_max - s_min)
    else:
        normalized = np.zeros_like(anomaly_scores)

    confidences = np.round(normalized, 2)

    return preds.astype(int), anomaly_scores.tolist(), confidences.tolist(), round(inference_time, 6)
