import os
import joblib
import pandas as pd

# Automatically locate model files in the same folder as this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "isof_model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.joblib")

def predict(df):
    """
    Load the Isolation Forest model and scaler,
    predict anomalies on extracted flow dataframe.
    """
    try:
        # Load the trained model and scaler
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except Exception as e:
        raise RuntimeError(f"Model or scaler not found: {e}")

    # Ensure required columns exist
    if "pkt_count" not in df.columns or "byte_count" not in df.columns:
        raise ValueError("Missing required features in dataframe")

    # Scale numerical features
    X = df[["pkt_count", "byte_count"]]
    X_scaled = scaler.transform(X)

    # Predict anomalies (-1 = anomaly, 1 = normal)
    preds = model.predict(X_scaled)
    df["is_anomaly"] = preds == -1

    return df.to_dict(orient="records")
