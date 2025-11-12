import os
import joblib
import pandas as pd
import numpy as np

# Automatically locate model files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "isof_model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.joblib")

def predict(df):
    """
    Enhanced prediction with confidence scores and additional features
    """
    try:
        # Load model and scaler
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except Exception as e:
        raise RuntimeError(f"Model or scaler not found: {e}")

    # Define feature columns (expand based on your enhanced features)
    feature_columns = ["pkt_count", "byte_count"]
    
    # Add optional features if they exist
    optional_features = ["pkt_rate", "byte_rate", "unique_src_ports", 
                        "unique_dst_ports", "duration", "avg_payload_size"]
    
    for feat in optional_features:
        if feat in df.columns:
            feature_columns.append(feat)
    
    # Ensure required columns exist
    missing_cols = [col for col in ["pkt_count", "byte_count"] if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required features: {missing_cols}")

    # Select features
    X = df[feature_columns]
    
    # Handle missing values
    X = X.fillna(0)
    
    # Scale features
    X_scaled = scaler.transform(X)

    # Predict anomalies
    predictions = model.predict(X_scaled)
    df["is_anomaly"] = predictions == -1
    
    # Get anomaly scores (decision function)
    # More negative = more anomalous
    scores = model.decision_function(X_scaled)
    df["anomaly_score"] = scores
    
    # Normalize scores to 0-100 (confidence)
    # Convert scores so that more negative = higher confidence
    min_score = scores.min()
    max_score = scores.max()
    
    if max_score != min_score:
        normalized_scores = 100 * (max_score - scores) / (max_score - min_score)
    else:
        normalized_scores = np.zeros(len(scores))
    
    df["confidence"] = normalized_scores.round(2)
    
    return df.to_dict(orient="records")

def predict_single_flow(flow_data):
    """
    Predict anomaly for a single flow
    """
    df = pd.DataFrame([flow_data])
    result = predict(df)
    return result[0] if result else None

def get_model_info():
    """
    Get information about the loaded model
    """
    try:
        model = joblib.load(MODEL_PATH)
        
        info = {
            "model_type": type(model).__name__,
            "contamination": model.contamination,
            "n_estimators": model.n_estimators,
            "max_samples": model.max_samples,
        }
        
        return info
    except Exception as e:
        return {"error": str(e)}