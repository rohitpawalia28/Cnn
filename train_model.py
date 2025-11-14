import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EllipticEnvelope
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from scipy.spatial.distance import cdist

from backend.app.feature_extract import extract_flows_from_pcap

# ------------------------------
# CONFIGURATION
# ------------------------------
PCAP_PATHS = [
    r"C:\Users\meroh\OneDrive\Desktop\CN Project\data\pcaps\sample3.pcap"
]

OUTPUT_DIR = os.path.join("backend", "app", "models")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SCORES_PATH = os.path.join(OUTPUT_DIR, "model_scores.json")
SCALER_PATH = os.path.join(OUTPUT_DIR, "scaler.joblib")

# ------------------------------
print("🔧 Training Advanced Models with Research-Grade Metrics")
print("=" * 70)

# 1) Load PCAP flows
all_flows = []
for file in PCAP_PATHS:
    df = extract_flows_from_pcap(file)
    if df is not None and len(df) > 0:
        all_flows.append(df)
        print(f"✔ Extracted {len(df)} flows from {file}")
    else:
        print(f"❌ No flows in: {file}")

if not all_flows:
    raise SystemExit("❌ No flows extracted. Training aborted.")

df = pd.concat(all_flows, ignore_index=True)

# 2) Select features
base = ["pkt_count", "byte_count"]
opt = ["pkt_rate", "byte_rate", "unique_src_ports", "unique_dst_ports",
       "duration", "avg_payload_size"]

features = base + [f for f in opt if f in df.columns]

X = df[features].fillna(0).replace([np.inf, -np.inf], 0)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, SCALER_PATH)

# 3) Define models
models = {
    "isolation_forest": IsolationForest(n_estimators=150, contamination=0.05, random_state=42),
    "oneclass_svm": OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
    "local_outlier_factor": LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.05),
    "elliptic_envelope": EllipticEnvelope(contamination=0.05, random_state=42)
}

# Helper: Safe decision scores
def safe_decision(model, X):
    try:
        raw = model.decision_function(X)
        return raw.max() - raw  # flip so high = more anomalous
    except:
        return (-model.predict(X)).astype(float)

# ------------------------------
# ADVANCED METRICS (UNSUPERVISED)
# ------------------------------

def silhouette_separation(X, preds):
    """Silhouette score between normal vs anomaly"""
    labels = np.where(preds == -1, 1, 0)
    if len(np.unique(labels)) < 2:
        return -1
    try:
        return round(float(silhouette_score(X, labels)), 5)
    except:
        return -1

def cluster_compactness(X, mask_normal):
    """Distance of normal points to their centroid"""
    if mask_normal.sum() < 2:
        return 999
    normal_pts = X[mask_normal]
    center = normal_pts.mean(axis=0)
    d = cdist(normal_pts, [center])
    return round(float(d.mean()), 5)

def anomaly_separation(X, mask_anomaly, mask_normal):
    """Distance between normal centroid and anomaly centroid"""
    if mask_anomaly.sum() < 1 or mask_normal.sum() < 1:
        return 0
    normal_c = X[mask_normal].mean(axis=0)
    anomaly_c = X[mask_anomaly].mean(axis=0)
    dist = np.linalg.norm(normal_c - anomaly_c)
    return round(float(dist), 5)

def density_drop_score(scores, preds):
    """Avg normal score - avg anomaly score"""
    mask_anomaly = preds == -1
    mask_normal = preds == 1
    if mask_anomaly.sum() < 1:
        return 0
    norm = scores[mask_normal].mean() if mask_normal.sum() else 0
    anom = scores[mask_anomaly].mean()
    return round(float(norm - anom), 5)

def global_outlier_factor(scores):
    """Measures rarity based on score distribution"""
    if len(scores) < 2:
        return 0
    return round(float(scores.std() / (scores.mean() + 1e-6)), 5)

def stability_index(model, X, preds):
    """Repeat predictions with noise; measure consistency"""
    stabilities = []
    for _ in range(3):
        noise = np.random.normal(0, 0.01, X.shape)
        try:
            new_preds = model.predict(X + noise)
        except:
            new_preds = preds
        stabilities.append((new_preds == preds).mean())
    return round(float(np.mean(stabilities) * 100), 2)

# Weighted Final Score
def model_strength_score(metrics):
    w = {
        "silhouette": 0.25,
        "separation": 0.25,
        "density_drop": 0.20,
        "gof": 0.10,
        "stability": 0.20
    }
    score = (
        w["silhouette"] * max(0, metrics["silhouette_separation"]) * 100 +
        w["separation"] * metrics["anomaly_separation"] +
        w["density_drop"] * metrics["density_drop"] * 10 +
        w["gof"] * metrics["global_outlier_factor"] * 10 +
        w["stability"] * (metrics["stability_index"] / 100) * 100
    )
    return round(float(score), 2)

# ------------------------------
# TRAIN + EVALUATE
# ------------------------------

results = {}

for name, model in models.items():
    print(f"\n⚡ Training {name} ...")
    t0 = t1 = time.time()

    model.fit(X_scaled)
    t1 = time.time()

    preds = model.predict(X_scaled)
    scores = safe_decision(model, X_scaled)

    mask_anom = preds == -1
    mask_norm = preds == 1

    metrics = {
        "training_time_sec": round(t1 - t0, 4),
        "n_anomalies": int(mask_anom.sum()),
        "silhouette_separation": silhouette_separation(X_scaled, preds),
        "cluster_compactness": cluster_compactness(X_scaled, mask_norm),
        "anomaly_separation": anomaly_separation(X_scaled, mask_anom, mask_norm),
        "density_drop": density_drop_score(scores, preds),
        "global_outlier_factor": global_outlier_factor(scores),
        "stability_index": stability_index(model, X_scaled, preds),
    }

    metrics["model_strength"] = model_strength_score(metrics)

    model_path = os.path.join(OUTPUT_DIR, f"{name}.joblib")
    joblib.dump(model, model_path)

    results[name] = metrics

    print(f"✔ {name} trained. Model Strength = {metrics['model_strength']}")

with open(SCORES_PATH, "w") as f:
    json.dump(results, f, indent=2)

print("\n🎉 Advanced Training Complete. Scores saved to:", SCORES_PATH)
