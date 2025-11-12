import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
from backend.app.feature_extract import extract_flows_from_pcap

# Path to your training PCAP files
pcap_paths = [
    r"C:\Users\meroh\OneDrive\Desktop\CN Project\data\pcaps\sample3.pcap",
    # Add more PCAP files for better training
]

print("🔧 Training Enhanced Network Anomaly Detection Model")
print("=" * 60)

# Collect data from all PCAP files
all_flows = []
for pcap_path in pcap_paths:
    print(f"\n📂 Processing: {pcap_path}")
    df = extract_flows_from_pcap(pcap_path)
    if len(df) > 0:
        all_flows.append(df)
        print(f"✅ Extracted {len(df)} flows")
    else:
        print(f"⚠️  No flows found in {pcap_path}")

if not all_flows:
    print("\n❌ No data available for training. Please check your PCAP files.")
    exit(1)

# Combine all flows
df = pd.concat(all_flows, ignore_index=True)
print(f"\n📊 Total flows for training: {len(df)}")

# Select features for training
base_features = ["pkt_count", "byte_count"]
optional_features = ["pkt_rate", "byte_rate", "unique_src_ports", 
                    "unique_dst_ports", "duration", "avg_payload_size"]

# Use features that are available
features = base_features.copy()
for feat in optional_features:
    if feat in df.columns:
        features.append(feat)

print(f"\n🎯 Using features: {features}")

# Prepare training data
X = df[features]

# Handle missing values
X = X.fillna(0)

# Handle infinite values
X = X.replace([np.inf, -np.inf], 0)

print(f"\n📈 Training data shape: {X.shape}")
print(f"   Features: {X.shape[1]}")
print(f"   Samples: {X.shape[0]}")

# Scale data
print("\n⚙️  Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest
print("\n🤖 Training Isolation Forest model...")
model = IsolationForest(
    n_estimators=150,          # Increased from 100
    contamination=0.05,        # Expect 5% anomalies
    max_samples='auto',        # Use all samples
    random_state=42,
    n_jobs=-1                  # Use all CPU cores
)

model.fit(X_scaled)

# Test the model on training data
print("\n🧪 Testing model on training data...")
predictions = model.predict(X_scaled)
anomalies_detected = (predictions == -1).sum()
normal_detected = (predictions == 1).sum()

print(f"   Normal flows: {normal_detected} ({normal_detected/len(df)*100:.1f}%)")
print(f"   Anomalies: {anomalies_detected} ({anomalies_detected/len(df)*100:.1f}%)")

# Save model and scaler
print("\n💾 Saving model and scaler...")
model_path = r"backend\app\isof_model.joblib"
scaler_path = r"backend\app\scaler.joblib"

joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)

print(f"   ✅ Model saved: {model_path}")
print(f"   ✅ Scaler saved: {scaler_path}")

# Print model parameters
print("\n📋 Model Parameters:")
print(f"   Estimators: {model.n_estimators}")
print(f"   Contamination: {model.contamination}")
print(f"   Max samples: {model.max_samples}")

print("\n" + "=" * 60)
print("✅ Training complete! Model ready for deployment.")
print("=" * 60)