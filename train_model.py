import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from backend.app.feature_extract import extract_flows_from_pcap

# Path to your working pcap
pcap_path = r"C:\Users\meroh\OneDrive\Desktop\CN Project\data\pcaps\sample3.pcap"

# Extract flow data
df = extract_flows_from_pcap(pcap_path)
print(f"✅ Extracted {len(df)} flows")

if len(df) == 0:
    print("⚠️ The PCAP contains no flow data. Try capturing more packets.")
else:
    # Select numeric features
    features = ["pkt_count", "byte_count"]
    X = df[features]

    # Scale data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(X_scaled)

    # Save trained model and scaler
    joblib.dump(model, r"backend\app\isof_model.joblib")
    joblib.dump(scaler, r"backend\app\scaler.joblib")

    print("✅ Model trained and saved successfully at backend/app/")
