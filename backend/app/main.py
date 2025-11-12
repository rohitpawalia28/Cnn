from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import json
import pandas as pd

from .feature_extract import extract_flows_from_pcap
from .model import predict, get_model_info
from .analysis import analyze_flows, detect_anomaly_patterns, calculate_severity
from .alert_system import generate_alert, save_alerts, get_recent_alerts, generate_alert_summary

# Initialize FastAPI App
app = FastAPI(
    title="Network Anomaly Detection API",
    description="Enhanced API for analyzing network traffic from PCAP files",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------
# Route: Upload and Analyze PCAP File (Enhanced)
# --------------------------------------------------------
@app.post("/upload_pcap/")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Accepts a .pcap file, extracts network flows with enhanced features,
    runs anomaly detection, and returns comprehensive analysis
    """
    # Ensure upload directory exists
    os.makedirs("data/uploads", exist_ok=True)

    # Save the uploaded file
    dest = f"data/uploads/{file.filename}"
    with open(dest, "wb") as buffer:
        buffer.write(await file.read())

    print(f"✅ File saved: {dest}")

    try:
        # Extract features from PCAP
        df = extract_flows_from_pcap(dest)
        print(f"✅ Extracted {len(df)} flows")

        if df is None or len(df) == 0:
            return JSONResponse(content={
                "flows": [],
                "message": "No valid network flows found in file.",
                "statistics": {},
                "patterns": {},
                "alerts": []
            })

        # Predict anomalies
        flows_with_predictions = predict(df)
        df = pd.DataFrame(flows_with_predictions)
        print("✅ Model prediction complete.")

        # Calculate severity and threat scores
        df = calculate_severity(df)

        # Perform comprehensive analysis
        statistics = analyze_flows(df)
        
        # Detect anomaly patterns
        patterns = detect_anomaly_patterns(df)
        
        # Generate alerts for anomalies
        alerts = []
        anomalies = df[df["is_anomaly"] == True]
        
        for _, flow in anomalies.iterrows():
            # Determine pattern type
            pattern_type = "anomaly"
            if flow.get("unique_dst_ports", 0) > 10:
                pattern_type = "port_scan"
            elif flow.get("pkt_rate", 0) > 100:
                pattern_type = "ddos_suspect"
            elif flow.get("byte_count", 0) > df["byte_count"].quantile(0.95):
                pattern_type = "data_exfiltration"
            
            alert = generate_alert(flow.to_dict(), pattern_type, flow.get("severity", "MEDIUM"))
            alerts.append(alert)
        
        # Save alerts
        if alerts:
            alert_file = save_alerts(alerts)
            print(f"✅ Saved {len(alerts)} alerts to {alert_file}")

        # Format response
        response_data = {
            "flows": df.to_dict(orient="records"),
            "statistics": statistics,
            "patterns": patterns,
            "alerts": alerts,
            "alert_summary": generate_alert_summary(alerts)
        }

        print("✅ Final response prepared.")
        return JSONResponse(content=response_data)

    except Exception as e:
        print(f"❌ Error processing PCAP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# --------------------------------------------------------
# Route: Get Statistics
# --------------------------------------------------------
@app.get("/statistics/")
def get_statistics():
    """
    Get current statistics from the most recent analysis
    """
    # This would typically query a database
    # For now, return placeholder
    return {
        "message": "Statistics endpoint",
        "note": "Statistics are returned with each PCAP upload"
    }

# --------------------------------------------------------
# Route: Get Recent Alerts
# --------------------------------------------------------
@app.get("/alerts/")
def get_alerts(limit: int = 50):
    """
    Retrieve recent alerts
    """
    try:
        alerts = get_recent_alerts(limit)
        summary = generate_alert_summary(alerts)
        
        return {
            "alerts": alerts,
            "summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --------------------------------------------------------
# Route: Get Model Information
# --------------------------------------------------------
@app.get("/model/info")
def model_info():
    """
    Get information about the loaded ML model
    """
    try:
        info = get_model_info()
        return info
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --------------------------------------------------------
# Route: Health Check
# --------------------------------------------------------
@app.get("/health")
def health_check():
    """
    Check if the API is running and models are loaded
    """
    try:
        model_status = get_model_info()
        return {
            "status": "healthy",
            "model_loaded": "error" not in model_status,
            "version": "2.0.0"
        }
    except:
        return {
            "status": "unhealthy",
            "model_loaded": False
        }

# --------------------------------------------------------
# Root Route
# --------------------------------------------------------
@app.get("/")
def root():
    return {
        "status": "running",
        "message": "Network Anomaly Detection API v2.0 🚀",
        "endpoints": {
            "/upload_pcap/": "Upload and analyze PCAP files",
            "/alerts/": "Get recent alerts",
            "/model/info": "Get model information",
            "/health": "Health check"
        }
    }