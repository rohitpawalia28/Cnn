from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import json

from .feature_extract import extract_flows_from_pcap
from .model import predict


# --------------------------------------------------------
# Initialize FastAPI App
# --------------------------------------------------------
app = FastAPI(
    title="Network Anomaly Detection API",
    description="Backend API for analyzing network traffic from PCAP files.",
    version="1.0.0"
)

# --------------------------------------------------------
# Enable CORS (Allow Frontend React App to Connect)
# --------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can later change this to ["http://localhost:5173"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------
# Route: Upload and Analyze PCAP File
# --------------------------------------------------------
@app.post("/upload_pcap/")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Accepts a .pcap file, extracts network flows, runs anomaly detection,
    and returns flow-level predictions.
    """

    # ✅ Ensure upload directory exists
    os.makedirs("data/uploads", exist_ok=True)

    # ✅ Save the uploaded file
    dest = f"data/uploads/{file.filename}"
    with open(dest, "wb") as buffer:
        buffer.write(await file.read())

    print(f"✅ File saved: {dest}")

    # ✅ Extract features from PCAP
    df = extract_flows_from_pcap(dest)
    print(f"✅ Extracted {len(df)} flows")

    # If no flows found, return empty response
    if df is None or len(df) == 0:
        return JSONResponse(content={"flows": [], "message": "No valid network flows found in file."})

    # ✅ Predict anomalies
    result = predict(df)
    print("✅ Model prediction complete.")

    # ✅ Format response properly
    if hasattr(result, "to_json"):
        response_data = json.loads(result.to_json(orient="records"))
    else:
        response_data = result

    print("✅ Final response prepared.")
    return JSONResponse(content={"flows": response_data})


# --------------------------------------------------------
# Root Route (for testing)
# --------------------------------------------------------
@app.get("/")
def root():
    return {"status": "running", "message": "Network Anomaly Detection API is live 🚀"}
