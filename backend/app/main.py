# backend/app/main.py
import os
import json
import traceback
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import numpy as np

from .feature_extract import extract_flows_from_pcap
from .model import predict_scores_and_confidence
# keep your analysis and alert modules
from .analysis import analyze_flows, detect_anomaly_patterns, calculate_severity
from .alert_system import generate_alert, save_alerts, get_recent_alerts, generate_alert_summary

app = FastAPI(
    title="Network Anomaly Detection API",
    description="Enhanced API for analyzing network traffic from PCAP files",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs("data/uploads", exist_ok=True)

def available_models():
    """
    Return the list of model names (exclude scaler files).
    """
    models = []
    for f in os.listdir(MODELS_DIR):
        if not f.endswith(".joblib"):
            continue
        if "scaler" in f.lower():
            continue
        name = f.replace(".joblib", "")
        models.append(name)
    return sorted(models)

@app.post("/upload_pcap/")
async def upload_pcap(
    file: UploadFile = File(...),
    model: str = Query(None, description="Optional single model to use (overrides multi-model eval)"),
    conf_thresh: float = Query(60.0, description="Confidence threshold (0-100) used for classification")
):
    """
    Uploads a PCAP, extracts flows, runs all available models on the UPLOADED file,
    and returns:
      - flows (with default model predictions attached),
      - statistics, patterns, alerts,
      - model_evaluations: per-model metrics computed on uploaded flows.
    """
    dest = f"data/uploads/{file.filename}"
    try:
        with open(dest, "wb") as buffer:
            buffer.write(await file.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to save uploaded file: {e}")

    try:
        df = extract_flows_from_pcap(dest)
        if df is None or len(df) == 0:
            return JSONResponse(content={
                "flows": [],
                "message": "No valid network flows found in file.",
                "statistics": {},
                "patterns": {},
                "alerts": [],
                "model_evaluations": {}
            })

        # Ensure numeric types for noise/stability routines
        df = df.reset_index(drop=True)

        # Determine which models to evaluate
        model_list = available_models()
        if model is not None:
            model_list = [m for m in model_list if m == model]

        model_evals = {}
        preds_matrix = {}

        # Evaluate each model on this uploaded dataset
        for model_name in model_list:
            try:
                preds, scores, confidences, infer_time = predict_scores_and_confidence(df, model_name=model_name)
                preds = np.array(preds)
                scores = np.array(scores, dtype=float)
                confidences = np.array(confidences, dtype=float)

                anomalies_count = int((preds == -1).sum())
                mean_conf = float(np.mean(confidences)) if confidences.size > 0 else 0.0
                score_var = float(np.var(scores)) if scores.size > 0 else 0.0

                # Predicted anomalies by confidence threshold (>= conf_thresh)
                predicted_anomaly_mask = confidences >= conf_thresh
                predicted_anomaly_count = int(predicted_anomaly_mask.sum())

                high_conf_anomaly_mask = (preds == -1) & (confidences >= conf_thresh)
                high_conf_anomaly_count = int(high_conf_anomaly_mask.sum())

                pseudo_precision = round((high_conf_anomaly_count / predicted_anomaly_count) * 100.0, 2) if predicted_anomaly_count > 0 else 0.0

                # Stability: repeated runs with small perturbation of numeric cols
                stability_checks = []
                numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

                for _ in range(3):
                    noisy = df.copy()
                    for c in numeric_cols:
                        col_std = noisy[c].std() if noisy[c].std() > 0 else 1.0
                        noisy[c] = noisy[c] + np.random.normal(0, 0.01 * col_std, size=len(noisy))
                    try:
                        n_preds, _, n_conf, _ = predict_scores_and_confidence(noisy, model_name=model_name)
                        n_conf = np.array(n_conf)
                        orig_label = (confidences >= conf_thresh).astype(int)
                        new_label = (n_conf >= conf_thresh).astype(int)
                        stability_checks.append((orig_label == new_label).mean())
                    except Exception:
                        stability_checks.append(0.0)

                stability_pct = round(np.mean(stability_checks) * 100.0, 2)

                # store thresholded labels (1 anomaly, 0 normal)
                threshold_labels = (confidences >= conf_thresh).astype(int)
                preds_matrix[model_name] = threshold_labels

                model_evals[model_name] = {
                    "inference_time_sec": round(float(infer_time), 6),
                    "anomalies_detected": int(anomalies_count),
                    "mean_confidence": round(mean_conf, 2),
                    "score_variance": round(score_var, 5),
                    "pseudo_precision_pct": pseudo_precision,
                    "stability_pct": stability_pct,
                    # accuracy will be filled after majority computed
                    "pseudo_accuracy_pct": None,
                    "high_conf_anomalies": high_conf_anomaly_count,
                    "predicted_anomalies_by_conf_thresh": predicted_anomaly_count
                }

            except Exception as me:
                tb = traceback.format_exc()
                print(f"❌ Error evaluating model {model_name} on uploaded file:\n{tb}")
                model_evals[model_name] = {"error": str(me), "traceback": tb}

        # Compute majority consensus and per-model pseudo-accuracy
        try:
            if preds_matrix:
                labels_arr = np.array([preds_matrix[m] for m in sorted(preds_matrix.keys())])
                majority = (labels_arr.sum(axis=0) >= (labels_arr.shape[0] / 2)).astype(int)
                for model_name in model_evals:
                    if "error" in model_evals[model_name]:
                        continue
                    labels = preds_matrix.get(model_name)
                    if labels is None:
                        model_evals[model_name]["pseudo_accuracy_pct"] = None
                    else:
                        acc = round(float((labels == majority).mean() * 100.0), 2)
                        model_evals[model_name]["pseudo_accuracy_pct"] = acc
            else:
                for m in model_evals:
                    model_evals[m]["pseudo_accuracy_pct"] = None
        except Exception:
            print("❌ Error computing majority-based accuracy:\n", traceback.format_exc())
            for m in model_evals:
                if "pseudo_accuracy_pct" not in model_evals[m]:
                    model_evals[m]["pseudo_accuracy_pct"] = None

        # Prepare flows output: attach predictions from a selected model or default first model
        selected_model = model if model is not None else (available_models()[0] if available_models() else None)
        flows_with_predictions = []
        if selected_model:
            try:
                preds, scores, confidences, _ = predict_scores_and_confidence(df, model_name=selected_model)
                df_out = df.copy()
                df_out["is_anomaly"] = (np.array(preds) == -1).tolist()
                df_out["anomaly_score"] = [float(s) for s in scores]
                df_out["confidence"] = [float(c) for c in confidences]
            except Exception:
                tb = traceback.format_exc()
                print("❌ Error predicting flows for response:\n", tb)
                df_out = df.copy()
                df_out["is_anomaly"] = False
                df_out["anomaly_score"] = 0.0
                df_out["confidence"] = 0.0
        else:
            df_out = df.copy()
            df_out["is_anomaly"] = False
            df_out["anomaly_score"] = 0.0
            df_out["confidence"] = 0.0

        # ------------------------------
        # Add 'reason' for anomalous flows (R3)
        # ------------------------------
        # initialize column
        df_out["reason"] = None

        # mark reasons for detected anomalies using same logic as your alert generation
        anomalies_df = df_out[(df_out["is_anomaly"] == True)].copy()
        for idx, flow in anomalies_df.iterrows():
            pattern_type = "anomaly"
            try:
                if flow.get("unique_dst_ports", 0) > 10:
                    pattern_type = "port_scan"
                elif flow.get("pkt_rate", 0) > 100:
                    pattern_type = "ddos_suspect"
                elif "byte_count" in df_out.columns and flow.get("byte_count", 0) > df_out["byte_count"].quantile(0.95):
                    pattern_type = "data_exfiltration"
            except Exception:
                pattern_type = "anomaly"

            df_out.at[idx, "reason"] = pattern_type

            # generate alert from original flow dict (use already-enriched df_out row)
            try:
                alert = generate_alert(flow.to_dict(), pattern_type, flow.get("severity", "MEDIUM"))
                # append alert (we will add below)
            except Exception:
                pass

        # fill normal flows reason
        df_out["reason"] = df_out["reason"].fillna("normal")

        # Run existing analysis pipeline on df_out
        try:
            df_analyzed = calculate_severity(df_out)
            statistics = analyze_flows(df_analyzed)
            patterns = detect_anomaly_patterns(df_analyzed)
        except Exception:
            tb = traceback.format_exc()
            print("❌ Error running analysis pipeline on uploaded flows:\n", tb)
            statistics = {}
            patterns = {}

        # Generate alerts list (from df_analyzed anomalies)
        alerts = []
        try:
            anomalies_for_alerts = df_analyzed[df_analyzed.get("is_anomaly") == True]
            for _, flow in anomalies_for_alerts.iterrows():
                ptype = flow.get("reason", "anomaly")
                alert = generate_alert(flow.to_dict(), ptype, flow.get("severity", "MEDIUM"))
                alerts.append(alert)
            if alerts:
                save_alerts(alerts)
        except Exception:
            tb = traceback.format_exc()
            print("❌ Error generating alerts:\n", tb)
            alerts = []

        response = {
            "flows": df_analyzed.to_dict(orient="records"),
            "statistics": statistics,
            "patterns": patterns,
            "alerts": alerts,
            "alert_summary": generate_alert_summary(alerts),
            "model_evaluations": model_evals
        }

        return JSONResponse(content=response)

    except Exception as e:
        tb = traceback.format_exc()
        print("❌ Exception while processing upload_pcap:\n", tb)
        return JSONResponse(status_code=500, content={"error": str(e), "traceback": tb})


@app.get("/model/scores")
def model_scores():
    try:
        scores_file = os.path.join(MODELS_DIR, "model_scores.json")
        if not os.path.exists(scores_file):
            return {"error": "Model scores file not found. Run train_model.py first."}
        with open(scores_file, "r") as fh:
            data = json.load(fh)
        return {"scores": data}
    except Exception as e:
        tb = traceback.format_exc()
        print("❌ Exception in model_scores:\n", tb)
        return JSONResponse(status_code=500, content={"error": str(e), "traceback": tb})


@app.get("/alerts/")
def get_alerts(limit: int = 50):
    try:
        alerts = get_recent_alerts(limit)
        summary = generate_alert_summary(alerts)
        return {"alerts": alerts, "summary": summary}
    except Exception as e:
        tb = traceback.format_exc()
        print("❌ Exception in get_alerts:\n", tb)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/")
def root():
    return {
        "status": "running",
        "message": "Network Anomaly Detection API v2.0 🚀",
        "endpoints": {
            "/upload_pcap/": "Upload and analyze PCAP files (supports conf_thresh param)",
            "/model/scores": "Get training-time model scores",
            "/alerts/": "Get recent alerts",
            "/health": "Health check"
        }
    }
