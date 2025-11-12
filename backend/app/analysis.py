import pandas as pd
import numpy as np
from collections import Counter

def analyze_flows(df):
    """
    Perform comprehensive analysis on network flows
    """
    if df.empty:
        return {}
    
    analysis = {}
    
    # Basic statistics
    analysis["total_flows"] = len(df)
    analysis["total_packets"] = int(df["pkt_count"].sum())
    analysis["total_bytes"] = int(df["byte_count"].sum())
    analysis["avg_packets_per_flow"] = round(df["pkt_count"].mean(), 2)
    analysis["avg_bytes_per_flow"] = round(df["byte_count"].mean(), 2)
    
    # Protocol distribution
    proto_dist = df["proto"].value_counts().to_dict()
    analysis["protocol_distribution"] = proto_dist
    
    # Top talkers (by packets and bytes)
    src_packets = df.groupby("src")["pkt_count"].sum().sort_values(ascending=False).head(10)
    analysis["top_sources"] = src_packets.to_dict()
    
    dst_packets = df.groupby("dst")["pkt_count"].sum().sort_values(ascending=False).head(10)
    analysis["top_destinations"] = dst_packets.to_dict()
    
    # Port analysis
    if "unique_src_ports" in df.columns:
        analysis["avg_unique_src_ports"] = round(df["unique_src_ports"].mean(), 2)
        analysis["avg_unique_dst_ports"] = round(df["unique_dst_ports"].mean(), 2)
    
    # Duration statistics
    if "duration" in df.columns:
        analysis["avg_flow_duration"] = round(df["duration"].mean(), 3)
        analysis["max_flow_duration"] = round(df["duration"].max(), 3)
        analysis["min_flow_duration"] = round(df["duration"].min(), 3)
    
    # Rate statistics
    if "pkt_rate" in df.columns:
        analysis["avg_packet_rate"] = round(df["pkt_rate"].mean(), 2)
        analysis["max_packet_rate"] = round(df["pkt_rate"].max(), 2)
    
    if "byte_rate" in df.columns:
        analysis["avg_byte_rate"] = round(df["byte_rate"].mean(), 2)
        analysis["max_byte_rate"] = round(df["byte_rate"].max(), 2)
    
    return analysis

def detect_anomaly_patterns(df):
    """
    Identify specific anomaly patterns
    """
    patterns = {
        "port_scan": [],
        "ddos_suspect": [],
        "data_exfiltration": [],
        "unusual_protocol": []
    }
    
    if df.empty or "is_anomaly" not in df.columns:
        return patterns
    
    anomalies = df[df["is_anomaly"] == True]
    
    # Port scan detection (high unique destination ports)
    if "unique_dst_ports" in anomalies.columns:
        port_scans = anomalies[anomalies["unique_dst_ports"] > 10]
        patterns["port_scan"] = port_scans[["src", "dst", "unique_dst_ports"]].to_dict("records")
    
    # DDoS suspects (high packet rate to single destination)
    if "pkt_rate" in anomalies.columns:
        ddos = anomalies[anomalies["pkt_rate"] > anomalies["pkt_rate"].quantile(0.95)]
        patterns["ddos_suspect"] = ddos[["src", "dst", "pkt_rate", "pkt_count"]].to_dict("records")
    
    # Data exfiltration (high byte count)
    if "byte_count" in anomalies.columns:
        exfil = anomalies[anomalies["byte_count"] > anomalies["byte_count"].quantile(0.95)]
        patterns["data_exfiltration"] = exfil[["src", "dst", "byte_count", "duration"]].to_dict("records")
    
    return patterns

def generate_threat_score(row):
    """
    Generate a threat score for each flow (0-100)
    """
    score = 0
    
    if row.get("is_anomaly"):
        score += 50
    
    # High packet rate
    if row.get("pkt_rate", 0) > 100:
        score += 15
    
    # High byte rate
    if row.get("byte_rate", 0) > 10000:
        score += 15
    
    # Many unique ports (possible scan)
    if row.get("unique_dst_ports", 0) > 10:
        score += 20
    
    return min(score, 100)

def calculate_severity(df):
    """
    Calculate severity levels for anomalies
    """
    if "is_anomaly" not in df.columns:
        return df
    
    df["threat_score"] = df.apply(generate_threat_score, axis=1)
    
    def get_severity(score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    df["severity"] = df["threat_score"].apply(get_severity)
    
    return df