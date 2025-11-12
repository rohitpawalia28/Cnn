import json
import os
from datetime import datetime

ALERT_DIR = "data/alerts"

def ensure_alert_dir():
    """Create alerts directory if it doesn't exist"""
    os.makedirs(ALERT_DIR, exist_ok=True)

def generate_alert(flow, pattern_type, severity):
    """
    Generate an alert for suspicious activity
    """
    alert = {
        "id": f"ALERT_{datetime.now().strftime('%Y%m%d%H%M%S')}_{flow['src']}",
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "pattern_type": pattern_type,
        "source_ip": flow.get("src"),
        "destination_ip": flow.get("dst"),
        "protocol": flow.get("proto"),
        "packet_count": flow.get("pkt_count"),
        "byte_count": flow.get("byte_count"),
        "threat_score": flow.get("threat_score", 0),
        "description": get_alert_description(pattern_type, flow)
    }
    
    return alert

def get_alert_description(pattern_type, flow):
    """
    Generate human-readable alert description
    """
    descriptions = {
        "port_scan": f"Possible port scan detected from {flow.get('src')} scanning {flow.get('unique_dst_ports', 0)} ports",
        "ddos_suspect": f"Potential DDoS attack detected with {flow.get('pkt_rate', 0)} packets/sec from {flow.get('src')}",
        "data_exfiltration": f"Large data transfer detected: {flow.get('byte_count', 0)} bytes from {flow.get('src')} to {flow.get('dst')}",
        "anomaly": f"Anomalous behavior detected in flow from {flow.get('src')} to {flow.get('dst')}"
    }
    
    return descriptions.get(pattern_type, "Unknown anomaly detected")

def save_alerts(alerts):
    """
    Save alerts to JSON file
    """
    ensure_alert_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(ALERT_DIR, f"alerts_{timestamp}.json")
    
    with open(filepath, 'w') as f:
        json.dump(alerts, f, indent=2)
    
    return filepath

def get_recent_alerts(limit=50):
    """
    Retrieve recent alerts
    """
    ensure_alert_dir()
    
    alert_files = sorted(
        [f for f in os.listdir(ALERT_DIR) if f.startswith("alerts_")],
        reverse=True
    )
    
    all_alerts = []
    for file in alert_files[:5]:  # Read last 5 files
        filepath = os.path.join(ALERT_DIR, file)
        try:
            with open(filepath, 'r') as f:
                alerts = json.load(f)
                all_alerts.extend(alerts)
        except Exception as e:
            print(f"Error reading {file}: {e}")
    
    return all_alerts[:limit]

def generate_alert_summary(alerts):
    """
    Generate summary statistics for alerts
    """
    if not alerts:
        return {
            "total": 0,
            "by_severity": {},
            "by_type": {},
            "recent_count": 0
        }
    
    from collections import Counter
    
    severities = Counter(a["severity"] for a in alerts)
    types = Counter(a["pattern_type"] for a in alerts)
    
    # Count recent alerts (last hour)
    now = datetime.now()
    recent = sum(1 for a in alerts 
                 if (now - datetime.fromisoformat(a["timestamp"])).seconds < 3600)
    
    return {
        "total": len(alerts),
        "by_severity": dict(severities),
        "by_type": dict(types),
        "recent_count": recent
    }