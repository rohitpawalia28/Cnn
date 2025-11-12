from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from collections import defaultdict
from datetime import datetime

def extract_flows_from_pcap(pcap_path):
    """
    Enhanced flow extraction with more features
    """
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")
        return pd.DataFrame()

    flows = defaultdict(lambda: {
        "pkt_count": 0,
        "byte_count": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "start_time": None,
        "end_time": None,
        "src_ports": set(),
        "dst_ports": set(),
        "flags": [],
        "payload_sizes": []
    })

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            size = len(pkt)
            timestamp = float(pkt.time)

            # Flow key (bidirectional)
            flow_key = tuple(sorted([src, dst])) + (proto,)

            # Update flow statistics
            flows[flow_key]["pkt_count"] += 1
            flows[flow_key]["byte_count"] += size
            
            # Track time
            if flows[flow_key]["start_time"] is None:
                flows[flow_key]["start_time"] = timestamp
            flows[flow_key]["end_time"] = timestamp

            # Protocol-specific features
            if TCP in pkt:
                flows[flow_key]["tcp_count"] += 1
                flows[flow_key]["src_ports"].add(pkt[TCP].sport)
                flows[flow_key]["dst_ports"].add(pkt[TCP].dport)
                flows[flow_key]["flags"].append(pkt[TCP].flags)
                
            elif UDP in pkt:
                flows[flow_key]["udp_count"] += 1
                flows[flow_key]["src_ports"].add(pkt[UDP].sport)
                flows[flow_key]["dst_ports"].add(pkt[UDP].dport)

            # Payload size
            if pkt.haslayer("Raw"):
                flows[flow_key]["payload_sizes"].append(len(pkt["Raw"].load))

    # Convert to DataFrame with enhanced features
    rows = []
    for (src, dst, proto), stats in flows.items():
        # Calculate duration
        duration = stats["end_time"] - stats["start_time"] if stats["end_time"] else 0
        
        # Calculate rates
        pkt_rate = stats["pkt_count"] / duration if duration > 0 else 0
        byte_rate = stats["byte_count"] / duration if duration > 0 else 0
        
        # Calculate averages
        avg_payload = sum(stats["payload_sizes"]) / len(stats["payload_sizes"]) if stats["payload_sizes"] else 0
        
        rows.append({
            "src": src,
            "dst": dst,
            "proto": "TCP" if stats["tcp_count"] > 0 else ("UDP" if stats["udp_count"] > 0 else "OTHER"),
            "pkt_count": stats["pkt_count"],
            "byte_count": stats["byte_count"],
            "duration": round(duration, 3),
            "pkt_rate": round(pkt_rate, 2),
            "byte_rate": round(byte_rate, 2),
            "unique_src_ports": len(stats["src_ports"]),
            "unique_dst_ports": len(stats["dst_ports"]),
            "avg_payload_size": round(avg_payload, 2),
            "tcp_flags_count": len(stats["flags"]),
            "start_time": datetime.fromtimestamp(stats["start_time"]).strftime("%Y-%m-%d %H:%M:%S") if stats["start_time"] else None,
        })

    df = pd.DataFrame(rows)
    print(f"✅ Extracted {len(df)} flows with enhanced features")
    return df