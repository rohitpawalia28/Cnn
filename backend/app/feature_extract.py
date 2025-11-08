import pyshark
import pandas as pd
import nest_asyncio
nest_asyncio.apply()

def extract_flows_from_pcap(pcap_path):
    """
    Extract basic flow features (source, destination, ports, counts, etc.)
    from a pcap file using pyshark in a safe synchronous way (Windows-compatible).
    """

    # Create capture object WITHOUT unsupported flags
    cap = pyshark.FileCapture(pcap_path, keep_packets=False)

    flows = {}
    for pkt in cap:
        try:
            # Skip non-IP packets
            if not hasattr(pkt, "ip"):
                continue

            proto = getattr(pkt, "transport_layer", None) or pkt.highest_layer
            src = pkt.ip.src
            dst = pkt.ip.dst
            sport = getattr(pkt[pkt.transport_layer], "srcport", 0) if pkt.transport_layer else 0
            dport = getattr(pkt[pkt.transport_layer], "dstport", 0) if pkt.transport_layer else 0

            key = (src, dst, sport, dport, proto)

            if key not in flows:
                flows[key] = {"pkt_count": 0, "byte_count": 0}

            flows[key]["pkt_count"] += 1
            flows[key]["byte_count"] += int(pkt.length)

        except Exception:
            # Ignore malformed or unsupported packets
            continue

    # Safe close
    try:
        cap.close()
    except Exception:
        pass

    # Convert flows dict to DataFrame
    rows = []
    for (src, dst, sport, dport, proto), f in flows.items():
        rows.append({
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "pkt_count": f["pkt_count"],
            "byte_count": f["byte_count"]
        })

    return pd.DataFrame(rows)
