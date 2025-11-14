// frontend/src/App.jsx
import React, { useState, useMemo } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, Legend
} from "recharts";

const API_URL = "http://127.0.0.1:8000";

const SEVERITY_COLORS = {
  CRITICAL: "#EF4444",
  HIGH: "#F97316",
  MEDIUM: "#FBBF24",
  LOW: "#10B981"
};

const COLORS = ["#3B82F6", "#EF4444", "#10B981", "#F59E0B", "#8B5CF6"];

const reasonIcon = (reason) => {
  const r = (reason || "").toLowerCase();
  if (r.includes("port_scan") || r.includes("port-scan")) return { icon: "🔍", label: "Port Scan" };
  if (r.includes("ddos") || r.includes("ddos_suspect") || r.includes("ddos-suspect")) return { icon: "🚀", label: "DDoS Suspect" };
  if (r.includes("exfil") || r.includes("data_exfiltration") || r.includes("data-exfiltration")) return { icon: "📤", label: "Data Exfiltration" };
  if (r.includes("normal")) return { icon: "✔️", label: "Normal" };
  if (r.includes("anomaly")) return { icon: "⚠️", label: "Anomaly" };
  return { icon: "❓", label: reason || "Unknown" };
};

// entropy helper
function entropyFromCounts(counts) {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  let ent = 0;
  for (let c of counts) {
    if (c <= 0) continue;
    const p = c / total;
    ent -= p * Math.log2(p);
  }
  return parseFloat(ent.toFixed(4));
}

export default function App() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [confThresh, setConfThresh] = useState(60);

  const handleUpload = async () => {
    if (!file) {
      alert("Select a PCAP file first.");
      return;
    }
    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/upload_pcap/?conf_thresh=${confThresh}`, {
        method: "POST",
        body: formData
      });
      const json = await res.json();
      if (res.status !== 200) {
        alert(json.error || "Server error");
        console.error(json.traceback);
        setData(null);
        return;
      }
      setData(json);
      setActiveTab("overview");
    } catch (err) {
      alert("Upload failed");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // flows returned by backend — we assume they are Isolation Forest predictions (per spec)
  const flows = data?.flows || [];
  const statisticsFromBackend = data?.statistics || {};
  const patterns = data?.patterns || {};
  const alerts = data?.alerts || [];
  const modelEvals = data?.model_evaluations || {};

  // derived datastructures
  const isolationFlows = flows; // per agreement: flows are from Isolation Forest

  const severityData = useMemo(() => {
    const map = isolationFlows.reduce((acc, f) => {
      const sev = (f.severity || "LOW").toUpperCase();
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [isolationFlows]);

  const protocolData = useMemo(() => {
    const map = isolationFlows.reduce((acc, f) => {
      const p = (f.proto || "UNKNOWN").toUpperCase();
      acc[p] = (acc[p] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  }, [isolationFlows]);

  const topSources = useMemo(() => {
    const map = {};
    isolationFlows.forEach(f => {
      const s = f.src || "unknown";
      map[s] = (map[s] || 0) + (f.pkt_count || 0) || 1;
    });
    return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, packets]) => ({ ip, packets }));
  }, [isolationFlows]);

  const topDestinations = useMemo(() => {
    const map = {};
    isolationFlows.forEach(f => {
      const d = f.dst || "unknown";
      map[d] = (map[d] || 0) + (f.pkt_count || 0) || 1;
    });
    return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, packets]) => ({ ip, packets }));
  }, [isolationFlows]);

  const totalFlows = isolationFlows.length;
  const totalAnomalies = isolationFlows.filter(f => f.is_anomaly).length;
  const anomalyRatio = totalFlows > 0 ? ((totalAnomalies / totalFlows) * 100).toFixed(2) : "0.00";

  // averages and extremes
  const avg_pkt_rate = useMemo(() => {
    const arr = isolationFlows.map(f => f.pkt_rate).filter(v => typeof v === "number");
    if (!arr.length) return 0;
    return parseFloat((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(3));
  }, [isolationFlows]);

  const avg_byte_rate = useMemo(() => {
    const arr = isolationFlows.map(f => f.byte_rate).filter(v => typeof v === "number");
    if (!arr.length) return 0;
    return parseFloat((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(3));
  }, [isolationFlows]);

  const avg_payload = useMemo(() => {
    const arr = isolationFlows.map(f => f.avg_payload_size).filter(v => typeof v === "number");
    if (!arr.length) return 0;
    return parseFloat((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2));
  }, [isolationFlows]);

  const avg_duration = useMemo(() => {
    const arr = isolationFlows.map(f => f.duration).filter(v => typeof v === "number");
    if (!arr.length) return 0;
    return parseFloat((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(3));
  }, [isolationFlows]);

  const total_bytes = useMemo(() => {
    return isolationFlows.reduce((s, f) => s + (f.byte_count || 0), 0);
  }, [isolationFlows]);

  const unique_src_ips = useMemo(() => {
    const set = new Set(isolationFlows.map(f => f.src).filter(Boolean));
    return set.size;
  }, [isolationFlows]);

  const unique_dst_ips = useMemo(() => {
    const set = new Set(isolationFlows.map(f => f.dst).filter(Boolean));
    return set.size;
  }, [isolationFlows]);

  // entropy metrics
  const srcEntropy = useMemo(() => {
    const freq = {};
    isolationFlows.forEach(f => { if (f.src) freq[f.src] = (freq[f.src] || 0) + 1; });
    return entropyFromCounts(Object.values(freq));
  }, [isolationFlows]);

  const dstEntropy = useMemo(() => {
    const freq = {};
    isolationFlows.forEach(f => { if (f.dst) freq[f.dst] = (freq[f.dst] || 0) + 1; });
    return entropyFromCounts(Object.values(freq));
  }, [isolationFlows]);

  // extremes
  const max_pkt_flow = useMemo(() => {
    if (!isolationFlows.length) return null;
    return isolationFlows.reduce((best, f) => (!best || (f.pkt_count || 0) > (best.pkt_count || 0) ? f : best), null);
  }, [isolationFlows]);

  const min_pkt_flow = useMemo(() => {
    if (!isolationFlows.length) return null;
    return isolationFlows.reduce((best, f) => (!best || (f.pkt_count || Infinity) < (best.pkt_count || Infinity) ? f : best), null);
  }, [isolationFlows]);

  const max_byte_flow = useMemo(() => {
    if (!isolationFlows.length) return null;
    return isolationFlows.reduce((best, f) => (!best || (f.byte_count || 0) > (best.byte_count || 0) ? f : best), null);
  }, [isolationFlows]);

  const min_byte_flow = useMemo(() => {
    if (!isolationFlows.length) return null;
    return isolationFlows.reduce((best, f) => (!best || (f.byte_count || Infinity) < (best.byte_count || Infinity) ? f : best), null);
  }, [isolationFlows]);

  // helper to compute Strength per model (same formula)
  const computeStrength = (stats) => {
    const accuracy = stats.pseudo_accuracy_pct ?? 0;
    const precision = stats.pseudo_precision_pct ?? 0;
    const stability = stats.stability_pct ?? 0;
    const time = stats.inference_time_sec ?? 0;
    const maxTime = Math.max(...Object.values(modelEvals || {}).map(m => m.inference_time_sec || 0), 0.000001);
    const timeScaled = maxTime > 0 ? (time / maxTime) * 100 : 0;
    const strength = 0.30 * accuracy + 0.25 * precision + 0.25 * stability - 0.20 * timeScaled;
    return parseFloat(strength.toFixed(2));
  };

  // small utility to format large numbers
  const human = (n) => {
    if (n === null || n === undefined) return "-";
    if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(2) + "K";
    return n;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50">
      {/* Header */}
      <header className="bg-white shadow-md border-b-4 border-blue-600">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-blue-700">🛡️ NetGuard</h1>
            <p className="text-sm text-gray-600">Network Anomaly Detection System — Isolation Forest Overview</p>
          </div>

          {data && (
            <div className="flex gap-6 text-sm">
              <div className="text-center">
                <p className="text-gray-500">Total Flows</p>
                <p className="text-2xl font-bold text-blue-600">{totalFlows}</p>
              </div>
              <div className="text-center">
                <p className="text-gray-500">Anomalies</p>
                <p className="text-2xl font-bold text-red-600">{totalAnomalies}</p>
              </div>
              <div className="text-center">
                <p className="text-gray-500">Anomaly Ratio</p>
                <p className="text-2xl font-bold text-orange-600">{anomalyRatio}%</p>
              </div>
            </div>
          )}
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Upload */}
        <div className="bg-white rounded-2xl shadow-lg p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">📤 Upload PCAP File</h2>
          <div className="flex gap-4 items-center">
            <input type="file" accept=".pcap,.pcapng" onChange={(e) => setFile(e.target.files[0])} className="flex-1 border-2 p-3 rounded-lg" />
            <div>
              <label className="block text-xs text-gray-600">Confidence threshold (%)</label>
              <input type="number" value={confThresh} onChange={(e) => setConfThresh(Number(e.target.value))} className="border px-2 py-1 w-20 rounded" />
            </div>
            <button onClick={handleUpload} disabled={loading} className="bg-blue-600 text-white px-6 py-2 rounded-lg">
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </div>

        {!data && (
          <div className="text-center text-gray-500 py-20">
            <p className="text-xl">Upload a PCAP file to view Isolation Forest overview & statistics.</p>
          </div>
        )}

        {data && (
          <>
            {/* Tabs */}
            <div className="bg-white rounded-t-2xl shadow-lg overflow-hidden mb-6">
              <div className="flex border-b">
                {["overview", "flows", "alerts", "patterns", "statistics", "model-scores"].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 py-3 px-4 font-semibold capitalize relative ${
                      activeTab === tab ? "text-white bg-blue-600" : "text-gray-600 bg-gray-100 hover:bg-gray-200"
                    }`}
                  >
                    {tab.replace("-", " ")}
                    {activeTab === tab && (
                      <span style={{ position: "absolute", left: 0, right: 0, bottom: 0, height: 4, background: "linear-gradient(90deg, #2563EB, #60A5FA)" }} />
                    )}
                  </button>
                ))}
              </div>

              <div className="p-6">
                {/* OVERVIEW (Isolation Forest Only) */}
                {activeTab === "overview" && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-4">Severity Distribution (Isolation Forest)</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <PieChart>
                            <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                              {severityData.map((entry, i) => (
                                <Cell key={i} fill={SEVERITY_COLORS[entry.name] || COLORS[i % COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>

                      <div className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-4">Protocol Distribution (Isolation Forest)</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <BarChart data={protocolData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="value" fill="#3B82F6" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    <div className="bg-gray-50 p-6 rounded-xl">
                      <h3 className="text-lg font-semibold mb-4">Top 5 Source IPs (Isolation Forest)</h3>
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={topSources} layout="vertical">
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" />
                          <YAxis type="category" dataKey="ip" width={140} />
                          <Tooltip />
                          <Bar dataKey="packets" fill="#10B981" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}

                {/* FLOWS */}
                {activeTab === "flows" && (
                  <div className="overflow-x-auto">
                    <table className="min-w-full">
                      <thead className="bg-gray-100">
                        <tr>
                          <th className="p-3 text-left">Source</th>
                          <th className="p-3 text-left">Destination</th>
                          <th className="p-3 text-center">Protocol</th>
                          <th className="p-3 text-center">Packets</th>
                          <th className="p-3 text-center">Bytes</th>
                          <th className="p-3 text-center">Severity</th>
                          <th className="p-3 text-center">Reason</th>
                          <th className="p-3 text-center">Confidence</th>
                          <th className="p-3 text-center">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {isolationFlows.slice(0, 200).map((f, i) => {
                          const r = reasonIcon(f.reason);
                          const sev = (f.severity || "LOW").toUpperCase();
                          return (
                            <tr key={i} className="border-t hover:bg-gray-50">
                              <td className="p-3 font-mono">{f.src}</td>
                              <td className="p-3 font-mono">{f.dst}</td>
                              <td className="p-3 text-center">{f.proto}</td>
                              <td className="p-3 text-center">{f.pkt_count}</td>
                              <td className="p-3 text-center">{f.byte_count}</td>
                              <td className="p-3 text-center">
                                <span className="px-2 py-1 rounded text-xs font-semibold text-white" style={{ backgroundColor: SEVERITY_COLORS[sev] || "#6B7280" }}>
                                  {sev}
                                </span>
                              </td>
                              <td className="p-3 text-center">
                                <div className="inline-flex items-center gap-2">
                                  <span>{r.icon}</span>
                                  <span className="text-sm text-gray-700">{r.label}</span>
                                </div>
                              </td>
                              <td className="p-3 text-center">{(f.confidence || 0).toFixed(2)}%</td>
                              <td className="p-3 text-center">
                                {f.is_anomaly ? (
                                  <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs">Anomaly</span>
                                ) : (
                                  <span className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs">Normal</span>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {isolationFlows.length > 200 && <p className="text-sm text-gray-500 mt-3 text-center">Showing first 200 flows of {isolationFlows.length}</p>}
                  </div>
                )}

                {/* ALERTS */}
                {activeTab === "alerts" && (
                  <div>
                    {alerts.length === 0 ? <p className="text-gray-500">No alerts</p> :
                      alerts.map((a, i) => (
                        <div key={i} className="border-l-4 p-4 rounded mb-3" style={{ borderColor: SEVERITY_COLORS[a.severity] }}>
                          <div className="flex justify-between">
                            <div>
                              <p className="font-semibold">{a.description}</p>
                              <p className="text-xs text-gray-500">{new Date(a.timestamp).toLocaleString()}</p>
                            </div>
                            <div className="text-right">
                              <p className="text-2xl font-bold text-red-600">{a.threat_score}</p>
                              <p className="text-xs text-gray-500">Threat</p>
                            </div>
                          </div>
                        </div>
                      ))
                    }
                  </div>
                )}

                {/* PATTERNS */}
                {activeTab === "patterns" && (
                  <div>
                    <pre className="bg-gray-100 p-4 rounded text-xs">{JSON.stringify(patterns, null, 2)}</pre>
                  </div>
                )}

                {/* STATISTICS (S-B Dashboard, Isolation Forest only) */}
                {activeTab === "statistics" && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Total Flows</p>
                        <p className="text-2xl font-bold">{totalFlows}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Total Anomalies</p>
                        <p className="text-2xl font-bold text-red-600">{totalAnomalies}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Anomaly Ratio</p>
                        <p className="text-2xl font-bold">{anomalyRatio}%</p>
                      </div>

                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Total Bytes</p>
                        <p className="text-2xl font-bold">{human(total_bytes)}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Avg Packet Rate</p>
                        <p className="text-2xl font-bold">{avg_pkt_rate}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Avg Byte Rate</p>
                        <p className="text-2xl font-bold">{avg_byte_rate}</p>
                      </div>

                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Avg Payload Size</p>
                        <p className="text-2xl font-bold">{avg_payload}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Avg Flow Duration (s)</p>
                        <p className="text-2xl font-bold">{avg_duration}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Unique Source IPs</p>
                        <p className="text-2xl font-bold">{unique_src_ips}</p>
                      </div>

                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Unique Destination IPs</p>
                        <p className="text-2xl font-bold">{unique_dst_ips}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Source IP Entropy</p>
                        <p className="text-2xl font-bold">{srcEntropy}</p>
                      </div>
                      <div className="bg-white p-4 rounded shadow">
                        <p className="text-sm text-gray-500">Destination IP Entropy</p>
                        <p className="text-2xl font-bold">{dstEntropy}</p>
                      </div>
                    </div>

                    {/* Protocol distribution + Top talkers */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-white p-4 rounded shadow">
                        <h4 className="font-semibold mb-3">Protocol Distribution</h4>
                        <ResponsiveContainer width="100%" height={220}>
                          <BarChart data={protocolData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="value" fill="#3B82F6" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>

                      <div className="bg-white p-4 rounded shadow">
                        <h4 className="font-semibold mb-3">Top Talkers (Sources)</h4>
                        <ResponsiveContainer width="100%" height={220}>
                          <BarChart data={topSources} layout="vertical">
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis type="number" />
                            <YAxis dataKey="ip" type="category" width={160} />
                            <Tooltip />
                            <Bar dataKey="packets" fill="#10B981" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* Extremes */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-white p-4 rounded shadow">
                        <h4 className="font-semibold mb-2">Max Packet Flow</h4>
                        {max_pkt_flow ? (
                          <div className="text-sm">
                            <p><b>Src:</b> {max_pkt_flow.src} → <b>Dst:</b> {max_pkt_flow.dst}</p>
                            <p><b>Packets:</b> {max_pkt_flow.pkt_count}</p>
                            <p><b>Bytes:</b> {max_pkt_flow.byte_count}</p>
                          </div>
                        ) : <p className="text-sm text-gray-500">N/A</p>}
                      </div>

                      <div className="bg-white p-4 rounded shadow">
                        <h4 className="font-semibold mb-2">Max Byte Flow</h4>
                        {max_byte_flow ? (
                          <div className="text-sm">
                            <p><b>Src:</b> {max_byte_flow.src} → <b>Dst:</b> {max_byte_flow.dst}</p>
                            <p><b>Bytes:</b> {max_byte_flow.byte_count}</p>
                            <p><b>Packets:</b> {max_byte_flow.pkt_count}</p>
                          </div>
                        ) : <p className="text-sm text-gray-500">N/A</p>}
                      </div>
                    </div>

                  </div>
                )}

                {/* MODEL SCORES */}
                {activeTab === "model-scores" && (
                  <div>
                    <h3 className="text-lg font-semibold mb-4">Model Scores (on uploaded file)</h3>
                    <div className="overflow-x-auto bg-gray-50 p-4 rounded">
                      <table className="min-w-full text-sm">
                        <thead className="bg-white border-b">
                          <tr>
                            <th className="p-2 text-left">Model</th>
                            <th className="p-2 text-right">Inference Time (s)</th>
                            <th className="p-2 text-right">Anomalies</th>
                            <th className="p-2 text-right">Accuracy (%)</th>
                            <th className="p-2 text-right">Precision (%)</th>
                            <th className="p-2 text-right">Stability (%)</th>
                            <th className="p-2 text-right font-semibold text-blue-700">Strength Score</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(modelEvals).map(([name, stats]) => {
                            const strength = computeStrength(stats);
                            return (
                              <tr key={name} className="border-t hover:bg-gray-100">
                                <td className="p-2 font-mono capitalize">{name.replace(/_/g, " ")}</td>
                                <td className="p-2 text-right">{(stats.inference_time_sec || 0).toFixed(6)}</td>
                                <td className="p-2 text-right">{stats.anomalies_detected ?? "-"}</td>
                                <td className="p-2 text-right">{stats.pseudo_accuracy_pct ?? "-"}</td>
                                <td className="p-2 text-right">{stats.pseudo_precision_pct ?? "-"}</td>
                                <td className="p-2 text-right">{stats.stability_pct ?? "-"}</td>
                                <td className="p-2 text-right font-bold text-blue-700">{strength.toFixed(2)}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
