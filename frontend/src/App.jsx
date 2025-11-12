import React, { useState } from "react";
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

export default function App() {
  const [file, setFile] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) {
      alert("Please select a .pcap file first!");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/upload_pcap/`, {
        method: "POST",
        body: formData,
      });
      const responseData = await res.json();
      setData(responseData);
    } catch (err) {
      alert("Error uploading file!");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const flows = data?.flows || [];
  const statistics = data?.statistics || {};
  const patterns = data?.patterns || {};
  const alerts = data?.alerts || [];
  const anomalies = flows.filter((f) => f.is_anomaly);

  // Prepare chart data
  const severityData = Object.entries(
    flows.reduce((acc, f) => {
      const sev = f.severity || "UNKNOWN";
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  const protocolData = Object.entries(statistics.protocol_distribution || {}).map(
    ([name, value]) => ({ name, value })
  );

  const topSources = Object.entries(statistics.top_sources || {})
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, packets: count }));

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-blue-50">
      {/* Header */}
      <header className="bg-white shadow-md border-b-4 border-blue-600">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-blue-700">🛡️ NetGuard</h1>
            <p className="text-sm text-gray-600">Network Anomaly Detection System</p>
          </div>
          {data && (
            <div className="flex gap-6 text-sm">
              <div className="text-center">
                <p className="text-gray-500">Total Flows</p>
                <p className="text-2xl font-bold text-blue-600">{flows.length}</p>
              </div>
              <div className="text-center">
                <p className="text-gray-500">Anomalies</p>
                <p className="text-2xl font-bold text-red-600">{anomalies.length}</p>
              </div>
              <div className="text-center">
                <p className="text-gray-500">Alerts</p>
                <p className="text-2xl font-bold text-orange-600">{alerts.length}</p>
              </div>
            </div>
          )}
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Upload Section */}
        <div className="bg-white rounded-2xl shadow-lg p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">📤 Upload PCAP File</h2>
          <div className="flex gap-4 items-center">
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setFile(e.target.files[0])}
              className="flex-1 border-2 border-gray-300 rounded-lg p-3 focus:border-blue-500 focus:outline-none"
            />
            <button
              onClick={handleUpload}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-lg font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </div>
        </div>

        {/* Main Content */}
        {data && (
          <>
            {/* Tabs */}
            <div className="bg-white rounded-t-2xl shadow-lg overflow-hidden">
              <div className="flex border-b">
                {["overview", "flows", "alerts", "patterns", "statistics"].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 py-3 px-4 font-semibold capitalize transition ${
                      activeTab === tab
                        ? "bg-blue-600 text-white"
                        : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              <div className="p-6">
                {/* Overview Tab */}
                {activeTab === "overview" && (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {/* Severity Distribution */}
                      <div className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
                        <ResponsiveContainer width="100%" height={250}>
                          <PieChart>
                            <Pie
                              data={severityData}
                              dataKey="value"
                              nameKey="name"
                              cx="50%"
                              cy="50%"
                              outerRadius={80}
                              label
                            >
                              {severityData.map((entry, i) => (
                                <Cell key={i} fill={SEVERITY_COLORS[entry.name] || COLORS[i]} />
                              ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>

                      {/* Protocol Distribution */}
                      <div className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-4">Protocol Distribution</h3>
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

                    {/* Top Sources */}
                    {topSources.length > 0 && (
                      <div className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-4">Top 5 Source IPs</h3>
                        <ResponsiveContainer width="100%" height={200}>
                          <BarChart data={topSources} layout="vertical">
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis type="number" />
                            <YAxis dataKey="ip" type="category" width={120} />
                            <Tooltip />
                            <Bar dataKey="packets" fill="#10B981" />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    )}
                  </div>
                )}

                {/* Flows Tab */}
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
                          <th className="p-3 text-center">Duration</th>
                          <th className="p-3 text-center">Severity</th>
                          <th className="p-3 text-center">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {flows.slice(0, 100).map((f, i) => (
                          <tr key={i} className="border-t hover:bg-gray-50">
                            <td className="p-3 text-sm font-mono">{f.src}</td>
                            <td className="p-3 text-sm font-mono">{f.dst}</td>
                            <td className="p-3 text-center text-sm">{f.proto}</td>
                            <td className="p-3 text-center">{f.pkt_count}</td>
                            <td className="p-3 text-center">{f.byte_count?.toLocaleString()}</td>
                            <td className="p-3 text-center">{f.duration}s</td>
                            <td className="p-3 text-center">
                              <span
                                className="px-2 py-1 rounded text-xs font-semibold text-white"
                                style={{ backgroundColor: SEVERITY_COLORS[f.severity] || "#6B7280" }}
                              >
                                {f.severity || "N/A"}
                              </span>
                            </td>
                            <td className="p-3 text-center">
                              <span
                                className={`px-2 py-1 rounded text-xs font-semibold ${
                                  f.is_anomaly
                                    ? "bg-red-100 text-red-700"
                                    : "bg-green-100 text-green-700"
                                }`}
                              >
                                {f.is_anomaly ? "Anomaly" : "Normal"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {flows.length > 100 && (
                      <p className="text-sm text-gray-500 mt-4 text-center">
                        Showing first 100 flows of {flows.length}
                      </p>
                    )}
                  </div>
                )}

                {/* Alerts Tab */}
                {activeTab === "alerts" && (
                  <div className="space-y-4">
                    {alerts.length === 0 ? (
                      <p className="text-center text-gray-500 py-8">No alerts generated</p>
                    ) : (
                      alerts.map((alert, i) => (
                        <div
                          key={i}
                          className="border-l-4 p-4 rounded-lg bg-gray-50"
                          style={{ borderColor: SEVERITY_COLORS[alert.severity] }}
                        >
                          <div className="flex justify-between items-start">
                            <div>
                              <div className="flex items-center gap-2 mb-2">
                                <span
                                  className="px-3 py-1 rounded text-sm font-semibold text-white"
                                  style={{ backgroundColor: SEVERITY_COLORS[alert.severity] }}
                                >
                                  {alert.severity}
                                </span>
                                <span className="text-sm text-gray-500">
                                  {new Date(alert.timestamp).toLocaleString()}
                                </span>
                              </div>
                              <p className="font-semibold text-gray-800">{alert.description}</p>
                              <div className="mt-2 text-sm text-gray-600 space-y-1">
                                <p>
                                  <span className="font-medium">Source:</span> {alert.source_ip}
                                </p>
                                <p>
                                  <span className="font-medium">Destination:</span>{" "}
                                  {alert.destination_ip}
                                </p>
                                <p>
                                  <span className="font-medium">Protocol:</span> {alert.protocol}
                                </p>
                              </div>
                            </div>
                            <div className="text-right">
                              <p className="text-2xl font-bold text-red-600">
                                {alert.threat_score}
                              </p>
                              <p className="text-xs text-gray-500">Threat Score</p>
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Patterns Tab */}
                {activeTab === "patterns" && (
                  <div className="space-y-6">
                    {Object.entries(patterns).map(([type, items]) => (
                      <div key={type} className="bg-gray-50 p-6 rounded-xl">
                        <h3 className="text-lg font-semibold mb-3 capitalize">
                          {type.replace("_", " ")} ({items.length})
                        </h3>
                        {items.length === 0 ? (
                          <p className="text-gray-500">No patterns detected</p>
                        ) : (
                          <div className="space-y-2">
                            {items.slice(0, 5).map((item, i) => (
                              <div
                                key={i}
                                className="bg-white p-3 rounded border border-gray-200 text-sm"
                              >
                                <pre className="text-xs overflow-x-auto">
                                  {JSON.stringify(item, null, 2)}
                                </pre>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Statistics Tab */}
                {activeTab === "statistics" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {Object.entries(statistics).map(([key, value]) => {
                      if (typeof value === "object") return null;
                      return (
                        <div key={key} className="bg-gray-50 p-4 rounded-lg">
                          <p className="text-sm text-gray-600 capitalize">
                            {key.replace(/_/g, " ")}
                          </p>
                          <p className="text-2xl font-bold text-blue-600">
                            {typeof value === "number" ? value.toLocaleString() : value}
                          </p>
                        </div>
                      );
                    })}
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