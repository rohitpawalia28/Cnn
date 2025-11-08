import React, { useState } from "react";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

export default function App() {
  const [file, setFile] = useState(null);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!file) return alert("Please select a .pcap file first!");

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      const res = await axios.post("http://127.0.0.1:8000/upload_pcap/", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setFlows(res.data.flows);
    } catch (err) {
      alert("Error uploading file!");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const anomalies = flows.filter((f) => f.is_anomaly);
  const normal = flows.length - anomalies.length;

  return (
    <div className="min-h-screen flex flex-col items-center p-6">
      <h1 className="text-3xl font-bold mb-6 text-blue-700">Network Anomaly Detection Dashboard</h1>

      <form onSubmit={handleUpload} className="flex flex-col items-center space-y-4 bg-white p-6 rounded-2xl shadow-md w-full max-w-lg">
        <input
          type="file"
          accept=".pcap"
          onChange={(e) => setFile(e.target.files[0])}
          className="border border-gray-300 rounded-md p-2 w-full"
        />
        <button
          type="submit"
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition"
        >
          {loading ? "Analyzing..." : "Upload & Analyze"}
        </button>
      </form>

      {flows.length > 0 && (
        <div className="w-full max-w-5xl mt-10 space-y-8">
          <div className="flex justify-between items-center">
            <p className="text-lg">📊 Total Flows: <b>{flows.length}</b></p>
            <p className="text-green-700">✅ Normal: {normal}</p>
            <p className="text-red-600">⚠️ Anomalies: {anomalies.length}</p>
          </div>

          {/* Chart */}
          <div className="bg-white p-6 rounded-2xl shadow-md">
            <h2 className="text-xl font-semibold mb-4">Anomaly Overview</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={[{ name: "Normal", count: normal }, { name: "Anomalies", count: anomalies.length }]}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3B82F6" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Table */}
          <div className="bg-white p-6 rounded-2xl shadow-md overflow-x-auto">
            <h2 className="text-xl font-semibold mb-4">Flow Details</h2>
            <table className="min-w-full border border-gray-200">
              <thead className="bg-gray-100">
                <tr>
                  <th className="p-2 text-left">Source</th>
                  <th className="p-2 text-left">Destination</th>
                  <th className="p-2">Packets</th>
                  <th className="p-2">Bytes</th>
                  <th className="p-2">Protocol</th>
                  <th className="p-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {flows.slice(0, 50).map((f, i) => (
                  <tr key={i} className="border-t hover:bg-gray-50">
                    <td className="p-2">{f.src}</td>
                    <td className="p-2">{f.dst}</td>
                    <td className="p-2 text-center">{f.pkt_count}</td>
                    <td className="p-2 text-center">{f.byte_count}</td>
                    <td className="p-2 text-center">{f.proto}</td>
                    <td className={`p-2 text-center font-semibold ${f.is_anomaly ? "text-red-600" : "text-green-600"}`}>
                      {f.is_anomaly ? "Anomaly" : "Normal"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {flows.length > 50 && <p className="text-sm text-gray-500 mt-2">Showing first 50 flows only...</p>}
          </div>
        </div>
      )}
    </div>
  );
}
