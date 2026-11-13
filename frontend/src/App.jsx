import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  ShieldAlert,
  Activity,
  Cpu,
  Network,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  X,
  Clock
} from 'lucide-react';

export default function App() {
  const [connected, setConnected] = useState(false);
  const [stats, setStats] = useState({
    total_packets: 0,
    total_flows: 0,
    normal_flows: 0,
    known_attacks: 0,
    unknown_anomalies: 0,
    uptime_seconds: 0
  });
  const [flows, setFlows] = useState([]);
  const [selectedFlow, setSelectedFlow] = useState(null);
  const wsRef = useRef(null);
  const epochRef = useRef(0);

  useEffect(() => {
    const connectWS = () => {
      const ws = new WebSocket('ws://localhost:8000/ws/live');
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connectWS, 2000);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'INITIAL_STATE') {
          // Adopt the server's epoch on (re)connect
          epochRef.current = data.epoch ?? 0;
          setStats(data.stats);
          setFlows((data.flows || []).slice(0, 20));
        } else if (data.type === 'RESET') {
          // Server-authoritative reset: clear everything and adopt new epoch
          epochRef.current = data.epoch;
          setFlows([]);
          setSelectedFlow(null);
          setStats(data.stats);
        } else if (data.type === 'FLOW_ANALYZED') {
          // Discard stale messages from before the most recent reset
          if (data.epoch !== undefined && data.epoch < epochRef.current) {
            return;
          }
          setStats(data.stats);
          const newFlow = data.flow;
          setFlows((prev) => [newFlow, ...prev.slice(0, 19)]);
        }
      };
    };

    connectWS();
    return () => wsRef.current?.close();
  }, []);

  const handleReset = async () => {
    // Optimistically clear UI immediately for responsive feel.
    // The server will also broadcast a RESET WebSocket event which
    // authoritatively sets the epoch and clears state for ALL clients.
    setFlows([]);
    setSelectedFlow(null);
    setStats({
      total_packets: 0,
      total_flows: 0,
      normal_flows: 0,
      known_attacks: 0,
      unknown_anomalies: 0,
      uptime_seconds: 0
    });

    try {
      const res = await fetch('http://localhost:8000/api/reset', { method: 'POST' });
      const body = await res.json();
      // Adopt the epoch from the HTTP response as a fallback in case
      // the WebSocket RESET message hasn't arrived yet.
      if (body.epoch !== undefined) {
        epochRef.current = body.epoch;
      }
    } catch (err) {
      console.error('Reset request failed:', err);
    }
  };
  const formatTime = (ts) => {
    if (!ts) return '--:--:--';
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const getVerdictBadge = (outcome) => {
    if (outcome === 'KNOWN_ATTACK') {
      return {
        text: 'KNOWN ATTACK',
        style: 'bg-rose-500/15 text-rose-400 border-rose-500/30'
      };
    }
    if (outcome === 'SUSPICIOUS_UNKNOWN') {
      return {
        text: 'UNKNOWN ANOMALY',
        style: 'bg-amber-500/15 text-amber-400 border-amber-500/30'
      };
    }
    return {
      text: 'NORMAL',
      style: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
    };
  };

  const getGuessText = (flow) => {
    if (flow.outcome === 'KNOWN_ATTACK') {
      return `${flow.label} (${Math.round(flow.rf_confidence * 100)}%)`;
    }
    if (flow.outcome === 'SUSPICIOUS_UNKNOWN') {
      return flow.cluster_id !== null && flow.cluster_id !== -1
        ? `Zero-Day · Cluster #${flow.cluster_id}`
        : 'Unseen Pattern';
    }
    return `Benign (${Math.round(flow.rf_confidence * 100)}%)`;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <header className="max-w-6xl mx-auto flex flex-wrap justify-between items-center gap-4 pb-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-indigo-500/10 border border-indigo-500/30 rounded-xl">
            <Shield className="w-7 h-7 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white">
              ZeroDay IDS — Live Threat Monitor
            </h1>
            <p className="text-xs text-slate-400">
              Click any traffic row below to inspect why it was classified as Normal, Known, or Unknown
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border ${connected
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}
          >
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
            {connected ? 'Sensor Active' : 'Reconnecting...'}
          </span>

          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium transition cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reset
          </button>
        </div>
      </header>

      <section className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-5 gap-4 my-6">
        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Packets Sniffed</span>
            <Activity className="w-4 h-4 text-sky-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.total_packets.toLocaleString()}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Analyzed Flows</span>
            <Network className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">{stats.total_flows.toLocaleString()}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Normal</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{stats.normal_flows.toLocaleString()}</div>
        </div>

        <div className="bg-slate-900/80 border border-rose-900/40 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Known Attacks</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{stats.known_attacks.toLocaleString()}</div>
        </div>

        <div className="bg-slate-900/80 border border-amber-900/40 p-4 rounded-xl">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Unknown Anomalies</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{stats.unknown_anomalies.toLocaleString()}</div>
        </div>
      </section>

      <main className="max-w-6xl mx-auto bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
            Recent Network Traffic (Latest 20 Flows)
          </h2>
          <span className="text-xs text-slate-500">
            Showing {Math.min(flows.length, 20)} of 20 max rows
          </span>
        </div>

        <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800 sticky top-0 z-10">
              <tr>
                <th className="py-3.5 px-6">Time</th>
                <th className="py-3.5 px-6">Source → Dest</th>
                <th className="py-3.5 px-6">Protocol</th>
                <th className="py-3.5 px-6">Guess</th>
                <th className="py-3.5 px-6">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {flows.slice(0, 20).map((f) => {
                const badge = getVerdictBadge(f.outcome);
                const isSelected = selectedFlow?.id === f.id;
                return (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFlow(f)}
                    className={`transition cursor-pointer ${
                      isSelected ? 'bg-indigo-950/40' : 'hover:bg-slate-800/50'
                    }`}
                  >
                    <td className="py-2 px-6 font-mono text-xs text-slate-400 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {formatTime(f.timestamp)}
                      </span>
                    </td>
                    <td className="py-2 px-6 font-mono text-xs text-slate-200">
                      {f.src_ip} → {f.dst_ip}:{f.dst_port}
                    </td>
                    <td className="py-2 px-6 text-xs text-slate-300 font-medium">
                      {f.protocol}
                    </td>
                    <td className="py-2 px-6 text-xs text-slate-300">
                      {getGuessText(f)}
                    </td>
                    <td className="py-2 px-6">
                      <span className={`px-2 py-0.5 rounded-md text-xs font-semibold border ${badge.style}`}>
                        {badge.text}
                      </span>
                    </td>
                  </tr>
                );
              })}

              {flows.length === 0 && (
                <tr>
                  <td colSpan="5" className="py-12 text-center text-slate-500 text-sm">
                    Waiting for live network flows... Browse or test the target website to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </main>

      {selectedFlow && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50"
          onClick={() => setSelectedFlow(null)}
        >
          <div
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-start border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2.5 mb-1">
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-bold border ${getVerdictBadge(selectedFlow.outcome).style
                      }`}
                  >
                    {getVerdictBadge(selectedFlow.outcome).text}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {formatTime(selectedFlow.timestamp)}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white font-mono mt-1">
                  {selectedFlow.src_ip} → {selectedFlow.dst_ip}:{selectedFlow.dst_port} ({selectedFlow.protocol})
                </h3>
              </div>

              <button
                onClick={() => setSelectedFlow(null)}
                className="p-1.5 text-slate-400 hover:text-white bg-slate-800 rounded-lg cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-400 uppercase">
                <Cpu className="w-4 h-4" />
                Why It Was Flagged ({selectedFlow.explanation?.method})
              </div>
              <p className="text-sm text-slate-200 leading-relaxed">
                {selectedFlow.explanation?.summary}
              </p>
            </div>

            <div className="grid grid-cols-3 gap-3 text-xs">
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 block mb-0.5">Autoencoder Error</span>
                <span className="font-mono font-bold text-slate-100">
                  {selectedFlow.ae_score?.toFixed(5)}
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 block mb-0.5">RF Classifier</span>
                <span className="font-bold text-slate-100">
                  {selectedFlow.rf_prediction} ({Math.round(selectedFlow.rf_confidence * 100)}%)
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 block mb-0.5">10s Window</span>
                <span className="font-bold text-slate-100">
                  {selectedFlow.behavioral?.connection_count ?? 1} conns · {selectedFlow.behavioral?.unique_destination_ports ?? 1} ports
                </span>
              </div>
            </div>

            {selectedFlow.explanation?.top_features?.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-semibold text-slate-400 uppercase">
                  Top Contributing Features
                </div>
                <div className="space-y-1.5">
                  {selectedFlow.explanation.top_features.map((feat, idx) => (
                    <div
                      key={idx}
                      className="flex justify-between items-center bg-slate-950 px-3 py-2 rounded-lg border border-slate-800/80 text-xs"
                    >
                      <span className="text-slate-200 font-medium">{feat.feature}</span>
                      <span className="font-mono text-indigo-400">{feat.contribution}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}