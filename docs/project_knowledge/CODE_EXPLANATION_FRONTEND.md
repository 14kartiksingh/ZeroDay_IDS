# ZeroDay IDS — Detailed Line-by-Line Code Explanation: Frontend Subsystems

This document provides a line-by-line technical explanation of all frontend source files in `ZeroDay_IDS`, detailing React hooks, reactive state flow, WebSocket message parsing, epoch guard logic, UI layout, and styling.

---

# Part 1: Primary React Dashboard (`frontend/src/App.jsx`)

### Lines 1–14: Imports & Lucide Icons
```javascript
1: import React, { useState, useEffect, useRef } from 'react';
2: import {
3:   Shield,
4:   ShieldAlert,
5:   Activity,
6:   Cpu,
7:   Network,
8:   RefreshCw,
9:   AlertTriangle,
10:   CheckCircle2,
11:   X,
12:   Clock
13: } from 'lucide-react';
```
- **Line 1**: Imports core React hooks: `useState` for reactive UI state, `useEffect` for lifecycle management, and `useRef` for mutable references across renders.
- **Lines 2–13**: Imports SVG icons from `lucide-react`: `Shield` (branding), `ShieldAlert` (known attacks), `Activity` (packets), `Cpu` (XAI engine), `Network` (analyzed flows), `RefreshCw` (reset button), `AlertTriangle` (anomalies), `CheckCircle2` (normal), `X` (close modal), and `Clock` (timestamps).

---

### Lines 15–29: State Variables & Mutable Refs
```javascript
15: export default function App() {
16:   const [connected, setConnected] = useState(false);
17:   const [stats, setStats] = useState({
18:     total_packets: 0,
19:     total_flows: 0,
20:     normal_flows: 0,
21:     known_attacks: 0,
22:     unknown_anomalies: 0,
23:     uptime_seconds: 0
24:   });
25:   const [flows, setFlows] = useState([]);
26:   const [selectedFlow, setSelectedFlow] = useState(null);
27:   const wsRef = useRef(null);
28:   const epochRef = useRef(0);
```
- **Line 16**: `connected`: Boolean driving connection badge ("Sensor Active" vs "Reconnecting...").
- **Lines 17–24**: `stats`: Object mirroring backend pipeline metrics.
- **Line 25**: `flows`: Array storing up to 20 flow records for the traffic table.
- **Line 26**: `selectedFlow`: Stores currently inspected flow for modal rendering (`null` when closed).
- **Line 27**: `wsRef`: Retains the active `WebSocket` instance across render cycles without re-triggering effects.
- **Line 28**: `epochRef`: Stores the active reset epoch generation counter. Crucial: `useRef` updates synchronously without causing re-renders, enabling immediate filtering in WebSocket callbacks.

---

### Lines 30–69: WebSocket Lifecycle & Event Handling (`useEffect`)
```javascript
30:   useEffect(() => {
31:     const connectWS = () => {
32:       const ws = new WebSocket('ws://localhost:8000/ws/live');
33:       wsRef.current = ws;
34: 
35:       ws.onopen = () => setConnected(true);
36:       ws.onclose = () => {
37:         setConnected(false);
38:         setTimeout(connectWS, 2000);
39:       };
40: 
41:       ws.onmessage = (event) => {
42:         const data = JSON.parse(event.data);
43: 
44:         if (data.type === 'INITIAL_STATE') {
45:           // Adopt the server's epoch on (re)connect
46:           epochRef.current = data.epoch ?? 0;
47:           setStats(data.stats);
48:           setFlows((data.flows || []).slice(0, 20));
49:         } else if (data.type === 'RESET') {
50:           // Server-authoritative reset: clear everything and adopt new epoch
51:           epochRef.current = data.epoch;
52:           setFlows([]);
53:           setSelectedFlow(null);
54:           setStats(data.stats);
55:         } else if (data.type === 'FLOW_ANALYZED') {
56:           // Discard stale messages from before the most recent reset
57:           if (data.epoch !== undefined && data.epoch < epochRef.current) {
58:             return;
59:           }
60:           setStats(data.stats);
61:           const newFlow = data.flow;
62:           setFlows((prev) => [newFlow, ...prev.slice(0, 19)]);
63:         }
64:       };
65:     };
66: 
67:     connectWS();
68:     return () => wsRef.current?.close();
69:   }, []);
```
- **Line 30**: Runs on mount (`[]`).
- **Lines 31–39**: Opens connection to `ws://localhost:8000/ws/live`. If closed, sets `connected = false` and retries after 2000 ms.
- **Lines 44–48 (`INITIAL_STATE`)**: Adopts the server's epoch and populates initial stats and flows.
- **Lines 49–54 (`RESET`)**: Server-authoritative reset. Synchronizes `epochRef.current = data.epoch`, clears flows (`setFlows([])`), closes modal (`setSelectedFlow(null)`), and zeroes stats.
- **Lines 55–63 (`FLOW_ANALYZED`)**:
  - **Line 57**: The Epoch Guard: `if (data.epoch !== undefined && data.epoch < epochRef.current) return;`. Stale pre-reset messages in flight are discarded.
  - **Lines 60–62**: Updates stats and prepends new flow: `[newFlow, ...prev.slice(0, 19)]`, maintaining 20 rows.
- **Line 68**: Cleanup function closes WebSocket on unmount.

---

### Lines 71–97: Thread-Safe Reset Action (`handleReset`)
```javascript
71:   const handleReset = async () => {
72:     // Optimistically clear UI immediately for responsive feel.
73:     setFlows([]);
74:     setSelectedFlow(null);
75:     setStats({
76:       total_packets: 0,
77:       total_flows: 0,
78:       normal_flows: 0,
79:       known_attacks: 0,
80:       unknown_anomalies: 0,
81:       uptime_seconds: 0
82:     });
83: 
84:     try {
85:       const res = await fetch('http://localhost:8000/api/reset', { method: 'POST' });
86:       const body = await res.json();
87:       // Adopt the epoch from the HTTP response as a fallback
88:       if (body.epoch !== undefined) {
89:         epochRef.current = body.epoch;
90:       }
91:     } catch (err) {
92:       console.error('Reset request failed:', err);
93:     }
94:   };
```
- **Lines 73–82**: Immediately clears UI state optimistically for instant responsiveness.
- **Line 85**: Sends `POST /api/reset` to the backend.
- **Lines 86–90**: Reads new epoch from HTTP response body. If the WebSocket `RESET` event is slightly delayed, `epochRef.current` is updated here immediately, ensuring zero-gap filtering.

---

### Lines 98–134: Formatting & Helper Functions
```javascript
98:   const formatTime = (ts) => {
99:     if (!ts) return '--:--:--';
100:     const d = new Date(ts * 1000);
101:     return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
102:   };
```
- **Lines 98–102**: Formats Unix timestamp (seconds) into local `HH:MM:SS`.
```javascript
104:   const getVerdictBadge = (outcome) => {
105:     if (outcome === 'KNOWN_ATTACK') {
106:       return {
107:         text: 'KNOWN ATTACK',
108:         style: 'bg-rose-500/15 text-rose-400 border-rose-500/30'
109:       };
110:     }
111:     if (outcome === 'SUSPICIOUS_UNKNOWN') {
112:       return {
113:         text: 'UNKNOWN ANOMALY',
114:         style: 'bg-amber-500/15 text-amber-400 border-amber-500/30'
115:       };
116:     }
117:     return {
118:       text: 'NORMAL',
119:       style: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
120:     };
121:   };
```
- **Lines 104–121**: Maps outcome strings to badge text and Tailwind color schemes (Rose for attacks, Amber for anomalies, Emerald for normal).
```javascript
123:   const getGuessText = (flow) => {
124:     if (flow.outcome === 'KNOWN_ATTACK') {
125:       return `${flow.label} (${Math.round(flow.rf_confidence * 100)}%)`;
126:     }
127:     if (flow.outcome === 'SUSPICIOUS_UNKNOWN') {
128:       return flow.cluster_id !== null && flow.cluster_id !== -1
129:         ? `Zero-Day · Cluster #${flow.cluster_id}`
130:         : 'Unseen Pattern';
131:     }
132:     return `Benign (${Math.round(flow.rf_confidence * 100)}%)`;
133:   };
```
- **Lines 123–133**: Generates context-aware classification summary in the table. Displays cluster assignment if known anomaly is grouped by DBSCAN.

---

### Lines 136–193: Header Bar & Five-Card Metric Strip
```jsx
136:   return (
137:     <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
138:       <header className="max-w-6xl mx-auto flex flex-wrap justify-between items-center gap-4 pb-6 border-b border-slate-800">
...
139:         <div className="flex items-center gap-3">
140:           <Shield className="w-7 h-7 text-indigo-400" />
141:           <h1 className="text-xl font-bold tracking-tight text-white">ZeroDay IDS — Live Threat Monitor</h1>
...
143:         <div className="flex items-center gap-3">
144:           <span className={...}>
145:             <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
146:             {connected ? 'Sensor Active' : 'Reconnecting...'}
147:           </span>
148:           <button onClick={handleReset} className="... cursor-pointer">
149:             <RefreshCw className="w-3.5 h-3.5" />
150:             Reset
151:           </button>
...
153:       <section className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-5 gap-4 my-6">
154:         {/* Packets Sniffed, Analyzed Flows, Normal, Known Attacks, Unknown Anomalies */}
```
- **Lines 136–151**: Renders header with brand icon, dynamic connection status indicator with CSS pulse animation, and Reset button.
- **Lines 153–193**: Renders the 5 KPI metric cards in a responsive grid.

---

### Lines 195–262: Recent Network Traffic Table & Empty State
```jsx
195:       <main className="max-w-6xl mx-auto bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
...
205:         <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
206:           <table className="w-full text-left text-sm">
207:             <thead className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800 sticky top-0 z-10">
...
217:               {flows.slice(0, 20).map((f) => {
218:                 const badge = getVerdictBadge(f.outcome);
219:                 const isSelected = selectedFlow?.id === f.id;
220:                 return (
221:                   <tr
222:                     key={f.id}
223:                     onClick={() => setSelectedFlow(f)}
224:                     className={`transition cursor-pointer ${
225:                       isSelected ? 'bg-indigo-950/40' : 'hover:bg-slate-800/50'
226:                     }`}
227:                   >
...
252:               {flows.length === 0 && (
253:                 <tr>
254:                   <td colSpan="5" className="py-12 text-center text-slate-500 text-sm">
255:                     Waiting for live network flows... Browse or test the target website to begin.
256:                   </td>
257:                 </tr>
258:               )}
```
- **Lines 205–216**: Scrollable container (`max-h-[420px]`) with sticky header (`sticky top-0 z-10`).
- **Lines 217–250**: Maps over latest 20 flows. Clicking a row sets `selectedFlow(f)`.
- **Lines 252–258**: Empty state row. When `flows.length === 0`, cleanly displays waiting placeholder.

---

### Lines 264–351: Deep-Inspection XAI Modal
```jsx
264:       {selectedFlow && (
265:         <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50" onClick={() => setSelectedFlow(null)}>
266:           <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5" onClick={(e) => e.stopPropagation()}>
...
302:                 Why It Was Flagged ({selectedFlow.explanation?.method})
303:                 <p className="text-sm text-slate-200 leading-relaxed">{selectedFlow.explanation?.summary}</p>
...
309:             <div className="grid grid-cols-3 gap-3 text-xs">
310:               {/* Autoencoder Error, RF Classifier, 10s Window stats */}
...
330:             {selectedFlow.explanation?.top_features?.length > 0 && (
331:               <div className="space-y-2">
...
337:                   {selectedFlow.explanation.top_features.map((feat, idx) => (
338:                     <div key={idx} className="flex justify-between items-center bg-slate-950 px-3 py-2 rounded-lg border border-slate-800/80 text-xs">
339:                       <span className="text-slate-200 font-medium">{feat.feature}</span>
340:                       <span className="font-mono text-indigo-400">{feat.contribution}</span>
341:                     </div>
342:                   ))}
```
- **Lines 264–272**: Modal overlay with background blur. `e.stopPropagation()` on the modal body prevents accidental closure when clicking inside.
- **Lines 300–307**: Displays XAI method and plain-English summary.
- **Lines 309–328**: Renders three metric tiles for Autoencoder MSE, RF prediction/confidence, and rolling 10s behavioral window stats.
- **Lines 330–346**: Iterates over `selectedFlow.explanation.top_features` to display individual feature contribution values.

---

# Part 2: Supporting Frontend Files

### `frontend/src/main.jsx` (Lines 1–10)
```javascript
1: import { StrictMode } from 'react'
2: import { createRoot } from 'react-dom/client'
3: import './index.css'
4: import App from './App.jsx'
5: 
6: createRoot(document.getElementById('root')).render(
7:   <StrictMode>
8:     <App />
9:   </StrictMode>,
10: )
```
Initializes React 19 root into DOM `#root` container under `StrictMode`.

### `frontend/src/index.css` (Lines 1–7)
```css
1: @import "tailwindcss";
2: 
3: body {
4:   background-color: #020617;
5:   color: #f8fafc;
6:   font-family: 'Inter', system-ui, -apple-system, sans-serif;
7: }
```
Imports Tailwind CSS v4 and applies dark-mode slate styling to HTML body.

### `frontend/vite.config.js` (Lines 1–7)
```javascript
1: import { defineConfig } from 'vite'
2: import react from '@vitejs/plugin-react'
3: import tailwindcss from '@tailwindcss/vite'
4: 
5: export default defineConfig({
6:   plugins: [react(), tailwindcss()],
7: })
```
Configures Vite build system enabling the React Fast Refresh plugin and Tailwind CSS Vite compiler plugin.

### `frontend/package.json` (Lines 1–32)
Specifies `react: ^19.3.1`, `react-dom: ^19.3.1`, `lucide-react: ^1.72.0`, `@tailwindcss/vite: ^4.3.5`, `vite: ^8.3.6`, and development scripts `npm run dev` and `npm run build`.

