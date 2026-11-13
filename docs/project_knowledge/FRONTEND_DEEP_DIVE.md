# ZeroDay IDS — Frontend Deep Dive

This document provides a technical audit of the frontend presentation layer, detailing the React 19 component tree, reactive state management, WebSocket integration, epoch-based filtering, UI rendering layout, and CSS styling.

---

## 1. Frontend Technology Stack & Build Architecture

- **Framework**: React 19.3.1 (`react`, `react-dom`)
- **Build Tool**: Vite 8.3.6 (`@vitejs/plugin-react`)
- **CSS Engine**: Tailwind CSS v4.3.5 via `@tailwindcss/vite`
- **Icon Library**: Lucide React (`lucide-react` v1.72.0)
- **Code Linter**: ESLint 10.14.0 with `eslint-plugin-react-hooks` and `eslint-plugin-react-refresh`
- **Port & Host**: Local development server bound to `http://localhost:5173`

---

## 2. Component Architecture (`frontend/src/App.jsx`)

The entire user interface is implemented within a cohesive single-file React component in `App.jsx`.

### 2.1 State Variables & Refs
```javascript
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
```

| State / Ref Identifier | Type | Responsibility & Purpose |
| :--- | :--- | :--- |
| `connected` | `boolean` | Tracks live WebSocket connection state; drives the status pill ("Sensor Active" vs "Reconnecting..."). |
| `stats` | `object` | Mirrors backend pipeline metrics for total packets, total flows, normal flows, known attacks, and zero-day anomalies. |
| `flows` | `Array<FlowRecord>` | Holds the rolling list of the latest 20 analyzed network flows displayed in the traffic table. |
| `selectedFlow` | `FlowRecord \| null` | Stores the flow currently selected for detailed inspection in the XAI modal; `null` when modal is closed. |
| `wsRef` | `useRef<WebSocket>` | Retains a mutable reference to the active `WebSocket` instance across render cycles without triggering re-renders. |
| `epochRef` | `useRef<number>` | Stores the active reset epoch generation counter. Used to synchronously filter out stale in-flight WebSocket messages. |

### 2.2 WebSocket Lifecycle & Message Handling
The WebSocket connection is established inside a `useEffect` hook with an empty dependency array (`[]`), running once when the component mounts.

```javascript
useEffect(() => {
  const connectWS = () => {
    const ws = new WebSocket('ws://localhost:8000/ws/live');
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setTimeout(connectWS, 2000); // Automatic reconnection
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      // Event Dispatch Logic
    };
  };

  connectWS();
  return () => wsRef.current?.close();
}, []);
```

#### Event Dispatch Logic inside `ws.onmessage`:
1. **`INITIAL_STATE`**:
   - Sent immediately by the server upon WebSocket handshake.
   - Sets `epochRef.current = data.epoch ?? 0`.
   - Populates initial `stats` and `flows` (sliced to latest 20).
2. **`RESET`**:
   - Broadcast by the server whenever `/api/reset` is called.
   - Authoritatively synchronizes `epochRef.current = data.epoch`.
   - Force-clears the flow list: `setFlows([])`.
   - Closes any open modal: `setSelectedFlow(null)`.
   - Resets KPI counters: `setStats(data.stats)`.
3. **`FLOW_ANALYZED`**:
   - Dispatched by the server when a flow completes ML inference.
   - **Epoch Guard**:
     ```javascript
     if (data.epoch !== undefined && data.epoch < epochRef.current) {
       return; // Discard stale in-flight message from prior epoch
     }
     ```
   - If valid: Updates `setStats(data.stats)` and prepends the new flow:
     ```javascript
     setFlows((prev) => [newFlow, ...prev.slice(0, 19)]);
     ```
     This maintains a strict 20-row maximum ceiling.

### 2.3 Reset Workflow & Race Condition Defense (`handleReset`)
The `handleReset` function implements a multi-tier defense against race conditions:
```javascript
const handleReset = async () => {
  // 1. Optimistic UI clear for immediate user feedback
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

  // 2. Transmit HTTP reset command to backend
  try {
    const res = await fetch('http://localhost:8000/api/reset', { method: 'POST' });
    const body = await res.json();
    // 3. Fallback epoch adoption from HTTP response
    if (body.epoch !== undefined) {
      epochRef.current = body.epoch;
    }
  } catch (err) {
    console.error('Reset request failed:', err);
  }
};
```
- **Optimistic Clear**: Immediately clears React state so the UI becomes empty without waiting for network round-trips.
- **WebSocket Broadcast**: The backend dispatches a `RESET` WebSocket event which authoritatively resets all connected client browsers.
- **HTTP Fallback**: If network latency delays the WebSocket `RESET` event, the HTTP response JSON provides the new epoch, updating `epochRef.current` immediately to reject any lingering pre-reset flows.

---

## 3. UI Layout & View Hierarchy

### 3.1 Header Bar
- **Branding**: Shield icon with title `"ZeroDay IDS — Live Threat Monitor"` and subtitle `"Click any traffic row below to inspect why it was classified as Normal, Known, or Unknown"`.
- **Status Indicator**: Dynamic pill displaying `"Sensor Active"` (emerald dot with CSS pulse animation) when connected, or `"Reconnecting..."` (rose dot) when disconnected.
- **Reset Button**: Compact slate button with `RefreshCw` icon triggering `handleReset()`.

### 3.2 Five-Card KPI Metric Strip
A responsive grid (`grid-cols-2 md:grid-cols-5`) rendering live traffic metrics:
1. **Packets Sniffed**: Blue activity icon, `stats.total_packets.toLocaleString()`.
2. **Analyzed Flows**: Indigo network icon, `stats.total_flows.toLocaleString()`.
3. **Normal**: Emerald checkmark icon, `stats.normal_flows.toLocaleString()`.
4. **Known Attacks**: Rose shield-alert icon, `stats.known_attacks.toLocaleString()`.
5. **Unknown Anomalies**: Amber triangle-alert icon, `stats.unknown_anomalies.toLocaleString()`.

### 3.3 Recent Network Traffic Table
- **Header**: Displays `"Recent Network Traffic (Latest 20 Flows)"` with a badge indicator showing `"Showing N of 20 max rows"`.
- **Columns**:
  - `Time`: Formatted as `HH:MM:SS` using `new Date(ts * 1000).toLocaleTimeString()`.
  - `Source → Dest`: Displays `{src_ip} → {dst_ip}:{dst_port}` in monospace font.
  - `Protocol`: Monospace label (`TCP`, `UDP`, or `Other`).
  - `Guess`: Human-readable classification hint:
    - Known Attack: e.g., `"DoS / DDoS (98%)"`
    - Unknown Anomaly: e.g., `"Zero-Day · Cluster #0"` or `"Unseen Pattern"`
    - Normal: e.g., `"Benign (99%)"`
  - `Verdict`: Color-coded status badge generated by `getVerdictBadge()`:
    - `NORMAL`: Emerald badge (`bg-emerald-500/15 text-emerald-400 border-emerald-500/30`)
    - `KNOWN_ATTACK`: Rose badge (`bg-rose-500/15 text-rose-400 border-rose-500/30`)
    - `SUSPICIOUS_UNKNOWN`: Amber badge (`bg-amber-500/15 text-amber-400 border-amber-500/30`)
- **Empty State Display**:
  ```jsx
  {flows.length === 0 && (
    <tr>
      <td colSpan="5" className="py-12 text-center text-slate-500 text-sm">
        Waiting for live network flows... Browse or test the target website to begin.
      </td>
    </tr>
  )}
  ```
  Rendered when `flows.length === 0`. Because epoch filtering guarantees stale flows are discarded, this message cleanly appears upon reset and is replaced once the first new flow arrives.

### 3.4 Deep-Inspection Modal (`selectedFlow`)
Clicking any table row sets `selectedFlow(f)`, rendering a fixed modal backdrop (`fixed inset-0 bg-black/70 backdrop-blur-sm`):
- **Header**: Verdict badge, timestamp, and connection 5-tuple (`src_ip -> dst_ip:dst_port (protocol)`).
- **Why It Was Flagged**: Explanation box displaying `selectedFlow.explanation.method` and plain-English `selectedFlow.explanation.summary`.
- **Three Telemetry Cards**:
  - `Autoencoder Error`: Formatted MSE score (`ae_score.toFixed(5)`).
  - `RF Classifier`: Predicted class and percentage confidence.
  - `10s Window`: Behavioral stats (`connection_count` and `unique_destination_ports`).
- **Top Contributing Features**: Rendered when `top_features` are available. Displays ranked list of feature names with positive/negative attribution values.
- **Dismissal**: Closes when clicking the `X` button, clicking the backdrop, or pressing reset.

---

## 4. Application Entry & Styling

### 4.1 `main.jsx`
Mounts `<App />` inside React's `StrictMode` to detect potential side-effects and deprecated APIs:
```jsx
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
```

### 4.2 `index.css`
Declares Tailwind CSS integration:
```css
@import "tailwindcss";

body {
  background-color: #020617;
  color: #f8fafc;
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
}
```

### 4.3 `App.css`
Contains legacy CSS classes (`.counter`, `.hero`, `.ticks`) from the initial Vite prototype. The active live monitor styling relies on Tailwind CSS utility classes defined directly in `App.jsx`.

