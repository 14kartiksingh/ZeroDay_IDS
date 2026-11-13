# ZeroDay IDS — Detailed Line-by-Line Code Explanation: Backend Subsystems

This document provides a line-by-line technical explanation of all 12 backend Python source files in `ZeroDay_IDS`. Every meaningful line or logical block is preserved with accurate line numbers, explaining syntax, design rationale, and failure modes.

---

# Part 1: Core Service & Pipeline (`backend/services/ids_pipeline.py`)

### Lines 1–12: Imports
```python
1: import time
2: import threading
3: from collections import deque
4: from scapy.all import sniff, IP, TCP, UDP, conf
5: 
6: from backend.capture.flow_manager import FlowManager
7: from backend.features.behavior_feature_engine import BehavioralFeatureEngine
8: from backend.detection.autoencoder_detector import AutoencoderDetector
9: from backend.detection.rf_detector import RandomForestDetector
10: from backend.detection.decision_engine import DecisionEngine
11: from backend.explainability.xai_engine import ExplainabilityEngine
12: from backend.clustering.cluster_engine import ClusteringEngine
```
- **Lines 1–3**: `time` provides epoch timestamps; `threading` provides `Lock` and concurrency tools; `deque` provides $O(1)$ double-ended bounded queues.
- **Line 4**: Imports Scapy primitives. `sniff` captures raw link-layer frames; `IP`, `TCP`, `UDP` are protocol layer classes; `conf` contains global Scapy settings and interface routing tables.
- **Lines 6–12**: Imports the six modular detection components and flow manager.
- **Impact if removed**: Removing `threading` would prevent thread synchronization, causing race conditions between Scapy packet capture and FastAPI resets.

---

### Lines 14–53: Service Initialization (`__init__`)
```python
14: class IDSPipelineService:
15:     def __init__(self, interface_index=12, model_dir="models/model B"):
16:         self.interface_index = interface_index
17:         self.interface = conf.ifaces.dev_from_index(interface_index)
18:         self.is_running = False
19: 
20:         # Thread-safety lock for shared state accessed by both the Scapy
21:         # capture thread and the FastAPI request threads (reset, stats, etc.)
22:         self._lock = threading.Lock()
23: 
24:         # Epoch counter: incremented on every reset.  Flow events carry the
25:         # epoch they were produced under so the frontend can discard stale
26:         # WebSocket messages that were in-flight when a reset occurred.
27:         self._reset_epoch = 0
28: 
29:         # Core Capture & 6 ML Components
30:         self.flow_manager = FlowManager(idle_timeout=5)  # 5s idle timeout for responsive live dashboard updates
31:         self.behavior_engine = BehavioralFeatureEngine(window_seconds=10)
32:         self.autoencoder = AutoencoderDetector(model_dir=model_dir)
33:         self.random_forest = RandomForestDetector(model_dir=model_dir)
34:         self.decision_engine = DecisionEngine()
35:         self.xai_engine = ExplainabilityEngine(self.random_forest.model)
36:         self.clustering_engine = ClusteringEngine(eps=1.2, min_samples=3)
37: 
38:         # Live State Buffers for Dashboard APIs
39:         self.stats = {
40:             "total_packets": 0,
41:             "total_flows": 0,
42:             "normal_flows": 0,
43:             "known_attacks": 0,
44:             "unknown_anomalies": 0,
45:             "start_time": time.time()
46:         }
47:         self.recent_flows = deque(maxlen=100)
48:         self.alerts = deque(maxlen=100)
49: 
50:         # Optional callback for real-time WebSocket pushing
51:         self.on_event_callback = None
```
- **Lines 16–17**: Binds Scapy to interface index 12 (VMnet1). If index 12 does not exist, an exception is raised.
- **Lines 22–27**: Initializes `_lock` (`threading.Lock()`) and `_reset_epoch = 0`.
- **Line 30**: Instantiates `FlowManager` with `idle_timeout=5`. Flows idle for 5 seconds expire and undergo ML analysis.
- **Lines 31–36**: Instantiates all 6 ML engines. Notice that `xai_engine` receives `self.random_forest.model` to build its `shap.TreeExplainer`.
- **Lines 39–48**: Allocates shared state. `recent_flows` and `alerts` are `deque(maxlen=100)`. When 100 items are reached, appending automatically drops the oldest item in $O(1)$ time.

---

### Lines 54–85: Packet Parser (`_parse_packet`)
```python
54:     def _parse_packet(self, packet):
55:         if IP not in packet:
56:             return None
57: 
58:         ip = packet[IP]
59:         src_port = None
60:         dst_port = None
61:         tcp_flags = None
62:         if ip.dst.startswith(("224.", "239.")) or ip.dst == "255.255.255.255":
63:             return None
64:         if TCP in packet:
65:             src_port = packet[TCP].sport
66:             dst_port = packet[TCP].dport
67:             tcp_flags = str(packet[TCP].flags)
68:             protocol = "TCP"
69:         elif UDP in packet:
70:             src_port = packet[UDP].sport
71:             dst_port = packet[UDP].dport
72:             protocol = "UDP"
73:         else:
74:             protocol = "Other"
75: 
76:         return {
77:             "timestamp": float(packet.time),
78:             "src_ip": ip.src,
79:             "dst_ip": ip.dst,
80:             "src_port": src_port,
81:             "dst_port": dst_port,
82:             "protocol": protocol,
83:             "packet_size": len(packet),
84:             "tcp_flags": tcp_flags
85:         }
```
- **Lines 55–56**: Drops non-IPv4 frames (ARP, LLC, IGMP, IPv6).
- **Line 62**: Drops multicast (`224.0.0.0/4`, `239.0.0.0/8`) and limited broadcast (`255.255.255.255`).
- **Lines 64–74**: Extracts layer 4 ports and protocol string. For TCP, flags are converted to string format (e.g. `'S'`, `'SA'`, `'PA'`).
- **Lines 76–85**: Constructs a dictionary record with float timestamp (`packet.time`) and byte length (`len(packet)`).

---

### Lines 87–180: Expired Flow Processing & ML Inference (`process_expired_flows`)
```python
87:     def process_expired_flows(self):
88:         expired_flows = self.flow_manager.get_expired_flows()
89: 
90:         for flow in expired_flows:
91:             # Run ML inference OUTSIDE the lock — these are pure computations
92:             # on the flow dict and do not touch shared dashboard state.
93: 
94:             # Component 1: Behavioral Feature Engine
95:             behavior_features = self.behavior_engine.add_flow(flow)
96: 
97:             # Component 2: Autoencoder (Benign Anomaly Detection)
98:             ae_result = self.autoencoder.predict(flow)
99: 
100:             # Component 3: Random Forest (Known Attack Classification)
101:             rf_result = self.random_forest.predict(flow)
102: 
103:             # Component 4: Decision Engine
104:             decision = self.decision_engine.evaluate(
105:                 flow, behavior_features, ae_result, rf_result
106:             )
107: 
108:             # Component 5: Explainable AI (XAI)
109:             explanation = self.xai_engine.explain(
110:                 decision, behavior_features, ae_result, rf_result
111:             )
112: 
113:             # Component 6: Clustering Engine (for Suspicious Unknown Anomalies)
114:             cluster_id = None
115:             if decision["outcome"] == "SUSPICIOUS_UNKNOWN":
116:                 cluster_id = self.clustering_engine.add_observation(
117:                     flow, behavior_features, ae_result, explanation
118:                 )
```
- **Line 88**: Pops expired flows from `flow_manager`.
- **Lines 94–118**: Sequentially calls all 6 ML components. Crucially, this compute-intensive inference runs **outside the lock**, ensuring that HTTP requests calling `/api/stats` or `/api/reset` are not blocked by PyTorch or SHAP calculations.
```python
120:             # ── Critical section: update shared dashboard state ──
121:             with self._lock:
122:                 self.stats["total_flows"] += 1
123: 
124:                 # Update dashboard counters
125:                 outcome = decision["outcome"]
126:                 if outcome == "NORMAL":
127:                     self.stats["normal_flows"] += 1
128:                 elif outcome == "KNOWN_ATTACK":
129:                     self.stats["known_attacks"] += 1
130:                 elif outcome == "SUSPICIOUS_UNKNOWN":
131:                     self.stats["unknown_anomalies"] += 1
132: 
133:                 flow_record = {
134:                     "id": f"flow_{self.stats['total_flows']}_{int(time.time() * 1000)}",
135:                     "timestamp": decision["timestamp"],
136:                     "src_ip": flow["src_ip"],
137:                     "dst_ip": flow["dst_ip"],
138:                     "src_port": flow["src_port"],
139:                     "dst_port": flow["dst_port"],
140:                     "protocol": flow["protocol"],
141:                     "packets": flow["packet_count"],
142:                     "bytes": flow["byte_count"],
143:                     "duration": round(float(flow["duration"]), 4),
144:                     "outcome": outcome,
145:                     "label": decision["label"],
146:                     "severity": decision["severity"],
147:                     "ae_score": decision["metrics"]["ae_score"],
148:                     "rf_prediction": decision["metrics"]["rf_prediction"],
149:                     "rf_confidence": decision["metrics"]["rf_confidence"],
150:                     "cluster_id": cluster_id,
151:                     "explanation": explanation,
152:                     "behavioral": behavior_features
153:                 }
154: 
155:                 self.recent_flows.appendleft(flow_record)
156: 
157:                 # Store non-duplicate alerts for the Security Alert Feed
158:                 if outcome != "NORMAL" and not decision["is_duplicate"]:
159:                     alert_record = {
160:                         **flow_record,
161:                         "reason": decision["reason"]
162:                     }
163:                     self.alerts.appendleft(alert_record)
164: 
165:                 # Snapshot epoch and payload while still holding the lock
166:                 epoch = self._reset_epoch
167:                 payload = {
168:                     "type": "FLOW_ANALYZED",
169:                     "epoch": epoch,
170:                     "stats": self.get_stats(),
171:                     "flow": flow_record,
172:                     "clusters": self.clustering_engine.get_clusters()
173:                 }
174: 
175:             # Broadcast OUTSIDE the lock to avoid blocking the reset path
176:             if self.on_event_callback:
177:                 self.on_event_callback(payload)
```
- **Line 121**: `with self._lock:` guarantees atomic mutation of `stats`, `recent_flows`, and `alerts`.
- **Line 134**: Generates unique flow ID combining counter and millisecond timestamp.
- **Lines 155–163**: Uses `appendleft()` so newest flows appear first. Non-normal and non-duplicate alerts are copied to `self.alerts`.
- **Lines 166–173**: Reads `epoch = self._reset_epoch` inside the lock, ensuring the payload carries the true epoch.
- **Lines 176–177**: Invokes `self.on_event_callback(payload)` outside the lock.

---

### Lines 182–231: Packet Ingestion, Thread-Safe Reset & Loop
```python
182:     def handle_packet(self, packet):
183:         data = self._parse_packet(packet)
184:         if data:
185:             self.stats["total_packets"] += 1
186:             self.flow_manager.add_packet(data)
187:         self.process_expired_flows()
188: 
189:     def reset(self):
190:         """Thread-safe reset of all dashboard state."""
191:         with self._lock:
192:             self._reset_epoch += 1
193:             self.flow_manager.flows.clear()
194:             self.recent_flows.clear()
195:             self.alerts.clear()
196:             self.clustering_engine.observations.clear()
197:             self.clustering_engine.clusters_summary.clear()
198:             self.behavior_engine.source_windows.clear()
199:             self.decision_engine.recent_alerts.clear()
200:             self.stats.update({
201:                 "total_packets": 0,
202:                 "total_flows": 0,
203:                 "normal_flows": 0,
204:                 "known_attacks": 0,
205:                 "unknown_anomalies": 0
206:             })
207:             epoch = self._reset_epoch
208:         return epoch
```
- **Lines 182–187**: Scapy callback. Increments `total_packets`, adds to `flow_manager`, and checks for expired flows.
- **Lines 189–208**: Atomically clears all buffers, clears in-progress flows in `flow_manager.flows`, purges behavioral windows and alert deduplication tables, increments `_reset_epoch`, and returns it.

---

### Lines 233–256: Run Loop, Stop & Stats
```python
233:     def run_capture_loop(self):
234:         self.is_running = True
235:         print(f"IDS Pipeline capturing live on interface: {self.interface}")
236:         while self.is_running:
237:             sniff(
238:                 iface=self.interface,
239:                 filter="ip",
240:                 prn=self.handle_packet,
241:                 store=False,
242:                 timeout=1
243:             )
244:             self.process_expired_flows()
245: 
246:     def stop(self):
247:         self.is_running = False
248: 
249:     def get_stats(self):
250:         uptime = int(time.time() - self.stats["start_time"])
251:         return {
252:             **self.stats,
253:             "uptime_seconds": uptime,
254:             "is_capturing": self.is_running,
255:             "epoch": self._reset_epoch
256:         }
```
- **Lines 233–244**: Infinite loop while `self.is_running is True`.
- **Line 246**: Sets `self.is_running = False` to break the sniffing loop.
- **Lines 249–256**: Returns a dictionary combining stats, calculated `uptime_seconds`, `is_capturing`, and `epoch`.

---

# Part 2: REST API & WebSocket Communication (`backend/api/main.py`)

### Lines 1–30: Imports, Global Instances & Broadcast Handlers
```python
1: import asyncio
2: import threading
3: from contextlib import asynccontextmanager
4: from fastapi import FastAPI, WebSocket, WebSocketDisconnect
5: from fastapi.middleware.cors import CORSMiddleware
6: 
7: from backend.services.ids_pipeline import IDSPipelineService
8: 
9: # Global pipeline instance
10: pipeline = IDSPipelineService(interface_index=12, model_dir="models/model B")
11: connected_clients = set()
12: main_event_loop = None
13: 
14: 
15: def broadcast_from_thread(payload: dict):
16:     """Safely schedules a WebSocket broadcast from the background Scapy sniffer thread."""
17:     if main_event_loop and connected_clients:
18:         asyncio.run_coroutine_threadsafe(broadcast_json(payload), main_event_loop)
19: 
20: 
21: async def broadcast_json(payload: dict):
22:     disconnected = []
23:     for ws in list(connected_clients):
24:         try:
25:             await ws.send_json(payload)
26:         except Exception:
27:             disconnected.append(ws)
28:     for ws in disconnected:
29:         connected_clients.discard(ws)
```
- **Line 10**: Global instantiation of `IDSPipelineService`.
- **Line 11**: `connected_clients = set()` stores active WebSocket connections.
- **Line 18**: `asyncio.run_coroutine_threadsafe()` safely posts coroutines across OS threads into `main_event_loop`.
- **Lines 21–29**: Iterates over a copy of `connected_clients` using `list()`, catches broken pipes, and discards disconnected clients.

---

### Lines 32–62: Lifespan Manager & CORS
```python
32: @asynccontextmanager
33: async def lifespan(app: FastAPI):
34:     global main_event_loop
35:     main_event_loop = asyncio.get_running_loop()
36:     pipeline.on_event_callback = broadcast_from_thread
37: 
38:     # Start live packet capture in a daemon background thread
39:     capture_thread = threading.Thread(target=pipeline.run_capture_loop, daemon=True)
40:     capture_thread.start()
41:     print("FastAPI + Live ML Detection Engine started on port 8000!")
42: 
43:     yield
44: 
45:     pipeline.stop()
46:     print("IDS Pipeline stopped.")
47: 
48: 
49: app = FastAPI(
50:     title="ZeroDay IDS — Hybrid ML Detection API",
51:     version="1.0.0",
52:     lifespan=lifespan
53: )
54: 
55: app.add_middleware(
56:     CORSMiddleware,
57:     allow_origins=["*"],
58:     allow_credentials=True,
59:     allow_methods=["*"],
60:     allow_headers=["*"],
61: )
```
- **Lines 32–46**: Asynchronous context manager managing application startup and shutdown. Captures event loop, assigns `broadcast_from_thread` callback, starts Scapy capture thread, and invokes `pipeline.stop()` on server exit.
- **Lines 55–61**: Enables permissive CORS middleware to allow cross-origin requests from the React development server on port 5173.

---

### Lines 64–103: REST Endpoints
```python
64: @app.get("/api/health")
65: def health_check():
66:     return {"status": "online", "capturing": pipeline.is_running}
67: 
68: @app.get("/api/stats")
69: def get_stats():
70:     return pipeline.get_stats()
71: 
72: @app.get("/api/flows")
73: def get_flows(limit: int = 50):
74:     return list(pipeline.recent_flows)[:limit]
75: 
76: @app.get("/api/alerts")
77: def get_alerts(limit: int = 50):
78:     return list(pipeline.alerts)[:limit]
79: 
80: @app.get("/api/clusters")
81: def get_clusters():
82:     return pipeline.clustering_engine.get_clusters()
83: 
84: @app.post("/api/reset")
85: def reset_dashboard_state():
86:     epoch = pipeline.reset()
87:     broadcast_from_thread({
88:         "type": "RESET",
89:         "epoch": epoch,
90:         "stats": pipeline.get_stats(),
91:         "clusters": pipeline.clustering_engine.get_clusters()
92:     })
93:     return {"status": "reset_complete", "epoch": epoch}
```
- **Lines 64–82**: Read-only queries against `pipeline` state.
- **Lines 84–93**: The `/api/reset` handler. Invokes `pipeline.reset()` and broadcasts a `RESET` event carrying the new epoch to all WebSocket clients.

---

### Lines 105–125: WebSocket Endpoint (`/ws/live`)
```python
105: @app.websocket("/ws/live")
106: async def websocket_live_feed(websocket: WebSocket):
107:     await websocket.accept()
108:     connected_clients.add(websocket)
109: 
110:     # Send initial state snapshot immediately on connect
111:     await websocket.send_json({
112:         "type": "INITIAL_STATE",
113:         "epoch": pipeline.get_stats().get("epoch", 0),
114:         "stats": pipeline.get_stats(),
115:         "flows": list(pipeline.recent_flows)[:30],
116:         "alerts": list(pipeline.alerts)[:30],
117:         "clusters": pipeline.clustering_engine.get_clusters()
118:     })
119: 
120:     try:
121:         while True:
122:             await websocket.receive_text()
123:     except WebSocketDisconnect:
124:         connected_clients.discard(websocket)
```
- **Lines 107–108**: Accepts WebSocket connection and registers client in `connected_clients`.
- **Lines 111–118**: Transmits `INITIAL_STATE` snapshot containing current epoch, stats, and latest 30 flows/alerts.
- **Lines 121–124**: Keeps connection open until client disconnects.

---

# Part 3: Flow Manager (`backend/capture/flow_manager.py`)

### Lines 1–22: Class Definition & Flow Key Generation
```python
1: import time
2: 
3: class FlowManager:
4:     def __init__(self, idle_timeout=10):
5:         self.flows = {}
6:         self.idle_timeout = idle_timeout
7: 
8:     def get_flow_key(self, packet):
9:         source = (packet["src_ip"], packet["src_port"])
10:         destination = (packet["dst_ip"], packet["dst_port"])
11:         endpoints = tuple(sorted([source, destination]))
12:         return endpoints, packet["protocol"]
```
- **Lines 4–6**: Initializes active flow dictionary `self.flows = {}` and stores `idle_timeout` (defaults to 10s).
- **Lines 8–12**: Computes direction-agnostic flow key. `sorted()` standardizes endpoints tuple order.

---

### Lines 16–60: Packet Addition & Role Normalization
```python
16:     def add_packet(self, packet):
17:         key = self.get_flow_key(packet)
18:         now = float(packet.get("timestamp", time.time()))
19:         flags = packet.get("tcp_flags") or ""
20:         src_port = packet.get("src_port") or 0
21:         dst_port = packet.get("dst_port") or 0
22: 
23:         if key not in self.flows:
24:             if "S" in flags and "A" not in flags:
25:                 is_server_first = False
26:             elif "S" in flags and "A" in flags:
27:                 is_server_first = True
28:             else:
29:                 is_server_first = src_port < dst_port
30: 
31:             if is_server_first:
32:                 fwd_ip, dst_ip = packet["dst_ip"], packet["src_ip"]
33:                 fwd_port, dst_port_norm = dst_port, src_port
34:             else:
35:                 fwd_ip, dst_ip = packet["src_ip"], packet["dst_ip"]
36:                 fwd_port, dst_port_norm = src_port, dst_port
37: 
38:             self.flows[key] = {
39:                 "src_ip": fwd_ip,
40:                 "dst_ip": dst_ip,
41:                 "src_port": fwd_port,
42:                 "dst_port": dst_port_norm,
43:                 "protocol": packet["protocol"],
44:                 "start_time": now,
45:                 "last_seen": now,
46:                 "packet_count": 0,
47:                 "byte_count": 0,
48:                 "fwd_packets": 0,
49:                 "bwd_packets": 0,
50:                 "fwd_bytes": 0,
51:                 "bwd_bytes": 0,
52:                 "tcp_flags": {},
53:                 "fwd_tcp_flags": {},
54:                 "bwd_tcp_flags": {}
55:             }
```
- **Lines 23–36**: Client/server role normalization. Evaluates SYN/ACK flags and port numbers to designate the initiating client as forward (`fwd_ip`, `fwd_port`) and the listening service as backward (`dst_ip`, `dst_port_norm`).
- **Lines 38–55**: Allocates a new flow dictionary tracking directional packet, byte, and TCP flag metrics.

---

### Lines 61–86: Directional Packet Accounting
```python
61:         flow = self.flows[key]
62:         flow["last_seen"] = now
63:         flow["packet_count"] += 1
64:         flow["byte_count"] += packet["packet_size"]
65: 
66:         is_forward = (
67:             packet["src_ip"] == flow["src_ip"]
68:             and src_port == flow["src_port"]
69:             and packet["dst_ip"] == flow["dst_ip"]
70:             and dst_port == flow["dst_port"]
71:         )
72: 
73:         if is_forward:
74:             flow["fwd_packets"] += 1
75:             flow["fwd_bytes"] += packet["packet_size"]
76:             direction_flags = flow["fwd_tcp_flags"]
77:         else:
78:             flow["bwd_packets"] += 1
79:             flow["bwd_bytes"] += packet["packet_size"]
80:             direction_flags = flow["bwd_tcp_flags"]
81: 
82:         if flags:
83:             for flag in flags:
84:                 flow["tcp_flags"][flag] = flow["tcp_flags"].get(flag, 0) + 1
85:                 direction_flags[flag] = direction_flags.get(flag, 0) + 1
```
- **Lines 61–64**: Updates `last_seen` timestamp and total counts.
- **Lines 66–80**: Compares packet source with `flow["src_ip"]` and `flow["src_port"]`. If matched, increments `fwd_packets` and `fwd_bytes`; otherwise increments `bwd_packets` and `bwd_bytes`.
- **Lines 82–86**: Tracks per-flag counts in `flow["tcp_flags"]` and directional flags (`fwd_tcp_flags` / `bwd_tcp_flags`).

---

### Lines 87–100: Flow Expiration Extraction
```python
87:     def get_expired_flows(self):
88:         now = time.time()
89:         expired = []
90: 
91:         for key, flow in list(self.flows.items()):
92:             if now - flow["last_seen"] >= self.idle_timeout:
93:                 completed_flow = flow.copy()
94:                 completed_flow["duration"] = (
95:                     flow["last_seen"] - flow["start_time"]
96:                 )
97:                 expired.append(completed_flow)
98:                 del self.flows[key]
99: 
100:         return expired
```
- **Line 91**: Iterates over `list(self.flows.items())` to allow safe deletion of items from `self.flows`.
- **Line 92**: Checks if inactivity duration exceeds `idle_timeout`.
- **Lines 93–98**: Calculates final duration ($\Delta t$), appends a copy to `expired`, and removes the flow from active tracking.

---

# Part 4: Autoencoder Detector (`backend/detection/autoencoder_detector.py`)

### Lines 1–30: Autoencoder Neural Network Definition
```python
10: class Autoencoder(nn.Module):
11:     def __init__(self):
12:         super().__init__()
13:         self.encoder = nn.Sequential(
14:             nn.Linear(9, 64),
15:             nn.ReLU(),
16:             nn.Linear(64, 32),
17:             nn.ReLU(),
18:             nn.Linear(32, 16)
19:         )
20:         self.decoder = nn.Sequential(
21:             nn.Linear(16, 32),
22:             nn.ReLU(),
23:             nn.Linear(32, 64),
24:             nn.ReLU(),
25:             nn.Linear(64, 9)
26:         )
27: 
28:     def forward(self, x):
29:         return self.decoder(self.encoder(x))
```
- **Lines 10–26**: Defines a 7-layer fully connected symmetric autoencoder in PyTorch with a 16-dimensional bottleneck.
- **Lines 28–29**: `forward(x)` passes input tensor $x$ through encoder then decoder.

---

### Lines 32–68: Detector Initialization & Model Loading
```python
32: class AutoencoderDetector:
33:     def __init__(self, model_dir=os.path.join("models", "model B")):
34:         self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
...
41:         if os.path.exists(metadata_path) and os.path.getsize(metadata_path) > 0:
42:             with open(metadata_path, "r", encoding="utf-8-sig") as f:
43:                 self.metadata = json.load(f)
44:             self.threshold = float(self.metadata["threshold"])
45:             self.features = self.metadata["input_features"]
46:         else:
47:             self.threshold = float(np.load(threshold_path).item())
48:             self.features = [...]
...
61:         self.scaler = joblib.load(scaler_path)
62:         self.model = Autoencoder().to(self.device)
63:         self.model.load_state_dict(
64:             torch.load(model_path, map_location=self.device, weights_only=True)
65:         )
66:         self.model.eval()
```
- **Line 34**: Automatically assigns device (`cuda` or `cpu`).
- **Lines 41–48**: Reads calibrated threshold and feature names from `metadata.json`, falling back to `threshold.npy` if needed.
- **Lines 61–66**: Loads Scikit-learn scaler and PyTorch weights, setting model to inference mode (`self.model.eval()`).

---

### Lines 69–119: Live Flow Inference & Error Attribution
```python
69:     def predict(self, flow):
70:         duration = max(float(flow["duration"]), 0.000001)
71:         duration_us = duration * 1_000_000
72: 
73:         total_packets = flow["fwd_packets"] + flow["bwd_packets"]
74:         total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
75:         syn_count = flow.get("tcp_flags", {}).get("S", 0)
76: 
77:         raw_features = np.array([[
78:             flow["dst_port"] or 0,
79:             duration_us,
80:             flow["fwd_packets"],
81:             flow["bwd_packets"],
82:             flow["fwd_bytes"],
83:             flow["bwd_bytes"],
84:             total_bytes / duration,
85:             total_packets / duration,
86:             syn_count
87:         ]], dtype=np.float64)
88: 
89:         # Match training preprocessing: log1p ONLY on Flow Bytes/s (index 6) and Flow Packets/s (index 7)
90:         raw_features[0, 6] = np.log1p(max(raw_features[0, 6], 0.0))
91:         raw_features[0, 7] = np.log1p(max(raw_features[0, 7], 0.0))
92: 
93:         scaled = self.scaler.transform(
94:             pd.DataFrame(raw_features, columns=self.features)
95:         )
96: 
97:         tensor = torch.tensor(scaled, dtype=torch.float32, device=self.device)
98: 
99:         with torch.no_grad():
100:             reconstructed = self.model(tensor)
101:             per_feature_errors = ((reconstructed - tensor) ** 2).squeeze(0).cpu().numpy()
102:             error = float(np.mean(per_feature_errors))
```
- **Lines 70–71**: Converts duration from seconds to microseconds.
- **Lines 90–91**: Applies $\ln(1+x)$ to rate features.
- **Lines 93–95**: Standardizes features using pre-fitted `StandardScaler`.
- **Lines 99–102**: Executes forward pass under `torch.no_grad()` to suppress gradient calculation. Computes per-feature squared error $(\hat{x}_i - x_i)^2$ and overall MSE `error`.
- **Lines 104–119**: Ranks features by error contribution and returns status dictionary (`is_anomaly = error > self.threshold`).

---

# Part 5: Random Forest Detector (`backend/detection/rf_detector.py`)

### Lines 1–69: Classifier Implementation
```python
7: class RandomForestDetector:
8:     def __init__(self, model_dir=os.path.join("models", "model B")):
9:         model_path = os.path.join(model_dir, "random_forest.joblib")
10:         self.model = joblib.load(model_path)
11:         self.classes = list(self.model.classes_)
...
25:     def extract_feature_df(self, flow):
26:         duration = max(float(flow["duration"]), 0.000001)
27:         duration_us = duration * 1_000_000
...
46:         raw_features[0, 6] = np.log1p(max(raw_features[0, 6], 0.0))
47:         raw_features[0, 7] = np.log1p(max(raw_features[0, 7], 0.0))
48:         return pd.DataFrame(raw_features, columns=self.features)
...
51:     def predict(self, flow):
52:         X_df = self.extract_feature_df(flow)
53:         probs = self.model.predict_proba(X_df)[0]
54:         best_idx = int(np.argmax(probs))
55:         predicted_class = str(self.classes[best_idx])
56:         confidence = float(probs[best_idx])
```
- **Lines 8–11**: Loads serialized Random Forest model with 100 decision trees.
- **Lines 25–49**: Constructs pandas DataFrame with matching column names and log1p rate transformations.
- **Lines 51–69**: Calls `predict_proba()`. Identifies best class index, calculates confidence, and returns class probabilities dictionary and feature DataFrame (used by SHAP).

---

# Part 6: Decision Engine (`backend/detection/decision_engine.py`)

### Lines 1–26: Configuration & Deduplication
```python
4: class DecisionEngine:
5:     def __init__(
6:         self,
7:         rf_confidence_threshold=0.75,
8:         ae_severe_multiplier=3.0,
9:         dedup_window_seconds=4
10:     ):
11:         self.rf_confidence_threshold = rf_confidence_threshold
12:         self.ae_severe_multiplier = ae_severe_multiplier
13:         self.dedup_window_seconds = dedup_window_seconds
14:         self.recent_alerts = {}
15: 
16:     def _is_duplicate(self, source_ip, outcome, attack_label):
17:         now = time.time()
18:         key = (source_ip, outcome, attack_label)
19:         last_time = self.recent_alerts.get(key)
20: 
21:         if last_time and (now - last_time) < self.dedup_window_seconds:
22:             return True
23: 
24:         self.recent_alerts[key] = now
25:         return False
```
- **Lines 5–14**: Configures RF confidence threshold ($0.75$), severe anomaly multiplier ($3.0\times$), and deduplication window ($4$ seconds).
- **Lines 16–25**: Deduplication cache. Suppresses duplicate alerts for the same source host and attack label within 4 seconds.

---

### Lines 27–129: Multi-Criteria Synthesis (`evaluate`)
```python
27:     def evaluate(self, flow, behavior_features, ae_result, rf_result):
...
48:         is_dos_flood = (
49:             unique_ports <= 2
50:             and (conn_count >= 25 or packet_rate >= 80.0 or syn_count >= 40)
51:         )
52:         is_multiport_recon = unique_ports >= 5
53: 
54:         # 1. SUSPICIOUS UNKNOWN (Zero-Day)
55:         if ae_anomalous and is_multiport_recon:
56:             outcome = "SUSPICIOUS_UNKNOWN"
57:             label = "Unseen Anomaly / Potential Zero-Day"
...
67:         # 2. KNOWN ATTACK
68:         elif rf_class != "BENIGN" and rf_conf >= self.rf_confidence_threshold:
69:             outcome = "KNOWN_ATTACK"
70:             label = rf_class
...
76:         elif is_dos_flood and ae_anomalous:
77:             outcome = "KNOWN_ATTACK"
78:             label = "DoS / DDoS"
...
87:         # 3. SEVERE SINGLE-FLOW STRUCTURAL ANOMALY
88:         elif ae_anomalous and ae_score >= (ae_thresh * self.ae_severe_multiplier):
89:             outcome = "SUSPICIOUS_UNKNOWN"
90:             label = "Unseen Structural Anomaly"
...
96:         # 4. NORMAL
97:         else:
98:             outcome = "NORMAL"
99:             label = "Benign Traffic"
```
- **Lines 54–65**: Prioritizes multi-port reconnaissance ($\ge 5$ ports) flagged by Autoencoder as zero-day threats over single-port RF classifications.
- **Lines 67–85**: Classifies as known attack if Random Forest confidence $\ge 0.75$ or if high-rate flood conditions are met.
- **Lines 87–94**: Flags unseen single-flow anomaly if reconstruction error exceeds $3\times$ baseline threshold.
- **Lines 96–101**: Falls back to `NORMAL`.

---

# Part 7: Explainable AI Engine (`backend/explainability/xai_engine.py`)

### Lines 1–70: SHAP TreeExplainer for Known Attacks
```python
5: class ExplainabilityEngine:
6:     def __init__(self, rf_model):
7:         self.rf_explainer = shap.TreeExplainer(rf_model)
8:         self.rf_classes = list(rf_model.classes_)
...
28:         if outcome == "KNOWN_ATTACK":
29:             pred_class = rf_result["predicted_class"]
...
35:                 shap_values = self.rf_explainer.shap_values(feature_df)
...
45:                 ranked = sorted(
46:                     zip(feature_names, class_shap),
47:                     key=lambda item: abs(float(item[1])),
48:                     reverse=True
49:                 )
```
- **Line 8**: Builds tree explainer on Random Forest model.
- **Lines 35–49**: Computes exact Shapley values for predicted attack class, ranks features by absolute magnitude, and returns top 4 drivers.

---

### Lines 71–143: Autoencoder Error & Behavioral Attribution
```python
100:         # Case B: Suspicious Unknown (Zero-Day)
101:         ae_errors = ae_result.get("top_contributing_features", {})
102:         top_ae = [...]
...
118:         if unique_ports >= 5:
119:             behavioral_drivers.append(f"probed {unique_ports} unique destination ports in {behavior_features.get('window_seconds', 10)}s")
120:         if conn_count >= 15:
121:             behavioral_drivers.append(f"opened {conn_count} rapid connections")
122:         if syn_count >= 15:
123:             behavioral_drivers.append(f"sent {syn_count} TCP SYN packets")
124:         if packet_rate >= 50.0:
125:             behavioral_drivers.append(f"generated a high packet burst ({packet_rate:.1f} pkts/s)")
```
- **Lines 101–109**: Extracts top 3 features with highest reconstruction error.
- **Lines 118–131**: Analyzes host-level behavioral metrics to synthesize a human-readable explanation of why the anomaly was flagged.

---

# Part 8: Clustering Engine (`backend/clustering/cluster_engine.py`)

### Lines 15–54: Observation Buffering & DBSCAN Trigger
```python
15:     def add_observation(self, flow, behavior_features, ae_result, explanation):
16:         vector = [
17:             float(flow.get("dst_port") or 0),
18:             float(flow.get("duration") or 0.0),
19:             float(flow.get("fwd_packets") or 0),
20:             float(flow.get("bwd_packets") or 0),
21:             float(flow.get("fwd_bytes") or 0),
22:             float(flow.get("bwd_bytes") or 0),
23:             float(behavior_features.get("unique_destination_ports", 1)),
24:             float(behavior_features.get("connection_count", 1)),
25:             float(behavior_features.get("packet_rate", 0.0)),
26:             float(ae_result.get("anomaly_score", 0.0)),
27:         ]
...
49:         self.observations.append(record)
50:         if len(self.observations) > self.max_buffer_size:
51:             self.observations.pop(0)
52: 
53:         self._run_dbscan()
54:         return record["cluster_id"]
```
- **Lines 16–27**: Constructs 10-dimensional feature vector.
- **Lines 49–51**: Enforces 500-sample maximum FIFO buffer.
- **Line 53**: Executes `_run_dbscan()` and returns assigned cluster ID.

---

### Lines 56–112: Density Clustering & Summary Generation
```python
56:     def _run_dbscan(self):
57:         if len(self.observations) < self.min_samples:
58:             self.clusters_summary = []
59:             return
60: 
61:         X = np.array([obs["vector"] for obs in self.observations], dtype=np.float64)
62:         X_scaled = StandardScaler().fit_transform(X)
63: 
64:         labels = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit_predict(X_scaled)
```
- **Lines 57–59**: Requires at least `min_samples=3` before clustering.
- **Lines 61–64**: Standardizes vectors and fits `DBSCAN(eps=1.2, min_samples=3)`.
- **Lines 85–91**: Analyzes member statistics to attach human-readable pattern tags (`"Multi-Port Probing / Reconnaissance Pattern"` or `"High-Frequency Connection Burst Pattern"`).

---

# Part 9: Behavioral Feature Profiler (`backend/features/behavior_feature_engine.py`)

### Lines 1–58: Sliding Window Calculation
```python
7:     def __init__(self, window_seconds=10):
8:         self.window_seconds = window_seconds
9:         self.source_windows = defaultdict(deque)
...
16:         window = self.source_windows[source_ip]
17:         window.append(flow)
18: 
19:         while window and event_time - window[0]["last_seen"] > self.window_seconds:
20:             window.popleft()
...
26:         total_packets = sum(f["packet_count"] for f in window)
27:         total_bytes = sum(f["byte_count"] for f in window)
28:         unique_destinations = {f["dst_ip"] for f in window}
29:         unique_ports = {f["dst_port"] for f in window if f["dst_port"] is not None}
30:         connection_count = len(window)
31:         syn_count = sum(f.get("tcp_flags", {}).get("S", 0) for f in window)
```
- **Lines 7–9**: Configures 10-second sliding window dictionary.
- **Lines 19–20**: Pops expired flows older than 10 seconds.
- **Lines 26–57**: Computes connection counts, unique destinations/ports, packet/byte rates, and SYN flag volume.

---

# Part 10: Diagnostic & Standalone Scripts

### `backend/capture/packet_collector.py` (Lines 1–107)
Standalone CLI sniffer. Replicates `IDSPipelineService` flow capture without FastAPI. Prints ASCII diagnostic blocks for each expired flow containing 5-tuple info, directionality, behavioral metrics, and Autoencoder inference results.

### `backend/capture/test_capture.py` (Lines 1–38)
Minimal Scapy verification script. Sniffs interface index 12 with `filter="ip"` and prints live packet timestamp, IP endpoints, protocol, and byte size to stdout to verify Npcap connectivity.

### `backend/features/test_behavior_feature_engine.py` (Lines 1–40)
Test harness for `BehavioralFeatureEngine`. Simulates three sequential flows from Kali Linux (`192.168.137.128`) to ports 8001, 443, and 22, verifying sliding window metrics.

