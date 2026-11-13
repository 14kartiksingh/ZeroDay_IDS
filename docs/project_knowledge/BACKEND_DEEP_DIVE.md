# ZeroDay IDS — Backend Deep Dive

This document provides a comprehensive technical breakdown of the ZeroDay IDS backend subsystems, detailing every module, class, method, data structure, concurrency primitive, and lifecycle mechanism.

---

## 1. FastAPI Application & WebSocket Hub (`backend/api/main.py`)

### 1.1 Module Overview
`main.py` serves as the entry point for the REST API and WebSocket communication layer. It instantiates the central `IDSPipelineService`, manages asynchronous WebSocket client pools, schedules cross-thread broadcasts, and defines the application lifecycle.

### 1.2 Global Variables & Data Structures
- `pipeline: IDSPipelineService`: Singleton pipeline instance initialized with `interface_index=12` and `model_dir="models/model B"`.
- `connected_clients: set`: A Python set storing active `fastapi.WebSocket` connection objects.
- `main_event_loop: asyncio.AbstractEventLoop`: Reference to the running asyncio event loop captured during FastAPI lifespan initialization.

### 1.3 Asynchronous Lifespan Management
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_event_loop
    main_event_loop = asyncio.get_running_loop()
    pipeline.on_event_callback = broadcast_from_thread

    # Start live packet capture in a daemon background thread
    capture_thread = threading.Thread(target=pipeline.run_capture_loop, daemon=True)
    capture_thread.start()
    print("FastAPI + Live ML Detection Engine started on port 8000!")

    yield

    pipeline.stop()
    print("IDS Pipeline stopped.")
```
- **Lifecycle Hook**: Uses FastAPI 0.93+ `@asynccontextmanager` pattern.
- **Loop Capture**: Stores `asyncio.get_running_loop()` so that background threads can schedule coroutines on the main thread's event loop.
- **Daemon Thread**: Spawns `pipeline.run_capture_loop` as a daemon thread, ensuring it terminates when the main Python process exits.
- **Graceful Shutdown**: Calls `pipeline.stop()`, setting `pipeline.is_running = False` to break Scapy's loop.

### 1.4 Cross-Thread WebSocket Broadcasting
- `broadcast_from_thread(payload: dict)`:
  Called by the Scapy sniffer thread when a flow has been analyzed. It invokes:
  ```python
  asyncio.run_coroutine_threadsafe(broadcast_json(payload), main_event_loop)
  ```
  This safely bridges the synchronous worker thread and the asynchronous ASGI event loop without thread deadlocks or event loop corruption.
- `broadcast_json(payload: dict)`:
  Iterates over `list(connected_clients)` and calls `await ws.send_json(payload)`. If a client socket is closed or raises an exception, it is appended to `disconnected` and discarded from `connected_clients`.

### 1.5 REST API Endpoints
| Endpoint | Method | Response / Description |
| :--- | :---: | :--- |
| `/api/health` | GET | Returns `{"status": "online", "capturing": pipeline.is_running}` for health probes. |
| `/api/stats` | GET | Returns `pipeline.get_stats()` containing total packets, flow breakdown, uptime, capturing status, and current epoch. |
| `/api/flows` | GET | Query param `limit` (default 50). Returns `list(pipeline.recent_flows)[:limit]`. |
| `/api/alerts` | GET | Query param `limit` (default 50). Returns `list(pipeline.alerts)[:limit]`. |
| `/api/clusters`| GET | Returns `pipeline.clustering_engine.get_clusters()`, summarizing active DBSCAN clusters. |
| `/api/reset` | POST | Calls `epoch = pipeline.reset()`, then immediately broadcasts a `{"type": "RESET", "epoch": epoch, ...}` WebSocket event to all connected clients and returns `{"status": "reset_complete", "epoch": epoch}`. |

### 1.6 WebSocket Route (`/ws/live`)
- Handshake: Accepts connection and adds `websocket` to `connected_clients`.
- Snapshot Push: Immediately transmits `INITIAL_STATE` payload containing current stats, latest 30 flows, latest 30 alerts, active clusters, and the server's current epoch.
- Keepalive Loop: Enters `while True: await websocket.receive_text()`. On disconnect, catches `WebSocketDisconnect` and removes the client.

---

## 2. Core Orchestration Service (`backend/services/ids_pipeline.py`)

### 2.1 Module Overview
`IDSPipelineService` coordinates the entire pipeline. It interfaces with Scapy for raw packet capture, delegates to `FlowManager` for stateful flow aggregation, invokes the six ML components upon flow expiration, and maintains thread-safe buffers for the REST and WebSocket APIs.

### 2.2 Class Variables & State Initialization
```python
self.interface_index = interface_index
self.interface = conf.ifaces.dev_from_index(interface_index)
self.is_running = False
self._lock = threading.Lock()
self._reset_epoch = 0
```
- `_lock`: Mutual exclusion lock preventing race conditions between the Scapy thread's flow processing and HTTP request threads calling `/api/reset`.
- `_reset_epoch`: Integer monotonically incremented on each reset to track generation numbers.
- `recent_flows`: `collections.deque(maxlen=100)` storing recent flow records for the dashboard.
- `alerts`: `collections.deque(maxlen=100)` storing flagged security alerts.
- `stats`: Dictionary tracking `total_packets`, `total_flows`, `normal_flows`, `known_attacks`, `unknown_anomalies`, and `start_time`.

### 2.3 Packet Parsing (`_parse_packet`)
```python
def _parse_packet(self, packet):
    if IP not in packet:
        return None
    ip = packet[IP]
    if ip.dst.startswith(("224.", "239.")) or ip.dst == "255.255.255.255":
        return None
    # Extracts ports, protocol (TCP/UDP/Other), packet length, and TCP flags
```
- Ignores non-IP frames (ARP, LLC, STP).
- Filters out multicast and local broadcast frames.
- Returns a structured dictionary containing `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `packet_size`, and `tcp_flags`.

### 2.4 Expired Flow Processing & ML Execution
`process_expired_flows()` is executed periodically within the capture loop.
1. Calls `self.flow_manager.get_expired_flows()` to extract completed flows.
2. For each flow, executes ML inference **outside the lock**:
   - `behavior_features = self.behavior_engine.add_flow(flow)`
   - `ae_result = self.autoencoder.predict(flow)`
   - `rf_result = self.random_forest.predict(flow)`
   - `decision = self.decision_engine.evaluate(flow, behavior_features, ae_result, rf_result)`
   - `explanation = self.xai_engine.explain(decision, behavior_features, ae_result, rf_result)`
   - If `decision["outcome"] == "SUSPICIOUS_UNKNOWN"`, invokes `cluster_id = self.clustering_engine.add_observation(...)`.
3. Enters the **critical section** protected by `with self._lock`:
   - Increments `total_flows` and specific outcome counters.
   - Creates the unified `flow_record` dictionary.
   - Appends to `self.recent_flows` (and `self.alerts` if non-normal and non-duplicate).
   - Snapshots the current `_reset_epoch` and builds the `FLOW_ANALYZED` payload.
4. Outside the lock, calls `self.on_event_callback(payload)` to dispatch the WebSocket broadcast.

### 2.5 Thread-Safe Reset Operation (`reset()`)
```python
def reset(self):
    with self._lock:
        self._reset_epoch += 1
        self.flow_manager.flows.clear()
        self.recent_flows.clear()
        self.alerts.clear()
        self.clustering_engine.observations.clear()
        self.clustering_engine.clusters_summary.clear()
        self.behavior_engine.source_windows.clear()
        self.decision_engine.recent_alerts.clear()
        self.stats.update({
            "total_packets": 0,
            "total_flows": 0,
            "normal_flows": 0,
            "known_attacks": 0,
            "unknown_anomalies": 0
        })
        return self._reset_epoch
```
- Acquires `self._lock` before modifying any state.
- Bumps `_reset_epoch`, invalidating any stale broadcasts in flight.
- Completely flushes active in-progress flows from `flow_manager.flows`, preventing partial flows from leaking post-reset.
- Flushes behavioral sliding windows and deduplication caches.
- Restores all counters to zero.

---

## 3. Bidirectional Flow Management (`backend/capture/flow_manager.py`)

### 3.1 Module Overview
`flow_manager.py` reconstructs network streams from unordered packet streams, tracking cumulative metrics for each bidirectional session.

### 3.2 Canonical Flow Key Formulation
```python
def get_flow_key(self, packet):
    source = (packet["src_ip"], packet["src_port"])
    destination = (packet["dst_ip"], packet["dst_port"])
    endpoints = tuple(sorted([source, destination]))
    return endpoints, packet["protocol"]
```
Because `sorted()` standardizes the order of endpoints, packets traveling from $A \to B$ and $B \to A$ hash to the exact same key.

### 3.3 Role Normalization Logic
When a new flow key is observed, the system determines which endpoint is the forward initiator (client) and which is the backward responder (server):
1. **Pure SYN Packet** (`"S" in flags and "A" not in flags`): The packet sender is the client (`is_server_first = False`).
2. **SYN-ACK Packet** (`"S" in flags and "A" in flags`): The packet sender is the server responding to a SYN (`is_server_first = True`).
3. **Mid-stream Packet without SYN**: Compares `src_port` and `dst_port`. The lower port ($< 32768$) is assumed to be the well-known listening service, making the sender with the higher port the client.

### 3.4 Directional Accounting
Every packet updates:
- `last_seen = now`
- `packet_count += 1`, `byte_count += packet_size`
- Forward/backward split: If `packet["src_ip"] == flow["src_ip"]` and `src_port == flow["src_port"]`, it increments `fwd_packets`, `fwd_bytes`, and records TCP flags in `fwd_tcp_flags`. Otherwise, it updates `bwd_packets`, `bwd_bytes`, and `bwd_tcp_flags`.

### 3.5 Expiration Extraction
`get_expired_flows()` checks every active flow:
```python
if now - flow["last_seen"] >= self.idle_timeout:
    completed_flow = flow.copy()
    completed_flow["duration"] = flow["last_seen"] - flow["start_time"]
    expired.append(completed_flow)
    del self.flows[key]
```
`idle_timeout` defaults to 10 seconds in `flow_manager.py`, but is instantiated with 5 seconds in `ids_pipeline.py` to provide rapid dashboard feedback.

---

## 4. Standalone Packet Collector (`backend/capture/packet_collector.py`)

### 4.1 Overview & Role
`packet_collector.py` is an independent command-line testing harness that duplicates core capture logic without launching FastAPI or the React dashboard.

### 4.2 Internal Architecture
- Instantiates `FlowManager(idle_timeout=10)`, `BehavioralFeatureEngine(window_seconds=10)`, and `AutoencoderDetector(model_dir="models/model B")`.
- Captures packets on interface index 12 using `sniff()`.
- Upon flow expiration, prints detailed ASCII diagnostic blocks to stdout:
  - Source/Destination IP and Ports
  - Directional confidence and SYN flag counts
  - Calculated behavioral features
  - Autoencoder anomaly score, threshold, and status

---

## 5. Behavioral Feature Profiler (`backend/features/behavior_feature_engine.py`)

### 5.1 Architecture & Sliding Window Algorithm
The engine tracks temporal host behavior to detect port scanning, brute force attacks, and high-frequency flood patterns.
- Data Structure: `self.source_windows = defaultdict(deque)`
- Window Purging:
  ```python
  window = self.source_windows[source_ip]
  window.append(flow)
  while window and event_time - window[0]["last_seen"] > self.window_seconds:
      window.popleft()
  ```
  Discards any flow whose `last_seen` timestamp is older than 10 seconds relative to the current flow's timestamp.

### 5.2 Computed Metrics
1. `connection_count`: `len(window)` — Total flows completed by this source in the last 10 seconds.
2. `unique_destination_ips`: `len({f["dst_ip"] for f in window})`.
3. `unique_destination_ports`: `len({f["dst_port"] for f in window if f["dst_port"] is not None})`.
4. `total_packets`: Cumulative packet count across window flows.
5. `total_bytes`: Cumulative byte volume across window flows.
6. `syn_count`: Total SYN flags emitted across window flows.
7. `packet_rate`: `total_packets / 10.0` (pkts/sec).
8. `byte_rate`: `total_bytes / 10.0` (bytes/sec).

---

## 6. Unsupervised Clustering Engine (`backend/clustering/cluster_engine.py`)

### 6.1 Purpose
When the Decision Engine flags a flow as `SUSPICIOUS_UNKNOWN`, the event is passed to `ClusteringEngine`. Rather than leaving zero-day events as disconnected alerts, this engine uses DBSCAN to automatically aggregate related events into behavioral attack clusters.

### 6.2 10-Dimensional Vector Formulation
For each zero-day observation, the engine extracts:
$$\vec{v} = \begin{bmatrix}
\text{dst\_port} \\
\text{duration} \\
\text{fwd\_packets} \\
\text{bwd\_packets} \\
\text{fwd\_bytes} \\
\text{bwd\_bytes} \\
\text{unique\_destination\_ports} \\
\text{connection\_count} \\
\text{packet\_rate} \\
\text{anomaly\_score}
\end{bmatrix}$$

### 6.3 DBSCAN Clustering Execution
- Buffer: Stores observations up to `max_buffer_size=500` (FIFO).
- Minimum Threshold: If `len(self.observations) < self.min_samples` (3), clustering is skipped.
- Standardization: Standardizes features using `sklearn.preprocessing.StandardScaler().fit_transform(X)`.
- Density Clustering: Executes `DBSCAN(eps=1.2, min_samples=3).fit_predict(X_scaled)`.
- Label Assignment: Assigns `cluster_id = int(label)` to each observation. Core/density reachable points receive non-negative integer IDs ($0, 1, 2\dots$), while sparse noise points receive `-1`.

### 6.4 Cluster Telemetry Summarization
For each discovered cluster ID ($c \neq -1$), the engine summarizes:
- `event_count`: Number of member flows in the cluster.
- `source_ips`: Sorted unique source IP addresses involved.
- `avg_anomaly_score`: Mean autoencoder error across cluster members.
- `max_unique_ports`: Maximum unique ports scanned by any member.
- `dominant_xai_driver`: Most frequent top feature driver identified by XAI.
- `pattern_summary`: Heuristic tag derived from cluster metrics:
  - If `max_ports >= 5`: `"Multi-Port Probing / Reconnaissance Pattern"`
  - Else if `max_conns >= 15`: `"High-Frequency Connection Burst Pattern"`
  - Else: `"Recurring Structural Payload Anomaly"`

