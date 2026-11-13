# ZeroDay IDS — Known Issues, Technical Debt & Limitations

This document provides a critical engineering audit of existing vulnerabilities, race conditions, design constraints, and technical debt identified within the ZeroDay IDS codebase.

---

## 1. Deep Dive: The Dashboard Reset Bug & Race Condition Analysis

### 1.1 Original Bug Symptoms
When an operator clicked the **Reset** button in the dashboard header:
1. **Counters reset**: KPI metric counters (Packets Sniffed, Analyzed Flows, Normal, etc.) dropped to zero.
2. **Old rows remained visible**: Old traffic rows sometimes remained visible in the Recent Network Traffic table.
3. **Contradictory UI state**: The empty-state placeholder message (*"Waiting for live network flows... Browse or test the target website to begin."*) appeared simultaneously alongside lingering traffic rows.

### 1.2 Root Cause Analysis
The bug was caused by **three concurrent race conditions** spanning the background Scapy capture thread, the FastAPI request handler, and the React WebSocket event loop:

```
[Scapy Capture Thread]           [FastAPI Request Thread]           [React Frontend]
        |                                   |                               |
        |                            POST /api/reset                        |
        |                                   |                      setFlows([]) (Optimistic)
        |                                   |                               |
  Expired flow                              |                               v
  extracted from dict                       |                      Render: "Waiting for
        |                                   |                       live network flows..."
        |                             reset() clears                        |
        |                             pipeline buffers                      |
        |                                   |                               |
  ML Inference finishes                     |                               |
        |                                   |                               |
  Flow appended to                          |                               |
  supposedly-cleared deque                  |                               |
        |                                   |                               |
  broadcast(FLOW_ANALYZED) ---------------------------------------------> ws.onmessage
                                                                            |
                                                                   setFlows([stale_flow])
                                                                            |
                                                                            v
                                                                   Old row reappears
                                                                   underneath empty state!
```

#### Race Condition 1: Asynchronous Gap Between Frontend and Backend Reset
In the original implementation of `App.jsx`, clicking Reset executed:
```javascript
setFlows([]); // Clears React UI immediately
await fetch('/api/reset', { method: 'POST' }); // Network roundtrip
```
During the network latency window (5–50 ms) before the HTTP request reached the server, any flow that expired in the Scapy thread was processed and broadcast. The frontend received this pre-reset flow *after* clearing its state, prepending the old flow back into the table.

#### Race Condition 2: Lack of Thread-Safety Lock on Shared Pipeline Buffers
The Scapy capture loop (`run_capture_loop`) runs in a background daemon thread, while `/api/reset` executes on an ASGI worker thread. The reset endpoint previously cleared buffers without acquiring a mutual exclusion lock:
```python
# Unprotected concurrent mutation:
pipeline.flow_manager.flows.clear()
pipeline.recent_flows.clear()
pipeline.stats.update({...})
```
If the Scapy thread was in the middle of `process_expired_flows()`, it had already extracted the flow from `flow_manager.flows` and was executing PyTorch / Random Forest inference. When the reset cleared `recent_flows`, the Scapy thread subsequently executed `recent_flows.appendleft(flow_record)` and incremented `stats["total_flows"]`, re-populating the buffers with pre-reset data.

#### Race Condition 3: In-Flight WebSocket Messages Lacked Generation Markers
Neither WebSocket broadcasts nor the client tracked generation numbers (epochs). If a `FLOW_ANALYZED` WebSocket packet was buffered in the network stack or OS socket buffer before the reset, the React client had no mechanism to identify it as stale.

#### Explanation of the Empty State Contradiction
In React 18/19, state updates are batched. When `setFlows([])` triggered, React rendered the `flows.length === 0` fallback row. When the delayed `FLOW_ANALYZED` WebSocket event arrived a millisecond later, React appended the stale row. Because DOM reconciliation and CSS transitions were occurring simultaneously, users observed the empty-state message alongside the resurrected traffic row.

### 1.3 Implemented Fix
The bug was resolved by implementing a multi-tier synchronization and epoch-filtering mechanism:

1. **`threading.Lock` in `IDSPipelineService`**:
   Shared buffers (`stats`, `recent_flows`, `alerts`, `flow_manager.flows`, `behavior_engine.source_windows`, and `decision_engine.recent_alerts`) are now guarded by `self._lock`.
2. **Reset Epoch Generation Tracking (`_reset_epoch`)**:
   Every reset monotonically increments `self._reset_epoch`. Every `FLOW_ANALYZED` broadcast carries the epoch under which it was generated.
3. **Authoritative `RESET` Broadcast**:
   The `/api/reset` endpoint broadcasts a `{"type": "RESET", "epoch": epoch, ...}` event over WebSockets to synchronize all connected clients simultaneously.
4. **Frontend Epoch Guard**:
   In `App.jsx`, `epochRef.current` stores the active epoch. In `ws.onmessage`:
   ```javascript
   if (data.epoch !== undefined && data.epoch < epochRef.current) {
     return; // Discard stale message from prior generation
   }
   ```
   Stale in-flight messages are rejected, guaranteeing that old flows cannot reappear.

### 1.4 Unverified Reset Edge Cases
- **Multi-Tab Socket Fanout**: Verified with single and dual tabs; behavior under high-concurrency multi-client stress (e.g. 50+ concurrent browser tabs resetting simultaneously) has not been benchmarked.
- **Client Disconnection During Reset**: If a client's network drops exactly when a reset occurs, the client will remain out of sync until the WebSocket reconnects and receives `INITIAL_STATE`.

---

## 2. Interface Index Fragility (Hardcoded Adapter Index)

### Description
In `backend/api/main.py`:
```python
pipeline = IDSPipelineService(interface_index=12, model_dir="models/model B")
```
### Technical Impact
The network interface index (`12`) is hardcoded to match the development machine's adapter table (`VMware Virtual Ethernet Adapter for VMnet1`). On any other host workstation or server, index 12 may correspond to a physical Wi-Fi card, an Ethernet interface, a loopback adapter, or be completely invalid. If the index does not exist, Scapy throws a runtime exception and the backend fails to start.

### Recommended Remediation
Implement automatic adapter discovery based on IP subnet matching (e.g., searching `conf.ifaces` for an adapter with IP `192.168.137.1`), or expose `INTERFACE_INDEX` / `INTERFACE_NAME` as an environment variable (`os.getenv("IDS_INTERFACE")`).

---

## 3. Synchronous ML Inference in Packet Sniffer Thread

### Description
In `backend/services/ids_pipeline.py`:
```python
def run_capture_loop(self):
    while self.is_running:
        sniff(..., timeout=1)
        self.process_expired_flows()
```
`process_expired_flows()` executes:
1. `BehavioralFeatureEngine.add_flow()`
2. PyTorch forward pass (`Autoencoder.forward()`)
3. Scikit-learn Random Forest inference (`predict_proba()`)
4. SHAP TreeExplainer calculation (`shap_values()`)
5. DBSCAN clustering (`DBSCAN.fit_predict()`)

### Technical Impact
All inference occurs **synchronously inside the Scapy sniffer thread**. During active attacks (e.g., an nmap scan across 1,000 ports causing 1,000 flows to expire at once), computing SHAP and DBSCAN across hundreds of flows can block the thread for several seconds. During this blocking period, Scapy is not actively sniffing, causing Windows kernel socket buffers to overflow and drop packets.

### Recommended Remediation
Decouple flow expiration and ML inference into a producer-consumer architecture using `queue.Queue` or a dedicated background worker thread pool (`concurrent.futures.ThreadPoolExecutor`).

---

## 4. FlowManager Incomplete Connection Accumulation (SYN Flood)

### Description
In `backend/capture/flow_manager.py`:
```python
if key not in self.flows:
    self.flows[key] = { ... }
```
Flows are only expired when:
```python
if now - flow["last_seen"] >= self.idle_timeout:
```

### Technical Impact
1. **Lack of Active Timeout**: If an attacker maintains an active, low-rate TCP connection (sending 1 packet every 4 seconds), `now - last_seen` will never reach the 5-second `idle_timeout`. The flow will accumulate packets indefinitely and never be analyzed by the ML engine until the connection goes completely silent.
2. **SYN Flood Memory Exhaustion**: During a high-rate SYN flood using spoofed source IPs and ports, `FlowManager` creates an entry in `self.flows` for every unique `(IP, Port)` combination. While each entry will expire after 5 seconds, a flood of 100,000 SYNs/sec will allocate hundreds of thousands of dictionary objects, consuming system RAM and degrading dictionary lookup performance.

### Recommended Remediation
1. Add an `active_timeout` (e.g., 60 seconds). If `now - flow["start_time"] >= active_timeout`, expire the flow slice immediately.
2. Implement an upper bound on `len(self.flows)` (e.g., maximum 50,000 active flows), evicting the oldest uncompleted flows when capacity is reached.

---

## 5. Missing Training Assets & Dataset Artifacts

### Description
The repository structure outlined in `README.md` references `training/`, `evaluation/`, and `dataset/` directories.
- `dataset/` exists on disk as an empty directory (0 bytes).
- `training/` and `evaluation/` directories do not exist in the active tree.

### Technical Impact
While pre-trained model weights (`autoencoder_best.pt`, `random_forest.joblib`, `scaler.joblib`) are present in `models/model B/`, the original Python training scripts, hyperparameter tuning notebooks, loss curves, and dataset splitting pipelines cannot be independently inspected or re-executed from this repository.

---

## 6. Omission of PyTorch in `requirements.txt`

### Description
`backend/requirements.txt` contains:
```
fastapi
uvicorn[standard]
scapy
numpy
pandas
scikit-learn
joblib
shap
```
`torch` is **missing** from `backend/requirements.txt`.

### Technical Impact
If a developer sets up a new environment using `pip install -r backend/requirements.txt`, launching the backend will immediately crash with:
`ModuleNotFoundError: No module named 'torch'`.
`torch` must be installed separately.

---

## 7. DBSCAN Buffer Scaling Complexity

### Description
In `backend/clustering/cluster_engine.py`:
```python
X = np.array([obs["vector"] for obs in self.observations], dtype=np.float64)
X_scaled = StandardScaler().fit_transform(X)
labels = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit_predict(X_scaled)
```
DBSCAN is executed across the entire buffer (up to 500 samples) every time a new `SUSPICIOUS_UNKNOWN` flow arrives.

### Technical Impact
Standard DBSCAN has a time complexity of $O(N^2)$ with respect to sample count $N$. While $N \le 500$ is fast on modern CPUs ($\approx 5$–15 ms), executing $O(N^2)$ clustering synchronously on every single incoming anomaly flow during sustained port scans creates redundant CPU load and thread stalls.

