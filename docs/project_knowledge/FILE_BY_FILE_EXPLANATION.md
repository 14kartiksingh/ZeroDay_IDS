# ZeroDay IDS — Master File-by-File Technical Index

This master index connects every source file across the `ZeroDay_IDS` repository to its detailed line-by-line technical documentation, cross-referencing responsibilities, imports, classes, functions, input/output contracts, and downstream consumers.

---

## 1. Documentation Index & Modular Breakdown

To prevent truncation while providing an exhaustive line-by-line analysis of all source files, the code explanations are organized into three dedicated companion documents:

1. [**Backend Code Explanation (`CODE_EXPLANATION_BACKEND.md`)**](file:///e:/ZeroDay_IDS/docs/project_knowledge/CODE_EXPLANATION_BACKEND.md)
   - `backend/services/ids_pipeline.py` (256 lines) — Central pipeline service, Scapy thread, locked buffer state, reset epoch.
   - `backend/api/main.py` (125 lines) — FastAPI REST API, WebSocket hub, lifespan manager, cross-thread broadcast.
   - `backend/capture/flow_manager.py` (100 lines) — Bidirectional flow aggregation, SYN-based role normalization, idle timeout.
   - `backend/capture/packet_collector.py` (107 lines) — Standalone capture CLI test harness.
   - `backend/capture/test_capture.py` (38 lines) — Scapy adapter verification script.
   - `backend/features/behavior_feature_engine.py` (58 lines) — 10-second rolling host window behavioral profiler.
   - `backend/features/test_behavior_feature_engine.py` (40 lines) — Behavioral engine test script.
   - `backend/detection/autoencoder_detector.py` (119 lines) — PyTorch deep autoencoder, per-feature reconstruction error.
   - `backend/detection/rf_detector.py` (69 lines) — Scikit-learn multi-class Random Forest classifier.
   - `backend/detection/decision_engine.py` (129 lines) — Multi-criteria heuristic and threshold synthesis, alert deduplication.
   - `backend/explainability/xai_engine.py` (143 lines) — SHAP TreeExplainer attributions and Autoencoder anomaly summaries.
   - `backend/clustering/cluster_engine.py` (112 lines) — 10D vector buffer, DBSCAN density-based clustering, threat pattern tagging.

2. [**Frontend Code Explanation (`CODE_EXPLANATION_FRONTEND.md`)**](file:///e:/ZeroDay_IDS/docs/project_knowledge/CODE_EXPLANATION_FRONTEND.md)
   - `frontend/src/App.jsx` (373 lines) — Primary React dashboard, WebSocket client, epoch guard, traffic table, XAI modal.
   - `frontend/src/main.jsx` (10 lines) — React 19 application mounting with StrictMode.
   - `frontend/src/index.css` (7 lines) — Tailwind CSS v4 imports and dark-mode styling.
   - `frontend/src/App.css` (184 lines) — Legacy 3D transform and layout styling.
   - `frontend/index.html` (13 lines) — HTML5 shell.
   - `frontend/vite.config.js` (7 lines) — Vite build configuration.
   - `frontend/eslint.config.js` (21 lines) — ESLint configuration.
   - `frontend/package.json` (32 lines) — NPM dependency manifest.

3. [**Website & Launcher Code Explanation (`CODE_EXPLANATION_WEBSITE_AND_LAUNCHER.md`)**](file:///e:/ZeroDay_IDS/docs/project_knowledge/CODE_EXPLANATION_WEBSITE_AND_LAUNCHER.md)
   - `website/index.html` (179 lines) — NexaVault Enterprise Portal (protected target asset, interactive traffic generation).
   - `website/style.css` (365 lines) — Custom enterprise styling for NexaVault.
   - `start_zeroday_ids.bat` (38 lines) — Multi-service orchestration batch script.

---

## 2. Complete Source File Technical Matrix

| File Path | Primary Class / Function | Inputs | Internal Processing | Outputs | Downstream Consumers |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `backend/services/ids_pipeline.py` | `IDSPipelineService` | Network packets from Scapy sniffer (Interface 12) | Aggregates packets into flows, extracts expired flows, coordinates 6 ML engines, updates deques under `_lock`, stamps epoch. | `FLOW_ANALYZED` event payloads, stats, recent flows deque | `main.py` (REST endpoints, WebSocket hub) |
| `backend/api/main.py` | FastAPI app, `websocket_live_feed`, `reset_dashboard_state` | HTTP requests, WebSocket connections | Dispatches REST queries, schedules cross-thread broadcasts via `asyncio.run_coroutine_threadsafe`, broadcasts `RESET`. | JSON API responses, live WebSocket JSON stream | `frontend/src/App.jsx` (React Dashboard) |
| `backend/capture/flow_manager.py` | `FlowManager` | Parsed packet dictionaries from `ids_pipeline.py` | 5-tuple canonical hashing, SYN-based client/server role normalization, directional counters, idle timeout slicing. | Completed bidirectional flow dictionaries | `ids_pipeline.py` (`process_expired_flows`) |
| `backend/capture/packet_collector.py` | `PacketCollector` | Raw packets on interface 12 | Standalone packet sniffing and flow aggregation. | ASCII diagnostic blocks to stdout | Security operator / manual CLI testing |
| `backend/capture/test_capture.py` | `process_packet` | Raw packets on interface 12 | Checks Scapy Npcap packet reception on Windows interface index 12. | Packet timestamp and size lines to stdout | Developer diagnostic check |
| `backend/features/behavior_feature_engine.py` | `BehavioralFeatureEngine` | Completed flow dictionary | Maintains 10-second sliding FIFO window per source IP; computes connection count, unique ports, packet/byte rates. | `behavior_features` dictionary | `ids_pipeline.py`, `decision_engine.py`, `xai_engine.py` |
| `backend/features/test_behavior_feature_engine.py` | Script execution | 3 synthetic flow dictionaries | Ingests sequential flows and validates rolling window calculations. | Printed behavioral feature dictionary | Unit verification |
| `backend/detection/autoencoder_detector.py` | `AutoencoderDetector`, `Autoencoder` | Completed flow dictionary | Converts duration to $\mu s$, $\ln(1+x)$ rate scaling, PyTorch forward pass, calculates MSE vs threshold `0.004877559`. | `ae_result` dictionary (anomaly score, status, per-feature errors) | `ids_pipeline.py`, `decision_engine.py`, `xai_engine.py` |
| `backend/detection/rf_detector.py` | `RandomForestDetector` | Completed flow dictionary | Extracts 9 features, $\ln(1+x)$ rate scaling, Scikit-learn Random Forest prediction across 6 classes. | `rf_result` dictionary (predicted class, confidence, probabilities) | `ids_pipeline.py`, `decision_engine.py`, `xai_engine.py` |
| `backend/detection/decision_engine.py` | `DecisionEngine` | `flow`, `behavior_features`, `ae_result`, `rf_result` | Multi-criteria conditional evaluation (Multi-port recon -> RF signature -> DoS flood -> Severe anomaly -> Normal); 4s deduplication. | `decision` dictionary (outcome, label, severity, reason) | `ids_pipeline.py`, `xai_engine.py`, `cluster_engine.py` |
| `backend/explainability/xai_engine.py` | `ExplainabilityEngine` | `decision`, `behavior_features`, `ae_result`, `rf_result` | SHAP TreeExplainer on Random Forest for known attacks; Autoencoder error ranking + behavioral context for zero-day anomalies. | `explanation` dictionary (method, summary, top features) | `ids_pipeline.py`, React UI modal |
| `backend/clustering/cluster_engine.py` | `ClusteringEngine` | `flow`, `behavior_features`, `ae_result`, `explanation` | Buffers up to 500 zero-day vectors, standardizes features, executes DBSCAN (`eps=1.2`, `min_samples=3`), computes cluster summaries. | `cluster_id` (integer) and cluster summaries | `ids_pipeline.py`, `main.py` (`/api/clusters`) |
| `frontend/src/App.jsx` | `App` | WebSocket messages (`INITIAL_STATE`, `RESET`, `FLOW_ANALYZED`) | Manages connection status, KPI metrics, epoch guard filtering, 20-row table slicing, inspection modal state. | Interactive Threat Monitor UI on port 5173 | Security analyst / end user |
| `frontend/src/main.jsx` | React root renderer | `<App />` component | StrictMode root initialization. | Mounts React virtual DOM into `#root` | Web browser |
| `website/index.html` | NexaVault Portal | User clicks and form submissions | Generates normal HTTP browsing traffic, SSO login attempts, and IT support ticket submissions on port 8001. | HTTP request/response traffic on port 8001 | Captured by Scapy on VMnet1 |
| `start_zeroday_ids.bat` | Windows Batch Script | User execution | Spawns NexaVault (8001), FastAPI backend (8000), Vite frontend (5173), and opens default browser. | Three background command windows and browser session | Operating system runtime |

