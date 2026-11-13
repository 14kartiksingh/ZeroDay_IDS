# ZeroDay IDS — Complete Project File Inventory

This inventory documents every file in the `ZeroDay_IDS` repository. Temporary directories, Python virtual environments (`venv/`), Node package dependencies (`node_modules/`), compiled bytecode (`__pycache__/`), and build output (`dist/`) are excluded from source-code listings.

---

## 1. Inventory Summary by Category

| Category | File Count | Primary Languages / Formats | Description |
| :--- | :---: | :--- | :--- |
| **1. Backend Source Code** | 3 | Python | Core service orchestration, API definitions, lifecycle management |
| **2. Network Packet Capture** | 3 | Python | Scapy sniffer wrappers, 5-tuple flow aggregation, verification scripts |
| **3. Feature Engineering** | 2 | Python | Rolling 10s behavioral host window feature extraction and test harness |
| **4. ML Detection Components** | 3 | Python | PyTorch Autoencoder detector, Scikit-learn RF detector, Decision Engine |
| **5. Explainability (XAI)** | 1 | Python | SHAP TreeExplainer integration and Autoencoder per-feature error analysis |
| **6. Clustering** | 1 | Python | Unsupervised DBSCAN clustering of unlabelled zero-day anomalies |
| **7. API & WebSocket Communication** | 1 | Python | FastAPI endpoints, WebSocket connection pool, broadcast dispatching |
| **8. Frontend Source Code** | 8 | JSX, JS, CSS, SVG | React 19 UI components, styling, Vite entry point, SVG brand assets |
| **9. Training Scripts** | 0 | N/A | *Not committed in repo tree* (performed offline; documented in section 3) |
| **10. Evaluation Scripts** | 0 | N/A | *Not committed in repo tree* (performed offline; documented in section 3) |
| **11. Configuration Files** | 6 | JSON, JS, TXT, BAT | Package configs, Vite config, ESLint config, requirements, launcher |
| **12. Dataset & Model Artifacts** | 11 | PT, JOBLIB, NPY, JSON, ZIP | Trained model weights, scalers, thresholds, model metadata, archives |
| **13. Documentation** | 1 | Markdown | Root repository README.md |
| **14. Protected Test Website** | 2 | HTML, CSS | NexaVault Enterprise Portal (benign target website hosted on port 8001) |
| **15. Project Archives & Backups** | 2 | ZIP, RAR | Compressed snapshots of codebase iterations (`f.zip`, `f.rar`) |
| **Total Tracked Project Files** | **44** | | *(Excludes venv, node_modules, .git, and cache files)* |

---

## 2. Detailed File-by-File Inventory

### 2.1 Backend Source Code & Orchestration
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `backend/services/ids_pipeline.py` | 10,213 | Backend / Core | Central orchestration engine. Manages Scapy packet capture thread, flow expiration loop, coordinates all 6 ML components, maintains live deques and counters, provides thread-safe locked reset with epoch stamping. |
| `backend/api/main.py` | 3,630 | Backend / API | FastAPI web server application. Exposes REST endpoints (`/api/stats`, `/api/flows`, `/api/alerts`, `/api/clusters`, `/api/reset`), handles WebSocket connections (`/ws/live`), and dispatches thread-safe broadcasts. |
| `backend/requirements.txt` | 71 | Configuration | Python package dependency specification (`fastapi`, `uvicorn`, `scapy`, `numpy`, `pandas`, `scikit-learn`, `joblib`, `shap`). Note: `torch` is additionally required at runtime. |

### 2.2 Network Packet Capture & Flow Aggregation
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `backend/capture/flow_manager.py` | 3,687 | Packet Capture | Bidirectional network flow reconstruction. Aggregates packets into 5-tuple keys `((src, sport), (dst, dport), proto)`. Implements SYN-based TCP/IP client-server role normalization and flow expiration via idle timeout (5s default). |
| `backend/capture/packet_collector.py` | 3,338 | Packet Capture | Standalone packet capture CLI harness. Runs Scapy sniffer on interface index 12, performs flow aggregation, and prints real-time flow metadata and Autoencoder predictions to stdout. |
| `backend/capture/test_capture.py` | 836 | Packet Capture / Test | Minimal Scapy packet sniffing diagnostic script. Confirms Npcap permissions and packet reception on interface index 12 without starting full pipeline. |

### 2.3 Feature Engineering
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `backend/features/behavior_feature_engine.py` | 1,742 | Feature Engineering | Host-level behavioral profiler. Maintains rolling 10-second sliding windows per source IP. Computes connection counts, unique destination IPs/ports, packet/byte transmission rates, and TCP SYN counts. |
| `backend/features/test_behavior_feature_engine.py` | 971 | Feature Engineering / Test | Unit verification script for `BehavioralFeatureEngine`. Feeds three synthetic flows from `192.168.137.128` to `192.168.137.1` and verifies rolling window calculations. |

### 2.4 Machine Learning Detection Components
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `backend/detection/autoencoder_detector.py` | 4,269 | ML Detection | PyTorch Deep Autoencoder detector (9 -> 64 -> 32 -> 16 -> 32 -> 64 -> 9). Computes flow reconstruction Mean Squared Error (MSE), compares against calibrated threshold (`0.004877559`), and outputs per-feature error contributions. |
| `backend/detection/rf_detector.py` | 2,460 | ML Detection | Scikit-learn Random Forest multiclass classifier (100 estimators, max depth 16). Predicts class probabilities across 6 categories: `BENIGN`, `Botnet`, `Brute Force`, `DoS / DDoS`, `Infiltration`, `Web Attack`. |
| `backend/detection/decision_engine.py` | 5,205 | ML Detection / Rules | Multi-criteria security verdict evaluator. Synthesizes Autoencoder anomaly score, Random Forest confidence, and behavioral metrics into verdicts: `NORMAL`, `KNOWN_ATTACK`, or `SUSPICIOUS_UNKNOWN`. Includes 4s alert deduplication. |

### 2.5 Explainability & Clustering
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `backend/explainability/xai_engine.py` | 6,209 | Explainability | Explainable AI engine using `shap.TreeExplainer` for Random Forest attack predictions, and Autoencoder per-feature reconstruction error rankings alongside rolling behavioral telemetry for zero-day anomalies. |
| `backend/clustering/cluster_engine.py` | 4,570 | Clustering | Unsupervised anomaly grouping engine. Maintains a rolling FIFO buffer of up to 500 `SUSPICIOUS_UNKNOWN` flows and applies DBSCAN (`eps=1.2`, `min_samples=3`) on standardized 10-dimensional feature vectors. |

### 2.6 Frontend Source Code & Web Assets
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `frontend/src/App.jsx` | 15,177 | Frontend / React | Primary React dashboard component. Establishes live WebSocket connection, manages KPI state counters, renders Recent 20 Network Traffic table with epoch-based stale message filtering, and renders flow inspection modal. |
| `frontend/src/main.jsx` | 229 | Frontend / React | React application entry point. Initializes React 19 `createRoot` with `StrictMode` and mounts `<App />` into `#root`. |
| `frontend/src/index.css` | 142 | Frontend / CSS | Global CSS entry importing Tailwind CSS (`@import "tailwindcss";`) and defining base dark-mode slate body styles. |
| `frontend/src/App.css` | 2,891 | Frontend / CSS | Legacy stylesheet containing hero 3D transform utility styles and landing page CSS rules. |
| `frontend/index.html` | 412 | Frontend / HTML | HTML5 shell for the React application with UTF-8 viewport meta tags, CDN script tag, and root container. |
| `frontend/public/favicon.svg` | 9,522 | Frontend / Asset | Scalable Vector Graphic browser tab icon representing a security shield. |
| `frontend/public/icons.svg` | 5,031 | Frontend / Asset | SVG icon sprite sheet for UI badges and indicators. |
| `frontend/src/assets/hero.png` | 13,057 | Frontend / Asset | Application hero image asset. |
| `frontend/src/assets/react.svg` | 4,126 | Frontend / Asset | Official React SVG logo asset. |
| `frontend/src/assets/vite.svg` | 8,709 | Frontend / Asset | Official Vite SVG build tool logo asset. |

### 2.7 Frontend Build & Linter Configurations
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `frontend/package.json` | 757 | Configuration | Node package manifest defining dependencies (`react` 19, `lucide-react`, `@tailwindcss/vite`, `vite` 8) and scripts (`dev`, `build`, `lint`). |
| `frontend/package-lock.json` | 93,632 | Configuration | Deterministic lockfile pinning exact versions of all transitive NPM dependencies. |
| `frontend/vite.config.js` | 192 | Configuration | Vite build configuration enabling `@vitejs/plugin-react` and `@tailwindcss/vite`. |
| `frontend/eslint.config.js` | 568 | Configuration | Flat ESLint configuration enabling React Hooks and React Refresh linting rules. |
| `frontend/.gitignore` | 70 | Configuration | Specifies files ignored by Git (`node_modules`, `dist`). |
| `frontend/README.md` | 1,027 | Documentation | Default Vite + React starter template documentation. |

### 2.8 Protected Test Web Application (NexaVault)
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `website/index.html` | 8,198 | Test Website | Realistic corporate cloud portal ("NexaVault Enterprise"). Features infrastructure metric tiles, interactive employee SSO login form, and IT support ticket form for generating realistic benign HTTP/TCP traffic. |
| `website/style.css` | 6,553 | Test Website | Custom CSS stylesheet for NexaVault portal, implementing responsive grid, navigation bar, interactive cards, and form styling. |

### 2.9 Machine Learning Model Artifacts
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `models/metadata.json` | 368 | Model Artifact | Root model metadata pointer defining Model B configuration, 9 input features, threshold `0.004877559`, and best validation loss `0.0004566`. |
| `models/model B/autoencoder_best.pt` | 31,073 | Model Artifact | PyTorch serialized state dictionary of the trained benign-only deep autoencoder (Model B). |
| `models/model B/random_forest.joblib` | 4,650,713 | Model Artifact | Serialized Scikit-learn RandomForestClassifier model (Model B) with 100 decision trees. |
| `models/model B/scaler.joblib` | 1,231 | Model Artifact | Serialized Scikit-learn StandardScaler trained on Model B dataset features. |
| `models/model B/threshold.npy` | 132 | Model Artifact | NumPy array storing the calibrated anomaly threshold (`0.004877559`). |
| `models/model B/metadata.json` | 368 | Model Artifact | JSON metadata file detailing Model B features, threshold, and training version. |
| `models/model B/Model_B.zip` | 27,069 | Model Artifact | Archive backup containing Model B scaler, autoencoder weights, and threshold array. |
| `models/model A/autoencoder_best.pt` | 31,073 | Model Artifact | PyTorch weights for earlier iteration Model A autoencoder. |
| `models/model A/scaler.joblib` | 1,247 | Model Artifact | StandardScaler for Model A features (uses `Destination Port` rather than `Dst Port`). |
| `models/model A/metadata.json` | 613 | Model Artifact | Metadata for Model A, threshold `0.01709`, threshold percentile `99.5%`. |
| `models/model A/ZeroDay_IDS_Artifacts.zip` | 27,313 | Model Artifact | Archive backup of Model A artifacts. |

### 2.10 Launchers, Root Metadata & Code Archives
| File Path | Size (Bytes) | Category | Responsibility & Purpose |
| :--- | :---: | :--- | :--- |
| `start_zeroday_ids.bat` | 1,409 | Automation / Launcher | Windows Batch script launching NexaVault (port 8001), FastAPI backend (port 8000), and React Vite dev server (port 5173), then launching the browser. |
| `README.md` | 765 | Documentation | High-level project summary and directory structure outline. |
| `f.zip` | 175,843 | Project Archive | Codebase snapshot archive of an earlier iteration containing earlier frontend and backend code. |
| `f.rar` | 169,891 | Project Archive | Codebase snapshot archive compressed with WinRAR. |
| `dataset/` | 0 (dir) | Dataset | Directory intended for training datasets; currently empty on disk. |

---

## 3. Audit of Missing or External Components

1. **Training Scripts (`training/`)**: Referenced in the root `README.md`, but no training scripts exist in the repository filesystem. Model training was performed offline and only the resulting binary artifacts (`.pt`, `.joblib`, `.npy`) were committed to `models/`.
2. **Evaluation Scripts (`evaluation/`)**: Referenced in `README.md`, but not present in the workspace filesystem. Evaluation was executed offline during the research phase.
3. **Raw Dataset Files (`dataset/`)**: The directory exists on disk but is empty (0 bytes). Training datasets (such as CSE-CIC-IDS2018 or CNS2022) were kept off the active repo tree due to large file sizes.
4. **Kali Linux Attack Generator Scripts**: Kali Linux operates as an external virtual machine (`192.168.137.128`) generating traffic via standard security auditing tools (`hping3`, `nmap`, `hydra`, `curl`, custom Python attack scripts). These scripts execute inside the Kali guest OS and are not stored in this Windows repository.

