# ZeroDay IDS — Project Overview & Technical Mission

## 1. Executive Summary

**ZeroDay IDS** is a hybrid, machine learning-driven Network Intrusion Detection System designed to monitor live network traffic, detect known attack vectors, and identify unknown or unseen zero-day anomalies in real time. 

Traditional Signature-based Intrusion Detection Systems (such as Snort or Suricata) rely on deterministic rule sets and known attack signatures. While effective against known threats, they are fundamentally incapable of recognizing zero-day exploits, novel evasion techniques, or structural deviations in network traffic for which no signature exists. Conversely, naive anomaly detection systems that flag any statistical deviation suffer from high false-positive rates, overwhelming security analysts with benign noise.

ZeroDay IDS addresses this challenge by deploying a **six-component hybrid machine learning pipeline**:
1. **Behavioral Feature Engine**: Tracks host-level activity across a rolling 10-second temporal window.
2. **Benign-only Deep Autoencoder (PyTorch)**: Measures flow-level structural deviations against a baseline trained purely on benign network traffic.
3. **Random Forest Classifier (Scikit-Learn)**: Classifies known attack signatures across six multiclass categories.
4. **Decision Engine**: Synthesizes statistical, signature, and behavioral telemetry into a single, actionable security verdict (`NORMAL`, `KNOWN_ATTACK`, or `SUSPICIOUS_UNKNOWN`).
5. **Explainable AI (XAI) Engine (SHAP)**: Explains *why* an alert was raised using TreeExplainer SHAP attributions for known attacks and per-feature reconstruction error metrics for zero-day anomalies.
6. **Clustering Engine (DBSCAN)**: Automatically groups recurring, unlabelled zero-day anomalies into behavioral threat clusters to identify coordinated reconnaissance or novel attack campaigns.

The system is deployed on a Windows host monitoring live traffic on a dedicated VMware virtual network adapter (`VMnet1`), defending a target enterprise web application (**NexaVault Enterprise Portal**, port 8001) against live penetration testing and traffic generation from a **Kali Linux virtual machine**. Live detections and forensic insights are pushed via WebSockets to a **React 19 + Tailwind CSS** dashboard.

---

## 2. Key Objectives & Design Principles

| Principle | Architectural Implementation |
| :--- | :--- |
| **Hybrid Dual-Path ML** | Combines supervised learning (Random Forest) for high-precision known attack classification with unsupervised representation learning (Autoencoder) for novel anomaly detection. |
| **Real-time Live Packet Sniffing** | Uses Scapy on the Windows host network stack to capture live IP packets, construct bidirectional flows, and analyze expired flows with sub-second latency. |
| **Explainable Security Decisions** | Every flagged flow includes human-interpretable feature attributions (SHAP values or Autoencoder error vectors) displayed directly in the dashboard modal. |
| **Zero-Day Grouping & Discovery** | Unsupervised DBSCAN density-based clustering groups isolated anomalous flows into cohesive attack campaigns without requiring retraining or manual labeling. |
| **Interactive Live Threat Monitoring** | WebSocket connection streams analyzed flows, live telemetry counters, and cluster summaries to a modern React UI with zero polling overhead. |

---

## 3. High-Level Architecture Overview

```
                                      +---------------------------------------------+
                                      |             Kali Linux VM                   |
                                      |            192.168.137.128                  |
                                      |  (Simulates Normal Browsing & Attacks)      |
                                      +----------------------+----------------------+
                                                             |
                                                             | Virtual Ethernet (VMnet1)
                                                             v
+=================================================================================================================+
|  WINDOWS HOST WORKSTATION (192.168.137.1)                                                                       |
|                                                                                                                 |
|   +---------------------------------------+               +---------------------------------------+             |
|   | Protected Target Web Application      |               | Scapy Packet Sniffer & Flow Manager   |             |
|   | NexaVault Enterprise Portal           |               | (ids_pipeline.py on Interface Index 12) |            |
|   | Python HTTP Server on Port 8001       |               | - Captures IP/TCP/UDP packets         |             |
|   | http://localhost:8001                 |               | - Aggregates 5-tuple bidirectional    |             |
|   +---------------------------------------+               |   flows with 5s idle timeout          |             |
|                                                           +-------------------+-------------------+             |
|                                                                               |                                 |
|                                                                               v (Expired Flow Dict)             |
|                                   +---------------------------------------------------------------+             |
|                                   |             SIX-COMPONENT HYBRID ML ENGINE                    |             |
|                                   |                                                               |             |
|                                   |  1. Behavioral Feature Engine (10s rolling host window)       |             |
|                                   |  2. PyTorch Autoencoder (Reconstruction error vs 0.00488)    |             |
|                                   |  3. Random Forest (Multi-class signature detection)           |             |
|                                   |  4. Decision Engine (NORMAL / KNOWN / ZERO-DAY verdict)       |             |
|                                   |  5. Explainable AI Engine (SHAP TreeExplainer & AE errors)   |             |
|                                   |  6. Clustering Engine (DBSCAN eps=1.2, min_samples=3)         |             |
|                                   +-------------------------------+-------------------------------+             |
|                                                                   |                                             |
|                                                                   v (Thread-safe locked state update)           |
|   +---------------------------------------------------------------+-------------------------------+             |
|   | FastAPI Web Service & WebSocket Hub (main.py, Port 8000)                                      |             |
|   | - REST Endpoints: /api/stats, /api/flows, /api/alerts, /api/clusters, /api/reset              |             |
|   | - WebSocket Endpoint: /ws/live (Pushes FLOW_ANALYZED, RESET, INITIAL_STATE)                   |             |
|   +---------------------------------------------------------------+-------------------------------+             |
|                                                                   |                                             |
|                                                                   v (WebSocket JSON Stream)                     |
|   +---------------------------------------------------------------+-------------------------------+             |
|   | React 19 Live Threat Monitor Frontend (Port 5173)                                              |             |
|   | - Live KPI stat counters (Packets, Analyzed Flows, Normal, Known Attacks, Zero-Day Anomalies) |             |
|   | - Recent 20 Network Traffic Table with real-time row insertion and epoch filtering            |             |
|   | - Detailed Flow Inspection Modal with SHAP attribution bars and Autoencoder error breakdown   |             |
|   +-----------------------------------------------------------------------------------------------+             |
+=================================================================================================================+
```

---

## 4. Current Repository Status & Verification Matrix

An exhaustive audit of the actual codebase reveals the implementation status of each architectural component:

| Component | Repository Path | Implementation Status | Notes |
| :--- | :--- | :--- | :--- |
| **FastAPI Backend & WS** | `backend/api/main.py` | **Implemented & Verified** | Provides REST endpoints and live WebSocket broadcasting. Includes thread-safe reset notification. |
| **Core IDS Pipeline** | `backend/services/ids_pipeline.py` | **Implemented & Verified** | Manages Scapy thread, flow expiration, ML invocation, and thread-safe locked buffer updates. |
| **Flow Manager** | `backend/capture/flow_manager.py` | **Implemented & Verified** | Bidirectional TCP/IP 5-tuple flow aggregation with SYN-based role normalization and idle timeout. |
| **Standalone Collector** | `backend/capture/packet_collector.py` | **Implemented & Verified** | CLI test harness for packet capture and single-model inference. |
| **Capture Test Script** | `backend/capture/test_capture.py` | **Implemented & Verified** | Minimal CLI verification script testing Scapy sniffing on interface index 12. |
| **Behavioral Engine** | `backend/features/behavior_feature_engine.py` | **Implemented & Verified** | Calculates rolling 10-second host metrics (connection count, unique ports, packet/byte rates). |
| **Autoencoder Model** | `backend/detection/autoencoder_detector.py` | **Implemented & Verified** | 9-input PyTorch MLP Autoencoder. Computes MSE against threshold `0.004877559`. |
| **Random Forest Model** | `backend/detection/rf_detector.py` | **Implemented & Verified** | Scikit-learn Random Forest (100 trees, depth 16) classifying 6 attack families. |
| **Decision Engine** | `backend/detection/decision_engine.py` | **Implemented & Verified** | Multi-criteria verdict evaluator with temporal deduplication. |
| **XAI Engine** | `backend/explainability/xai_engine.py` | **Implemented & Verified** | Generates SHAP attributions for RF attacks and per-feature error rankings for anomalies. |
| **Clustering Engine** | `backend/clustering/cluster_engine.py` | **Implemented & Verified** | Buffers up to 500 zero-day anomalies and runs DBSCAN on 10D scaled feature vectors. |
| **React Dashboard** | `frontend/src/App.jsx` | **Implemented & Verified** | React 19 UI with Lucide icons, real-time WebSocket ingestion, and epoch-filtered reset. |
| **Protected Website** | `website/index.html`, `style.css` | **Implemented & Verified** | NexaVault Enterprise portal with interactive login and ticket forms for generating benign flows. |
| **Master Launcher** | `start_zeroday_ids.bat` | **Implemented & Verified** | Spawns Website (8001), Backend (8000), and Frontend (5173) in separate command windows. |
| **Model Artifacts (A & B)**| `models/model A/`, `models/model B/` | **Implemented & Verified** | Trained PyTorch weights (`autoencoder_best.pt`), Scalers (`scaler.joblib`), RF (`random_forest.joblib`). |
| **Offline Training Scripts** | `training/` | **Missing / External** | Not present in active repo tree; referenced in README. Model training was conducted offline. |
| **Raw Datasets** | `dataset/` | **Empty Directory** | Directory exists on disk but contains 0 files. Datasets were stored externally. |
| **Kali VM Scripts** | External Kali VM | **External Component** | Attack scripts (e.g., hping3, nmap, hydra) run externally from the Kali Linux virtual machine. |

