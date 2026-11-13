import time
import threading
from collections import deque
from scapy.all import sniff, IP, TCP, UDP, conf

from backend.capture.flow_manager import FlowManager
from backend.features.behavior_feature_engine import BehavioralFeatureEngine
from backend.detection.autoencoder_detector import AutoencoderDetector
from backend.detection.rf_detector import RandomForestDetector
from backend.detection.decision_engine import DecisionEngine
from backend.explainability.xai_engine import ExplainabilityEngine
from backend.clustering.cluster_engine import ClusteringEngine


class IDSPipelineService:
    def __init__(self, interface_index=12, model_dir="models/model B"):
        self.interface_index = interface_index
        self.interface = conf.ifaces.dev_from_index(interface_index)
        self.is_running = False

        # Thread-safety lock for shared state accessed by both the Scapy
        # capture thread and the FastAPI request threads (reset, stats, etc.)
        self._lock = threading.Lock()

        # Epoch counter: incremented on every reset.  Flow events carry the
        # epoch they were produced under so the frontend can discard stale
        # WebSocket messages that were in-flight when a reset occurred.
        self._reset_epoch = 0

        # Core Capture & 6 ML Components
        self.flow_manager = FlowManager(idle_timeout=5)  # 5s idle timeout for responsive live dashboard updates
        self.behavior_engine = BehavioralFeatureEngine(window_seconds=10)
        self.autoencoder = AutoencoderDetector(model_dir=model_dir)
        self.random_forest = RandomForestDetector(model_dir=model_dir)
        self.decision_engine = DecisionEngine()
        self.xai_engine = ExplainabilityEngine(self.random_forest.model)
        self.clustering_engine = ClusteringEngine(eps=1.2, min_samples=3)

        # Live State Buffers for Dashboard APIs
        self.stats = {
            "total_packets": 0,
            "total_flows": 0,
            "normal_flows": 0,
            "known_attacks": 0,
            "unknown_anomalies": 0,
            "start_time": time.time()
        }
        self.recent_flows = deque(maxlen=100)
        self.alerts = deque(maxlen=100)

        # Optional callback for real-time WebSocket pushing
        self.on_event_callback = None

    def _parse_packet(self, packet):
        if IP not in packet:
            return None

        ip = packet[IP]
        src_port = None
        dst_port = None
        tcp_flags = None
        if ip.dst.startswith(("224.", "239.")) or ip.dst == "255.255.255.255":
            return None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        else:
            protocol = "Other"

        return {
            "timestamp": float(packet.time),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_size": len(packet),
            "tcp_flags": tcp_flags
        }

    def process_expired_flows(self):
        expired_flows = self.flow_manager.get_expired_flows()

        for flow in expired_flows:
            # Run ML inference OUTSIDE the lock — these are pure computations
            # on the flow dict and do not touch shared dashboard state.

            # Component 1: Behavioral Feature Engine
            behavior_features = self.behavior_engine.add_flow(flow)

            # Component 2: Autoencoder (Benign Anomaly Detection)
            ae_result = self.autoencoder.predict(flow)

            # Component 3: Random Forest (Known Attack Classification)
            rf_result = self.random_forest.predict(flow)

            # Component 4: Decision Engine
            decision = self.decision_engine.evaluate(
                flow, behavior_features, ae_result, rf_result
            )

            # Component 5: Explainable AI (XAI)
            explanation = self.xai_engine.explain(
                decision, behavior_features, ae_result, rf_result
            )

            # Component 6: Clustering Engine (for Suspicious Unknown Anomalies)
            cluster_id = None
            if decision["outcome"] == "SUSPICIOUS_UNKNOWN":
                cluster_id = self.clustering_engine.add_observation(
                    flow, behavior_features, ae_result, explanation
                )

            # ── Critical section: update shared dashboard state ──
            # Hold the lock while touching stats / recent_flows / alerts
            # and while reading the epoch, so a concurrent reset() cannot
            # clear state between our writes and our broadcast.
            with self._lock:
                self.stats["total_flows"] += 1

                # Update dashboard counters
                outcome = decision["outcome"]
                if outcome == "NORMAL":
                    self.stats["normal_flows"] += 1
                elif outcome == "KNOWN_ATTACK":
                    self.stats["known_attacks"] += 1
                elif outcome == "SUSPICIOUS_UNKNOWN":
                    self.stats["unknown_anomalies"] += 1

                flow_record = {
                    "id": f"flow_{self.stats['total_flows']}_{int(time.time() * 1000)}",
                    "timestamp": decision["timestamp"],
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "packets": flow["packet_count"],
                    "bytes": flow["byte_count"],
                    "duration": round(float(flow["duration"]), 4),
                    "outcome": outcome,
                    "label": decision["label"],
                    "severity": decision["severity"],
                    "ae_score": decision["metrics"]["ae_score"],
                    "rf_prediction": decision["metrics"]["rf_prediction"],
                    "rf_confidence": decision["metrics"]["rf_confidence"],
                    "cluster_id": cluster_id,
                    "explanation": explanation,
                    "behavioral": behavior_features
                }

                self.recent_flows.appendleft(flow_record)

                # Store non-duplicate alerts for the Security Alert Feed
                if outcome != "NORMAL" and not decision["is_duplicate"]:
                    alert_record = {
                        **flow_record,
                        "reason": decision["reason"]
                    }
                    self.alerts.appendleft(alert_record)

                # Snapshot epoch and payload while still holding the lock
                epoch = self._reset_epoch
                payload = {
                    "type": "FLOW_ANALYZED",
                    "epoch": epoch,
                    "stats": self.get_stats(),
                    "flow": flow_record,
                    "clusters": self.clustering_engine.get_clusters()
                }

            # Broadcast OUTSIDE the lock to avoid blocking the reset path
            if self.on_event_callback:
                self.on_event_callback(payload)

    def handle_packet(self, packet):
        data = self._parse_packet(packet)
        if data:
            self.stats["total_packets"] += 1
            self.flow_manager.add_packet(data)
        self.process_expired_flows()

    def reset(self):
        """Thread-safe reset of all dashboard state.

        Called from the FastAPI /api/reset endpoint (runs on a request
        thread).  The lock ensures we never interleave with the Scapy
        thread's critical section in process_expired_flows().
        """
        with self._lock:
            # Bump epoch FIRST — any FLOW_ANALYZED message produced after
            # this point will carry the new epoch, letting the frontend
            # discard any stale messages still in transit.
            self._reset_epoch += 1

            # Clear accumulated flows waiting for expiration
            self.flow_manager.flows.clear()

            # Clear dashboard buffers
            self.recent_flows.clear()
            self.alerts.clear()

            # Clear clustering state
            self.clustering_engine.observations.clear()
            self.clustering_engine.clusters_summary.clear()

            # Clear behavioral sliding windows so old flow history doesn't
            # contaminate post-reset behavioural feature calculations
            self.behavior_engine.source_windows.clear()

            # Clear the decision engine's deduplication window
            self.decision_engine.recent_alerts.clear()

            # Reset counters
            self.stats.update({
                "total_packets": 0,
                "total_flows": 0,
                "normal_flows": 0,
                "known_attacks": 0,
                "unknown_anomalies": 0
            })

            epoch = self._reset_epoch

        return epoch

    def run_capture_loop(self):
        self.is_running = True
        print(f"IDS Pipeline capturing live on interface: {self.interface}")
        while self.is_running:
            sniff(
                iface=self.interface,
                filter="ip",
                prn=self.handle_packet,
                store=False,
                timeout=1
            )
            self.process_expired_flows()

    def stop(self):
        self.is_running = False

    def get_stats(self):
        uptime = int(time.time() - self.stats["start_time"])
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "is_capturing": self.is_running,
            "epoch": self._reset_epoch
        }
