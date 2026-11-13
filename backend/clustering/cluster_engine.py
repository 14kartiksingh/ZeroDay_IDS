import time
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN


class ClusteringEngine:
    def __init__(self, eps=1.2, min_samples=3, max_buffer_size=500):
        self.eps = eps
        self.min_samples = min_samples
        self.max_buffer_size = max_buffer_size
        self.observations = []
        self.clusters_summary = []

    def add_observation(self, flow, behavior_features, ae_result, explanation):
        """
        Stores a SUSPICIOUS_UNKNOWN event and updates DBSCAN clusters.
        """
        vector = [
            float(flow.get("dst_port") or 0),
            float(flow.get("duration") or 0.0),
            float(flow.get("fwd_packets") or 0),
            float(flow.get("bwd_packets") or 0),
            float(flow.get("fwd_bytes") or 0),
            float(flow.get("bwd_bytes") or 0),
            float(behavior_features.get("unique_destination_ports", 1)),
            float(behavior_features.get("connection_count", 1)),
            float(behavior_features.get("packet_rate", 0.0)),
            float(ae_result.get("anomaly_score", 0.0)),
        ]

        record = {
            "timestamp": time.time(),
            "source_ip": flow["src_ip"],
            "destination_ip": flow["dst_ip"],
            "destination_port": flow["dst_port"],
            "ae_score": round(float(ae_result.get("anomaly_score", 0.0)), 6),
            "unique_ports": behavior_features.get("unique_destination_ports", 1),
            "connections": behavior_features.get("connection_count", 1),
            "top_driver": (
                explanation["top_features"][0]["feature"]
                if explanation.get("top_features")
                else "Unknown"
            ),
            "vector": vector,
            "cluster_id": -1
        }

        self.observations.append(record)
        if len(self.observations) > self.max_buffer_size:
            self.observations.pop(0)

        self._run_dbscan()
        return record["cluster_id"]

    def _run_dbscan(self):
        if len(self.observations) < self.min_samples:
            self.clusters_summary = []
            return

        X = np.array([obs["vector"] for obs in self.observations], dtype=np.float64)
        X_scaled = StandardScaler().fit_transform(X)

        labels = DBSCAN(eps=self.eps, min_samples=self.min_samples).fit_predict(X_scaled)

        for obs, lbl in zip(self.observations, labels):
            obs["cluster_id"] = int(lbl)

        # Build clean summaries for each discovered cluster (excluding noise label -1)
        unique_labels = sorted(set(int(l) for l in labels if l != -1))
        summaries = []

        for cid in unique_labels:
            members = [obs for obs in self.observations if obs["cluster_id"] == cid]
            source_ips = sorted(set(m["source_ip"] for m in members))
            avg_ae = float(np.mean([m["ae_score"] for m in members]))
            max_ports = max(m["unique_ports"] for m in members)
            max_conns = max(m["connections"] for m in members)

            # Most frequent primary XAI feature driver in this cluster
            drivers = [m["top_driver"] for m in members]
            dominant_driver = max(set(drivers), key=drivers.count)

            # High-level behavioral pattern tag derived from cluster telemetry
            if max_ports >= 5:
                pattern_hint = "Multi-Port Probing / Reconnaissance Pattern"
            elif max_conns >= 15:
                pattern_hint = "High-Frequency Connection Burst Pattern"
            else:
                pattern_hint = "Recurring Structural Payload Anomaly"

            summaries.append({
                "cluster_id": cid,
                "event_count": len(members),
                "source_ips": source_ips,
                "avg_anomaly_score": round(avg_ae, 6),
                "max_unique_ports": max_ports,
                "dominant_xai_driver": dominant_driver,
                "pattern_summary": pattern_hint,
                "last_seen": members[-1]["timestamp"]
            })

        self.clusters_summary = summaries

    def get_clusters(self):
        noise_count = sum(1 for obs in self.observations if obs["cluster_id"] == -1)
        return {
            "total_unknown_events": len(self.observations),
            "active_clusters": len(self.clusters_summary),
            "isolated_noise_events": noise_count,
            "clusters": self.clusters_summary
        }
