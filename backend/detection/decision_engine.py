import time


class DecisionEngine:
    def __init__(
        self,
        rf_confidence_threshold=0.75,
        ae_severe_multiplier=3.0,
        dedup_window_seconds=4
    ):
        self.rf_confidence_threshold = rf_confidence_threshold
        self.ae_severe_multiplier = ae_severe_multiplier
        self.dedup_window_seconds = dedup_window_seconds
        self.recent_alerts = {}

    def _is_duplicate(self, source_ip, outcome, attack_label):
        now = time.time()
        key = (source_ip, outcome, attack_label)
        last_time = self.recent_alerts.get(key)

        if last_time and (now - last_time) < self.dedup_window_seconds:
            return True

        self.recent_alerts[key] = now
        return False

    def evaluate(self, flow, behavior_features, ae_result, rf_result):
        """
        Combines Component 1 (Behavioral), Component 2 (Autoencoder),
        and Component 3 (Random Forest) into a unified verdict:
        - NORMAL
        - KNOWN_ATTACK
        - SUSPICIOUS_UNKNOWN
        """
        ae_score = float(ae_result["anomaly_score"])
        ae_thresh = float(ae_result["threshold"])
        ae_anomalous = bool(ae_result["is_anomaly"])

        rf_class = rf_result["predicted_class"]
        rf_conf = float(rf_result["confidence"])

        conn_count = behavior_features.get("connection_count", 1)
        unique_ports = behavior_features.get("unique_destination_ports", 1)
        packet_rate = behavior_features.get("packet_rate", 0.0)
        syn_count = behavior_features.get("syn_count", 0)

        # Single-service high-volume flood pattern (DoS / DDoS)
        is_dos_flood = (
            unique_ports <= 2
            and (conn_count >= 25 or packet_rate >= 80.0 or syn_count >= 40)
        )

        # Multi-port reconnaissance pattern (e.g., withheld PortScan)
        is_multiport_recon = unique_ports >= 5

        # 1. SUSPICIOUS UNKNOWN (Zero-Day): Multi-port reconnaissance overrides single-port RF overlap
        if ae_anomalous and is_multiport_recon:
            outcome = "SUSPICIOUS_UNKNOWN"
            label = "Unseen Anomaly / Potential Zero-Day"
            severity = "HIGH" if unique_ports >= 10 else "MEDIUM"
            reason = (
                f"Autoencoder flagged structural anomaly (score={ae_score:.5f} > {ae_thresh:.5f}) "
                f"with multi-port probing ({unique_ports} unique ports, {conn_count} connections in 10s), "
                f"unrecognized as a standalone known attack class."
            )

        # 2. KNOWN ATTACK: Random Forest signature match OR confirmed single-service DoS flood
        elif rf_class != "BENIGN" and rf_conf >= self.rf_confidence_threshold:
            outcome = "KNOWN_ATTACK"
            label = rf_class
            severity = "HIGH" if rf_conf >= 0.85 else "MEDIUM"
            reason = (
                f"Random Forest matched known signature '{rf_class}' "
                f"with {rf_conf * 100:.1f}% confidence."
            )
        elif is_dos_flood and ae_anomalous:
            outcome = "KNOWN_ATTACK"
            label = "DoS / DDoS"
            severity = "HIGH"
            reason = (
                f"High-volume single-service flood detected "
                f"({conn_count} connections, {packet_rate:.1f} pkts/s on {unique_ports} port) "
                f"with Autoencoder score {ae_score:.5f}."
            )

        # 3. SEVERE SINGLE-FLOW STRUCTURAL ANOMALY (e.g., Heartbleed / payload exploit)
        elif ae_anomalous and ae_score >= (ae_thresh * self.ae_severe_multiplier):
            outcome = "SUSPICIOUS_UNKNOWN"
            label = "Unseen Structural Anomaly"
            severity = "MEDIUM"
            reason = (
                f"Autoencoder reconstruction error ({ae_score:.5f}) exceeded 3x baseline threshold "
                f"without matching any known attack signature."
            )

        # 4. NORMAL: Single-session browsing
        else:
            outcome = "NORMAL"
            label = "Benign Traffic"
            severity = "LOW"
            reason = "Traffic aligns with normal single-session behavioral and statistical baselines."

        is_duplicate = (
            False
            if outcome == "NORMAL"
            else self._is_duplicate(flow["src_ip"], outcome, label)
        )

        return {
            "timestamp": time.time(),
            "source_ip": flow["src_ip"],
            "destination_ip": flow["dst_ip"],
            "destination_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "outcome": outcome,
            "label": label,
            "severity": severity,
            "is_duplicate": is_duplicate,
            "reason": reason,
            "metrics": {
                "ae_score": round(ae_score, 6),
                "ae_threshold": round(ae_thresh, 6),
                "rf_prediction": rf_class,
                "rf_confidence": rf_conf,
                "window_connections": conn_count,
                "window_unique_ports": unique_ports,
                "window_packet_rate": packet_rate,
            }
        }
