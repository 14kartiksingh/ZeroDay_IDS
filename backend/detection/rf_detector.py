import os
import joblib
import numpy as np
import pandas as pd


class RandomForestDetector:
    def __init__(self, model_dir=os.path.join("models", "model B")):
        model_path = os.path.join(model_dir, "random_forest.joblib")
        self.model = joblib.load(model_path)
        self.classes = list(self.model.classes_)
        self.features = [
            "Dst Port",
            "Flow Duration",
            "Total Fwd Packet",
            "Total Bwd packets",
            "Total Length of Fwd Packet",
            "Total Length of Bwd Packet",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
        ]
        print(f"Random Forest loaded from {model_dir} | Classes: {self.classes}")

    def extract_feature_df(self, flow):
        duration = max(float(flow["duration"]), 0.000001)
        duration_us = duration * 1_000_000

        total_packets = flow["fwd_packets"] + flow["bwd_packets"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
        syn_count = flow.get("tcp_flags", {}).get("S", 0)

        raw_features = np.array([[
            flow["dst_port"] or 0,
            duration_us,
            flow["fwd_packets"],
            flow["bwd_packets"],
            flow["fwd_bytes"],
            flow["bwd_bytes"],
            total_bytes / duration,
            total_packets / duration,
            syn_count
        ]], dtype=np.float64)

        # Match training preprocessing (log1p on rate features)
        raw_features[0, 6] = np.log1p(max(raw_features[0, 6], 0.0))
        raw_features[0, 7] = np.log1p(max(raw_features[0, 7], 0.0))

        return pd.DataFrame(raw_features, columns=self.features)

    def predict(self, flow):
        X_df = self.extract_feature_df(flow)
        probs = self.model.predict_proba(X_df)[0]
        best_idx = int(np.argmax(probs))
        predicted_class = str(self.classes[best_idx])
        confidence = float(probs[best_idx])

        class_probabilities = {
            str(cls): round(float(prob), 4)
            for cls, prob in zip(self.classes, probs)
        }

        return {
            "predicted_class": predicted_class,
            "confidence": round(confidence, 4),
            "is_known_attack": predicted_class != "BENIGN",
            "probabilities": class_probabilities,
            "feature_df": X_df  # Passed to Component 5 (SHAP) when needed
        }
