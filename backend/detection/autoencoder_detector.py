import os
import json
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn


class Autoencoder(nn.Module):
    def __init__(self):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(9, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, 9)
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


class AutoencoderDetector:
    def __init__(self, model_dir=os.path.join("models", "model B")):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        model_path = os.path.join(model_dir, "autoencoder_best.pt")
        scaler_path = os.path.join(model_dir, "scaler.joblib")
        threshold_path = os.path.join(model_dir, "threshold.npy")
        metadata_path = os.path.join(model_dir, "metadata.json")

        # Only read metadata.json if it exists AND is not empty (> 0 bytes)
        if os.path.exists(metadata_path) and os.path.getsize(metadata_path) > 0:
            with open(metadata_path, "r", encoding="utf-8-sig") as f:
                self.metadata = json.load(f)
            self.threshold = float(self.metadata["threshold"])
            self.features = self.metadata["input_features"]
        else:
            self.threshold = float(np.load(threshold_path).item())
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

        self.scaler = joblib.load(scaler_path)
        self.model = Autoencoder().to(self.device)
        self.model.load_state_dict(
            torch.load(model_path, map_location=self.device, weights_only=True)
        )
        self.model.eval()
        print(f"Model B loaded from {model_dir} | Threshold: {self.threshold}")

    def predict(self, flow):
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

        # Match training preprocessing: log1p ONLY on Flow Bytes/s (index 6) and Flow Packets/s (index 7)
        raw_features[0, 6] = np.log1p(max(raw_features[0, 6], 0.0))
        raw_features[0, 7] = np.log1p(max(raw_features[0, 7], 0.0))

        scaled = self.scaler.transform(
            pd.DataFrame(raw_features, columns=self.features)
        )

        tensor = torch.tensor(scaled, dtype=torch.float32, device=self.device)

        with torch.no_grad():
            reconstructed = self.model(tensor)
            per_feature_errors = ((reconstructed - tensor) ** 2).squeeze(0).cpu().numpy()
            error = float(np.mean(per_feature_errors))

        feature_contributions = dict(
            sorted(
                zip(self.features, [round(float(e), 6) for e in per_feature_errors]),
                key=lambda item: item[1],
                reverse=True
            )
        )

        return {
            "model_version": "B",
            "anomaly_score": error,
            "threshold": self.threshold,
            "is_anomaly": error > self.threshold,
            "status": "SUSPICIOUS" if error > self.threshold else "NORMAL",
            "top_contributing_features": feature_contributions
        }
