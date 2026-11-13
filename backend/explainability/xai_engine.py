import numpy as np
import shap


class ExplainabilityEngine:
    def __init__(self, rf_model):
        # Fast exact SHAP explainer for tree-based models (Random Forest)
        self.rf_explainer = shap.TreeExplainer(rf_model)
        self.rf_classes = list(rf_model.classes_)

    def explain(self, decision, behavior_features, ae_result, rf_result):
        """
        Generates structured feature attributions and plain-English explanations:
        - Uses SHAP values when Random Forest identifies a KNOWN_ATTACK.
        - Uses Autoencoder per-feature reconstruction errors + behavioral metrics
          when an unseen SUSPICIOUS_UNKNOWN anomaly is detected.
        """
        outcome = decision["outcome"]

        if outcome == "NORMAL":
            return {
                "method": "Baseline Verification",
                "summary": "Traffic conforms to normal flow and rolling behavioral baselines.",
                "top_features": []
            }

                # Case A: Known Attack -> Explain using SHAP (if RF matched) or Behavioral Flood Telemetry
        if outcome == "KNOWN_ATTACK":
            pred_class = rf_result["predicted_class"]
            attack_label = decision.get("label", pred_class)

            if pred_class != "BENIGN":
                feature_df = rf_result["feature_df"]
                class_idx = self.rf_classes.index(pred_class)
                shap_values = self.rf_explainer.shap_values(feature_df)

                if isinstance(shap_values, list):
                    class_shap = np.array(shap_values[class_idx]).flatten()
                elif shap_values.ndim == 3:
                    class_shap = shap_values[0, :, class_idx]
                else:
                    class_shap = shap_values.flatten()

                feature_names = list(feature_df.columns)
                ranked = sorted(
                    zip(feature_names, class_shap),
                    key=lambda item: abs(float(item[1])),
                    reverse=True
                )

                top_features = [
                    {
                        "feature": name,
                        "contribution": round(float(val), 4),
                        "source": "SHAP (Random Forest)"
                    }
                    for name, val in ranked[:4]
                ]

                top_names = ", ".join([f"{f['feature']} ({f['contribution']:+.3f})" for f in top_features[:3]])
                summary = (
                    f"Flagged as known '{attack_label}' attack. "
                    f"Primary SHAP drivers: {top_names}."
                )

                return {
                    "method": "SHAP TreeExplainer",
                    "summary": summary,
                    "top_features": top_features
                }
            else:
                # Caught by Behavioral Engine + Autoencoder flood detection on hosted port
                conn_count = behavior_features.get("connection_count", 1)
                packet_rate = behavior_features.get("packet_rate", 0.0)
                syn_count = behavior_features.get("syn_count", 0)
                ae_errors = ae_result.get("top_contributing_features", {})

                top_ae = [
                    {
                        "feature": name,
                        "contribution": round(float(err), 6),
                        "source": "Autoencoder + Behavioral Flood"
                    }
                    for name, err in list(ae_errors.items())[:3]
                ]

                summary = (
                    f"Flagged as known '{attack_label}' flood attack. "
                    f"Source host generated {conn_count} rapid connections ({packet_rate:.1f} pkts/s, "
                    f"{syn_count} SYNs) targeting a single service port alongside elevated Autoencoder error."
                )

                return {
                    "method": "Behavioral Flood + Autoencoder Attribution",
                    "summary": summary,
                    "top_features": top_ae
                }


        # Case B: Suspicious Unknown (Zero-Day) -> Explain via Autoencoder Error + Behavioral Telemetry
        ae_errors = ae_result.get("top_contributing_features", {})
        top_ae = [
            {
                "feature": name,
                "contribution": round(float(err), 6),
                "source": "Autoencoder Reconstruction Error"
            }
            for name, err in list(ae_errors.items())[:3]
        ]

        # Highlight abnormal rolling window behaviors
        behavioral_drivers = []
        unique_ports = behavior_features.get("unique_destination_ports", 1)
        conn_count = behavior_features.get("connection_count", 1)
        syn_count = behavior_features.get("syn_count", 0)
        packet_rate = behavior_features.get("packet_rate", 0.0)

        if unique_ports >= 5:
            behavioral_drivers.append(f"probed {unique_ports} unique destination ports in {behavior_features.get('window_seconds', 10)}s")
        if conn_count >= 15:
            behavioral_drivers.append(f"opened {conn_count} rapid connections")
        if syn_count >= 15:
            behavioral_drivers.append(f"sent {syn_count} TCP SYN packets")
        if packet_rate >= 50.0:
            behavioral_drivers.append(f"generated a high packet burst ({packet_rate:.1f} pkts/s)")

        behavior_text = (
            "Behaviorally, the source host " + " and ".join(behavioral_drivers) + "."
            if behavioral_drivers
            else "Single-flow statistical reconstruction error exceeded normal boundaries."
        )

        top_ae_names = ", ".join([f"{f['feature']} (err={f['contribution']:.4f})" for f in top_ae[:2]])
        summary = (
            f"Unseen anomaly detected (not matched to any known attack signature). "
            f"Top Autoencoder deviations: {top_ae_names}. {behavior_text}"
        )

        return {
            "method": "Autoencoder Reconstruction Error + Behavioral Attribution",
            "summary": summary,
            "top_features": top_ae
        }
