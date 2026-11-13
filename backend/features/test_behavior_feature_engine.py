
from backend.features.behavior_feature_engine import BehavioralFeatureEngine

engine = BehavioralFeatureEngine(window_seconds=10)

sample_flows = [
    {
        "src_ip": "192.168.137.128",
        "dst_ip": "192.168.137.1",
        "dst_port": 8001,
        "last_seen": 1000,
        "packet_count": 5,
        "byte_count": 700,
        "tcp_flags": {"S": 1}
    },
    {
        "src_ip": "192.168.137.128",
        "dst_ip": "192.168.137.10",
        "dst_port": 443,
        "last_seen": 1002,
        "packet_count": 8,
        "byte_count": 1200,
        "tcp_flags": {"S": 2}
    },
    {
        "src_ip": "192.168.137.128",
        "dst_ip": "192.168.137.20",
        "dst_port": 22,
        "last_seen": 1004,
        "packet_count": 10,
        "byte_count": 1800,
        "tcp_flags": {"S": 3}
    }
]

for flow in sample_flows:
    features = engine.add_flow(flow)

print("\nBehavioral Features:")
print(features)
