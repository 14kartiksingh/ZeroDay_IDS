
from collections import defaultdict, deque


class BehavioralFeatureEngine:

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.source_windows = defaultdict(deque)

    def add_flow(self, flow):

        source_ip = flow["src_ip"]
        event_time = flow["last_seen"]

        window = self.source_windows[source_ip]

        # Add the newly completed flow
        window.append(flow)

        # Remove flows outside the rolling time window
        while window and event_time - window[0]["last_seen"] > self.window_seconds:
            window.popleft()

        # Calculate behavioural features
        total_packets = sum(f["packet_count"] for f in window)
        total_bytes = sum(f["byte_count"] for f in window)

        unique_destinations = {
            f["dst_ip"] for f in window
        }

        unique_ports = {
            f["dst_port"] for f in window
            if f["dst_port"] is not None
        }

        connection_count = len(window)

        syn_count = sum(
            f.get("tcp_flags", {}).get("S", 0)
            for f in window
        )

        features = {
            "source_ip": source_ip,
            "window_seconds": self.window_seconds,
            "connection_count": connection_count,
            "unique_destination_ips": len(unique_destinations),
            "unique_destination_ports": len(unique_ports),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "syn_count": syn_count,
            "packet_rate": total_packets / self.window_seconds,
            "byte_rate": total_bytes / self.window_seconds
        }

        return features
