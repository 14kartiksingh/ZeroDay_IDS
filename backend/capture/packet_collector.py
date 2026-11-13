
from scapy.all import sniff, IP, TCP, UDP, conf
from backend.detection.autoencoder_detector import AutoencoderDetector
from backend.capture.flow_manager import FlowManager
from backend.features.behavior_feature_engine import BehavioralFeatureEngine


class PacketCollector:

    def __init__(self, interface_index=12):
        self.interface = conf.ifaces.dev_from_index(interface_index)
        self.flow_manager = FlowManager(idle_timeout=10)
        self.behavior_engine = BehavioralFeatureEngine(window_seconds=10)
        self.autoencoder = AutoencoderDetector(
            model_dir="models/model B"
        )

    def process_packet(self, packet):
        if IP not in packet:
            return None

        ip = packet[IP]
        src_port = None
        dst_port = None
        tcp_flags = None

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

        # Component 1: Behavioral features
            features = self.behavior_engine.add_flow(flow)

        # Component 2: Autoencoder inference
            result = self.autoencoder.predict(flow)

            print("\n[LIVE FLOW]")
            print("Source:", flow["src_ip"])
            print("Destination:", flow["dst_ip"])
            print("Source Port:", flow["src_port"])
            print("Destination Port:", flow["dst_port"])
            print("Direction Confident:", flow.get("direction_confident"))
            print("Forward SYN:", flow["fwd_tcp_flags"].get("S", 0))
            print("Backward SYN:", flow["bwd_tcp_flags"].get("S", 0))
            print("\n[BEHAVIORAL FEATURES]")
            print(features)

            print("\n[AUTOENCODER RESULT]")
            print(result)

    def handle_packet(self, packet):
        data = self.process_packet(packet)

        if data:
            self.flow_manager.add_packet(data)

        self.process_expired_flows()

    def start_capture(self):
        print(f"Monitoring: {self.interface}")
        print("Live behavioral monitoring started. CTRL+C to stop.")

        try:
            while True:
                sniff(
                    iface=self.interface,
                    filter="ip",
                    prn=self.handle_packet,
                    store=False,
                    timeout=1
                )

                self.process_expired_flows()

        except KeyboardInterrupt:
            print("\nMonitoring stopped.")


if __name__ == "__main__":
    collector = PacketCollector()
    collector.start_capture()
