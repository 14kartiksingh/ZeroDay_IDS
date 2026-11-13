
from datetime import datetime
from scapy.all import sniff, conf, IP, TCP, UDP

INTERFACE_INDEX = 12

iface = conf.ifaces.dev_from_index(INTERFACE_INDEX)

def process_packet(packet):
    if IP not in packet:
        return

    protocol = (
        "TCP" if TCP in packet else
        "UDP" if UDP in packet else
        "Other"
    )

    timestamp = datetime.fromtimestamp(float(packet.time))

    print(
        f"[{timestamp:%H:%M:%S}] "
        f"{packet[IP].src} -> {packet[IP].dst} | "
        f"{protocol} | {len(packet)} bytes"
    )

print(f"Monitoring interface: {iface}")
print("Press CTRL+C to stop.\n")

try:
    sniff(
        iface=iface,
        filter="ip",
        prn=process_packet,
        store=False
    )
except KeyboardInterrupt:
    print("\nPacket monitoring stopped.")
