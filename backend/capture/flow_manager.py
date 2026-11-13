import time


class FlowManager:

    def __init__(self, idle_timeout=10):
        self.flows = {}
        self.idle_timeout = idle_timeout

    def get_flow_key(self, packet):
        source = (packet["src_ip"], packet["src_port"])
        destination = (packet["dst_ip"], packet["dst_port"])
        endpoints = tuple(sorted([source, destination]))
        return endpoints, packet["protocol"]

    def add_packet(self, packet):
        key = self.get_flow_key(packet)
        now = float(packet.get("timestamp", time.time()))
        flags = packet.get("tcp_flags") or ""
        src_port = packet.get("src_port") or 0
        dst_port = packet.get("dst_port") or 0

        if key not in self.flows:
            # General TCP/IP Role Normalization (No hardcoded ports):
            # 1. Pure SYN ('S' without 'A') is always initiated by the client (Forward).
            # 2. SYN-ACK ('S' and 'A') is always sent by the server (Backward).
            # 3. Mid-stream packet without SYN: the lower port (< 32768) is the listening service.
            if "S" in flags and "A" not in flags:
                is_server_first = False
            elif "S" in flags and "A" in flags:
                is_server_first = True
            else:
                is_server_first = src_port < dst_port

            if is_server_first:
                fwd_ip, dst_ip = packet["dst_ip"], packet["src_ip"]
                fwd_port, dst_port_norm = dst_port, src_port
            else:
                fwd_ip, dst_ip = packet["src_ip"], packet["dst_ip"]
                fwd_port, dst_port_norm = src_port, dst_port

            self.flows[key] = {
                "src_ip": fwd_ip,
                "dst_ip": dst_ip,
                "src_port": fwd_port,
                "dst_port": dst_port_norm,
                "protocol": packet["protocol"],
                "start_time": now,
                "last_seen": now,
                "packet_count": 0,
                "byte_count": 0,
                "fwd_packets": 0,
                "bwd_packets": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "tcp_flags": {},
                "fwd_tcp_flags": {},
                "bwd_tcp_flags": {}
            }

        flow = self.flows[key]
        flow["last_seen"] = now
        flow["packet_count"] += 1
        flow["byte_count"] += packet["packet_size"]

        is_forward = (
            packet["src_ip"] == flow["src_ip"]
            and src_port == flow["src_port"]
            and packet["dst_ip"] == flow["dst_ip"]
            and dst_port == flow["dst_port"]
        )

        if is_forward:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet["packet_size"]
            direction_flags = flow["fwd_tcp_flags"]
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet["packet_size"]
            direction_flags = flow["bwd_tcp_flags"]

        if flags:
            for flag in flags:
                flow["tcp_flags"][flag] = flow["tcp_flags"].get(flag, 0) + 1
                direction_flags[flag] = direction_flags.get(flag, 0) + 1

    def get_expired_flows(self):
        now = time.time()
        expired = []

        for key, flow in list(self.flows.items()):
            if now - flow["last_seen"] >= self.idle_timeout:
                completed_flow = flow.copy()
                completed_flow["duration"] = (
                    flow["last_seen"] - flow["start_time"]
                )
                expired.append(completed_flow)
                del self.flows[key]

        return expired
