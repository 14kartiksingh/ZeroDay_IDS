# ZeroDay IDS — Network Capture & Simulation Environment

This document details the live packet capture mechanics, network interface configuration, packet parsing rules, flow aggregation algorithms, and the multi-VM attack simulation testbed.

---

## 1. Network Topology & Environment

The ZeroDay IDS testbed consists of a dual-node virtualized network environment linking a Windows Host development environment and a Kali Linux penetration testing virtual machine:

```
+-----------------------------------------------------------------------------------------+
|                                    VMware Workstation                                   |
|                                                                                         |
|  +----------------------------------+             +----------------------------------+  |
|  | KALI LINUX VM                    |             | WINDOWS HOST WORKSTATION         |  |
|  | IP: 192.168.137.128              |             | IP: 192.168.137.1                |  |
|  | Role: Penetration Testing Node   |             | Role: Protected Server + IDS     |  |
|  | - Web Browsing Simulation        |             | - NexaVault Website (Port 8001)  |  |
|  | - Port Scanning (Nmap)           |             | - IDS Backend API (Port 8000)    |  |
|  | - SYN Flood (Hping3)             |             | - React UI Dashboard (Port 5173) |  |
|  | - Password Brute Force (Hydra)   |             | - Scapy Sniffer on VMnet1        |  |
|  +----------------+-----------------+             +----------------+-----------------+  |
|                   |                                                |                    |
|                   +------------------ VMnet1 ----------------------+                    |
|                         (Host-Only Virtual Network: 192.168.137.0/24)                   |
+-----------------------------------------------------------------------------------------+
```

### 1.1 IP Allocation & Network Roles
- **Subnet**: `192.168.137.0/24` (VMware Host-Only Network `VMnet1`)
- **Windows Host Interface**: `VMware Virtual Ethernet Adapter for VMnet1`
  - Assigned Host IP: `192.168.137.1`
  - Scapy Interface Index: `12`
  - Device Name: `\Device\NPF_{...}`
- **Kali Linux Attacker VM**:
  - Assigned Guest IP: `192.168.137.128`
  - Default Gateway / Target: `192.168.137.1`
- **Application Services Bound on Windows**:
  - `0.0.0.0:8001`: NexaVault Enterprise Portal (Protected Target Website)
  - `0.0.0.0:8000`: FastAPI Backend and WebSocket Threat Feed
  - `localhost:5173`: React 19 / Vite Development Server

---

## 2. Packet Capture Architecture (`Scapy` & `Npcap`)

### 2.1 Interface Selection
In `backend/services/ids_pipeline.py`:
```python
self.interface_index = 12
self.interface = conf.ifaces.dev_from_index(12)
```
Scapy queries Windows network adapters through the Npcap packet capture driver. Index 12 maps specifically to `VMware Virtual Ethernet Adapter for VMnet1`, isolating traffic generated across the VM host-only bridge while ignoring unrelated host LAN or Wi-Fi traffic.

### 2.2 Sniffing Loop Configuration
```python
def run_capture_loop(self):
    self.is_running = True
    print(f"IDS Pipeline capturing live on interface: {self.interface}")
    while self.is_running:
        sniff(
            iface=self.interface,
            filter="ip",
            prn=self.handle_packet,
            store=False,
            timeout=1
        )
        self.process_expired_flows()
```
- `filter="ip"`: Berkeley Packet Filter (BPF) syntax instructing the Npcap kernel driver to forward only IPv4 packets, dropping ARP and link-layer discovery packets.
- `store=False`: Disables internal packet buffering in Scapy, preventing memory leaks during high-volume traffic bursts.
- `timeout=1`: Forces `sniff()` to return control every 1.0 second. This ensures that `self.process_expired_flows()` executes regularly, even if no new packets arrive.

### 2.3 Packet Parsing & Protocol Filtering (`_parse_packet`)
Each intercepted packet is processed through `_parse_packet()`:
1. **IPv4 Validation**: Drops non-IPv4 frames (`if IP not in packet: return None`).
2. **Multicast and Broadcast Suppression**:
   ```python
   if ip.dst.startswith(("224.", "239.")) or ip.dst == "255.255.255.255":
       return None
   ```
   Filters SSDP, mDNS, and local subnet broadcasts that could artificially inflate connection counts.
3. **Transport Layer Extraction**:
   - `TCP`: Extracts `sport`, `dport`, and string representation of TCP flags (`flags = str(packet[TCP].flags)`).
   - `UDP`: Extracts `sport`, `dport`; sets `tcp_flags = None`.
   - Other: Marks protocol as `"Other"`.
4. **Normalized Output**: Returns a standard dictionary:
   ```python
   {
       "timestamp": float(packet.time),
       "src_ip": ip.src, "dst_ip": ip.dst,
       "src_port": src_port, "dst_port": dst_port,
       "protocol": protocol, "packet_size": len(packet),
       "tcp_flags": tcp_flags
   }
   ```

---

## 3. Bidirectional Flow Aggregation (`FlowManager`)

### 3.1 5-Tuple Key & Endpoint Normalization
To group reciprocal communications (e.g., HTTP request and response) into a single bidirectional flow:
```python
def get_flow_key(self, packet):
    source = (packet["src_ip"], packet["src_port"])
    destination = (packet["dst_ip"], packet["dst_port"])
    endpoints = tuple(sorted([source, destination]))
    return endpoints, packet["protocol"]
```
Because the pair of `(IP, Port)` tuples is sorted, packets traveling $A \to B$ and $B \to A$ yield the identical dictionary key.

### 3.2 Client/Server Role Normalization
To ensure consistent forward/backward packet accounting regardless of packet arrival order:
```python
if "S" in flags and "A" not in flags:
    is_server_first = False   # Pure SYN: Initiator is Client
elif "S" in flags and "A" in flags:
    is_server_first = True    # SYN-ACK: Initiator is Server responding
else:
    is_server_first = src_port < dst_port # Mid-stream: Lower port is listening service
```
If `is_server_first` is `True`, the flow's forward endpoints (`src_ip`, `src_port`) are swapped with destination endpoints, ensuring the client is always recorded as forward.

### 3.3 Flow Lifetime & Expiration
Every matching packet updates `flow["last_seen"] = now` and increments directional packet and byte counts.
In `get_expired_flows()`:
$$\text{idle\_duration} = \text{now} - \text{flow}[\text{"last\_seen"}]$$
- If $\text{idle\_duration} \ge \text{idle\_timeout}$ (configured to **5 seconds** in `ids_pipeline.py`):
  1. The total duration is calculated: $\Delta t = \text{flow}[\text{"last\_seen"}] - \text{flow}[\text{"start\_time"}]$.
  2. A copy of the completed flow record is appended to `expired`.
  3. The flow is deleted from `self.flows`.
  4. The list of expired flows is returned for immediate ML inference.

---

## 4. Protected Test Application (NexaVault Enterprise Portal)

The protected test asset is a static corporate web application located in `website/`:
- **Server**: Spawns via `python -m http.server 8001 --bind 0.0.0.0`.
- **Pages & Interactive Elements**:
  1. **Infrastructure Metrics Bar**: Displays simulated 99.98% uptime, active nodes, and IDS status.
  2. **Hosted Modules**: Three interactive cards:
     - `Financial Ledger Vault`
     - `Cloud Compute Console`
     - `Identity Directory`
     Clicking a module triggers `simulateActivity()`, generating HTTP GET requests to simulate standard employee browsing.
  3. **Employee SSO Login**: Form taking Corporate ID and passphrase. Submitting triggers client-side validation and generates interactive HTTP traffic.
  4. **IT Support Desk**: Ticket submission form taking Name, Department Email, and Request Details.

---

## 5. Traffic Generation & Attack Simulation Scenarios

The testbed supports four distinct operational traffic profiles:

### 5.1 Scenario 1: Benign Employee Browsing (Normal Baseline)
- **Source**: Kali Linux (`192.168.137.128`) via Chromium or curl.
- **Action**: Accessing `http://192.168.137.1:8001/`, browsing modules, submitting tickets.
- **Traffic Pattern**: Low connection density (1–3 connections in 10s), single destination port (`8001`), balanced bidirectional exchange, low packet rate ($< 5$ pkts/s).
- **IDS Verdict**: `NORMAL` (Autoencoder score $< 0.00488$, RF predicts `BENIGN`).

### 5.2 Scenario 2: High-Volume Single-Service Flood (DoS / DDoS)
- **Source**: Kali Linux terminal.
- **Command**: `hping3 -S -p 8001 --flood 192.168.137.1` or high-rate curl loop.
- **Traffic Pattern**: Massive packet burst ($> 80$ pkts/s), high connection count ($> 25$ connections in 10s), high SYN flag density ($> 40$ SYNs), targeting single service port (`8001`).
- **IDS Verdict**: `KNOWN_ATTACK` (Decision Engine Branch 3 or RF signature match).
- **XAI Explanation**: Highlights connection frequency, packet rate, and SYN count targeting port 8001.

### 5.3 Scenario 3: Multi-Port Reconnaissance / Zero-Day Scan
- **Source**: Kali Linux terminal.
- **Command**: `nmap -sS -p 21,22,25,80,443,8000,8001,8080,8443 192.168.137.1`
- **Traffic Pattern**: Rapid connection attempts across multiple distinct destination ports ($\ge 5$ unique ports in 10s), high forward packet count with minimal or no backward response.
- **IDS Verdict**: `SUSPICIOUS_UNKNOWN` (Decision Engine Branch 1: `ae_anomalous is True` AND `unique_ports >= 5`).
- **Clustering**: Grouped by DBSCAN into a discovered cluster tagged `"Multi-Port Probing / Reconnaissance Pattern"`.
- **XAI Explanation**: Explains that the host probed $\ge 5$ distinct ports within a 10s window alongside elevated Autoencoder reconstruction error.

### 5.4 Scenario 4: Automated Web Authentication Brute Force
- **Source**: Kali Linux terminal.
- **Command**: `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.137.1 http-post-form ...` or rapid POST script.
- **Traffic Pattern**: Multiple repetitive HTTP POST requests to port 8001 with high forward packet ratios and moderate connection rates.
- **IDS Verdict**: `KNOWN_ATTACK` (`Brute Force` or `Web Attack` by Random Forest with confidence $\ge 0.75$).
- **XAI Explanation**: SHAP TreeExplainer identifies `Total Length of Bwd Packet` and `Total Fwd Packet` as primary drivers.

