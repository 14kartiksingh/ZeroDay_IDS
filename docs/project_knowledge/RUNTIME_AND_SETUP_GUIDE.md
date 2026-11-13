# ZeroDay IDS — Runtime & Setup Guide

This guide provides instructions for configuring, launching, verifying, and shutting down the complete ZeroDay IDS environment on a Windows host with a Kali Linux penetration testing virtual machine.

---

## 1. System Requirements & Prerequisites

### 1.1 Host Operating System
- **Windows**: Windows 10 or Windows 11 (64-bit) with Administrator privileges (required for raw packet capture).
- **Virtualization Software**: VMware Workstation Pro / Player or VirtualBox with Host-Only Virtual Networking configured.

### 1.2 Required Software & Drivers
1. **Python**: Python 3.10 or 3.11 (64-bit). Verify with:
   ```powershell
   python --version
   ```
2. **Node.js**: Node.js 18.x, 20.x, or 22.x with npm. Verify with:
   ```powershell
   node -v
   npm -v
   ```
3. **Npcap**: Npcap packet capture driver for Windows (must be installed with **"Install Npcap in WinPcap API-compatible Mode"** enabled). Download from [npcap.com](https://npcap.com/).

---

## 2. Environment Setup & Dependency Installation

### 2.1 Python Virtual Environment
A dedicated virtual environment should be configured at the root of `ZeroDay_IDS`:

```powershell
# Navigate to project root
cd E:\ZeroDay_IDS

# Create virtual environment (if not already present)
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### 2.2 Install Python Dependencies
Install packages listed in `backend/requirements.txt`, plus `torch` (which is required by the Autoencoder detector):

```powershell
# Install core requirements
.\venv\Scripts\pip.exe install -r backend\requirements.txt

# Install PyTorch (CPU or CUDA build)
.\venv\Scripts\pip.exe install torch --index-url https://download.pytorch.org/whl/cpu
```

#### Verified Installed Packages:
- `fastapi` (0.115+)
- `uvicorn[standard]` (0.34+)
- `scapy` (2.6+)
- `torch` (2.6+)
- `scikit-learn` (1.6+)
- `pandas` (2.2+)
- `numpy` (2.2+)
- `shap` (0.46+)
- `joblib` (1.4+)

### 2.3 Install Frontend NPM Packages
```powershell
cd E:\ZeroDay_IDS\frontend
npm install
```
Installs React 19, Lucide React, Tailwind CSS v4, and Vite.

---

## 3. Network Interface Configuration

### 3.1 Identifying the Capture Interface Index
Scapy binds to the network adapter using its internal index. In `backend/services/ids_pipeline.py`, the index is configured as:
```python
pipeline = IDSPipelineService(interface_index=12, model_dir="models/model B")
```

To verify the interface index corresponding to your virtual network adapter (VMware VMnet1):
```powershell
.\venv\Scripts\python.exe -c "from scapy.all import conf; print('\n'.join(f'Index: {getattr(i, \"index\", None)} | Name: {getattr(i, \"name\", None)} | IP: {getattr(i, \"ip\", None)}' for i in conf.ifaces.values()))"
```
Ensure that the index configured in `backend/api/main.py` (line 10) matches the index of your `VMware Virtual Ethernet Adapter for VMnet1` (Host IP: `192.168.137.1`). If your VMware adapter has a different index, update line 10 in `backend/api/main.py`.

### 3.2 Kali Linux Network Settings
In VMware Workstation:
1. Open Kali Linux VM Settings -> **Network Adapter**.
2. Select **Custom: Specific virtual network** -> Choose **VMnet1 (Host-only)**.
3. Power on Kali Linux and configure its IP:
   ```bash
   sudo ip addr add 192.168.137.128/24 dev eth0
   sudo ip link set eth0 up
   # Verify connectivity to Windows host
   ping -c 3 192.168.137.1
   ```

---

## 4. Starting the System

### 4.1 Automated Startup via Master Batch Script
The repository provides `start_zeroday_ids.bat`, which launches all three services in separate command windows:

```cmd
E:\ZeroDay_IDS\start_zeroday_ids.bat
```

#### What `start_zeroday_ids.bat` executes:
1. **Service 1**: Starts NexaVault Protected Website:
   ```cmd
   cmd /k "cd website && ..\venv\Scripts\python.exe -m http.server 8001 --bind 0.0.0.0"
   ```
2. **Service 2**: Starts FastAPI ML Detection Backend:
   ```cmd
   cmd /k "venv\Scripts\uvicorn.exe backend.api.main:app --host 0.0.0.0 --port 8000"
   ```
3. **Service 3**: Starts React Threat Dashboard:
   ```cmd
   cmd /k "cd frontend && npm run dev"
   ```
4. **Browser Launch**: Opens `http://localhost:5173` automatically.

### 4.2 Manual Step-by-Step Startup
If you prefer running services manually across three terminal windows:

#### Terminal 1 — Protected Target Website (Port 8001)
```powershell
cd E:\ZeroDay_IDS\website
..\venv\Scripts\python.exe -m http.server 8001 --bind 0.0.0.0
```

#### Terminal 2 — FastAPI Detection Backend (Port 8000)
*Run PowerShell as Administrator to ensure Scapy has raw packet sniffing permissions.*
```powershell
cd E:\ZeroDay_IDS
.\venv\Scripts\uvicorn.exe backend.api.main:app --host 0.0.0.0 --port 8000
```
Expected output:
```
Model B loaded from models/model B | Threshold: 0.004877559
Random Forest loaded from models/model B | Classes: ['BENIGN', 'Botnet', 'Brute Force', 'DoS / DDoS', 'Infiltration', 'Web Attack']
IDS Pipeline capturing live on interface: <NetworkInterface_Win VMware Virtual Ethernet Adapter for VMnet1>
FastAPI + Live ML Detection Engine started on port 8000!
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

#### Terminal 3 — React Dashboard (Port 5173)
```powershell
cd E:\ZeroDay_IDS\frontend
npm run dev
```
Expected output:
```
  VITE v8.3.6  ready in 240 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

---

## 5. Port Allocation & Verification Matrix

| Port | Protocol | Binding | Service | Health Verification |
| :---: | :---: | :---: | :--- | :--- |
| **8001** | TCP / HTTP | `0.0.0.0` | NexaVault Enterprise Portal | Open `http://localhost:8001` or `curl http://192.168.137.1:8001` |
| **8000** | TCP / HTTP / WS | `0.0.0.0` | FastAPI Backend & WebSocket | `curl http://localhost:8000/api/health` -> `{"status":"online","capturing":true}` |
| **5173** | TCP / HTTP | `localhost` | React 19 Live Threat Monitor | Open `http://localhost:5173` in browser; verify "Sensor Active" indicator |

---

## 6. Verifying the End-to-End Pipeline

1. **Verify Backend Health**:
   ```powershell
   Invoke-RestMethod http://localhost:8000/api/health
   ```
   Should return: `{"status": "online", "capturing": true}`.

2. **Generate Benign Test Flow**:
   From Kali Linux:
   ```bash
   curl http://192.168.137.1:8001/
   ```
   Wait 5 seconds for flow expiration. Observe the React dashboard at `http://localhost:5173`. A new row should appear with green `NORMAL` verdict badge and Benign confidence score.

3. **Generate Port Scan (Zero-Day Reconnaissance)**:
   From Kali Linux:
   ```bash
   nmap -sS -p 21,22,80,443,8001 192.168.137.1
   ```
   Wait 5 seconds. A new row should appear in the table with amber `UNKNOWN ANOMALY` verdict badge. Clicking the row will reveal the XAI explanation attributing the alert to multi-port probing.

4. **Verify Reset Functionality**:
   Click the **Reset** button in the dashboard header.
   - All KPI counters immediately reset to 0.
   - The Recent Network Traffic table empties, displaying: `"Waiting for live network flows... Browse or test the target website to begin."`
   - Subsequent test flows appear normally and populate the empty table without ghost rows.

---

## 7. Graceful Shutdown Procedure

To cleanly stop the system and release network sockets:
1. In the **React Frontend** window: Press `Ctrl + C`.
2. In the **FastAPI Backend** window: Press `Ctrl + C`. The lifespan handler will execute `pipeline.stop()`, terminating the Scapy capture loop and closing the database deques.
3. In the **Protected Website** window: Press `Ctrl + C`.

