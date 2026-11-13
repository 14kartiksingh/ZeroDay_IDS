# ZeroDay IDS — Detailed Line-by-Line Code Explanation: Website & Launcher

This document details the source code of the protected target web application (**NexaVault Enterprise Portal**) and the automated Windows master launcher script (`start_zeroday_ids.bat`).

---

# Part 1: Protected Target Website (`website/index.html`)

### Lines 1–32: Document Header & Navigation Bar
```html
1: <!DOCTYPE html>
2: <html lang="en">
3: <head>
4:     <meta charset="UTF-8">
5:     <meta name="viewport" content="width=device-width, initial-scale=1.0">
6:     <title>NexaVault Cloud — Enterprise Portal</title>
7:     <link rel="stylesheet" href="style.css">
8: </head>
9: <body>
10:     <!-- Top Navigation -->
11:     <header class="navbar">
12:         <div class="nav-container">
13:             <div class="brand">
14:                 <div class="logo-icon">NV</div>
15:                 <div>
16:                     <span class="brand-name">NexaVault</span>
17:                     <span class="brand-tag">ENTERPRISE</span>
18:                 </div>
19:             </div>
20:             <nav class="nav-links">
21:                 <a href="#overview" class="active">Overview</a>
22:                 <a href="#services">Cloud Services</a>
23:                 <a href="#portal">Employee Login</a>
24:                 <a href="#support">IT Support</a>
25:             </nav>
26:             <div class="status-pill">
27:                 <span class="pulse-dot"></span>
28:                 Protected Asset · Port 8001
29:             </div>
30:         </div>
31:     </header>
```
- **Lines 1–8**: Standard HTML5 header linking to `style.css`.
- **Lines 11–31**: Enterprise navigation bar featuring the "NV" logo icon, internal section navigation links, and a status pill indicating that this web asset is hosted on port 8001 and protected by ZeroDay IDS.

---

### Lines 33–71: Hero Banner & Infrastructure Metrics Strip
```html
33:     <!-- Hero Banner -->
34:     <section id="overview" class="hero">
35:         <div class="hero-content">
36:             <span class="eyebrow">INTERNAL CORPORATE INFRASTRUCTURE</span>
37:             <h1>Next-Generation Cloud Operations & Data Gateway</h1>
38:             <p>
39:                 Welcome to the NexaVault Enterprise Workspace. Access internal repositories,
40:                 cloud compute clusters, and financial analytics securely. All network sessions
41:                 are monitored in real time.
42:             </p>
43:             <div class="hero-actions">
44:                 <a href="#portal" class="btn-primary">Access Employee Portal</a>
45:                 <a href="#services" class="btn-secondary">Explore Infrastructure</a>
46:             </div>
47:         </div>
48:     </section>
49: 
50:     <!-- Main Content Grid -->
51:     <main class="container">
52:         <!-- Infrastructure Metrics Strip -->
53:         <div class="metrics-strip">
54:             <div class="metric-box">
55:                 <span class="metric-label">API Gateway</span>
56:                 <span class="metric-value text-green">99.98% Uptime</span>
57:             </div>
58:             <div class="metric-box">
59:                 <span class="metric-label">Active Nodes</span>
60:                 <span class="metric-value">14 Clusters</span>
61:             </div>
62:             <div class="metric-box">
63:                 <span class="metric-label">Encryption</span>
64:                 <span class="metric-value">TLS 1.3 / AES-256</span>
65:             </div>
66:             <div class="metric-box">
67:                 <span class="metric-label">Security Posture</span>
68:                 <span class="metric-value text-blue">ZeroDay IDS Active</span>
69:             </div>
70:         </div>
```
- **Lines 34–48**: Enterprise hero section establishing the pretext of a corporate intranet gateway.
- **Lines 53–70**: Metrics strip showing operational KPIs ("API Gateway 99.98%", "14 Clusters", "TLS 1.3", "ZeroDay IDS Active").

---

### Lines 73–100: Interactive Corporate Modules
```html
73:         <section id="services" class="section-block">
74:             <div class="section-header">
75:                 <h2>Hosted Enterprise Modules</h2>
76:                 <p>Click any module below to simulate standard employee browsing traffic.</p>
77:             </div>
78:             <div class="cards-grid">
79:                 <div class="card" onclick="simulateActivity('Financial Ledger Vault')">
80:                     <div class="card-icon">📊</div>
81:                     <h3>Financial Ledger Vault</h3>
82:                     <p>Quarterly revenue reports, payroll records, and encrypted audit trails.</p>
83:                     <span class="card-link">Open Module →</span>
84:                 </div>
85:                 <div class="card" onclick="simulateActivity('Cloud Compute Console')">
86:                     <div class="card-icon">☁️</div>
87:                     <h3>Cloud Compute Console</h3>
88:                     <p>Manage virtual machine instances, storage buckets, and internal APIs.</p>
89:                     <span class="card-link">Open Module →</span>
90:                 </div>
91:                 <div class="card" onclick="simulateActivity('Identity Directory')">
92:                     <div class="card-icon">🔐</div>
93:                     <h3>Identity Directory</h3>
94:                     <p>Role-based access control, SSH key management, and SSO certificates.</p>
95:                     <span class="card-link">Open Module →</span>
96:                 </div>
97:             </div>
98:             <div id="moduleBanner" class="toast-banner hidden"></div>
99:         </section>
```
- **Lines 79, 85, 91**: Interactive cards wired with `onclick="simulateActivity(...)"`. When clicked, users generate standard HTTP sessions that travel over the virtual network interface to be captured and classified as `NORMAL` by the IDS.

---

### Lines 102–148: Two-Column Interactive Forms
```html
102:         <div class="two-col-grid">
103:             <!-- Employee Portal Login -->
104:             <section id="portal" class="section-block form-card">
105:                 <div class="section-header">
106:                     <h2>Employee SSO Login</h2>
107:                     <p>Authenticate with your corporate credentials.</p>
108:                 </div>
109:                 <form id="loginForm">
110:                     <div class="form-group">
111:                         <label>Corporate Email or ID</label>
112:                         <input type="text" id="empId" placeholder="alex.mercer@nexavault.local" required>
113:                     </div>
114:                     <div class="form-group">
115:                         <label>Security Passphrase</label>
116:                         <input type="password" id="empPass" placeholder="••••••••••••" required>
117:                     </div>
118:                     <button type="submit" class="btn-primary full-width">Sign In to Workspace</button>
119:                 </form>
120:                 <div id="loginFeedback" class="feedback-msg hidden"></div>
121:             </section>
122: 
123:             <!-- IT Support Ticket Form -->
124:             <section id="support" class="section-block form-card">
125:                 <div class="section-header">
126:                     <h2>IT Operations Desk</h2>
127:                     <p>Submit an internal infrastructure or access request.</p>
128:                 </div>
129:                 <form id="supportForm">
130:                     <div class="form-group">
131:                         <label>Full Name</label>
132:                         <input type="text" placeholder="Your full name" required>
133:                     </div>
134:                     <div class="form-group">
135:                         <label>Department Email</label>
136:                         <input type="email" placeholder="name@nexavault.local" required>
137:                     </div>
138:                     <div class="form-group">
139:                         <label>Request Details</label>
140:                         <textarea rows="2" placeholder="Describe your request..." required></textarea>
141:                     </div>
142:                     <button type="submit" class="btn-secondary full-width">Submit Support Ticket</button>
143:                 </form>
144:                 <div id="supportFeedback" class="feedback-msg hidden"></div>
145:             </section>
146:         </div>
```
- **Lines 109–121**: Employee SSO Login form. Submitting simulates user authentication. Also serves as the target endpoint for Kali Linux password brute force attacks (Hydra / Python scripts).
- **Lines 129–145**: IT support ticket form allowing submission of multi-line request payloads.

---

### Lines 153–178: Client-Side Interaction Handlers
```javascript
153:     <script>
154:         function simulateActivity(moduleName) {
155:             const banner = document.getElementById('moduleBanner');
156:             banner.textContent = `✓ Accessed "${moduleName}" — Normal HTTP session traffic generated.`;
157:             banner.classList.remove('hidden');
158:             setTimeout(() => banner.classList.add('hidden'), 3500);
159:         }
160: 
161:         document.getElementById('loginForm').addEventListener('submit', function(e) {
162:             e.preventDefault();
163:             const fb = document.getElementById('loginFeedback');
164:             const user = document.getElementById('empId').value;
165:             fb.textContent = `✓ Session authenticated for ${user}. Dashboard token issued.`;
166:             fb.className = 'feedback-msg success';
167:             this.reset();
168:         });
169: 
170:         document.getElementById('supportForm').addEventListener('submit', function(e) {
171:             e.preventDefault();
172:             const fb = document.getElementById('supportFeedback');
173:             fb.textContent = '✓ Ticket #NV-4092 logged with IT Operations.';
174:             fb.className = 'feedback-msg success';
175:             this.reset();
176:         });
177:     </script>
```
- **Lines 154–159**: Displays a temporary toast notification when enterprise module cards are clicked.
- **Lines 161–176**: Form submission event listeners intercepting `submit`, displaying confirmation feedback, and resetting form fields without page reloads.

---

# Part 2: Website Stylesheet (`website/style.css`)

### Key CSS Architecture Sections:
- **Lines 1–13 (Reset & Typography)**: Configures global box-sizing (`border-box`), font-family (`'Inter', system-ui, sans-serif`), and background (`#f8fafc`).
- **Lines 14–100 (Navbar & Status Pill)**: Fixed top dark navigation bar (`#0f172a`), brand icon gradient (`linear-gradient(135deg, #3b82f6, #1d4ed8)`), and green glowing pulse indicator (`.pulse-dot`).
- **Lines 101–144 (Hero Banner & Buttons)**: Dark slate hero background gradient (`linear-gradient(135deg, #0f172a 0%, #1e293b 100%)`) with primary blue (`#2563eb`) and secondary slate button styles.
- **Lines 184–222 (Metrics Strip)**: Responsive grid displaying white rounded KPI metric boxes with drop shadows (`0 4px 12px rgba(15, 23, 42, 0.04)`).
- **Lines 223–296 (Cards Grid & Transitions)**: Interactive card styling with hover elevation (`transform: translateY(-3px)`, `box-shadow: 0 10px 24px rgba(37, 99, 235, 0.08)`).
- **Lines 297–356 (Form Cards)**: Responsive two-column grid (`minmax(340px, 1fr)`), clean input field borders, focus states, and emerald success toast alerts.
- **Lines 357–365 (Footer)**: Centered copyright footer on light background.

---

# Part 3: Master Launcher Script (`start_zeroday_ids.bat`)

```cmd
1: @echo off
2: title ZeroDay IDS — Master Demo Launcher
3: color 0B
4: 
5: echo ============================================================
6: echo        ZeroDay IDS - Starting Complete Demo Environment
7: echo ============================================================
8: echo.
9: 
10: cd /d "%~dp0"
```
- **Line 1**: Suppresses command echoing for clean terminal output.
- **Lines 2–3**: Sets window title and light-aqua text color (`color 0B`).
- **Line 10**: Changes current directory to the folder containing the batch script (`%~dp0`), ensuring relative paths resolve reliably regardless of how the script was launched.

```cmd
12: echo [1/3] Starting Protected Target Website (NexaVault on Port 8001)...
13: start "1. Protected Website (Port 8001)" cmd /k "cd /d "%~dp0website" && ..\venv\Scripts\python.exe -m http.server 8001 --bind 0.0.0.0"
14: 
15: timeout /t 2 /nobreak >nul
```
- **Line 13**: Spawns Service 1 in a new command window named `"1. Protected Website (Port 8001)"`. Starts Python's built-in HTTP server on port 8001 bound to all interfaces (`--bind 0.0.0.0`), allowing external access from Kali Linux.
- **Line 15**: Pauses for 2 seconds to allow the HTTP socket to bind.

```cmd
17: echo [2/3] Starting 6-Component ML Detection Backend (FastAPI on Port 8000)...
18: start "2. ML Detection Backend (Port 8000)" cmd /k "cd /d "%~dp0" && venv\Scripts\uvicorn.exe backend.api.main:app --host 0.0.0.0 --port 8000"
19: 
20: timeout /t 4 /nobreak >nul
```
- **Line 18**: Spawns Service 2 in a new command window. Starts the FastAPI backend with Uvicorn on port 8000 (`--host 0.0.0.0 --port 8000`). This initializes PyTorch, Scikit-learn, and the Scapy background sniffer thread.
- **Line 20**: Pauses for 4 seconds to allow model loading and Npcap packet sniffer initialization.

```cmd
22: echo [3/3] Starting React Live Threat Monitor (Port 5173)...
23: start "3. React Detection Dashboard (Port 5173)" cmd /k "cd /d "%~dp0frontend" && npm run dev"
24: 
25: timeout /t 3 /nobreak >nul
```
- **Line 23**: Spawns Service 3 in a new command window. Launches Vite development server for the React frontend on port 5173.
- **Line 25**: Pauses for 3 seconds for Vite compilation.

```cmd
27: echo.
28: echo Opening Live Threat Monitor in your browser...
29: start http://localhost:5173
30: 
31: echo.
32: echo ============================================================
33: echo   All 3 services are running!
34: echo   - Protected Website : http://localhost:8001
35: echo   - ML Backend API    : http://localhost:8000
36: echo   - Threat Dashboard  : http://localhost:5173
37: echo ============================================================
38: pause
```
- **Line 29**: Launches the default Windows web browser pointing to `http://localhost:5173`.
- **Line 38**: Pauses execution, keeping the master console window open to display service addresses.

