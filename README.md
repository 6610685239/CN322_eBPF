<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=32&pause=1000&color=1a6b3a&center=true&vCenter=true&width=800&lines=Great+Icewall+of+Thailand;High-Performance+Network+Firewall;eBPF+%2F+XDP+on+Linux" alt="Great Icewall Typing" />

<br/>

A **high-performance programmable firewall** built on **eBPF/XDP** with a full-stack web dashboard.  
Packet filtering runs directly at the **Network Driver level** — before the kernel networking stack.

---

![Platform](https://img.shields.io/badge/Platform-Linux-1a6b3a?style=flat-square)
![Kernel](https://img.shields.io/badge/Kernel-eBPF%2FXDP-0d4f2b?style=flat-square)
![Backend](https://img.shields.io/badge/Backend-Node.js_Express-black?style=flat-square)
![Frontend](https://img.shields.io/badge/Frontend-React_+_Vite-61DAFB?style=flat-square&logo=react&logoColor=black)
![Database](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active_Development-8B0000?style=flat-square)

</div>

---

## Course & Institution

> **Course:** CN322 (Network Computer Security)  
> **Institution:** Thammasat University — Faculty of Engineering

---

## Tech Stack & Ecosystem

<div align="center">

| Kernel Space | Backend API | Frontend |
| :---: | :---: | :---: |
| ![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white) | ![NodeJS](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white) | ![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB) |
| ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) | ![Express](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white) | ![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white) |

| Auth & Security | Real-time & IPC | Environment |
| :---: | :---: | :---: |
| ![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white) | ![WebSocket](https://img.shields.io/badge/WebSocket-010101?style=for-the-badge&logo=socketdotio&logoColor=white) | ![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black) |
| ![bcrypt](https://img.shields.io/badge/bcryptjs-1a6b3a?style=for-the-badge) | ![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white) | ![Ubuntu](https://img.shields.io/badge/Ubuntu_24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white) |

</div>

---

## Architecture

```
React (browser)
  │   REST API + WebSocket (port 3001)
  ▼
Node.js (server.js)
  │   SQLite (/var/lib/firewall/firewall.db)
  │   Unix Socket (/tmp/firewall.sock)
  ▼
loader.py (Python / BPF)
  │
  ▼
Linux Kernel — XDP (firewall.c)
```

The system is split into **3 planes**:
- **Data Plane** — `firewall.c` runs in the kernel, drops/passes packets at wire speed
- **Control Plane** — `loader.py` compiles & loads the eBPF program, manages BPF maps via IPC
- **Management Plane** — Node.js + React provides a web UI with real-time WebSocket updates

---

## Features

| Feature | Description |
|---|---|
| **Feature Toggles** | Enable/disable Blacklist / Ping Block / Port Block in real-time |
| **IP Blacklist** | Add/remove IPs via web UI; persisted in SQLite; applied to BPF instantly |
| **Port Blocklist** | Add/remove TCP ports via web UI; quick-add buttons for common ports |
| **UDP Flood Prevention** | Rate-limit UDP packets per source IP (soft + hard limit) |
| **SYN Flood Prevention** | Rate-limit incoming TCP SYN packets per source IP |
| **ICMP Flood Prevention** | Rate-limit ICMP packets per source IP |
| **Temporary IP Ban** | Hard-limit triggers automatic 60-second IP ban via BPF map |
| **Live Log** | Real-time WebSocket stream of blocked packets with filter by type |
| **Stats Dashboard** | Total blocked count, breakdown by type, last 24h activity |
| **JWT Authentication** | Secure admin login; all API endpoints require valid token |

---

## Project Structure

```
CN322_eBPF/
├── setup.sh                     ← Install all dependencies
├── firewall.c                   ← BPF/XDP kernel program
├── loader.py                    ← Python loader + IPC client
│
├── backend/                     ← Node.js Backend (OOAD)
│   ├── server.js                ← Entry point (Bootstrap + DI)
│   ├── config/
│   │   └── Database.js          ← Singleton Pattern
│   ├── repositories/            ← Repository Pattern
│   │   ├── UserRepository.js
│   │   ├── BlacklistRepository.js
│   │   ├── PortRepository.js
│   │   ├── LogRepository.js
│   │   ├── FloodRateRepository.js
│   │   └── FeatureFlagRepository.js
│   ├── services/                ← Service Layer (Business Logic)
│   │   ├── AuthService.js
│   │   ├── FirewallService.js
│   │   ├── FloodService.js
│   │   └── LogService.js
│   ├── controllers/             ← MVC Controllers
│   │   ├── AuthController.js
│   │   ├── FeatureController.js
│   │   ├── FloodController.js
│   │   ├── BlacklistController.js
│   │   ├── PortController.js
│   │   └── LogController.js
│   ├── routes/
│   │   └── index.js             ← URL → Controller mapping
│   ├── middleware/
│   │   └── authMiddleware.js    ← JWT verification
│   ├── ipc/
│   │   └── IPCServer.js         ← Observer Pattern (Unix Socket)
│   └── websocket/
│       └── WSServer.js          ← Observer Pattern (WebSocket)
│
└── frontend/                    ← React + Vite SPA
    └── src/
        ├── App.jsx              ← Dashboard UI
        ├── App.css
        ├── index.css
        └── main.jsx
```

---

## Quick Start

```bash
# 1. Clone repository
git clone git@github.com:6610685239/CN322_eBPF.git
cd CN322_eBPF

# 2. Run setup script
chmod +x setup.sh && sudo ./setup.sh

# 3. Run Backend (Terminal 1)
cd backend && node server.js

# 4. Run Firewall Loader (Terminal 2 — requires root)
sudo python3 loader.py

# 5. Run Frontend (Terminal 3)
cd frontend && npm run dev
```

### Default Login

```
Username: admin
Password: admin1234
```

---

## Manual Setup

### 1. Prepare database directory

```bash
sudo mkdir -p /var/lib/firewall && chmod 777 /var/lib/firewall
```

### 2. Install & start the Node.js backend

```bash
cd backend && npm install && node server.js
```

### 3. Start the React frontend

```bash
cd frontend && npm install && npm run dev   # http://localhost:5173
```

### 4. Run the firewall loader (requires root + BCC)

```bash
sudo python3 loader.py
```

The loader will:
1. Compile and attach the XDP BPF program to all network interfaces
2. Read initial state (blacklist IPs, blocked ports, feature flags) from SQLite
3. Connect to Node.js via `/tmp/firewall.sock`
4. Stream live packet drop events to Node.js → forwarded to browser via WebSocket

---

## Notes

- `python3-bcc` must be installed on the firewall machine
- `loader.py` must run as root (required for XDP)
- Node.js does **not** need root privileges
- The IPC socket (`/tmp/firewall.sock`) is created by Node.js; `loader.py` connects to it
- All rules are persisted in SQLite and automatically reloaded on `loader.py` restart

---

## Project Members

<table>
  <thead>
    <tr>
      <th align="center">Student ID</th>
      <th align="left">Name</th>
      <th align="left">Role & Responsibility</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="center"><b>6610685056</b></td>
      <td>Chonchanan Jitrawang</td>
      <td>Kernel Space / eBPF Program</td>
    </tr>
    <tr>
      <td align="center"><b>6610685098</b></td>
      <td>Kittidet Wichaidit</td>
      <td>Python Loader / BPF Map Management</td>
    </tr>
    <tr>
      <td align="center"><b>6610685122</b></td>
      <td>Chayawat Kanjanakaew</td>
      <td>Backend API / WebSocket</td>
    </tr>
    <tr>
      <td align="center"><b>6610685205</b></td>
      <td>Nonthapat Boonprasith</td>
      <td>Frontend Dashboard / UX</td>
    </tr>
    <tr>
      <td align="center"><b>6610685239</b></td>
      <td>Parunchai Timklip</td>
      <td>Database / IPC / DevOps</td>
    </tr>
  </tbody>
</table>
