# XDP Firewall Dashboard

Web-based control panel for the XDP BPF firewall — built with React + Node.js + SQLite.

## Project Structure

```
firewall-dashboard/
├── setup.sh                     ← ติดตั้ง dependencies ทั้งหมด
├── firewall.c                   ← BPF/XDP kernel program
├── loader.py                    ← Python loader + IPC client
│
├── backend/                     ← Node.js Backend (OOAD)
│   ├── server.js                ← Entry point (Bootstrap)                  
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
|   |   ├── FloodService.js
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
└── frontend/                    ← React.js Frontend
    └── src/
        ├── App.jsx
        ├── App.css
        ├── Index.css
        └── Main.jsx
      
    
```

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

## Quick Start
 
```bash
# 1. Clone repository
git clone git@github.com:6610685239/CN322_eBPF.git 
cd CN322_eBPF
 
# 2. run setup script 
chmod +x setup.sh
sudo ./setup.sh
 
# 3. run Backend (Terminal 1)
cd backend
node server.js
 
# 4. run Firewall Loader (Terminal 2 — ต้องการ root)
sudo python3 loader.py

# 5. run Frontend (Terminal 3)
cd frontend
npm run dev
```
## Default Login

```
Username: admin
Password: admin1234
```

## Or Setup

### 1. Prepare database directory

```bash
sudo mkdir -p /var/lib/firewall && chmod 777 /var/lib/firewall
```

### 2. Install & start the Node.js backend

```bash
cd backend
npm install
node server.js
```

### 3. Start the React frontend (development)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

### 4. Run the firewall loader (requires root + BCC)

```bash
sudo python3 loader.py
```

The loader will:
1. Load and attach the XDP BPF program to all network interfaces
2. Read initial state (blacklist IPs, blocked ports, feature flags) from SQLite
3. Connect to Node.js via `/tmp/firewall.sock`
4. Stream live packet events to Node.js → forwarded to browser via WebSocket

## Default Login

```
Username: admin
Password: admin1234
```

## Features

| Feature | Description |
|---|---|
| Feature Toggles | Enable/disable Blacklist / Ping Block / Port Block in real-time |
| IP Blacklist | Add/remove IPs via web UI; persisted in SQLite; applied to BPF instantly |
| Port Blocklist | Add/remove TCP ports via web UI; quick-add buttons for common ports |
| UDP Flood Prevention | Rate-limit UDP packets per source IP |
| SYN Flood Prevention | Rate-limit incoming TCP SYN packets per source IP |
| ICMP Flood Prevention | Rate-limit ICMP packets per source IP |
| Live Log | Real-time WebSocket stream of blocked packets with filter by type |
| Stats | Total blocked count, breakdown by type |

## Notes

- BCC (`python3-bcc`) must be installed on the firewall machine
- `loader.py` must run as root (required for XDP)
- Node.js does NOT need root privileges
- The IPC socket (`/tmp/firewall.sock`) is created by Node.js; loader.py connects to it
- All rules are persisted in SQLite and automatically reloaded on loader.py restart
