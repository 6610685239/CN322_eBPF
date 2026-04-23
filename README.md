# XDP Firewall Dashboard

Web-based control panel for the XDP BPF firewall — built with React + Node.js + SQLite.

## Project Structure

```
firewall-dashboard/
├── firewall.c          ← BPF kernel program (XDP)
├── loader.py           ← Python BPF loader + IPC client
├── backend/
│   ├── server.js       ← Node.js REST API + WebSocket + IPC server
│   └── package.json
└── frontend/
    ├── index.html
    ├── vite.config.js
    └── src/
        ├── main.jsx
        └── App.jsx     ← React Dashboard
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

## Setup

### 1. Prepare database directory

```bash
sudo mkdir -p /var/lib/firewall
sudo chmod 777 /var/lib/firewall
```

### 2. Install & start the Node.js backend

```bash
cd backend
npm install
node server.js
```

Environment variables (optional):
```bash
PORT=3001
JWT_SECRET=your_secret_here
FIREWALL_DB=/var/lib/firewall/firewall.db
IPC_SOCK_PATH=/tmp/firewall.sock
ADMIN_USER=admin
ADMIN_PASS=admin1234
```

### 3. Start the React frontend (development)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

For production build:
```bash
npm run build
# Serve the dist/ folder with any static server or nginx
```

### 4. Run the firewall loader (requires root + BCC)

Copy `firewall.c` and `loader.py` to a working directory, then:

```bash
sudo FIREWALL_DB=/var/lib/firewall/firewall.db python3 loader.py
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

Change via environment variables: `ADMIN_USER` and `ADMIN_PASS`

## Features

| Feature | Description |
|---|---|
| Feature Toggles | Enable/disable Blacklist / Ping Block / Port Block in real-time |
| IP Blacklist | Add/remove IPs via web UI; persisted in SQLite; applied to BPF instantly |
| Port Blocklist | Add/remove TCP ports via web UI; quick-add buttons for common ports |
| Live Log | Real-time WebSocket stream of blocked packets with filter by type |
| Stats | Total blocked count, breakdown by type |

## Notes

- BCC (`python3-bcc`) must be installed on the firewall machine
- `loader.py` must run as root (required for XDP)
- Node.js does NOT need root privileges
- The IPC socket (`/tmp/firewall.sock`) is created by Node.js; loader.py connects to it
- All rules are persisted in SQLite and automatically reloaded on loader.py restart
