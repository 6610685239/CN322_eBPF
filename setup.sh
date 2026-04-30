#!/usr/bin/env bash
# =============================================================================
#  setup.sh — XDP Firewall Dashboard
#  รันบน Ubuntu 22.04+ เท่านั้น ต้องใช้ root (sudo)
#
#  วิธีใช้:
#    chmod +x setup.sh
#    sudo ./setup.sh
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "
${BOLD}วิธีใช้งาน:${NC}

  ${YELLOW}# Terminal 1 — Node.js Backend${NC}
  sudo mkdir -p /var/lib/firewall && chmod 777 /var/lib/firewall

  ${YELLOW}# Terminal 1 — Node.js Backend${NC}
  cd backend
  npm install
  node server.js

  ${YELLOW}# Terminal 2 — Node.js Frontend${NC}
  cd frontend
  npm install
  npm run dev

  ${YELLOW}# Terminal 3 — Firewall Loader (ต้องการ root)${NC}
  sudo python3 loader.py

  ${YELLOW}# เปิดเบราว์เซอร์${NC}
  http://localhost:5173

${BOLD}หมายเหตุ:${NC}
  • loader.py ต้องรันด้วย root เพราะต้องเข้าถึง XDP/BPF
  • Node.js ไม่ต้องการ root
  • ข้อมูล database อยู่ที่ /var/lib/firewall/firewall.db
"