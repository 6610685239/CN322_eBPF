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

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${GREEN}════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${GREEN}  $*${NC}"; \
            echo -e "${BOLD}${GREEN}════════════════════════════════════════${NC}"; }

# ── Pre-flight checks ─────────────────────────────────────────────────────────
header "XDP Firewall Dashboard — Setup"

[[ "$EUID" -ne 0 ]] && error "กรุณารันด้วย sudo: sudo ./setup.sh"

# ตรวจ Ubuntu version
if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
  warn "ไม่ใช่ Ubuntu อาจมีปัญหาบางส่วน"
fi

UBUNTU_VER=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2 | cut -d'.' -f1)
if [[ "$UBUNTU_VER" -lt 20 ]]; then
  error "ต้องการ Ubuntu 20.04 ขึ้นไป (พบ: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2))"
fi

# ตรวจสอบว่ารันจาก project root
[[ ! -f "backend/package.json" ]] && error "กรุณารัน setup.sh จาก root ของ project"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
info "Project directory: ${SCRIPT_DIR}"

# ── Step 1: System packages ───────────────────────────────────────────────────
header "1/4  ติดตั้ง System Packages"

info "อัปเดต package list..."
apt-get update -qq

info "ติดตั้ง dependencies..."
apt-get install -y -qq \
  python3 \
  python3-pip \
  python3-bcc \
  bpfcc-tools \
  linux-headers-"$(uname -r)" \
  curl \
  git \
  build-essential \
  2>/dev/null || true

success "System packages พร้อม"

# ── Step 2: npm install ───────────────────────────────────────────────────────
header "2/4  ติดตั้ง Node.js Dependencies"

info "Backend (server.js)..."
cd "${SCRIPT_DIR}/backend"
npm install --silent
success "Backend dependencies พร้อม"

info "Frontend (React)..."
cd "${SCRIPT_DIR}/frontend"
npm install --silent
success "Frontend dependencies พร้อม"

cd "${SCRIPT_DIR}"

# ── Step 3: สร้าง directories + environment ───────────────────────────────────
header "3/4  ตั้งค่า Environment"

# สร้าง DB directory
DB_DIR="/var/lib/firewall"
info "สร้าง database directory: ${DB_DIR}"
mkdir -p "${DB_DIR}"
chmod 777 "${DB_DIR}"
success "Database directory พร้อม"



# ── Step 4: Build frontend ────────────────────────────────────────────────────
header "4/4  Build React Frontend"

info "Building..."
cd "${SCRIPT_DIR}/frontend"
npm install --silent
success "Frontend build เสร็จแล้ว → frontend/dist/"

cd "${SCRIPT_DIR}"

# ── Done ──────────────────────────────────────────────────────────────────────
header "✅  Setup เสร็จสมบูรณ์!"

echo -e "
${BOLD}วิธีรัน:${NC}

  ${YELLOW}# Terminal 1 — Node.js Backend${NC}
  cd backend
  node server.js

  ${YELLOW}# Terminal 2 — Firewall Loader (ต้องการ root)${NC}
  sudo python3 loader.py

  ${YELLOW}# เปิดเบราว์เซอร์${NC}
  http://localhost:5173

${BOLD}หมายเหตุ:${NC}
  • loader.py ต้องรันด้วย root เพราะต้องเข้าถึง XDP/BPF
  • Node.js ไม่ต้องการ root
  • ข้อมูล database อยู่ที่ /var/lib/firewall/firewall.db
"