#!/usr/bin/env bash
# ==============================================================================
# NetWatch - Automated Production Installer for Ubuntu / Debian
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "          NetWatch Enterprise Deployment Installer        "
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root or with sudo:"
  echo "    sudo bash deploy/install.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "[1/5] Installing OS dependencies (apt)..."
apt-get update -qq
apt-get install -y -qq \
  python3 \
  python3-pip \
  python3-venv \
  libpcap-dev \
  iputils-ping \
  libcap2-bin \
  curl \
  git

# Install Node.js LTS if not already installed
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "[+] Installing Node.js LTS (v20)..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
fi

echo "[2/5] Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
  python3 -m venv venv
fi

# Activate venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Grant raw packet capture capabilities to venv python binary so root isn't strictly mandatory
PYTHON_BIN="$(readlink -f venv/bin/python)"
if command -v setcap >/dev/null 2>&1; then
  echo "[+] Granting CAP_NET_RAW and CAP_NET_ADMIN to $PYTHON_BIN..."
  setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" || true
fi

echo "[3/5] Building React + Chart.js Single-Page Frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
  npm ci || npm install
fi
npm run build
cd "$PROJECT_ROOT"

echo "[4/5] Initializing SQLite database schema (WAL mode)..."
venv/bin/python -m backend.db --init

echo "[5/5] Configuring systemd unit..."
SERVICE_FILE="/etc/systemd/system/netwatch.service"
sed -e "s|{{PROJECT_ROOT}}|$PROJECT_ROOT|g" \
    -e "s|{{PYTHON_BIN}}|$PROJECT_ROOT/venv/bin/python|g" \
    deploy/netwatch.service > "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable netwatch.service

echo "=========================================================="
echo "      NetWatch Installation Successfully Completed!       "
echo "=========================================================="
echo "To start the service:"
echo "    sudo systemctl start netwatch"
echo ""
echo "To check service status:"
echo "    sudo systemctl status netwatch"
echo ""
echo "To view live logs:"
echo "    journalctl -u netwatch -f"
echo ""
echo "Or run directly in terminal:"
echo "    sudo venv/bin/python -m backend.run_all"
echo ""
echo "Access Dashboard: http://localhost:8000"
echo "API Documentation: http://localhost:8000/docs"
echo "=========================================================="
