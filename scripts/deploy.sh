#!/usr/bin/env bash
# ============================================================
#  hack-detector 서버 업데이트 스크립트
#  서버에서 실행: bash scripts/deploy.sh
# ============================================================
set -euo pipefail

APP_DIR="/opt/hack-detector"
SERVICE="hack-detector"

cd "$APP_DIR"

echo "-- pulling latest code"
git pull origin main

echo "-- installing dependencies"
.venv/bin/pip install -q -e .

echo "-- restarting service"
sudo systemctl restart "$SERVICE"

echo "-- checking status"
sleep 2
sudo systemctl status "$SERVICE" --no-pager -l

echo ""
echo "-- deploy complete"
echo "-- logs: journalctl -u $SERVICE -f"
