#!/usr/bin/env bash
# ============================================================
#  hack-detector 설정 파일 동기화 (로컬 → 서버)
#  로컬에서 실행: bash scripts/sync-config.sh [VM_NAME] [ZONE]
# ============================================================
set -euo pipefail

VM_NAME="${1:-hack-detector-vm}"
ZONE="${2:-us-central1-a}"
DEST="/opt/hack-detector/config/"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "-- syncing config files to $VM_NAME ($ZONE)"

for FILE in channels.yaml accounts.yaml protocols.yaml; do
    SRC="$SCRIPT_DIR/config/$FILE"
    if [ -f "$SRC" ]; then
        echo "   uploading $FILE"
        gcloud compute scp "$SRC" "$VM_NAME:$DEST" --zone="$ZONE"
    fi
done

echo "-- restarting service"
gcloud compute ssh "$VM_NAME" --zone="$ZONE" \
    --command="sudo systemctl restart hack-detector"

echo "-- done"
echo "-- verify: gcloud compute ssh $VM_NAME --zone=$ZONE --command='journalctl -u hack-detector -n 5'"
