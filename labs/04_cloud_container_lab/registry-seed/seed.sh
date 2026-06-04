#!/bin/sh
# Registry 이미지 사전 로드 스크립트 — 교육 목적 전용

set -e

REGISTRY="localhost:5000"
MAX_WAIT=30
waited=0

echo "[*] Registry 준비 대기 중..."
until wget -q -O /dev/null "http://${REGISTRY}/v2/" 2>/dev/null; do
    sleep 2
    waited=$((waited + 2))
    if [ "$waited" -ge "$MAX_WAIT" ]; then
        echo "[!] Registry 응답 없음 — 종료"
        exit 1
    fi
done
echo "[+] Registry 준비 완료"

echo "[*] corp-app:latest 빌드 및 푸시..."
docker build -t "${REGISTRY}/corp-app:latest" /seed/corp-app/
docker push "${REGISTRY}/corp-app:latest"

echo "[*] backup-tool:v1.2 빌드 및 푸시..."
docker build -t "${REGISTRY}/backup-tool:v1.2" /seed/backup-tool/
docker push "${REGISTRY}/backup-tool:v1.2"

echo "[+] Registry 시딩 완료 — 이미지 2개 로드"
docker images | grep "${REGISTRY}"
