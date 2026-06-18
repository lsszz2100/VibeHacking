#!/usr/bin/env bash
# stop_all.sh — 모든 실행 중인 랩 컨테이너 정리 스크립트

set -e

# 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# docker compose 명령어 결정
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo "Docker Compose가 설치되어 있지 않습니다."
    exit 1
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║     바이브 해킹 Labs — 전체 컨테이너 정리  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# 옵션 파싱
REMOVE_VOLUMES=false
REMOVE_IMAGES=false

for arg in "$@"; do
    case "$arg" in
        -v|--volumes) REMOVE_VOLUMES=true ;;
        -i|--images)  REMOVE_IMAGES=true ;;
        --all)        REMOVE_VOLUMES=true; REMOVE_IMAGES=true ;;
        -h|--help)
            echo "사용법: $0 [옵션]"
            echo ""
            echo "옵션:"
            echo "  -v, --volumes   볼륨도 함께 삭제"
            echo "  -i, --images    빌드된 이미지도 삭제"
            echo "  --all           볼륨 + 이미지 모두 삭제"
            echo "  -h, --help      도움말"
            exit 0
            ;;
    esac
done

# -------------------------------------------------------
# 각 랩 디렉토리 순서대로 종료
# -------------------------------------------------------
LAB_DIRS=(
    "01_web_hacking_lab"
    "02_pwn_lab"
    "03_network_lab"
    "04_cloud_container_lab"
    "05_full_scenario_lab"
    "06_firmware_lab"
    "07_mobile_lab"
)

LAB_NAMES=(
    "웹 해킹 랩"
    "바이너리 익스플로잇 랩"
    "네트워크 해킹 랩"
    "클라우드/컨테이너 보안 랩"
    "전체 시나리오 통합 랩"
    "펌웨어 해킹 랩"
    "모바일 보안 랩"
)

stopped_count=0

for i in "${!LAB_DIRS[@]}"; do
    dir="${LAB_DIRS[$i]}"
    name="${LAB_NAMES[$i]}"
    lab_path="$SCRIPT_DIR/$dir"

    if [[ ! -f "$lab_path/docker-compose.yml" ]]; then
        continue
    fi

    # 해당 랩에 실행 중인 컨테이너가 있는지 확인
    running=$(cd "$lab_path" && $COMPOSE_CMD ps --quiet 2>/dev/null | wc -l)
    if [[ "$running" -eq 0 ]]; then
        info "$name — 실행 중인 컨테이너 없음 (건너뜀)"
        continue
    fi

    info "$name 종료 중..."
    cd "$lab_path"

    if [[ "$REMOVE_VOLUMES" == "true" ]]; then
        $COMPOSE_CMD down -v 2>/dev/null || $COMPOSE_CMD down
    else
        $COMPOSE_CMD down 2>/dev/null || true
    fi

    success "$name 종료 완료"
    ((stopped_count++)) || true

    cd "$SCRIPT_DIR"
done

# -------------------------------------------------------
# 이미지 정리 (--images 옵션 시)
# -------------------------------------------------------
if [[ "$REMOVE_IMAGES" == "true" ]]; then
    info "랩 관련 이미지 정리 중..."
    docker images --filter "label=lab" -q | xargs -r docker rmi -f 2>/dev/null || true
    # dangling 이미지 정리
    docker image prune -f 2>/dev/null || true
    success "이미지 정리 완료"
fi

# -------------------------------------------------------
# 고아 컨테이너/네트워크 정리
# -------------------------------------------------------
info "사용하지 않는 네트워크 정리 중..."
docker network prune -f 2>/dev/null || true

# -------------------------------------------------------
# 최종 상태 출력
# -------------------------------------------------------
echo ""
if [[ "$stopped_count" -gt 0 ]]; then
    success "총 ${stopped_count}개 랩 종료 완료"
else
    info "종료할 실행 중인 랩이 없었습니다"
fi

# 남은 컨테이너 확인
remaining=$(docker ps --filter "label=lab" --quiet 2>/dev/null | wc -l)
if [[ "$remaining" -gt 0 ]]; then
    warn "아직 실행 중인 랩 컨테이너가 ${remaining}개 있습니다:"
    docker ps --filter "label=lab" --format "  {{.Names}} — {{.Status}}"
else
    success "모든 랩 컨테이너가 정리되었습니다"
fi

echo ""
echo -e "${BOLD}다시 시작하려면:${RESET}"
echo "  ./start_lab.sh 01   # 특정 랩 시작"
echo "  ./start_lab.sh all  # 전체 랩 시작"
