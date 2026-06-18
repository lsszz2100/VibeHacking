#!/usr/bin/env bash
# start_lab.sh — CTF 스타일 취약 환경 시작 스크립트
# 사용법: ./start_lab.sh [01|02|03|04|05|06|07|all]

set -e

# -------------------------------------------------------
# 색상 출력 헬퍼
# -------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*"; exit 1; }

# -------------------------------------------------------
# 스크립트 위치 기준으로 labs/ 경로 설정
# -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABS_DIR="$SCRIPT_DIR"

# -------------------------------------------------------
# 의존성 확인
# -------------------------------------------------------
check_deps() {
    info "의존성 확인 중..."

    if ! command -v docker &>/dev/null; then
        error "Docker가 설치되어 있지 않습니다. https://docs.docker.com/get-docker/ 참조"
    fi
    success "Docker: $(docker --version)"

    # docker compose v2 또는 docker-compose v1 확인
    if docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
        success "Docker Compose: $(docker compose version)"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
        success "docker-compose: $(docker-compose --version)"
    else
        error "Docker Compose가 설치되어 있지 않습니다."
    fi

    # Docker 데몬 실행 확인
    if ! docker info &>/dev/null 2>&1; then
        error "Docker 데몬이 실행 중이지 않습니다. 'sudo systemctl start docker' 또는 Docker Desktop을 시작하세요."
    fi
    success "Docker 데몬 실행 중"
}

# -------------------------------------------------------
# 랩 정보 출력
# -------------------------------------------------------
print_banner() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          바이브 해킹 — CTF 취약 환경 번들            ║"
    echo "║             교육 목적 전용 | 로컬 환경에서만 사용     ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# -------------------------------------------------------
# 각 랩 시작 함수
# -------------------------------------------------------
start_lab() {
    local lab_num="$1"
    local lab_dirs=(
        ""                          # 0 (미사용)
        "01_web_hacking_lab"
        "02_pwn_lab"
        "03_network_lab"
        "04_cloud_container_lab"
        "05_full_scenario_lab"
        "06_firmware_lab"
        "07_mobile_lab"
    )

    local lab_names=(
        ""
        "웹 해킹 랩"
        "바이너리 익스플로잇 랩"
        "네트워크 해킹 랩"
        "클라우드/컨테이너 보안 랩"
        "전체 시나리오 통합 랩"
        "펌웨어 해킹 랩"
        "모바일 보안 랩"
    )

    local lab_ports=(
        ""
        "DVWA: http://localhost:8080/dvwa/  |  Juice Shop: http://localhost:3001  |  WebGoat: http://localhost:8081/WebGoat"
        "nc localhost 10001~10005"
        "docker exec -it net_lab_attacker bash"
        "http://localhost:8080 (SSRF), http://localhost:8443 (K8s API)"
        "http://localhost:8888 (DMZ 웹)"
        "취약 펌웨어 웹 패널: http://localhost:8062  |  분석: docker exec -it firmware_analyzer bash"
        "취약 모바일 API: http://localhost:8072  |  분석: docker exec -it apk_analyzer bash"
    )

    if [[ $lab_num -lt 1 || $lab_num -gt 7 ]]; then
        error "잘못된 랩 번호: $lab_num (1~7 사이)"
    fi

    local dir_name="${lab_dirs[$lab_num]}"
    local lab_path="$LABS_DIR/$dir_name"

    if [[ ! -d "$lab_path" ]]; then
        error "랩 디렉토리를 찾을 수 없습니다: $lab_path"
    fi

    info "랩 ${lab_num}: ${lab_names[$lab_num]} 시작 중..."
    info "경로: $lab_path"

    cd "$lab_path"
    $COMPOSE_CMD up -d --build

    echo ""
    success "랩 ${lab_num} 시작 완료!"
    echo -e "  접근 방법: ${CYAN}${lab_ports[$lab_num]}${RESET}"
    echo -e "  로그 확인: ${CYAN}cd $lab_path && $COMPOSE_CMD logs -f${RESET}"
    echo -e "  종료 방법: ${CYAN}cd $lab_path && $COMPOSE_CMD down${RESET}"

    cd "$LABS_DIR"
}

# -------------------------------------------------------
# 전체 랩 시작
# -------------------------------------------------------
start_all() {
    warn "전체 랩을 시작합니다. 충분한 메모리(8GB+)와 디스크(20GB+)가 필요합니다."
    echo -n "계속하시겠습니까? (y/N): "
    read -r confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "취소되었습니다."
        exit 0
    fi

    for i in 1 2 3 4 5 6 7; do
        start_lab "$i"
        echo ""
    done

    echo ""
    success "모든 랩 시작 완료!"
    print_summary
}

# -------------------------------------------------------
# 실행 중인 랩 요약
# -------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${BOLD}=== 실행 중인 랩 컨테이너 ===${RESET}"
    docker ps --filter "label=lab" \
        --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
    docker ps --filter "label=lab"
    echo ""
    echo -e "${BOLD}=== 접근 URL ===${RESET}"
    echo "  01 웹 해킹:          http://localhost:8080"
    echo "  02 바이너리 익스플로잇: nc localhost 10001~10005"
    echo "  03 네트워크:         docker exec -it net_lab_attacker bash"
    echo "  04 클라우드:         http://localhost:8080 (SSRF)"
    echo "  05 전체 시나리오:    http://localhost:8888"
    echo "  06 펌웨어:           http://localhost:8062 (취약 펌웨어 웹 패널)"
    echo "  07 모바일:           http://localhost:8072 (취약 모바일 API)"
}

# -------------------------------------------------------
# 사용법 출력
# -------------------------------------------------------
usage() {
    echo -e "${BOLD}사용법:${RESET}"
    echo "  $0 [랩번호|all]"
    echo ""
    echo -e "${BOLD}옵션:${RESET}"
    echo "  01    웹 해킹 랩 (DVWA, Juice Shop, WebGoat, SQLi)"
    echo "  02    바이너리 익스플로잇 랩 (BOF, ret2libc, ROP, fmtstr, heap)"
    echo "  03    네트워크 해킹 랩 (SSH, FTP, DNS, SMTP)"
    echo "  04    클라우드/컨테이너 보안 랩 (SSRF, IMDS, K8s, 컨테이너 탈출)"
    echo "  05    전체 시나리오 통합 랩 (기업환경 APT 시뮬레이션)"
    echo "  06    펌웨어 해킹 랩 (binwalk, QEMU 에뮬레이션, 하드코딩 자격증명)"
    echo "  07    모바일 보안 랩 (APK 정적분석, Frida, JWT alg:none 우회)"
    echo "  all   모든 랩 시작"
    echo "  ps    실행 중인 랩 목록"
    echo ""
    echo -e "${BOLD}예시:${RESET}"
    echo "  $0 01        # 웹 해킹 랩만 시작"
    echo "  $0 all       # 전체 랩 시작"
    echo "  $0 ps        # 상태 확인"
    echo ""
    echo -e "${YELLOW}주의: 이 랩은 의도적으로 취약합니다. 로컬 환경에서만 실행하세요!${RESET}"
}

# -------------------------------------------------------
# 메인
# -------------------------------------------------------
print_banner
check_deps

ARG="${1:-}"

case "$ARG" in
    01|1) start_lab 1 ;;
    02|2) start_lab 2 ;;
    03|3) start_lab 3 ;;
    04|4) start_lab 4 ;;
    05|5) start_lab 5 ;;
    06|6) start_lab 6 ;;
    07|7) start_lab 7 ;;
    all|ALL) start_all ;;
    ps|status) print_summary ;;
    ""|--help|-h) usage ;;
    *) error "알 수 없는 인자: $ARG\n$(usage)" ;;
esac
