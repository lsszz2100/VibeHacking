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
    "08_llm_security_lab"
    "09_ics_scada_lab"
    "10_k8s_security_lab"
    "11_ad_kerberos_lab"
    "12_cicd_supply_chain_lab"
    "13_ebpf_kernel_lab"
    "14_maldoc_lab"
    "15_web3_smart_contract_lab"
    "16_memory_forensics_lab"
    "17_kubernetes_cloud_native_lab"
    "18_ai_agent_mcp_lab"
    "19_android_frida_lab"
    "20_winapp_exploit_lab"
    "21_automotive_can_lab"
    "22_api_security_lab"
    "23_soc_threat_hunting_lab"
    "24_fuzzing_vulnerability_lab"
    "25_ai_redteam_lab"
    "26_malware_sandbox_lab"
    "27_wifi_wpa3_security_lab"
    "28_cisco_network_device_lab"
    "29_adcs_kerberos_delegation_lab"
    "30_ghidra_deobfuscation_lab"
    "31_oauth_sso_lab"
    "32_bgp_routeguard_lab"
    "33_kisa_infrastructure_audit_lab"
    "34_osint_surface_recon_lab"
    "35_cloud_iam_privilege_escalation_lab"
    "36_enterprise_database_security_lab"
    "37_bluetooth_sdr_security_lab"
    "38_edr_evasion_c2_lab"
    "39_modern_cryptography_lab"
    "40_enterprise_dfir_ir_lab"
    "41_supply_chain_security_lab"
    "42_serverless_security_lab"
    "43_cloud_incident_response_lab"
    "44_browser_extension_security_lab"
    "45_quantum_cryptography_pqc_lab"
    "46_linux_kernel_hardening_lab"
    "47_ai_agent_mcp_security_lab"
    "48_firmware_iot_rce_lab"
    "49_pqc_hybrid_tls_lab"
    "50_sans_dfir_hunting_lab"
    "51_ebpf_runtime_security_lab"
    "52_c2_tunneling_and_exfiltration_lab"
    "53_ad_bloodhound_lab"
)

LAB_NAMES=(
    "웹 해킹 랩"
    "바이너리 익스플로잇 랩"
    "네트워크 해킹 랩"
    "클라우드/컨테이너 보안 랩"
    "전체 시나리오 통합 랩"
    "펌웨어 해킹 랩"
    "모바일 보안 랩"
    "AI/LLM 보안 랩"
    "ICS/SCADA 제어 보안 랩"
    "Kubernetes & 컨테이너 보안 랩"
    "Active Directory & Kerberos 침투 랩"
    "CI/CD & 소프트웨어 공급망 침투 랩"
    "eBPF 커널 침투 및 런타임 보안 랩"
    "문서형 악성코드 & PDF 분석 랩"
    "Web3 & 스마트 컨트랙트 보안 랩"
    "메모리 포렌식 & Volatility 3 분석 랩"
    "클라우드 네이티브 & Kubernetes 보안 랩"
    "AI 에이전트 & MCP 보안 랩"
    "안드로이드 악성코드 & Frida 후킹 랩"
    "윈도우 애플리케이션 & 커널 취약점 랩"
    "차량 보안 & CAN Bus 랩"
    "API 보안 & Modern Auth 랩"
    "SOC 위협 헌팅 & SIEM/IR 랩"
    "퍼징 & 취약점 발굴 랩"
    "AI 레드팀 & 탈옥 평가 랩"
    "악성코드 자동 분석 & 동적 샌드박스 랩"
    "무선 네트워크 & WPA3 보안 실전 랩"
    "네트워크 인프라 & L2 스위치 보안 실전 랩"
    "AD CS 인증서 침투 & Kerberos 위임 실전 랩"
    "바이너리 분석 & 고급 난독화 해제 랩"
    "OAuth 2.0 & OIDC SSO 취약점 실전 랩"
    "BGP 라우팅 하이재킹 & RPKI ROA 실전 랩"
    "KISA 주요정보통신기반시설 취약점 평가 & 하드닝 랩"
    "OSINT 서피스 정찰 & 섀도우 IT 헌터 랩"
    "클라우드 IAM 권한 상승 & 조직 거버넌스 랩"
    "엔터프라이즈 데이터베이스 보안 & 권한 탈취/하드닝 랩"
    "블루투스 저에너지 & SDR 무선 보안 실전 랩"
    "EDR 유저랜드 후킹 우회 & 차세대 C2 실전 랩"
    "현대 응용 암호학 & 암호 분석 실전 랩"
    "엔터프라이즈 침해사고 대응 & DFIR 실전 랩"
    "소프트웨어 공급망 보안 & SBOM 실전 랩"
    "서버리스 클라우드 보안 & 이벤트 인젝션 랩"
    "클라우드 사고 대응 & 위협 헌팅 랩"
    "브라우저 확장 프로그램 보안 & Manifest V3 실전 랩"
    "양자 내성 암호 & PQC 마이그레이션 실전 랩"
    "리눅스 커널 하드닝 & 런타임 방어 실습"
    "AI 에이전트 & MCP 보안 실전 랩"
    "임베디드 펌웨어 & IoT RCE 실전 랩"
    "양자 내성 하이브리드 TLS 1.3 실습"
    "SANS DFIR 엔터프라이즈 아티팩트 헌팅 랩"
    "클라우드 네이티브 eBPF 런타임 보안 랩"
    "C2 네트워크 터널링 & 은닉 채널 방어 랩"
    "AD BloodHound 공격 그래프 & ACL 익스플로잇 랩"
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
