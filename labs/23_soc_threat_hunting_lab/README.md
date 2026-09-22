# Lab 23: SOCHunter — SOC Threat Hunting & SIEM/Incident Response 랩

## 1. 개요 (Overview)
- **대상**: 차세대 보안관제센터(SOC), SIEM(Splunk/Sentinel/Elastic), NIDS(Suricata), 엔드포인트 텔레메트리(Sysmon)
- **주요 표준**: SANS PICERL 프레임워크, MITRE ATT&CK Matrix (Execution, Defense Evasion, Credential Access, Command and Control)
  - `T1055` Process Injection: CreateRemoteThread into spoolsv.exe
  - `T1071.004` Application Layer Protocol: DNS Tunneling & C2 Beaconing
  - `T1003.001` OS Credential Dumping: LSASS Memory (GrantedAccess 0x1010)
  - `T1550.002` Use Alternate Authentication Material: Pass-the-Hash (LogonType 9/3)
- **포트**: `8023`
- **웹 대시보드**: `http://localhost:8023/`

---

## 2. 미션 및 플래그 획득 시나리오

### Mission 1: Sysmon 프로세스 인젝션 & Parent PID Spoofing 탐지
1. `/api/v1/telemetry/sysmon` 또는 `/api/v1/hunting/query`에서 EventCode 1(프로세스 생성) 및 EventCode 8(CreateRemoteThread) 로그를 분석합니다.
2. 악성 워드 문서에서 파생된 의심스러운 `powershell.exe`가 인쇄 스풀러 `spoolsv.exe` (PID: 4892)에 원격 스레드를 주입한 정황을 식별합니다.
3. `/api/v1/hunting/contain_process`에 타깃 감염 프로세스 PID (`4892`)를 제출하여 프로세스를 강제 종료하고 1단계 플래그를 획득합니다.
- **플래그 1**: `FLAG{sysmon_parent_pid_spoofing_remote_thread_injected_3821}`

### Mission 2: Suricata NIDS 알림 & DNS C2 비콘 상관분석
1. `/api/v1/telemetry/network`에서 IDS 경보 및 DNS/TLS 로그를 분석합니다.
2. 60자 이상의 Base32 서브도메인을 사용하는 DNS 터널링 통신과 Cobalt Strike 표준 JA3 지문(`72a589da586844d7f0818ce684948eea`)으로 비콘을 주기적으로 전송하는 외부 C2 서버 IP (`198.51.100.88`)를 특정합니다.
3. `/api/v1/firewall/block_ip`에 C2 IP (`198.51.100.88`)를 전송하여 방화벽 차단 정책을 배포하고 2단계 플래그를 획득합니다.
- **플래그 2**: `FLAG{suricata_dns_tunnel_ja3_c2_beacon_correlated_9482}`

### Mission 3: SIEM Pass-the-Hash 분석 & SOAR 자동화 격리
1. `/api/v1/telemetry/winevent`에서 Windows 보안 이벤트(EventCode 4624 LogonType 9/3, EventCode 10 ProcessAccess `lsass.exe`)를 확인합니다.
2. 재무팀 단말(`WKSTN-FIN-04`)의 관리자 계정(`FIN_ADMIN`)이 침해되어 NTLM 해시 재사용으로 도메인 컨트롤러에 비인가 인증을 시도한 정황을 확정합니다.
3. `/api/v1/soar/isolate_endpoint`에 침해 호스트(`WKSTN-FIN-04`)와 계정(`FIN_ADMIN`)을 전달하여 SOAR 격리 플레이북을 트리거하고 최종 플래그를 획득합니다.
- **플래그 3**: `FLAG{siem_lsass_mimikatz_pass_the_hash_soar_contained_7129}`

---

## 3. 방어 대책 (Remediation)
1. **Sysmon & EDR 강화**:
   - 공격 표면 축소(ASR) 규칙을 적용하여 오피스 애플리케이션의 자식 프로세스 생성을 원천 차단.
   - Mimikatz 및 덤프 툴에 대응하여 Windows Defender Credential Guard 및 LSA PPL(Protected Process Light) 활성화.
2. **네트워크 침입 방지**:
   - 내부 DNS 해석기를 통하지 않는 직접 외부 포트 53 아웃바운드 차단.
   - NIDS/NGFW에서 JA3/JA3S 기반 알려진 C2 프레임워크(Cobalt Strike, Sliver) 차단 룰셋 항시 유지.
3. **SOAR & 신원 보안**:
   - Tier 0/1 자격증명 분리 모델 적용(Active Directory Administrative Tiering) 및 로컬 관리자 비밀번호 솔루션(LAPS) 배포.
   - 이상 징후 탐지 즉시 감염 단말을 네트워크 격리하고 계정 세션을 파기하는 SOAR 자동화 파이프라인 구축.
