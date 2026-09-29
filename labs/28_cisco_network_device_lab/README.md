# Lab 28: NetShield - 네트워크 장비 & Cisco 인프라 보안 실전 랩

> **포트**: `8028` | **난이도**: `★★★★` | **주요 공격/방어 기법**: SNMPv2c R/W Running-Config 유출, DTP Dynamic Trunking VLAN Hopping, 802.1D STP Root Bridge 탈취, L2 Switch Hardening (Port Security, DAI, DHCP Snooping, BPDU Guard, SNMPv3, CoPP)

---

## 1. 랩 개요

기업 엔터프라이즈 환경의 네트워크 중추인 Cisco Catalyst 스위치와 엔터프라이즈 라우터는 침투 테스트와 레드팀 작전에서 가장 치명적인 공격 벡터 중 하나입니다. 기본 설정된 취약한 SNMP 커뮤니티 스트링을 통해 시스템 전반의 환경설정 파일(Running-Config)이 유출될 수 있으며, DTP(Dynamic Trunking Protocol)의 자동 협상 모드를 악용해 트렁크 링크를 강제 협상함으로써 분리된 격리 VLAN(예: 서버 관리망, 금융망)으로 트래픽을 주입하는 VLAN Hopping이 발생합니다. 또한 BPDU Guard 부재 시 802.1D STP 토폴로지를 장악하여 모든 L2 프레임을 도청하는 공격이 가능합니다.

Lab 28(NetShield)에서는 가상 Cisco IOS Catalyst L2/L3 스위치 에뮬레이션 환경을 통해 관리 플레인(Management Plane) 및 데이터 플레인(Data Plane) 공격을 시뮬레이션하고, 이에 대응하는 기업급 L2 보안 하드닝 정책을 단계별로 검증합니다.

---

## 2. 실습 단계 및 플래그 획득

### Step 1: SNMPv2c 커뮤니티 브루트포스 & Running-Config 덤프
- **공격 벡터**: 관리망 스위치에 활성화된 기본 SNMPv2c 커뮤니티 스트링을 무차별 대입하여 R/W 권한을 탈취하고, `ciscoConfigCopyMIB` (OID: `1.3.6.1.4.1.9.9.96`) 트리거를 통해 TFTP/HTTP로 running-config 덤프를 유출합니다. 유출된 설정 파일에서 Type 7 암호화 패스워드를 역산하여 `enable secret` 권한을 획득합니다.
- **타깃**: `POST /api/cisco/snmp/bruteforce`
- **유효 커뮤니티 키워드**: `private` (R/W), `public` (R/O)
- **플래그 형식**: `FLAG{cisco_snmpv2c_rw_community_running_config_dumped_8028}`

### Step 2: DTP 트렁크 스푸핑 & 802.1D STP Root Bridge 탈취
- **공격 벡터**: Access 포트로 지정되어야 할 스위치 포트가 DTP `dynamic desirable` 기본 모드로 방치된 점을 악용하여, 공격자가 DTP 조작 패킷을 전송해 포트를 802.1Q 트렁크 모드로 협상합니다. 이후 관리 VLAN 100으로 프레임을 인젝션(VLAN Hopping)하고, Priority 0의 위조 STP BPDU를 전송하여 네트워크 토폴로지의 Root Bridge를 탈취(STP Hijacking)합니다.
- **타깃**: `POST /api/cisco/vlan/dtp-attack`
- **플래그 형식**: `FLAG{dtp_vlan_hopping_and_stp_bpdu_root_bridge_hijacked_4192}`

### Step 3: 엔터프라이즈 L2 스위치 하드닝 & 제어 플레인 보호 (CoPP)
- **방어 대책**:
  1. 스위치 포트 고정 및 DTP 비활성화 (`switchport mode access`, `switchport nonegotiate`)
  2. Port Security 활성화 (최대 MAC 제한 및 위반 시 shutdown)
  3. DHCP Snooping & Dynamic ARP Inspection (DAI) 활성화
  4. STP BPDU Guard 및 Root Guard 설정 (`spanning-tree bpduguard enable`)
  5. SNMPv3 (SHA-256 Auth + AES-256 Priv) 암호화 전환 및 ACL 바인딩
  6. Control Plane Policing (CoPP) 정책 적용
- **타깃**: `POST /api/cisco/defense/hardening`
- **플래그 형식**: `FLAG{cisco_ios_l2_hardened_portsec_dai_bpduguard_copp_secured_7731}`

---

## 3. 실행 및 테스트

```bash
# 랩 단독 실행
vhack lab start 28

# 브라우저 웹 대시보드 접속
open http://localhost:8028

# 자동 무결성 테스트 실행
vhack lab test 28
```
