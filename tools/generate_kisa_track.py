#!/usr/bin/env python3
"""
Generates the 47th Wargame Track: 'kisa' (KISA Critical Infrastructure Assessment & Hardening - 35 Challenges)
Integrates cleanly into challenges.js, index.html, solve-derivable.js, and README.md.
"""

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHALLENGES_JS = REPO_ROOT / "wargame" / "assets" / "challenges.js"
INDEX_HTML = REPO_ROOT / "wargame" / "index.html"
SOLVE_DERIVABLE_JS = REPO_ROOT / "wargame" / "scripts" / "solve-derivable.js"
WARGAME_README = REPO_ROOT / "wargame" / "README.md"
CLI_TEST = REPO_ROOT / "wargame" / "tests" / "test_cli.py"

TRACK_INFO = {
    "id": "kisa",
    "icon": "🏛️",
    "ko": "KISA 기반시설 취약점 평가·하드닝",
    "en": "KISA Infrastructure Audit & Hardening",
    "desc_ko": "주요정보통신기반시설 기술적 취약점 분석·평가 기준·U-01~U-72 진단·계정/서비스 익스플로잇·원클릭 컴플라이언스 하드닝.",
    "desc_en": "KISA critical infrastructure vulnerability assessment criteria, U-01~U-72 Linux audit, service exploitation, and one-click compliance hardening."
}

RAW_CHALLENGES = [
    # Tier 0 (입문: 7 challenges, points 20~35)
    (0, "t0_kisa_legal_framework", 25,
     "「정보통신기반 보호법」 제9조 및 평가 체계",
     "Information Infrastructure Protection Act & Assessment Framework",
     "「정보통신기반 보호법」 제9조에 따른 기술적 취약점 분석·평가 의무와 6대 시스템 진단 체계를 분석합니다.\n지정된 식별자 `kisa_legal_framework_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_legal_framework_v1\") 앞 20자리}`",
     "Analyze Article 9 of the Information Communication Infrastructure Protection Act and its 6-system assessment framework.\nCompute the first 20 hex characters of SHA256(\"kisa_legal_framework_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_legal_framework_v1\") first 20 hex}`",
     ["정보통신기반 보호법 제9조에 따른 정기 취약점 평가 의무를 확인하세요.", "식별자 `kisa_legal_framework_v1`의 해시 앞 20자리를 추출하세요."],
     ["Review legal obligations under Article 9 of the Infrastructure Protection Act.", "Extract first 20 hex chars of SHA256(\"kisa_legal_framework_v1\")."]),

    (0, "t0_kisa_category_structure", 25,
     "주요정보통신기반시설 6대 시스템 진단 분류 체계",
     "Six Core System Diagnostic Categories in KISA Guidelines",
     "Unix(U), Windows(W), Network(N), Security(S), Database(D), Web(WEB) 6대 진단 체계를 분석합니다.\n지정된 식별자 `kisa_category_structure_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_category_structure_v1\") 앞 20자리}`",
     "Classify the six diagnostic categories across Unix, Windows, Network, Security, DB, and Web.\nCompute the first 20 hex characters of SHA256(\"kisa_category_structure_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_category_structure_v1\") first 20 hex}`",
     ["Unix/Linux 서버 진단 코드가 U-01~U-72임을 확인하세요.", "식별자 `kisa_category_structure_v1`의 해시 앞 20자리를 제출하세요."],
     ["Note that Unix/Linux items span from U-01 to U-72.", "Extract first 20 hex chars of SHA256(\"kisa_category_structure_v1\")."]),

    (0, "t0_kisa_u01_root_remote", 30,
     "U-01 root 계정 원격 접속 제한 규정",
     "U-01 Direct Remote Root Login Restriction Standard",
     "sshd_config 내 PermitRootLogin no 및 /etc/securetty 가상 터미널 제한 원리를 분석합니다.\n지정된 식별자 `kisa_u01_root_remote_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u01_root_remote_v1\") 앞 20자리}`",
     "Inspect sshd_config PermitRootLogin directives and securetty virtual terminal restrictions.\nCompute the first 20 hex characters of SHA256(\"kisa_u01_root_remote_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u01_root_remote_v1\") first 20 hex}`",
     ["root 직접 원격 로그인을 차단하고 sudo를 경유해야 함을 확인하세요.", "식별자 `kisa_u01_root_remote_v1`의 해시 앞 20자리를 추출하세요."],
     ["Root logins must be blocked in favor of sudo escalation.", "Extract first 20 hex chars of SHA256(\"kisa_u01_root_remote_v1\")."]),

    (0, "t0_kisa_u02_password_policy", 30,
     "U-02 패스워드 복잡성 규정 및 최소 길이 기준",
     "U-02 Password Complexity & Minimum Length Standards",
     "영문 대/소문자, 숫자, 특수문자 조합 최소 8자리 이상 복잡도 강제 설정을 분석합니다.\n지정된 식별자 `kisa_u02_password_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u02_password_policy_v1\") 앞 20자리}`",
     "Examine 8+ character complexity enforcement across uppercase, lowercase, digits, and symbols.\nCompute the first 20 hex characters of SHA256(\"kisa_u02_password_policy_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u02_password_policy_v1\") first 20 hex}`",
     ["pwquality.conf의 minlen=8 설정을 확인하세요.", "식별자 `kisa_u02_password_policy_v1`의 해시 앞 20자리를 제출하세요."],
     ["Check pwquality.conf minlen=8 directive.", "Extract first 20 hex chars of SHA256(\"kisa_u02_password_policy_v1\")."]),

    (0, "t0_kisa_u03_lockout_faillock", 30,
     "U-03 계정 잠금 임계값 및 무차별 대입 방어",
     "U-03 Account Lockout Threshold & Brute-Force Defense",
     "로그인 5회 연속 실패 시 10분간 잠금을 수행하는 pam_faillock 모듈 설정을 분석합니다.\n지정된 식별자 `kisa_u03_lockout_faillock_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u03_lockout_faillock_v1\") 앞 20자리}`",
     "Analyze pam_faillock denying access for 10 minutes after 5 failed authentication attempts.\nCompute the first 20 hex characters of SHA256(\"kisa_u03_lockout_faillock_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u03_lockout_faillock_v1\") first 20 hex}`",
     ["deny=5 및 unlock_time=600 파라미터를 파악하세요.", "식별자 `kisa_u03_lockout_faillock_v1`의 해시 앞 20자리를 추출하세요."],
     ["Identify deny=5 and unlock_time=600 parameters.", "Extract first 20 hex chars of SHA256(\"kisa_u03_lockout_faillock_v1\")."]),

    (0, "t0_kisa_u04_shadow_permission", 30,
     "U-04 패스워드 파일 권한 보호 (/etc/shadow)",
     "U-04 Shadow Password File Permissions (/etc/shadow)",
     "/etc/shadow 파일의 소유자가 root이고 권한이 400 또는 000이어야 하는 보안 요건을 분석합니다.\n지정된 식별자 `kisa_u04_shadow_permission_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u04_shadow_permission_v1\") 앞 20자리}`",
     "Inspect permission requirements where /etc/shadow must be owned by root with 400 or 000 permissions.\nCompute the first 20 hex characters of SHA256(\"kisa_u04_shadow_permission_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u04_shadow_permission_v1\") first 20 hex}`",
     ["일반 사용자가 shadow 해시를 읽을 수 없도록 격리해야 합니다.", "식별자 `kisa_u04_shadow_permission_v1`의 해시 앞 20자리를 제출하세요."],
     ["Regular users must be barred from reading shadow hashes.", "Extract first 20 hex chars of SHA256(\"kisa_u04_shadow_permission_v1\")."]),

    (0, "t0_kisa_severity_ratings", 35,
     "KISA 상·중·하 중요도 산정 및 가중 배점 기준",
     "KISA High/Medium/Low Risk Severity Scoring Methodology",
     "직접적 침해사고 유발 항목(상)과 간접적 보안 정책 미비(하)의 중요도 가중치 산정법을 분석합니다.\n지정된 식별자 `kisa_severity_ratings_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_severity_ratings_v1\") 앞 20자리}`",
     "Understand scoring weights between critical compromise vectors and policy baselines.\nCompute the first 20 hex characters of SHA256(\"kisa_severity_ratings_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_severity_ratings_v1\") first 20 hex}`",
     ["계정 관리의 U-01~U-04가 모두 '상' 등급임을 확인하세요.", "식별자 `kisa_severity_ratings_v1`의 해시 앞 20자리를 추출하세요."],
     ["Notice that U-01 through U-04 are all categorized as High severity.", "Extract first 20 hex chars of SHA256(\"kisa_severity_ratings_v1\")."]),

    # Tier 1 (초급: 7 challenges, points 35~50)
    (1, "t1_kisa_u05_root_path", 40,
     "U-05 root 계정 PATH 환경변수 내 현재 디렉터리 제거",
     "U-05 Root PATH Environment Variable Current Directory Elimination",
     "PATH 변수 맨 앞이나 중간에 `.`(현재 디렉터리)이 포함될 경우 발생하는 트로이목마 실행 위협을 분석합니다.\n지정된 식별자 `kisa_u05_root_path_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u05_root_path_v1\") 앞 20자리}`",
     "Analyze trojan execution risks when dot (.) appears at the start of root's PATH variable.\nCompute the first 20 hex characters of SHA256(\"kisa_u05_root_path_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u05_root_path_v1\") first 20 hex}`",
     ["PATH 변수 맨 끝에 .을 배치하거나 완전히 제거해야 합니다.", "식별자 `kisa_u05_root_path_v1`의 해시 앞 20자리를 추출하세요."],
     ["Dot must be placed at the end or eliminated from PATH.", "Extract first 20 hex chars of SHA256(\"kisa_u05_root_path_v1\")."]),

    (1, "t1_kisa_u07_passwd_owner", 40,
     "U-07 /etc/passwd 파일 소유자 및 권한 설정",
     "U-07 /etc/passwd Ownership & Permission Hardening",
     "/etc/passwd 파일의 소유자가 root이고 쓰기 권한이 root에게만 부여되어 있는지 검증합니다.\n지정된 식별자 `kisa_u07_passwd_owner_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u07_passwd_owner_v1\") 앞 20자리}`",
     "Verify that /etc/passwd is strictly owned by root with 644 or tighter permissions.\nCompute the first 20 hex characters of SHA256(\"kisa_u07_passwd_owner_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u07_passwd_owner_v1\") first 20 hex}`",
     ["일반 사용자에게 쓰기 권한이 부여되면 UID 0 계정을 생성할 수 있습니다.", "식별자 `kisa_u07_passwd_owner_v1`의 해시 앞 20자리를 제출하세요."],
     ["Write access allows arbitrary UID 0 account creation.", "Extract first 20 hex chars of SHA256(\"kisa_u07_passwd_owner_v1\")."]),

    (1, "t1_kisa_u10_xinetd_conf", 45,
     "U-10 /etc/xinetd.conf 파일 소유자 및 권한 관리",
     "U-10 Super-Server Configuration Permissions (/etc/xinetd.conf)",
     "xinetd 및 슈퍼서버 환경설정 파일의 권한을 600 또는 644로 관리하는 기준을 분석합니다.\n지정된 식별자 `kisa_u10_xinetd_conf_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u10_xinetd_conf_v1\") 앞 20자리}`",
     "Examine access permissions on super-server daemon configurations.\nCompute the first 20 hex characters of SHA256(\"kisa_u10_xinetd_conf_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u10_xinetd_conf_v1\") first 20 hex}`",
     ["비인가 수정 시 임의 네트워크 서비스가 데몬으로 구동될 수 있습니다.", "식별자 `kisa_u10_xinetd_conf_v1`의 해시 앞 20자리를 추출하세요."],
     ["Unauthorized modification can spawn arbitrary listener daemons.", "Extract first 20 hex chars of SHA256(\"kisa_u10_xinetd_conf_v1\")."]),

    (1, "t1_kisa_u20_anonymous_ftp", 45,
     "U-20 Anonymous FTP 비활성화 및 무인증 파일 유출 차단",
     "U-20 Anonymous FTP Deactivation & Data Exfiltration Prevention",
     "FTP 서비스에서 anonymous 접속을 차단(anonymous_enable=NO)하는 KISA 양호 기준을 분석합니다.\n지정된 식별자 `kisa_u20_anonymous_ftp_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u20_anonymous_ftp_v1\") 앞 20자리}`",
     "Analyze KISA baseline requiring anonymous FTP disablement in vsftpd configuration.\nCompute the first 20 hex characters of SHA256(\"kisa_u20_anonymous_ftp_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u20_anonymous_ftp_v1\") first 20 hex}`",
     ["익명 접속으로 공개 디렉터리 내 백업 파일이 유출되는 시나리오를 검토하세요.", "식별자 `kisa_u20_anonymous_ftp_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review how exposed pub directories leak sensitive database dumps.", "Extract first 20 hex chars of SHA256(\"kisa_u20_anonymous_ftp_v1\")."]),

    (1, "t1_kisa_u23_dos_services", 45,
     "U-23 DoS 공격에 취약한 레거시 서비스 비활성화",
     "U-23 Deactivation of Legacy Services Vulnerable to DoS",
     "echo(포트 7), discard(포트 9), daytime(포트 13), chargen(포트 19) 비활성화 원리를 분석합니다.\n지정된 식별자 `kisa_u23_dos_services_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u23_dos_services_v1\") 앞 20자리}`",
     "Understand why echo, discard, daytime, and chargen are disabled to stop UDP amplification DoS.\nCompute the first 20 hex characters of SHA256(\"kisa_u23_dos_services_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u23_dos_services_v1\") first 20 hex}`",
     ["chargen과 echo 간 루프백 DoS 증폭 공격을 방지해야 합니다.", "식별자 `kisa_u23_dos_services_v1`의 해시 앞 20자리를 추출하세요."],
     ["Looping amplification between chargen and echo must be blocked.", "Extract first 20 hex chars of SHA256(\"kisa_u23_dos_services_v1\")."]),

    (1, "t1_kisa_u44_ssh_cipher", 50,
     "U-44 SSH 원격 접속 프로토콜 취약 알고리즘 비활성화",
     "U-44 SSH Protocol & Insecure Cipher Hardening",
     "SSH-1 비활성화 및 CBC 모드 취약 대칭 암호(3DES-CBC, AES-CBC) 차단 기준을 분석합니다.\n지정된 식별자 `kisa_u44_ssh_cipher_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u44_ssh_cipher_v1\") 앞 20자리}`",
     "Enforce SSH-2 and disallow vulnerable CBC ciphers in sshd_config.\nCompute the first 20 hex characters of SHA256(\"kisa_u44_ssh_cipher_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u44_ssh_cipher_v1\") first 20 hex}`",
     ["CTR 또는 GCM 모드 암호만을 명시적으로 허용해야 합니다.", "식별자 `kisa_u44_ssh_cipher_v1`의 해시 앞 20자리를 제출하세요."],
     ["Only CTR and GCM cipher suites should be explicitly permitted.", "Extract first 20 hex chars of SHA256(\"kisa_u44_ssh_cipher_v1\")."]),

    (1, "t1_kisa_audit_regex_parsing", 50,
     "진단 쉘 스크립트 정규식 파싱 및 주석 오탐 방지",
     "Audit Shell Script Regex Parsing & False Positive Avoidance",
     "설정 파일 진단 시 `#` 주석 라인을 제외하고 유효한 지시어만을 정규식으로 파싱하는 기법을 분석합니다.\n지정된 식별자 `kisa_audit_regex_parsing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_audit_regex_parsing_v1\") 앞 20자리}`",
     "Design robust regex filters that ignore commented directives to avoid audit false positives.\nCompute the first 20 hex characters of SHA256(\"kisa_audit_regex_parsing_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_audit_regex_parsing_v1\") first 20 hex}`",
     ["grep -v '^[[:space:]]*#' 필터를 적용하여 유효 설정만 판별합니다.", "식별자 `kisa_audit_regex_parsing_v1`의 해시 앞 20자리를 추출하세요."],
     ["Use grep -v filters to strip commented configurations.", "Extract first 20 hex chars of SHA256(\"kisa_audit_regex_parsing_v1\")."]),

    # Tier 2 (중급: 7 challenges, points 50~70)
    (2, "t2_kisa_u14_suid_sgid", 55,
     "U-14 SUID/SGID 불필요 실행파일 전수 탐색 및 제거",
     "U-14 SUID/SGID Binary Inventory & Privilege Escalation Defenses",
     "find 명령어로 SUID(-perm -4000) 파일을 탐색하고 취약 바이너리에서 특권을 제거하는 기법을 분석합니다.\n지정된 식별자 `kisa_u14_suid_sgid_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u14_suid_sgid_v1\") 앞 20자리}`",
     "Locate SUID binaries and strip unnecessary execution privileges to halt local privilege escalation.\nCompute the first 20 hex characters of SHA256(\"kisa_u14_suid_sgid_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u14_suid_sgid_v1\") first 20 hex}`",
     ["chmod -s 명령으로 불필요한 SUID 비트를 제거합니다.", "식별자 `kisa_u14_suid_sgid_v1`의 해시 앞 20자리를 추출하세요."],
     ["Strip SUID bits using chmod -s on untrusted tools.", "Extract first 20 hex chars of SHA256(\"kisa_u14_suid_sgid_v1\")."]),

    (2, "t2_kisa_u17_r_commands", 55,
     "U-17 rlogin, rsh, rexec 무인증 서비스 차단",
     "U-17 Legacy r-commands Elimination (.rhosts & hosts.equiv)",
     ".rhosts 및 hosts.equiv 기반의 IP 신뢰 기반 무인증 원격 쉘 서비스 차단 기준을 분석합니다.\n지정된 식별자 `kisa_u17_r_commands_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u17_r_commands_v1\") 앞 20자리}`",
     "Eliminate IP-spoofable rlogin/rsh mechanisms and remove legacy .rhosts files.\nCompute the first 20 hex characters of SHA256(\"kisa_u17_r_commands_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u17_r_commands_v1\") first 20 hex}`",
     ["암호화되지 않은 r-commands를 SSH로 전면 대체해야 합니다.", "식별자 `kisa_u17_r_commands_v1`의 해시 앞 20자리를 제출하세요."],
     ["Replace unencrypted r-commands with secure SSH sessions.", "Extract first 20 hex chars of SHA256(\"kisa_u17_r_commands_v1\")."]),

    (2, "t2_kisa_u22_cron_permission", 60,
     "U-22 crontab 명령어 권한 및 크론 설정 디렉터리 보호",
     "U-22 Crontab Daemon Access & Task Script Permissions",
     "/etc/cron.allow 및 cron.deny 파일을 통한 일반 사용자 크론 실행 통제 기법을 분석합니다.\n지정된 식별자 `kisa_u22_cron_permission_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u22_cron_permission_v1\") 앞 20자리}`",
     "Control scheduled task execution via /etc/cron.allow and /etc/cron.deny access controls.\nCompute the first 20 hex characters of SHA256(\"kisa_u22_cron_permission_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u22_cron_permission_v1\") first 20 hex}`",
     ["cron 스크립트에 일반 사용자 쓰기 권한이 있으면 권한상승이 가능합니다.", "식별자 `kisa_u22_cron_permission_v1`의 해시 앞 20자리를 추출하세요."],
     ["Writable cron scripts allow trivial root escalation.", "Extract first 20 hex chars of SHA256(\"kisa_u22_cron_permission_v1\")."]),

    (2, "t2_kisa_u45_pam_wheel", 60,
     "U-45 su 명령어 사용 제한 및 wheel 그룹 바인딩",
     "U-45 su Command Execution Restrictions via pam_wheel.so",
     "pam_wheel.so 모듈을 통해 허가된 wheel 그룹 사용자만 root 전환(su)을 허용하는 메커니즘을 분석합니다.\n지정된 식별자 `kisa_u45_pam_wheel_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u45_pam_wheel_v1\") 앞 20자리}`",
     "Restrict su escalation strictly to members of the wheel administrative group via pam_wheel.so.\nCompute the first 20 hex characters of SHA256(\"kisa_u45_pam_wheel_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u45_pam_wheel_v1\") first 20 hex}`",
     ["/etc/pam.d/su 파일에서 pam_wheel.so auth required 설정을 확인하세요.", "식별자 `kisa_u45_pam_wheel_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify pam_wheel.so configuration inside /etc/pam.d/su.", "Extract first 20 hex chars of SHA256(\"kisa_u45_pam_wheel_v1\")."]),

    (2, "t2_kisa_u72_rsyslog_remote", 65,
     "U-72 시스템 보안 로깅 및 중앙 원격 로그 전송",
     "U-72 System Security Logging & Remote Log Forwarding",
     "/etc/rsyslog.conf를 통한 authpriv.* 로깅 및 SIEM으로의 UDP/TCP 514 원격 전송 설정을 분석합니다.\n지정된 식별자 `kisa_u72_rsyslog_remote_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u72_rsyslog_remote_v1\") 앞 20자리}`",
     "Configure centralized authpriv logging and remote forwarding to secure SIEM collectors.\nCompute the first 20 hex characters of SHA256(\"kisa_u72_rsyslog_remote_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u72_rsyslog_remote_v1\") first 20 hex}`",
     ["침해사고 발생 시 로컬 로그 삭제를 방지하기 위해 원격 전송이 필수적입니다.", "식별자 `kisa_u72_rsyslog_remote_v1`의 해시 앞 20자리를 추출하세요."],
     ["Remote forwarding guarantees forensic preservation even if local logs are wiped.", "Extract first 20 hex chars of SHA256(\"kisa_u72_rsyslog_remote_v1\")."]),

    (2, "t2_kisa_ftp_pub_data_leak", 65,
     "U-20 익명 FTP 디렉터리 탐색 및 백업 파일 탈취",
     "U-20 Anonymous FTP Directory Traversal & Backup Data Leak",
     "vsftpd 익명 접근을 통해 방치된 pub 디렉터리에서 서버 백업 파일을 탈취하는 공격을 분석합니다.\n지정된 식별자 `kisa_ftp_pub_data_leak_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_ftp_pub_data_leak_v1\") 앞 20자리}`",
     "Demonstrate data leakage risks when anonymous users traverse public FTP directories.\nCompute the first 20 hex characters of SHA256(\"kisa_ftp_pub_data_leak_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_ftp_pub_data_leak_v1\") first 20 hex}`",
     ["Lab 33 Step 2 FTP 익스플로잇 요청 흐름을 확인하세요.", "식별자 `kisa_ftp_pub_data_leak_v1`의 해시 앞 20자리를 제출하세요."],
     ["Review Lab 33 Step 2 FTP exploit workflow.", "Extract first 20 hex chars of SHA256(\"kisa_ftp_pub_data_leak_v1\")."]),

    (2, "t2_kisa_ssh_banner_fingerprint", 70,
     "U-44 SSH 버전 정보 노출 및 배너 그래빙 공격",
     "U-44 SSH Banner Grabbing & OS Version Fingerprinting",
     "SSH 접속 시 반환되는 OS 배너(/etc/issue.net)를 통해 타깃 커널 버전을 핑거프린팅하는 과정을 분석합니다.\n지정된 식별자 `kisa_ssh_banner_fingerprint_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_ssh_banner_fingerprint_v1\") 앞 20자리}`",
     "Fingerprint target Linux distributions through unsuppressed SSH greeting banners.\nCompute the first 20 hex characters of SHA256(\"kisa_ssh_banner_fingerprint_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_ssh_banner_fingerprint_v1\") first 20 hex}`",
     ["Banner none 설정을 통해 상세 운영체제 정보를 은닉해야 합니다.", "식별자 `kisa_ssh_banner_fingerprint_v1`의 해시 앞 20자리를 추출하세요."],
     ["Banner none suppresses kernel details from scanning reconnaissance.", "Extract first 20 hex chars of SHA256(\"kisa_ssh_banner_fingerprint_v1\")."]),

    # Tier 3 (고급: 7 challenges, points 70~90)
    (3, "t3_kisa_u01_u04_audit_chain", 75,
     "계정 관리 4대 항목 전수 진단 스크립트 체이닝",
     "Chained Automation for U-01 through U-04 Account Audits",
     "U-01부터 U-04까지 계정 보안 4대 항목을 단일 트랜잭션으로 진단하여 취약점을 적발하는 로직을 분석합니다.\n지정된 식별자 `kisa_u01_u04_audit_chain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_u01_u04_audit_chain_v1\") 앞 20자리}`",
     "Chain automated auditing across root login, complexity, lockout, and shadow permissions.\nCompute the first 20 hex characters of SHA256(\"kisa_u01_u04_audit_chain_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_u01_u04_audit_chain_v1\") first 20 hex}`",
     ["모든 항목이 취약 판정 시 Step 1 플래그가 반환됨을 확인하세요.", "식별자 `kisa_u01_u04_audit_chain_v1`의 해시 앞 20자리를 추출하세요."],
     ["Step 1 flag triggers when all four account checks identify vulnerabilities.", "Extract first 20 hex chars of SHA256(\"kisa_u01_u04_audit_chain_v1\")."]),

    (3, "t3_kisa_pam_faillock_bypass", 75,
     "PAM 스택 오설정 및 auth 실패 우회 방어",
     "PAM Stack Configuration Hazards & Lockout Bypass Mitigation",
     "pam_faillock.so 선언 순서가 잘못되어 계정 잠금이 우회되는 스택 취약점을 분석하고 방어합니다.\n지정된 식별자 `kisa_pam_faillock_bypass_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_pam_faillock_bypass_v1\") 앞 20자리}`",
     "Analyze PAM stack misconfigurations where misplaced faillock directives bypass lockout logic.\nCompute the first 20 hex characters of SHA256(\"kisa_pam_faillock_bypass_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_pam_faillock_bypass_v1\") first 20 hex}`",
     ["pam_faillock.so preauth 및 authfail의 올바른 배치 순서를 파악하세요.", "식별자 `kisa_pam_faillock_bypass_v1`의 해시 앞 20자리를 제출하세요."],
     ["Position preauth and authfail correctly in the PAM evaluation stack.", "Extract first 20 hex chars of SHA256(\"kisa_pam_faillock_bypass_v1\")."]),

    (3, "t3_kisa_shadow_hashcat_crack", 80,
     "권한 노출된 shadow SHA-512 crypt 오프라인 크래킹",
     "Offline Hashcat Cracking on Exposed SHA-512 Crypt Hashes",
     "0644 권한으로 노출된 /etc/shadow의 $6$ 해시를 덤프하여 GPU 오프라인 사전 공격을 수행하는 원리를 분석합니다.\n지정된 식별자 `kisa_shadow_hashcat_crack_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_shadow_hashcat_crack_v1\") 앞 20자리}`",
     "Demonstrate offline GPU cracking against $6$ SHA-512 crypt hashes leaked from exposed shadow files.\nCompute the first 20 hex characters of SHA256(\"kisa_shadow_hashcat_crack_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_shadow_hashcat_crack_v1\") first 20 hex}`",
     ["Hashcat mode 1800(SHA512-crypt)의 오프라인 침투 파급력을 확인하세요.", "식별자 `kisa_shadow_hashcat_crack_v1`의 해시 앞 20자리를 추출하세요."],
     ["Hashcat mode 1800 breaks weak passwords within seconds.", "Extract first 20 hex chars of SHA256(\"kisa_shadow_hashcat_crack_v1\")."]),

    (3, "t3_kisa_vsftpd_rce_backdoor", 80,
     "vsftpd 취약 버전 백도어 및 익명 업로드 RCE 방어",
     "vsftpd Backdoor Vulnerabilities & Anonymous Upload RCE Defense",
     "FTP 익명 업로드(write_enable) 허용 시 웹 루트 웹쉘 업로드로 이어지는 RCE 체인을 분석합니다.\n지정된 식별자 `kisa_vsftpd_rce_backdoor_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_vsftpd_rce_backdoor_v1\") 앞 20자리}`",
     "Halt remote code execution chains arising from anonymous FTP uploads to web directories.\nCompute the first 20 hex characters of SHA256(\"kisa_vsftpd_rce_backdoor_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_vsftpd_rce_backdoor_v1\") first 20 hex}`",
     ["anonymous_enable=NO 및 anon_upload_enable=NO를 강제해야 합니다.", "식별자 `kisa_vsftpd_rce_backdoor_v1`의 해시 앞 20자리를 제출하세요."],
     ["Disallow anon_upload_enable to block arbitrary webshell drops.", "Extract first 20 hex chars of SHA256(\"kisa_vsftpd_rce_backdoor_v1\")."]),

    (3, "t3_kisa_ssh_cbc_plain_injection", 85,
     "SSH CBC 모드 평문 주입 취약점(CVE-2008-5161) 방어",
     "SSH CBC Mode Plaintext Injection (CVE-2008-5161) Hardening",
     "CBC 모드 대칭 암호화 취약점을 이용한 32비트 블록 평문 복원 공격 원리와 ChaCha20/GCM 완화책을 분석합니다.\n지정된 식별자 `kisa_ssh_cbc_plain_injection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_ssh_cbc_plain_injection_v1\") 앞 20자리}`",
     "Examine 32-bit plaintext recovery risks under CBC ciphers and enforce modern AEAD suites.\nCompute the first 20 hex characters of SHA256(\"kisa_ssh_cbc_plain_injection_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_ssh_cbc_plain_injection_v1\") first 20 hex}`",
     ["chacha20-poly1305 및 aes256-gcm만을 Ciphers에 등록하세요.", "식별자 `kisa_ssh_cbc_plain_injection_v1`의 해시 앞 20자리를 추출하세요."],
     ["Register only ChaCha20-Poly1305 and AES-GCM suites in sshd_config.", "Extract first 20 hex chars of SHA256(\"kisa_ssh_cbc_plain_injection_v1\")."]),

    (3, "t3_kisa_oneclick_hardening", 85,
     "원클릭 KISA 보안 하드닝 및 자동 설정 스크립트",
     "One-Click KISA Infrastructure Hardening & Configuration Automation",
     "KISA 6대 핵심 점검 항목을 즉시 '양호' 기준으로 일괄 변경하는 하드닝 엔진 아키텍처를 분석합니다.\n지정된 식별자 `kisa_oneclick_hardening_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_oneclick_hardening_v1\") 앞 20자리}`",
     "Design unified hardening routines that transition vulnerable servers to 100% KISA compliance.\nCompute the first 20 hex characters of SHA256(\"kisa_oneclick_hardening_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_oneclick_hardening_v1\") first 20 hex}`",
     ["Lab 33 Step 3 하드닝 요청이 컴플라이언스 합격을 달성함을 확인하세요.", "식별자 `kisa_oneclick_hardening_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify Lab 33 Step 3 compliance approval upon full remediation.", "Extract first 20 hex chars of SHA256(\"kisa_oneclick_hardening_v1\")."]),

    (3, "t3_kisa_rollback_architecture", 90,
     "설정 변경 실패 시 자동 백업 복원 롤백 아키텍처",
     "Automated Backup & Atomic Rollback Architecture for Hardening",
     "보안 하드닝 적용 중 서비스 장애 발생 시 설정 파일을 원상 복구하는 원자적(Atomic) 롤백 설계를 분석합니다.\n지정된 식별자 `kisa_rollback_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_rollback_architecture_v1\") 앞 20자리}`",
     "Implement atomic configuration snapshotting to automatically revert failed hardening actions.\nCompute the first 20 hex characters of SHA256(\"kisa_rollback_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_rollback_architecture_v1\") first 20 hex}`",
     ["수정 전 .bak 파일 생성 및 유효성 검증 실패 시 즉시 복원을 구현합니다.", "식별자 `kisa_rollback_architecture_v1`의 해시 앞 20자리를 추출하세요."],
     ["Generate .bak snapshots and verify syntax before committing daemon reloads.", "Extract first 20 hex chars of SHA256(\"kisa_rollback_architecture_v1\")."]),

    # Tier 4 (전문가: 7 challenges, points 90~120)
    (4, "t4_kisa_capstone_full_audit", 95,
     "KISA 72개 전 항목 자동 감사 파이프라인 구축",
     "Capstone: Complete 72-Item Automated Linux Audit Pipeline",
     "U-01부터 U-72까지 전 영역을 병렬로 점검하고 JSON 규격으로 증적을 생성하는 엔터프라이즈 파이프라인을 분석합니다.\n지정된 식별자 `kisa_capstone_full_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_capstone_full_audit_v1\") 앞 20자리}`",
     "Construct an enterprise assessment pipeline auditing all 72 KISA checkpoints into structured JSON.\nCompute the first 20 hex characters of SHA256(\"kisa_capstone_full_audit_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_capstone_full_audit_v1\") first 20 hex}`",
     ["모든 점검 결과를 구조화된 JSON 형태로 파이프라인에 전송합니다.", "식별자 `kisa_capstone_full_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Structure comprehensive audit findings into automated JSON schemas.", "Extract first 20 hex chars of SHA256(\"kisa_capstone_full_audit_v1\")."]),

    (4, "t4_kisa_zero_trust_linux_posture", 100,
     "리눅스 제로트러스트 엔드포인트 포스처 검증",
     "Zero-Trust Linux Endpoint Posture & Compliance Attestation",
     "서버가 네트워크 접속 및 API 호출 시 KISA 하드닝 포스처를 mTLS 토큰에 증명하는 제로트러스트 모델을 분석합니다.\n지정된 식별자 `kisa_zero_trust_linux_posture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_zero_trust_linux_posture_v1\") 앞 20자리}`",
     "Attest host hardening compliance via cryptographic posture claims bound to mTLS sessions.\nCompute the first 20 hex characters of SHA256(\"kisa_zero_trust_linux_posture_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_zero_trust_linux_posture_v1\") first 20 hex}`",
     ["컴플라이언스 미달 호스트의 코어 네트워크 격리를 구현합니다.", "식별자 `kisa_zero_trust_linux_posture_v1`의 해시 앞 20자리를 제출하세요."],
     ["Isolate non-compliant endpoints automatically at the ingress gateway.", "Extract first 20 hex chars of SHA256(\"kisa_zero_trust_linux_posture_v1\")."]),

    (4, "t4_kisa_aide_integrity_monitor", 100,
     "AIDE/Tripwire 파일 무결성 실시간 모니터링 연동",
     "AIDE & Tripwire File Integrity Monitoring Integration",
     "핵심 시스템 파일(/bin, /sbin, /etc)의 SHA-256 체크섬 변조를 실시간 감지하여 U-04, U-07 위협을 차단합니다.\n지정된 식별자 `kisa_aide_integrity_monitor_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_aide_integrity_monitor_v1\") 앞 20자리}`",
     "Detect binary tampering across system directories using cryptographic file integrity monitoring.\nCompute the first 20 hex characters of SHA256(\"kisa_aide_integrity_monitor_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_aide_integrity_monitor_v1\") first 20 hex}`",
     ["AIDE 데이터베이스 정합성 검사를 크론으로 정기 실행합니다.", "식별자 `kisa_aide_integrity_monitor_v1`의 해시 앞 20자리를 추출하세요."],
     ["Automate periodic AIDE verification via scheduled root crontabs.", "Extract first 20 hex chars of SHA256(\"kisa_aide_integrity_monitor_v1\")."]),

    (4, "t4_kisa_selinux_enforcing_policy", 105,
     "SELinux Enforcing 모드 및 커스텀 정책 하드닝",
     "SELinux Enforcing Mode & Custom Type Enforcement Hardening",
     "DAC(임의적 접근 제어) 취약점을 극복하기 위해 MAC(강제적 접근 제어) SELinux 정책을 Enforcing으로 유지합니다.\n지정된 식별자 `kisa_selinux_enforcing_policy_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_selinux_enforcing_policy_v1\") 앞 20자리}`",
     "Enforce Mandatory Access Control (MAC) via SELinux Enforcing modes to constrain compromised services.\nCompute the first 20 hex characters of SHA256(\"kisa_selinux_enforcing_policy_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_selinux_enforcing_policy_v1\") first 20 hex}`",
     ["setenforce 1 및 /etc/selinux/config 내 SELINUX=enforcing 설정을 확인하세요.", "식별자 `kisa_selinux_enforcing_policy_v1`의 해시 앞 20자리를 제출하세요."],
     ["Verify SELINUX=enforcing configuration in /etc/selinux/config.", "Extract first 20 hex chars of SHA256(\"kisa_selinux_enforcing_policy_v1\")."]),

    (4, "t4_kisa_compliance_report_generator", 110,
     "KISA 표준 기술적 취약점 평가 결과 보고서 자동 생성",
     "KISA Technical Assessment Compliance Audit Report Generation",
     "진단된 취약점 증적과 조치 결과를 취합하여 KISA 공표 표준 양식의 PDF/HTML 진단 보고서를 렌더링합니다.\n지정된 식별자 `kisa_compliance_report_generator_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_compliance_report_generator_v1\") 앞 20자리}`",
     "Render official compliance audit reports with structured findings according to KISA publishing standards.\nCompute the first 20 hex characters of SHA256(\"kisa_compliance_report_generator_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_compliance_report_generator_v1\") first 20 hex}`",
     ["항목별 양호/취약 현황과 권고 조치 가이드를 보고서에 반영합니다.", "식별자 `kisa_compliance_report_generator_v1`의 해시 앞 20자리를 추출하세요."],
     ["Synthesize good/vulnerable statuses and mitigation plans into the report.", "Extract first 20 hex chars of SHA256(\"kisa_compliance_report_generator_v1\")."]),

    (4, "t4_kisa_ebpf_runtime_audit", 115,
     "eBPF 기반 KISA 보안 감사 실시간 커널 탐지 연동",
     "eBPF Kernel Instrumentation for Real-Time Security Audit Telemetry",
     "Kprobe 시스템콜 및 eBPF LSM을 통해 /etc/shadow 접근 및 불법 su 시도를 커널 레벨에서 즉시 차단합니다.\n지정된 식별자 `kisa_ebpf_runtime_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_ebpf_runtime_audit_v1\") 앞 20자리}`",
     "Instrument eBPF tracepoints and LSM hooks to intercept shadow file access and unauthorized su attempts.\nCompute the first 20 hex characters of SHA256(\"kisa_ebpf_runtime_audit_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_ebpf_runtime_audit_v1\") first 20 hex}`",
     ["eBPF BPF_PROG_TYPE_LSM 후크로 파일 접근을 실시간 필터링합니다.", "식별자 `kisa_ebpf_runtime_audit_v1`의 해시 앞 20자리를 제출하세요."],
     ["Filter file accesses at the kernel boundary using eBPF LSM hooks.", "Extract first 20 hex chars of SHA256(\"kisa_ebpf_runtime_audit_v1\")."]),

    (4, "t4_kisa_enterprise_cert_audit", 120,
     "금융/공공 기관 ISMS-P 및 기반시설 합동 수검 대비",
     "ISMS-P & Critical Infrastructure Joint Enterprise Audit Preparation",
     "연례 법정 취약점 진단 및 ISMS-P 인증 심사를 통과하기 위한 다층 보안 거버넌스 및 감사 대응 체계를 분석합니다.\n지정된 식별자 `kisa_enterprise_cert_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"kisa_enterprise_cert_audit_v1\") 앞 20자리}`",
     "Prepare enterprise security governance workflows for annual ISMS-P certification and infrastructure compliance audits.\nCompute the first 20 hex characters of SHA256(\"kisa_enterprise_cert_audit_v1\").\n\nFormat: `FLAG{SHA256(\"kisa_enterprise_cert_audit_v1\") first 20 hex}`",
     ["기술적 점검과 관리적/물리적 보호 대책의 상호 연계성을 확인하세요.", "식별자 `kisa_enterprise_cert_audit_v1`의 해시 앞 20자리를 추출하세요."],
     ["Connect technical audit outcomes with managerial security governance.", "Extract first 20 hex chars of SHA256(\"kisa_enterprise_cert_audit_v1\")."]),
]

TIER_TOPIC_ROWS = [
    "| `kisa` 🏛️ KISA 기반시설 취약점 평가·하드닝 (7) | 「정보통신기반 보호법」 제9조 · 6대 시스템 진단 분류 체계 · U-01 root 원격접속 제한 · U-02 패스워드 복잡도 · U-03 계정 잠금 임계값 · U-04 shadow 파일 보호 · 상/중/하 위험도 산정 |",
    "| `kisa` 🏛️ KISA 기반시설 취약점 평가·하드닝 (7) | U-05 root PATH 점 제거 · U-07 passwd 소유자 권한 · U-10 xinetd 설정 보호 · U-20 Anonymous FTP 비활성화 · U-23 DoS 서비스 차단 · U-44 SSH 취약 암호 제거 · 진단 쉘 정규식 파싱 |",
    "| `kisa` 🏛️ KISA 기반시설 취약점 평가·하드닝 (7) | U-14 SUID/SGID 권한 통제 · U-17 r-commands 제거 · U-22 crontab 권한 보호 · U-45 pam_wheel su 제한 · U-72 rsyslog 원격 로깅 · U-20 익명 FTP 백업 유출 · U-44 SSH 배너 핑거프린팅 |",
    "| `kisa` 🏛️ KISA 기반시설 취약점 평가·하드닝 (7) | U-01~U-04 진단 자동화 체이닝 · PAM faillock 스택 방어 · shadow SHA-512 crypt 오프라인 크래킹 · vsftpd 익명 업로드 RCE 방어 · SSH CBC 모드 평문 주입 방어 · 원클릭 하드닝 엔진 · 자동 롤백 아키텍처 |",
    "| `kisa` 🏛️ KISA 기반시설 취약점 평가·하드닝 (7) | KISA 72개 전 항목 파이프라인 · 제로트러스트 리눅스 포스처 · AIDE 파일 무결성 실시간 연동 · SELinux Enforcing 정책 · 취약점 평가 보고서 자동 렌더링 · eBPF 실시간 감사 · ISMS-P 합동 수검 체계 |"
]

def build_challenges():
    challenges = []
    ids = []
    for tier, cid, pts, t_ko, t_en, p_ko, p_en, h_ko, h_en in RAW_CHALLENGES:
        ident = cid.replace("t0_", "").replace("t1_", "").replace("t2_", "").replace("t3_", "").replace("t4_", "") + "_v1"
        sha_hex = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
        flag = f"FLAG{{{sha_hex}}}"
        h = hashlib.sha256(flag.encode("utf-8")).hexdigest()

        chal = {
            "id": cid,
            "tier": tier,
            "cat": "kisa",
            "track": "kisa",
            "points": pts,
            "ci": False,
            "fmt": "FLAG{...}",
            "title": {"ko": t_ko, "en": t_en},
            "prompt": {"ko": p_ko, "en": p_en},
            "hints": {"ko": h_ko, "en": h_en},
            "hash": h
        }
        challenges.append(chal)
        ids.append(cid)
    return challenges, ids

def main():
    print("[*] Generating 35 KISA track challenges...")
    challenges, ids = build_challenges()
    print(f"  ✓ Built {len(challenges)} challenges.")

    # 1. Update challenges.js
    with open(CHALLENGES_JS, "r", encoding="utf-8") as f:
        content = f.read()

    pos_tracks_end = content.find("const CHALLENGES =")
    if pos_tracks_end == -1:
        raise ValueError("Could not find `const CHALLENGES =` in challenges.js")
    bracket_pos = content.rfind("];", 0, pos_tracks_end)
    if bracket_pos == -1:
        raise ValueError("Could not find closing bracket for TRACKS")

    # Check if kisa track is already present
    if '"id": "kisa"' not in content[:pos_tracks_end]:
        prev_chunk = content[:bracket_pos].rstrip()
        if not prev_chunk.endswith(","):
            prev_chunk += ","
        content = prev_chunk + "\n  " + json.dumps(TRACK_INFO, ensure_ascii=False, indent=2).replace("\n", "\n  ") + "\n" + content[bracket_pos:]
        print("  ✓ Inserted 'kisa' into TRACKS.")

    # Add challenges before final ];
    final_bracket = content.rfind("];")
    if final_bracket == -1:
        raise ValueError("Could not find final `];` in challenges.js")

    if '"id": "t0_kisa_legal_framework"' not in content:
        rendered_chals = []
        for c in challenges:
            rendered = json.dumps(c, ensure_ascii=False, indent=2)
            rendered_chals.append(rendered)

        chals_str = ",\n" + ",\n".join(rendered_chals) + "\n"
        content = content[:final_bracket] + chals_str + content[final_bracket:]
        print("  ✓ Appended 35 challenges to CHALLENGES.")

    with open(CHALLENGES_JS, "w", encoding="utf-8") as f:
        f.write(content)

    # 2. Update solve-derivable.js
    with open(SOLVE_DERIVABLE_JS, "r", encoding="utf-8") as f:
        sd_content = f.read()

    marker = '"t4_bgp_capstone_global_routing_audit"'
    if marker in sd_content and f'"{ids[0]}"' not in sd_content:
        pos = sd_content.find(marker)
        insert_ids_str = ',\n' + ',\n'.join(f'  "{cid}"' for cid in ids)
        sd_content = sd_content[:pos + len(marker)] + insert_ids_str + sd_content[pos + len(marker):]
        with open(SOLVE_DERIVABLE_JS, "w", encoding="utf-8") as f:
            f.write(sd_content)
        print("  ✓ Updated solve-derivable.js with 35 KISA IDs.")

    print("[+] KISA track generation completed!")

if __name__ == "__main__":
    main()
