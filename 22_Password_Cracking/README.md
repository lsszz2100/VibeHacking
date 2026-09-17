# 22. 비밀번호 크래킹 (Password_Cracking)

> 🔑 **VibeHacking 교재 섹션 22**
> - **CLI 학습**: `python3 vhack.py study 22`

## 📚 목차

| 파일 | 제목 / 핵심 내용 |
|:-----|:-----------------|
| [01_Hash_Types_and_Wordlists.md](./01_Hash_Types_and_Wordlists.md) | **Hash Types and Wordlists** — 해시(Hash)는 임의의 데이터를 고정 길이의 문자열로 변환하는 단방향 함수의 결과물이다. 비밀번호를 데이터베이스에 저장할 때 평문 대신 해시값을 저장하여 유출 시 피해를 줄인다. 패... |
| [02_Hashcat_and_John.md](./02_Hashcat_and_John.md) | **Hashcat and John the Ripper** — Hashcat과 John the Ripper(이하 JtR)는 세계에서 가장 널리 사용되는 패스워드 크래킹 도구다. 해시값을 입력받아 다양한 방법으로 원래 비밀번호를 역추적한다. 보안 ... |
| [03_Advanced_Cracking_Techniques.md](./03_Advanced_Cracking_Techniques.md) | **Advanced Cracking Techniques** — 기본적인 사전 공격이나 브루트포스만으로는 복잡한 비밀번호를 크래킹하기 어렵다. 고급 크래킹 기법은 인간이 비밀번호를 만드는 패턴(P@ssw0rd, 이름+연도 등)을 활용한 규칙 기반 ... |
| [04_Credential_Stuffing_Automation.md](./04_Credential_Stuffing_Automation.md) | **크리덴셜 스터핑 및 패스워드 분석 자동화** — 크리덴셜 스터핑(Credential Stuffing)은 다른 서비스에서 유출된 아이디/비밀번호 쌍을 자동으로 다른 사이트에 대입하는 공격이다. 사용자들이 여러 사이트에서 같은 비밀번호... |
| [05_password_policy_audit.md](./05_password_policy_audit.md) | **패스워드 정책 감사 — 약한 정책 탐지·해시 강도 분석·권고사항** — 패스워드 정책 감사(Password Policy Audit)는 조직의 비밀번호 요구사항이 실제로 충분히 강한지 평가하는 과정이다. 단순히 "최소 8자 이상" 같은 규칙이 있다고 안전한... |
| [06_password_ctf_lab.md](./06_password_ctf_lab.md) | **패스워드 크래킹 CTF 실습 랩** — docker run -d --name crack-lab \ |

## 🎯 학습 목표

- Hash Types and Wordlists 원리 및 실전 공격/방어 기법 습득
- Hashcat and John the Ripper 원리 및 실전 공격/방어 기법 습득
- Advanced Cracking Techniques 원리 및 실전 공격/방어 기법 습득
- 크리덴셜 스터핑 및 패스워드 분석 자동화 원리 및 실전 공격/방어 기법 습득
- 실무 시나리오 기반 실습 및 자동화 스크립트 작성 역량 강화

## 💡 실습 및 연계 학습

- 터미널에서 전체 내용 읽기: `python3 vhack.py study 22 1`
- 웹 워게임 도전: 브라우저 워게임 콘솔(`wargame/`)에서 관련 트랙 풀이
