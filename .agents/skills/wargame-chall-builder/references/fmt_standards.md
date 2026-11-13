# Wargame Format (`fmt`) Standards

Every challenge in `wargame/assets/challenges.js` has a `"fmt"` field that guides the user on what format to submit.

## 1. Approved Base Phrases

Always start `fmt` with one of the following canonical dual-language phrases:

- `한 단어 / one word`
- `두 단어 / two words`
- `세 단어 / three words`
- `네 단어 / four words`
- `숫자 / number`
- `명령어 / command`
- `헤더 접미사 / header suffix`
- `경로 / path`
- `포트 번호 / port number`
- `도메인 / domain`
- `CVE 번호 / CVE identifier`
- `IP 주소 / IP address`
- `MAC 주소 / MAC address`
- `파일 이름 / filename`
- `레지스트리 키 / registry key`
- `JSON 속성 / JSON property`
- `함수 이름 / function name`
- `옵션 플래그 / option flag`
- `단일 문자 / single character`
- `시스템 콜 / syscall`
- `어셈블리 니모닉 / assembly mnemonic`
- `환경 변수 / environment variable`

## 2. Length Pinning Syntax

To avoid ambiguity when an answer can be singular or plural (e.g., `header` vs `headers`, `credential` vs `credentials`), you must append explicit character length in parentheses:

```json
"fmt": "한 단어 / one word (11글자 / 11 chars)"
"fmt": "헤더 접미사 / header suffix (11글자 / 11 chars)"
```

## 3. Case Insensitivity (`ci`)
- When `"ci": true`, the answer hash in `challenges.js` is computed on `answer.trim().toLowerCase()`.
- Do not add case qualification in `fmt` if `"ci": true`.
- Never prompt for `FLAG{...}` wrappers if `"ci": true`.
