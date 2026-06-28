// AUTO-GENERATED. Flags stored as SHA-256 only (no plaintext).
const TIERS = [
  {
    "id": 0,
    "ko": "입문",
    "en": "Onboarding",
    "need": 3,
    "desc_ko": "브라우저 개발자 도구와 기본 인코딩에 익숙해지기.",
    "desc_en": "Get comfortable with browser devtools and basic encoding."
  },
  {
    "id": 1,
    "ko": "기초",
    "en": "Beginner",
    "need": 4,
    "desc_ko": "고전 암호·웹 기초·HTTP 지식.",
    "desc_en": "Classic ciphers, web basics, HTTP knowledge."
  },
  {
    "id": 2,
    "ko": "중급",
    "en": "Intermediate",
    "need": 4,
    "desc_ko": "인젝션·해시·JWT·간단한 리버싱.",
    "desc_en": "Injection, hashing, JWT, light reversing."
  },
  {
    "id": 3,
    "ko": "고급",
    "en": "Advanced",
    "need": 3,
    "desc_ko": "XOR 암호·익스플로잇·포렌식·AD/시스템.",
    "desc_en": "XOR crypto, exploitation, forensics, AD/system."
  },
  {
    "id": 4,
    "ko": "전문가",
    "en": "Expert",
    "need": 4,
    "desc_ko": "체인 디코딩·클라우드·AI 보안 종합.",
    "desc_en": "Chained decoding, cloud, AI security capstone."
  }
];

const CHALLENGES = [
  {
    "id": "t0_source",
    "tier": 0,
    "cat": "web",
    "points": 50,
    "ci": false,
    "hash": "c5c8705bc1be2d75c0e25081c9a52ab81f90b50ad8ee73e38467740f9a844fc9",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "소스를 보라",
      "en": "View the Source"
    },
    "prompt": {
      "ko": "이 페이지의 HTML 소스 어딘가에 플래그가 주석으로 숨겨져 있습니다. 페이지 소스 보기(Ctrl+U) 또는 개발자도구로 찾으세요.",
      "en": "A flag is hidden in this page's HTML source as a comment. Use View Source (Ctrl+U) or DevTools."
    },
    "hints": {
      "ko": [
        "브라우저에서 Ctrl+U 를 눌러 보세요.",
        "HTML 주석은 <!-- 로 시작합니다."
      ],
      "en": [
        "Press Ctrl+U in your browser.",
        "HTML comments start with <!--."
      ]
    }
  },
  {
    "id": "t0_base64",
    "tier": 0,
    "cat": "crypto",
    "points": 50,
    "ci": false,
    "hash": "e522e8e38fdb6db3a667432087916a6abe7deb7400e3d58e92e1470cb3b1e054",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "비밀의 문자열",
      "en": "Secret String"
    },
    "prompt": {
      "ko": "다음 문자열을 디코딩하면 플래그가 됩니다:\n\n`RkxBR3tiYXNlNjRfaXNfZW5jb2Rpbmd9`",
      "en": "Decode this string to reveal the flag:\n\n`RkxBR3tiYXNlNjRfaXNfZW5jb2Rpbmd9`"
    },
    "hints": {
      "ko": [
        "= 로 끝나는 문자열은 보통 Base64입니다.",
        "터미널: `echo '...' | base64 -d` 또는 브라우저 콘솔: `atob('...')`"
      ],
      "en": [
        "Strings ending with = are often Base64.",
        "Try `echo '...' | base64 -d` or in the console: `atob('...')`"
      ]
    }
  },
  {
    "id": "t0_devtools",
    "tier": 0,
    "cat": "web",
    "points": 60,
    "ci": false,
    "hash": "66ecc396caa1aca3a50d4dabc2703a01bc89e2acf9e3725bb11b16d8e8ddaf81",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "콘솔의 비밀",
      "en": "Console Secret"
    },
    "prompt": {
      "ko": "개발자도구(F12) 콘솔을 열고 `window.__hint` 전역 변수를 출력해 보세요.",
      "en": "Open DevTools (F12), go to the Console, and print the global variable `window.__hint`."
    },
    "hints": {
      "ko": [
        "F12 → Console 탭.",
        "콘솔에 `window.__hint` 를 입력하고 Enter."
      ],
      "en": [
        "F12 -> Console tab.",
        "Type `window.__hint` and press Enter."
      ]
    }
  },
  {
    "id": "t0_ls",
    "tier": 0,
    "cat": "linux",
    "points": 40,
    "ci": true,
    "hash": "1de700c29687cae34561545f50d3c8b3d9afe88e04cc11069f8a6dc6e4ce9464",
    "fmt": "명령어 / command",
    "title": {
      "ko": "모든 것을 보여줘",
      "en": "Show Me Everything"
    },
    "prompt": {
      "ko": "리눅스에서 숨김 파일을 포함해 현재 디렉터리의 모든 파일을 권한·소유자와 함께 자세히 나열하는 명령은? (명령어만, 예: `cmd -opt`)",
      "en": "Which Linux command lists all files in the current directory in long format, including hidden files? (command only, e.g. `cmd -opt`)"
    },
    "hints": {
      "ko": [
        "`ls` 명령의 옵션 두 개를 조합합니다.",
        "`-l`(자세히)과 `-a`(숨김 포함)."
      ],
      "en": [
        "Combine two options of `ls`.",
        "`-l` (long) and `-a` (all/hidden)."
      ]
    }
  },
  {
    "id": "t1_rot13",
    "tier": 1,
    "cat": "crypto",
    "points": 70,
    "ci": false,
    "hash": "26b345b8a42722db6e8d75a2aba4ad401924477eb7934287b4efc47cfd07ea8b",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "13칸의 마법",
      "en": "Thirteen Steps"
    },
    "prompt": {
      "ko": "다음은 알파벳을 13칸 민 결과입니다. 원문을 구하세요:\n\n`SYNT{ebg13_pnrfne_pbhfva}`",
      "en": "The following was shifted by 13 letters. Recover the original:\n\n`SYNT{ebg13_pnrfne_pbhfva}`"
    },
    "hints": {
      "ko": [
        "ROT13 입니다. 한 번 더 ROT13 하면 원문.",
        "`tr 'A-Za-z' 'N-ZA-Mn-za-m'` 또는 온라인 ROT13."
      ],
      "en": [
        "It's ROT13. Applying ROT13 again restores it.",
        "Use `tr 'A-Za-z' 'N-ZA-Mn-za-m'` or an online ROT13."
      ]
    }
  },
  {
    "id": "t1_hex",
    "tier": 1,
    "cat": "crypto",
    "points": 70,
    "ci": false,
    "hash": "047ca2f904ff08b38c24c5a77da663b2c7f52e3457a47e97a4337b32e75c48db",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "16진수의 세계",
      "en": "Hex World"
    },
    "prompt": {
      "ko": "16진수로 인코딩된 플래그입니다. 디코딩하세요:\n\n`464c41477b6865785f69735f6261736531367d`",
      "en": "A hex-encoded flag. Decode it:\n\n`464c41477b6865785f69735f6261736531367d`"
    },
    "hints": {
      "ko": [
        "두 자리씩 한 바이트입니다.",
        "`echo '...' | xxd -r -p` 또는 콘솔에서 파싱."
      ],
      "en": [
        "Every two digits is one byte.",
        "Try `echo '...' | xxd -r -p`."
      ]
    }
  },
  {
    "id": "t1_cookie",
    "tier": 1,
    "cat": "web",
    "points": 70,
    "ci": false,
    "hash": "e0b7c03a863b596a51608cc06f09a60618cfc61d2e9372ff03a4fc5133cb60ea",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "쿠키 몬스터",
      "en": "Cookie Monster"
    },
    "prompt": {
      "ko": "이 사이트가 당신의 브라우저에 쿠키를 하나 구워뒀습니다. 개발자도구 Application(Storage) → Cookies 또는 콘솔의 `document.cookie` 로 확인하세요.",
      "en": "This site baked a cookie into your browser. Check DevTools Application -> Cookies, or `document.cookie` in the console."
    },
    "hints": {
      "ko": [
        "콘솔에 `document.cookie` 입력.",
        "`wg_flag` 라는 이름의 쿠키를 찾으세요."
      ],
      "en": [
        "Type `document.cookie` in the console.",
        "Look for a cookie named `wg_flag`."
      ]
    }
  },
  {
    "id": "t1_teapot",
    "tier": 1,
    "cat": "web",
    "points": 60,
    "ci": true,
    "hash": "4c8d5b6c695d265fb63dd73f275a21043a5887b37cb4fea0552ecc7b417c8f88",
    "fmt": "숫자 / number",
    "title": {
      "ko": "나는 주전자",
      "en": "I'm a Teapot"
    },
    "prompt": {
      "ko": "HTTP 상태 코드 중 \"I'm a teapot\"(나는 찻주전자다)에 해당하는 숫자는? (숫자만)",
      "en": "Which HTTP status code corresponds to \"I'm a teapot\"? (number only)"
    },
    "hints": {
      "ko": [
        "RFC 2324, 만우절 농담에서 유래한 4xx 코드.",
        "4로 시작하는 세 자리."
      ],
      "en": [
        "RFC 2324, an April Fools' joke 4xx code.",
        "Three digits, starts with 4."
      ]
    }
  },
  {
    "id": "t1_css",
    "tier": 1,
    "cat": "web",
    "points": 70,
    "ci": false,
    "hash": "c79ba81d3c97cd4663bdca70adfc48d9814ba5e9d7aa381907aaf6e6a32bc8ff",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "보이지 않는 것",
      "en": "The Invisible"
    },
    "prompt": {
      "ko": "화면에는 안 보이지만 DOM에는 존재하는 요소가 있습니다. `display:none` 이라고 안전한 건 아니죠. 페이지에서 숨겨진 요소를 찾으세요.",
      "en": "Something is in the DOM but not visible on screen. `display:none` doesn't mean safe. Find the hidden element."
    },
    "hints": {
      "ko": [
        "개발자도구 Elements 에서 id=`ghost` 요소를 찾으세요.",
        "Ctrl+F 로 'FLAG' 검색."
      ],
      "en": [
        "In DevTools Elements, find the element with id=`ghost`.",
        "Ctrl+F for 'FLAG'."
      ]
    }
  },
  {
    "id": "t2_union",
    "tier": 2,
    "cat": "web",
    "points": 90,
    "ci": true,
    "hash": "e1023fc6a5fa259e278448b65d01cad04eebb01fc0b420c5def2a7d7900c15fd",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "다른 테이블을 합쳐라",
      "en": "Join Another Table"
    },
    "prompt": {
      "ko": "SQL 인젝션에서 다른 테이블의 데이터를 기존 쿼리 결과에 결합해 추출할 때 쓰는 두 단어 키워드는? (영문)",
      "en": "In SQL injection, which two-word keyword combines another table's data into the original query result? (English)"
    },
    "hints": {
      "ko": [
        "컬럼 수가 같아야 동작합니다.",
        "`UNION ...`"
      ],
      "en": [
        "Column counts must match.",
        "`UNION ...`"
      ]
    }
  },
  {
    "id": "t2_md5",
    "tier": 2,
    "cat": "crypto",
    "points": 90,
    "ci": true,
    "hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "fmt": "단어 / word",
    "title": {
      "ko": "가장 흔한 비밀번호",
      "en": "The Most Common Password"
    },
    "prompt": {
      "ko": "MD5 해시 `5f4dcc3b5aa765d61d8327deb882cf99` 의 평문은? (아주 유명한 단어)",
      "en": "What is the plaintext of the MD5 hash `5f4dcc3b5aa765d61d8327deb882cf99`? (a very famous word)"
    },
    "hints": {
      "ko": [
        "레인보우 테이블/구글에 해시를 검색해 보세요.",
        "가장 흔한 비밀번호 중 하나입니다."
      ],
      "en": [
        "Search the hash in a rainbow table / Google.",
        "It's one of the most common passwords."
      ]
    }
  },
  {
    "id": "t2_jwt",
    "tier": 2,
    "cat": "web",
    "points": 90,
    "ci": true,
    "hash": "140bedbf9c3f6d56a9846d2ba7088798683f4da0c248231336e6a05679e4fdfe",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "서명을 무력화하라",
      "en": "Defeat the Signature"
    },
    "prompt": {
      "ko": "JWT에서 `alg` 헤더를 무엇으로 바꾸면 서명 검증을 우회할 수 있나요? (소문자 한 단어)",
      "en": "Setting the JWT `alg` header to which value can bypass signature verification? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "'알고리즘 없음'을 의미합니다.",
        "`{\"alg\":\"____\"}`"
      ],
      "en": [
        "It means 'no algorithm'.",
        "`{\"alg\":\"____\"}`"
      ]
    }
  },
  {
    "id": "t2_reverse",
    "tier": 2,
    "cat": "reversing",
    "points": 100,
    "ci": false,
    "hash": "a5fc290ac7280cc55af945e695d8d2aedfbf2bc649f0eec9b5ba857b30f83e74",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "거꾸로 그리고 인코딩",
      "en": "Reverse then Encode"
    },
    "prompt": {
      "ko": "어떤 플래그를 문자열 뒤집기 후 Base64 인코딩했더니 아래가 나왔습니다. 원래 플래그는?\n\n`fTQ2Yl9uZWh0X2VzcmV2ZXJ7R0FMRg==`\n\n변환: `btoa(flag.split('').reverse().join(''))`",
      "en": "A flag was reversed then Base64-encoded into the value below. What was the original flag?\n\n`fTQ2Yl9uZWh0X2VzcmV2ZXJ7R0FMRg==`\n\nTransform: `btoa(flag.split('').reverse().join(''))`"
    },
    "hints": {
      "ko": [
        "먼저 Base64 디코드: `atob('...')`.",
        "그 결과를 다시 뒤집으세요."
      ],
      "en": [
        "First Base64-decode: `atob('...')`.",
        "Then reverse the result."
      ]
    }
  },
  {
    "id": "t2_url",
    "tier": 2,
    "cat": "web",
    "points": 80,
    "ci": true,
    "hash": "f1d8d5da9b6d11e01b22c1aa927e6e5cc7f23339adda6b39764d7d6fe9fca84e",
    "fmt": "값 그대로 / literal",
    "title": {
      "ko": "이중 인코딩",
      "en": "Double Encoding"
    },
    "prompt": {
      "ko": "WAF 우회에 자주 쓰이는 이중 URL 인코딩입니다. `%2553` 을 한 번만 URL 디코딩하면 무엇이 되나요? (그대로 입력)",
      "en": "Double URL encoding is common for WAF bypass. What does `%2553` become after decoding URL-encoding once? (enter as-is)"
    },
    "hints": {
      "ko": [
        "`%25` 는 `%` 문자입니다.",
        "`%25` + `53` → ?"
      ],
      "en": [
        "`%25` decodes to `%`.",
        "`%25` + `53` -> ?"
      ]
    }
  },
  {
    "id": "t2_xss",
    "tier": 2,
    "cat": "web",
    "points": 80,
    "ci": true,
    "hash": "33d8ce420e65b03cd89a4de87decd82e0c0358e10e96a31738ee16f0c41059b6",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "쿠키를 지켜라",
      "en": "Protect the Cookie"
    },
    "prompt": {
      "ko": "XSS로 자바스크립트가 쿠키(document.cookie)를 읽지 못하게 막는 쿠키 속성은? (한 단어)",
      "en": "Which cookie attribute prevents JavaScript (document.cookie) from reading a cookie during XSS? (one word)"
    },
    "hints": {
      "ko": [
        "쿠키 설정의 플래그입니다.",
        "`Set-Cookie: ...; ________`"
      ],
      "en": [
        "A flag in the cookie setting.",
        "`Set-Cookie: ...; ________`"
      ]
    }
  },
  {
    "id": "t3_xor",
    "tier": 3,
    "cat": "crypto",
    "points": 130,
    "ci": false,
    "hash": "1923dcadd8af7b2f13a42f6c77e17d6d7d537f402457a78423006f2316637ae8",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "단일 바이트 XOR",
      "en": "Single-Byte XOR"
    },
    "prompt": {
      "ko": "아래 16진 바이트열은 어떤 플래그를 단일 바이트 키 `0x42` 로 XOR한 결과입니다. 복호화하세요:\n\n`040e030539312b2c252e271d203b36271d3a2d301d76703f`",
      "en": "The hex bytes below are a flag XOR-ed with the single-byte key `0x42`. Decrypt it:\n\n`040e030539312b2c252e271d203b36271d3a2d301d76703f`"
    },
    "hints": {
      "ko": [
        "각 바이트를 0x42 와 XOR 하세요.",
        "Python: `bytes.fromhex(h)` 후 `b ^ 0x42`."
      ],
      "en": [
        "XOR each byte with 0x42.",
        "Python: `bytes.fromhex(h)` then `b ^ 0x42`."
      ]
    }
  },
  {
    "id": "t3_kerb",
    "tier": 3,
    "cat": "windows",
    "points": 110,
    "ci": true,
    "hash": "f596dc40b19f77eede697e09e6b240defb8a9fa20976531511fc3df92030b772",
    "fmt": "숫자 / number",
    "title": {
      "ko": "케르베로스의 흔적",
      "en": "Trace of Kerberos"
    },
    "prompt": {
      "ko": "Kerberoasting 공격 탐지의 핵심이 되는, RC4 서비스 티켓 요청을 나타내는 Windows 보안 이벤트 ID는? (숫자)",
      "en": "Which Windows Security Event ID (for an RC4 service ticket request) is key to detecting Kerberoasting? (number)"
    },
    "hints": {
      "ko": [
        "TGS 티켓 요청 이벤트입니다.",
        "47 로 시작하는 네 자리."
      ],
      "en": [
        "A TGS ticket request event.",
        "Four digits starting with 47."
      ]
    }
  },
  {
    "id": "t3_fmt",
    "tier": 3,
    "cat": "pwn",
    "points": 120,
    "ci": true,
    "hash": "7892df0e4b5a59123524a5c4c4de70dee9a9cd65e29fa21deb8a50e812c1f4a4",
    "fmt": "예: %x 형식 / e.g. %x",
    "title": {
      "ko": "메모리에 쓰기",
      "en": "Write to Memory"
    },
    "prompt": {
      "ko": "포맷 스트링 취약점에서 지금까지 출력된 바이트 수를 임의 주소에 '쓰는' 데 사용되는 포맷 지정자는?",
      "en": "In a format string vulnerability, which format specifier is used to WRITE the number of bytes printed so far to an arbitrary address?"
    },
    "hints": {
      "ko": [
        "%x, %p 는 읽기. 쓰기는 다른 것.",
        "`%____`"
      ],
      "en": [
        "%x, %p read. Writing uses another one.",
        "`%____`"
      ]
    }
  },
  {
    "id": "t3_sig",
    "tier": 3,
    "cat": "forensics",
    "points": 110,
    "ci": true,
    "hash": "8f8cbb7dcf46e0bc7d53265749a6c17d116093a6ba95e442764060c76fd4a86c",
    "fmt": "확장자 / extension",
    "title": {
      "ko": "파일 시그니처",
      "en": "File Signature"
    },
    "prompt": {
      "ko": "파일의 처음 바이트가 `89 50 4E 47 0D 0A 1A 0A` 입니다. 이 파일의 형식(확장자, 점 없이)은?",
      "en": "A file starts with the bytes `89 50 4E 47 0D 0A 1A 0A`. What file type is this (extension, no dot)?"
    },
    "hints": {
      "ko": [
        "50 4E 47 는 ASCII로 'PNG' 입니다.",
        "이미지 형식."
      ],
      "en": [
        "50 4E 47 is 'PNG' in ASCII.",
        "An image format."
      ]
    }
  },
  {
    "id": "t3_suid",
    "tier": 3,
    "cat": "linux",
    "points": 120,
    "ci": true,
    "hash": "b090147020e033534635010c4f7eb6fc270d44e5df67ea9e744a8087df9ca106",
    "fmt": "8진수 / octal",
    "title": {
      "ko": "권한 상승의 단서",
      "en": "Privesc Clue"
    },
    "prompt": {
      "ko": "리눅스 권한 상승 점검 시 `find / -perm -____ -type f` 로 검색하는, SUID 비트를 나타내는 8진수 권한 값은?",
      "en": "During Linux privesc checks, `find / -perm -____ -type f` searches for the SUID bit. What octal permission value represents SUID?"
    },
    "hints": {
      "ko": [
        "SUID, SGID, sticky 중 SUID.",
        "4 로 시작하는 네 자리 8진수."
      ],
      "en": [
        "SUID among SUID/SGID/sticky.",
        "Four-digit octal starting with 4."
      ]
    }
  },
  {
    "id": "t4_chain",
    "tier": 4,
    "cat": "crypto",
    "points": 170,
    "ci": false,
    "hash": "400b7f9dd47dd8aafbdf1c0650ac6f4b9871167364133b93fbee2958daefef17",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "연쇄 디코딩",
      "en": "Chained Decoding"
    },
    "prompt": {
      "ko": "아래 문자열을 먼저 Base64 디코드한 뒤, 그 결과를 ROT13 하면 플래그가 나옵니다:\n\n`U1lOVHtwdW52YXJxX282NF9ndXJhX2ViZzEzfQ==`",
      "en": "Base64-decode the string below, then ROT13 the result to get the flag:\n\n`U1lOVHtwdW52YXJxX282NF9ndXJhX2ViZzEzfQ==`"
    },
    "hints": {
      "ko": [
        "1단계: `atob('...')`.",
        "2단계: 그 결과에 ROT13 적용."
      ],
      "en": [
        "Step 1: `atob('...')`.",
        "Step 2: apply ROT13 to the result."
      ]
    }
  },
  {
    "id": "t4_container",
    "tier": 4,
    "cat": "cloud",
    "points": 140,
    "ci": true,
    "hash": "5b56570fc818acea65eb7a740b4c95bbf7ebc5fb83f2f016924d10cacfae5dff",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "컨테이너 탈출",
      "en": "Container Escape"
    },
    "prompt": {
      "ko": "컨테이너 탈출에 자주 악용되는, 호스트의 모든 권한·디바이스 접근을 부여하는 `docker run` 플래그는? `--________` (한 단어)",
      "en": "Which `docker run` flag grants full host privileges/device access and is often abused for container escape? `--________` (one word)"
    },
    "hints": {
      "ko": [
        "보안 격리를 사실상 해제합니다.",
        "`--priv...`"
      ],
      "en": [
        "It effectively removes security isolation.",
        "`--priv...`"
      ]
    }
  },
  {
    "id": "t4_llm",
    "tier": 4,
    "cat": "ai",
    "points": 140,
    "ci": true,
    "hash": "3173623593e219d749ba0b87944e71f791b273b17498cba70d48be2af367b7c1",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "시스템 프롬프트 탈취",
      "en": "Hijack the System Prompt"
    },
    "prompt": {
      "ko": "LLM에게 \"이전 지시를 무시하라\"는 식으로 시스템 프롬프트를 무력화하는 공격 기법의 이름은? (영문 두 단어)",
      "en": "What is the name of the attack that overrides an LLM's system prompt with input like \"ignore previous instructions\"? (two English words)"
    },
    "hints": {
      "ko": [
        "OWASP LLM Top 10 의 1위 항목입니다.",
        "`prompt ________`"
      ],
      "en": [
        "The #1 item in the OWASP LLM Top 10.",
        "`prompt ________`"
      ]
    }
  },
  {
    "id": "t4_capstone",
    "tier": 4,
    "cat": "crypto",
    "points": 200,
    "ci": false,
    "hash": "0eab38f585377e7f6bc16e86f306132116868bc5879a182287cc16859a30cc05",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "최종 관문",
      "en": "The Final Gate"
    },
    "prompt": {
      "ko": "마지막 도전입니다. 아래는 단일 바이트 키 `0x37` 로 XOR된 플래그입니다. 복호화하면 당신은 진정한 해커:\n\n`717b76704c4e58426854585a475b5243525368435f5268415e55526840564550565a524a`",
      "en": "The final challenge. Below is a flag XOR-ed with the single-byte key `0x37`. Decrypt it and you are a true hacker:\n\n`717b76704c4e58426854585a475b5243525368435f5268415e55526840564550565a524a`"
    },
    "hints": {
      "ko": [
        "t3의 단일 바이트 XOR과 동일한 기법, 키만 0x37.",
        "Python 한 줄이면 충분합니다."
      ],
      "en": [
        "Same single-byte XOR as t3, key is 0x37.",
        "One line of Python is enough."
      ]
    }
  }
];
