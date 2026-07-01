// AUTO-GENERATED. Flags stored as SHA-256 only (no plaintext).
const TIERS = [
  {
    "id": 0,
    "ko": "입문",
    "en": "Onboarding",
    "need": 4,
    "desc_ko": "브라우저 개발자 도구와 기본 인코딩에 익숙해지기.",
    "desc_en": "Get comfortable with browser devtools and basic encoding."
  },
  {
    "id": 1,
    "ko": "기초",
    "en": "Beginner",
    "need": 6,
    "desc_ko": "고전 암호·웹 기초·HTTP 지식.",
    "desc_en": "Classic ciphers, web basics, HTTP knowledge."
  },
  {
    "id": 2,
    "ko": "중급",
    "en": "Intermediate",
    "need": 9,
    "desc_ko": "인젝션·해시·JWT·인코딩·간단한 리버싱.",
    "desc_en": "Injection, hashing, JWT, encoding, light reversing."
  },
  {
    "id": 3,
    "ko": "고급",
    "en": "Advanced",
    "need": 7,
    "desc_ko": "XOR/ROT47 암호·익스플로잇·포렌식·탐지.",
    "desc_en": "XOR/ROT47 crypto, exploitation, forensics, detection."
  },
  {
    "id": 4,
    "ko": "전문가",
    "en": "Expert",
    "need": 5,
    "desc_ko": "체인 디코딩·클라우드·암호 운영모드·AI 보안 종합.",
    "desc_en": "Chained decoding, cloud, crypto modes, AI security capstone."
  }
];

const TRACKS = [
  {
    "id": "web",
    "icon": "🌐",
    "ko": "웹 해킹",
    "en": "Web & App",
    "desc_ko": "소스 분석·세션·인젝션·SSTI 등 웹 공격면.",
    "desc_en": "Source review, sessions, injection, SSTI."
  },
  {
    "id": "crypto",
    "icon": "🔐",
    "ko": "암호·인코딩",
    "en": "Crypto & Encoding",
    "desc_ko": "고전 암호·인코딩·해시·현대 암호 운영모드.",
    "desc_en": "Classic ciphers, encoding, hashing, modern modes."
  },
  {
    "id": "system",
    "icon": "💻",
    "ko": "시스템·리버싱·Pwn",
    "en": "System, Reversing & Pwn",
    "desc_ko": "리눅스·윈도우/AD·리버싱·바이너리 익스플로잇.",
    "desc_en": "Linux, Windows/AD, reversing, binary exploitation."
  },
  {
    "id": "forensics",
    "icon": "🔍",
    "ko": "포렌식·멀웨어·네트워크",
    "en": "Forensics, Malware & Network",
    "desc_ko": "파일 시그니처·메타데이터·탐지·패킷 분석.",
    "desc_en": "File signatures, metadata, detection, packets."
  },
  {
    "id": "cloud",
    "icon": "☁️",
    "ko": "클라우드·AI",
    "en": "Cloud, Container & AI",
    "desc_ko": "컨테이너/쿠버네티스·클라우드 메타데이터·LLM 보안.",
    "desc_en": "Containers/K8s, cloud metadata, LLM security."
  }
];

const CHALLENGES = [
  {
    "id": "t0_source",
    "tier": 0,
    "cat": "web",
    "track": "web",
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
    "track": "crypto",
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
    "track": "web",
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
    "track": "system",
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
    "id": "t0_binary",
    "tier": 0,
    "cat": "crypto",
    "track": "crypto",
    "points": 50,
    "ci": true,
    "hash": "e7d3685715939842749cc27b38d0ccb9706d4d14a5304ef9eee093780eab5df9",
    "fmt": "단어 / word",
    "title": {
      "ko": "0과 1의 언어",
      "en": "Language of 0s and 1s"
    },
    "prompt": {
      "ko": "다음 이진수(8비트씩)를 ASCII 텍스트로 디코딩하세요:\n\n`01101000 01100001 01100011 01101011 01100101 01110010`",
      "en": "Decode this binary (8 bits each) into ASCII text:\n\n`01101000 01100001 01100011 01101011 01100101 01110010`"
    },
    "hints": {
      "ko": [
        "8자리마다 한 글자입니다.",
        "01001000 = 0x48 = 'H'."
      ],
      "en": [
        "Each 8 digits is one character.",
        "01001000 = 0x48 = 'H'."
      ]
    }
  },
  {
    "id": "t0_title",
    "tier": 0,
    "cat": "web",
    "track": "web",
    "points": 40,
    "ci": true,
    "hash": "41619bedb010a070affe3cba11e586db3c73043f09b6a616f77fcb03f84d8e43",
    "fmt": "제목 / title",
    "title": {
      "ko": "탭의 제목",
      "en": "The Tab Title"
    },
    "prompt": {
      "ko": "브라우저 탭(또는 HTML `<title>` 태그)에 표시되는 이 페이지의 제목은 무엇인가요? (정확히 입력)",
      "en": "What is this page's title shown in the browser tab (the HTML `<title>` tag)? (exact)"
    },
    "hints": {
      "ko": [
        "브라우저 탭 위쪽을 보세요.",
        "소스의 `<title>...</title>` 안."
      ],
      "en": [
        "Look at the top of the browser tab.",
        "Inside `<title>...</title>` in the source."
      ]
    }
  },
  {
    "id": "t1_rot13",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
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
    "track": "crypto",
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
    "track": "web",
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
    "track": "web",
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
    "track": "web",
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
    "id": "t1_caesar",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
    "points": 70,
    "ci": false,
    "hash": "c3514a33998970b1f29cb055f594b73ea43624abe7143bc3eaee49366d94250c",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "카이사르의 암호",
      "en": "Caesar's Cipher"
    },
    "prompt": {
      "ko": "율리우스 카이사르가 쓰던 방식으로 각 글자를 3칸 밀었습니다. 원문을 복원하세요:\n\n`IODJ{fdhvdu_vkliw_wkuhh}`",
      "en": "Each letter was shifted by 3, as Julius Caesar did. Recover the original:\n\n`IODJ{fdhvdu_vkliw_wkuhh}`"
    },
    "hints": {
      "ko": [
        "반대로 3칸 당기면 됩니다.",
        "ROT13과 같은 원리, 이동량만 3."
      ],
      "en": [
        "Shift back by 3.",
        "Same idea as ROT13, but a shift of 3."
      ]
    }
  },
  {
    "id": "t1_morse",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
    "points": 60,
    "ci": true,
    "hash": "c0946106b732f9f6ae889101ab987ed1bbcfe3eda2ad0a971be31575ad676851",
    "fmt": "단어 / word",
    "title": {
      "ko": "점과 선",
      "en": "Dots and Dashes"
    },
    "prompt": {
      "ko": "다음 모스 부호를 해독하세요 (공백은 글자 구분):\n\n`... --- ...`",
      "en": "Decode this Morse code (spaces separate letters):\n\n`... --- ...`"
    },
    "hints": {
      "ko": [
        "... 는 S, --- 는 O 입니다.",
        "가장 유명한 구조 신호."
      ],
      "en": [
        "... is S, --- is O.",
        "The most famous distress signal."
      ]
    }
  },
  {
    "id": "t1_robots",
    "tier": 1,
    "cat": "web",
    "track": "web",
    "points": 60,
    "ci": true,
    "hash": "870b1fc137c2af20441f74a26febf99739d79cee1246063e279ca05f288e943c",
    "fmt": "파일명 / filename",
    "title": {
      "ko": "크롤러에게 보내는 쪽지",
      "en": "Note to Crawlers"
    },
    "prompt": {
      "ko": "웹사이트가 검색엔진 크롤러에게 접근 규칙을 알려줄 때 루트에 두는 표준 파일의 이름은? (확장자 포함)",
      "en": "What standard file does a website place at its root to tell search crawlers the access rules? (with extension)"
    },
    "hints": {
      "ko": [
        "펜테스트 정찰 때도 가장 먼저 확인합니다.",
        "`/______.txt`"
      ],
      "en": [
        "Recon's first stop in a pentest, too.",
        "`/______.txt`"
      ]
    }
  },
  {
    "id": "t2_union",
    "tier": 2,
    "cat": "web",
    "track": "web",
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
    "track": "crypto",
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
    "track": "web",
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
    "track": "system",
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
    "track": "web",
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
    "track": "web",
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
    "id": "t2_lfi",
    "tier": 2,
    "cat": "web",
    "track": "web",
    "points": 90,
    "ci": false,
    "hash": "fa08499e14d0113ba6794623f1badedcc8e9ae51cb5bafc7e14a5af1454bcfe7",
    "fmt": "3글자 / 3 chars",
    "title": {
      "ko": "상위로 올라가기",
      "en": "Climb Up"
    },
    "prompt": {
      "ko": "경로 순회(Path Traversal/LFI)에서 상위 디렉터리로 한 단계 올라갈 때 쓰는 세 글자 시퀀스는?",
      "en": "In path traversal (LFI), what three-character sequence moves up one directory level?"
    },
    "hints": {
      "ko": [
        "`/etc/passwd` 를 읽으려면 여러 번 반복합니다.",
        "점 두 개와 슬래시."
      ],
      "en": [
        "Repeated many times to reach `/etc/passwd`.",
        "Two dots and a slash."
      ]
    }
  },
  {
    "id": "t2_b32",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 100,
    "ci": false,
    "hash": "e56dd9eb62ba3233649372c53139b1564e508f2c8189a9e62e3d223fff2f40d0",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "32진법 인코딩",
      "en": "Base32 Encoding"
    },
    "prompt": {
      "ko": "대문자와 숫자 2-7만 쓰는 인코딩입니다. 디코딩하세요:\n\n`IZGECR33MJQXGZJTGJPXK43FONPXEZTDGQ3DIOD5`",
      "en": "An encoding that uses only uppercase letters and digits 2-7. Decode it:\n\n`IZGECR33MJQXGZJTGJPXK43FONPXEZTDGQ3DIOD5`"
    },
    "hints": {
      "ko": [
        "= 패딩이 있지만 Base64는 아닙니다 — Base32.",
        "`echo '...' | base32 -d`"
      ],
      "en": [
        "Has = padding but isn't Base64 — it's Base32.",
        "`echo '...' | base32 -d`"
      ]
    }
  },
  {
    "id": "t2_sha1",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 90,
    "ci": true,
    "hash": "b1565820a5cdac40e0520d23f9d0b1497f240ddc51d72eac6423d97d952d444f",
    "fmt": "알고리즘명 / name",
    "title": {
      "ko": "해시의 정체",
      "en": "Identify the Hash"
    },
    "prompt": {
      "ko": "40자리 16진수(160비트)로 출력되며, 충돌 공격이 발견되어 사용이 권장되지 않는 해시 알고리즘은? (이름)",
      "en": "Which hash algorithm outputs 40 hex chars (160-bit) and is deprecated due to collision attacks? (name)"
    },
    "hints": {
      "ko": [
        "MD5(32자리)보다 길고 SHA-256(64자리)보다 짧습니다.",
        "Git이 오래 쓰던 그 해시."
      ],
      "en": [
        "Longer than MD5 (32) and shorter than SHA-256 (64).",
        "The hash Git used for years."
      ]
    }
  },
  {
    "id": "t3_xor",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
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
    "track": "system",
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
    "track": "system",
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
    "track": "forensics",
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
    "track": "system",
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
    "id": "t3_rot47",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 130,
    "ci": false,
    "hash": "679d8874e27f74e5aa45c8bfaf20e805bca35f975e0581ddb78749fe5e6b40ab",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "ROT47의 영역",
      "en": "The ROT47 Zone"
    },
    "prompt": {
      "ko": "ROT13의 확장판으로, 출력 가능한 ASCII(33~126) 94문자를 47칸 회전시킵니다. 복호화하세요:\n\n`u{pvLC@Ecf0AC:?E23=602D4::N`",
      "en": "An extension of ROT13 that rotates the 94 printable ASCII chars (33-126) by 47. Decode it:\n\n`u{pvLC@Ecf0AC:?E23=602D4::N`"
    },
    "hints": {
      "ko": [
        "ROT47도 자기역원입니다 — 한 번 더 ROT47.",
        "CyberChef 'ROT47' 또는 직접 구현."
      ],
      "en": [
        "ROT47 is its own inverse — apply ROT47 again.",
        "CyberChef 'ROT47' or implement it."
      ]
    }
  },
  {
    "id": "t3_ssti",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": false,
    "hash": "a02c3fa3bddb079181b9360380870fb5799c5fc8cdbe3ebb0ea223b5a6f4d5ca",
    "fmt": "식 / expression",
    "title": {
      "ko": "템플릿 인젝션",
      "en": "Template Injection"
    },
    "prompt": {
      "ko": "Jinja2 SSTI 취약점을 1차 확인할 때, 49가 출력되는지 보려고 `{{ ____ }}` 안에 넣는 가장 흔한 식은? (공백 없이)",
      "en": "To first confirm a Jinja2 SSTI, what is the most common expression placed inside `{{ ____ }}` to see if 49 is rendered? (no spaces)"
    },
    "hints": {
      "ko": [
        "곱셈으로 49를 만듭니다.",
        "`{{7__7}}` 의 빈칸은 곱셈 연산자."
      ],
      "en": [
        "Multiply to make 49.",
        "The blank in `{{7__7}}` is the multiply operator."
      ]
    }
  },
  {
    "id": "t3_yara",
    "tier": 3,
    "cat": "malware",
    "track": "forensics",
    "points": 110,
    "ci": true,
    "hash": "a38933a27dad50fd2ed7cf588ca553d2b4d1fc704e103dc99b22cb13a32bba56",
    "fmt": "도구명 / tool name",
    "title": {
      "ko": "악성코드 패턴 매칭",
      "en": "Malware Pattern Matching"
    },
    "prompt": {
      "ko": "문자열·바이트 패턴 규칙으로 악성코드를 분류·탐지하는, '패턴 매칭계의 맥가이버 칼'로 불리는 도구는? (이름)",
      "en": "Which tool, called 'the pattern matching swiss knife', classifies/detects malware with string/byte rules? (name)"
    },
    "hints": {
      "ko": [
        "규칙 파일 확장자는 .yar / .yara.",
        "`rule { strings: ... condition: ... }`"
      ],
      "en": [
        "Rule files end in .yar / .yara.",
        "`rule { strings: ... condition: ... }`"
      ]
    }
  },
  {
    "id": "t3_syn",
    "tier": 3,
    "cat": "network",
    "track": "forensics",
    "points": 110,
    "ci": true,
    "hash": "ed415da6d67dcb38258965b9a3abec2cbc2ec61710b7b66dedd3e27168e7d2c8",
    "fmt": "플래그 / flag",
    "title": {
      "ko": "3-way 핸드셰이크",
      "en": "3-Way Handshake"
    },
    "prompt": {
      "ko": "TCP 3-way 핸드셰이크에서 클라이언트가 가장 먼저 보내는 패킷에 설정되는 플래그는? (한 단어)",
      "en": "In the TCP 3-way handshake, which flag is set on the very first packet the client sends? (one word)"
    },
    "hints": {
      "ko": [
        "순서: ___ → SYN-ACK → ACK.",
        "'동기화(synchronize)'의 약자."
      ],
      "en": [
        "Order: ___ -> SYN-ACK -> ACK.",
        "Short for 'synchronize'."
      ]
    }
  },
  {
    "id": "t4_chain",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
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
    "track": "cloud",
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
    "track": "cloud",
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
    "id": "t4_jwtsig",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "1a2fc26dc7ea5a2a4748b7cb2b1ef193d96ab2c99f93092f69e63075b28d1278",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "JWT의 세 조각",
      "en": "Three Parts of a JWT"
    },
    "prompt": {
      "ko": "JWT는 점(.)으로 구분된 세 부분으로 구성됩니다: header . payload . ________ ? (세 번째 부분의 이름, 영문)",
      "en": "A JWT has three dot-separated parts: header . payload . ________ ? (name of the third part, English)"
    },
    "hints": {
      "ko": [
        "변조를 검증하는 부분입니다.",
        "alg=none 공격은 이 부분을 비웁니다."
      ],
      "en": [
        "The part that verifies integrity.",
        "The alg=none attack empties this part."
      ]
    }
  },
  {
    "id": "t4_gcm",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 160,
    "ci": true,
    "hash": "68c6bc126c7cf29755cb01bd3f683526cc1ec205f8aea51f9c6129cbde83cc91",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "논스를 재사용하지 마라",
      "en": "Never Reuse the Nonce"
    },
    "prompt": {
      "ko": "인증(무결성)까지 제공하는 AES AEAD 운영 모드로, 동일 nonce를 두 번 쓰면 인증 키까지 복구될 수 있는 모드는? (약자 3글자)",
      "en": "Which AES AEAD mode (provides authentication) can leak its auth key if the same nonce is reused twice? (3-letter abbreviation)"
    },
    "hints": {
      "ko": [
        "Galois/Counter Mode.",
        "TLS 1.3에서 널리 쓰입니다."
      ],
      "en": [
        "Galois/Counter Mode.",
        "Widely used in TLS 1.3."
      ]
    }
  },
  {
    "id": "t4_megachain",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 190,
    "ci": false,
    "hash": "edc75474191ebe0ecdead94c2ac3c32c1a706009292d047cbc1a27ff51ae28a5",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "이중 인코딩 보스",
      "en": "Double-Encoded Boss"
    },
    "prompt": {
      "ko": "플래그를 16진수로 바꾼 뒤 그 결과를 Base64로 인코딩했습니다. 두 단계를 역순으로 풀어 플래그를 복원하세요:\n\n`NDY0YzQxNDc3YjY0NmY3NTYyNmM2NTVmNjU2ZTYzNmY2NDY1NjQ1ZjY2Njk2ZTYxNmM1ZjYyNmY3MzczN2Q=`",
      "en": "The flag was hex-encoded, then that result was Base64-encoded. Reverse both steps to recover the flag:\n\n`NDY0YzQxNDc3YjY0NmY3NTYyNmM2NTVmNjU2ZTYzNmY2NDY1NjQ1ZjY2Njk2ZTYxNmM1ZjYyNmY3MzczN2Q=`"
    },
    "hints": {
      "ko": [
        "1단계: Base64 디코드 → 16진 문자열이 나옵니다.",
        "2단계: 그 16진 문자열을 바이트로 디코드."
      ],
      "en": [
        "Step 1: Base64-decode -> you get a hex string.",
        "Step 2: hex-decode that string into bytes."
      ]
    }
  },
  {
    "id": "t4_capstone",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
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
  },
  {
    "id": "t1_chmod",
    "tier": 1,
    "cat": "linux",
    "track": "system",
    "points": 70,
    "ci": true,
    "hash": "86ab8cbe5869bd1f9c70924e9c04fef3bbe3bbaaf4e816efeeaf7eb6a31937d2",
    "fmt": "8진수 / octal",
    "title": {
      "ko": "권한의 숫자",
      "en": "Permission Numbers"
    },
    "prompt": {
      "ko": "리눅스 파일 권한 `rwxr-xr-x` 를 8진수 표기로 바꾸면? (3자리 숫자)",
      "en": "Convert the Linux permission `rwxr-xr-x` to octal notation. (3-digit number)"
    },
    "hints": {
      "ko": [
        "r=4, w=2, x=1 을 그룹별로 더합니다.",
        "rwx=7, r-x=5."
      ],
      "en": [
        "Sum r=4, w=2, x=1 per group.",
        "rwx=7, r-x=5."
      ]
    }
  },
  {
    "id": "t2_strings",
    "tier": 2,
    "cat": "reversing",
    "track": "system",
    "points": 90,
    "ci": true,
    "hash": "e967d16dae74a49b5e0e051225c5dac0d76e5e38f13dd1628028cbce108c25b6",
    "fmt": "명령어 / command",
    "title": {
      "ko": "숨은 문자열",
      "en": "Hidden Strings"
    },
    "prompt": {
      "ko": "바이너리에서 사람이 읽을 수 있는 ASCII 문자열만 뽑아내는 고전 유닉스 명령은? (명령어 이름)",
      "en": "Which classic Unix command extracts human-readable ASCII strings from a binary? (command name)"
    },
    "hints": {
      "ko": [
        "이름 그대로 '문자열들'.",
        "`____ ./malware.bin | grep FLAG`"
      ],
      "en": [
        "The name literally means 'strings'.",
        "`____ ./malware.bin | grep FLAG`"
      ]
    }
  },
  {
    "id": "t3_nop",
    "tier": 3,
    "cat": "pwn",
    "track": "system",
    "points": 120,
    "ci": true,
    "hash": "69f59c273b6e669ac32a6dd5e1b2cb63333d8b004f9696447aee2d422ce63763",
    "fmt": "16진수 2자리 / 2 hex digits",
    "title": {
      "ko": "아무것도 하지 않는 명령",
      "en": "The Do-Nothing Instruction"
    },
    "prompt": {
      "ko": "x86에서 아무 동작도 하지 않으며 'NOP 슬레드'에 쓰이는 1바이트 명령의 16진수 값은? (0x__ 의 두 자리)",
      "en": "What is the 1-byte hex opcode of the x86 instruction that does nothing and is used in a 'NOP sled'? (two hex digits)"
    },
    "hints": {
      "ko": [
        "NOP = No OPeration.",
        "쉘코드 앞에 0x__ 을 잔뜩 깝니다."
      ],
      "en": [
        "NOP = No OPeration.",
        "Padded before shellcode."
      ]
    }
  },
  {
    "id": "t1_nmap",
    "tier": 1,
    "cat": "network",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "5286b91aa11e48184da2c742f7f08492b8be0e02c01188b55b47d4be0e23fb18",
    "fmt": "명령어 / command",
    "title": {
      "ko": "포트 스캐너의 왕",
      "en": "King of Port Scanners"
    },
    "prompt": {
      "ko": "네트워크 정찰에서 열린 포트와 서비스를 찾는 사실상 표준 스캔 도구는? (명령어 이름)",
      "en": "What is the de-facto standard tool for scanning open ports/services in recon? (command name)"
    },
    "hints": {
      "ko": [
        "`____ -sV -p- target` 형태로 씁니다.",
        "Network Mapper."
      ],
      "en": [
        "Used like `____ -sV -p- target`.",
        "Network Mapper."
      ]
    }
  },
  {
    "id": "t2_wireshark",
    "tier": 2,
    "cat": "network",
    "track": "forensics",
    "points": 80,
    "ci": true,
    "hash": "28662759fcf7454b4388d4ff2798bf5c3c7dbe92090612b4214a411ea5d17cc8",
    "fmt": "도구명 / tool name",
    "title": {
      "ko": "패킷을 들여다보다",
      "en": "Look Inside Packets"
    },
    "prompt": {
      "ko": "네트워크 패킷을 캡처하고 분석하는 가장 대표적인 GUI 도구의 이름은?",
      "en": "Name the most iconic GUI tool for capturing and analyzing network packets."
    },
    "hints": {
      "ko": [
        "상어 지느러미 로고.",
        "CLI 버전은 tshark."
      ],
      "en": [
        "Shark-fin logo.",
        "Its CLI cousin is tshark."
      ]
    }
  },
  {
    "id": "t2_exif",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 90,
    "ci": true,
    "hash": "0747314e16d27a5ae07a3326e52544a2f5871891995fecb4492929c32ed2166d",
    "fmt": "명령어 / command",
    "title": {
      "ko": "사진 속 단서",
      "en": "Clues in the Photo"
    },
    "prompt": {
      "ko": "이미지의 촬영 시각·카메라·GPS 같은 메타데이터(EXIF)를 추출/편집하는 대표 도구는? (명령어 이름)",
      "en": "Which tool extracts/edits image metadata (EXIF) like timestamp, camera, GPS? (command name)"
    },
    "hints": {
      "ko": [
        "이름에 'exif'가 들어갑니다.",
        "`____ photo.jpg | grep GPS`"
      ],
      "en": [
        "Its name contains 'exif'.",
        "`____ photo.jpg | grep GPS`"
      ]
    }
  },
  {
    "id": "t3_virustotal",
    "tier": 3,
    "cat": "malware",
    "track": "forensics",
    "points": 110,
    "ci": true,
    "hash": "1051e9777bf787abf20a473ebff51e7416354624cf6071ad45127b069feb474f",
    "fmt": "서비스명 / service",
    "title": {
      "ko": "해시로 평판 조회",
      "en": "Reputation by Hash"
    },
    "prompt": {
      "ko": "파일 해시(또는 파일)를 업로드해 수십 개 백신 엔진의 탐지 결과를 한 번에 보여주는 구글 소유의 대표 웹 서비스는? (한 단어)",
      "en": "Which Google-owned web service shows detection results from dozens of AV engines for an uploaded hash/file? (one word)"
    },
    "hints": {
      "ko": [
        "주소: ____.com.",
        "'바이러스'와 '전체'의 합성어."
      ],
      "en": [
        "URL: ____.com.",
        "'virus' + 'total'."
      ]
    }
  },
  {
    "id": "t2_s3",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "41242b9fae56fad4e6e77dfe33cb18d1c3fc583f988cf25ef9f2d9be0d440bbb",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "공개된 버킷",
      "en": "The Public Bucket"
    },
    "prompt": {
      "ko": "잘못된 설정으로 데이터가 공개 노출되는 사고가 잦은, AWS의 객체 스토리지 서비스 이름은? (약자)",
      "en": "Which AWS object storage service is frequently exposed publicly via misconfiguration? (abbreviation)"
    },
    "hints": {
      "ko": [
        "Simple Storage Service.",
        "버킷(bucket) 단위로 저장."
      ],
      "en": [
        "Simple Storage Service.",
        "Stored in 'buckets'."
      ]
    }
  },
  {
    "id": "t2_pod",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "425c89ed5bb78a7623fae60fd8a6f648488168740fe82cf6ad34caa4d07aa972",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "쿠버네티스의 최소 단위",
      "en": "K8s Smallest Unit"
    },
    "prompt": {
      "ko": "쿠버네티스에서 하나 이상의 컨테이너를 묶어 배포하는 최소 실행 단위의 이름은?",
      "en": "In Kubernetes, what is the smallest deployable unit that groups one or more containers?"
    },
    "hints": {
      "ko": [
        "고래 떼(pod)에서 따온 이름.",
        "`kubectl get ____`"
      ],
      "en": [
        "Named after a pod of whales.",
        "`kubectl get ____`"
      ]
    }
  },
  {
    "id": "t2_jailbreak",
    "tier": 2,
    "cat": "ai",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "bd168d2f02fe220eb62f5bf0e285b846f9f568af9abb99d578776cb7e9488c70",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "가드레일 우회",
      "en": "Bypassing Guardrails"
    },
    "prompt": {
      "ko": "LLM의 안전 정책을 우회해 거부되어야 할 출력을 끌어내는 기법을 통칭하는 영어 단어는? (한 단어)",
      "en": "What single English word collectively names techniques that bypass an LLM's safety policy to elicit forbidden output?"
    },
    "hints": {
      "ko": [
        "탈옥(脫獄)을 뜻하는 영어.",
        "DAN 프롬프트가 대표적."
      ],
      "en": [
        "English for 'escaping jail'.",
        "The DAN prompt is a classic example."
      ]
    }
  },
  {
    "id": "t3_imds",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": false,
    "hash": "34146ce1ba492ed7acf9a9925a04541645c203d9652183c6e238f55786c8b66f",
    "fmt": "IP 주소 / IP",
    "title": {
      "ko": "메타데이터의 IP",
      "en": "The Metadata IP"
    },
    "prompt": {
      "ko": "SSRF로 클라우드 인스턴스의 임시 자격증명을 탈취할 때 노리는, 모든 주요 클라우드의 메타데이터 서비스 링크-로컬 IP 주소는?",
      "en": "Which link-local IP address (the metadata service across major clouds) do attackers target via SSRF to steal instance credentials?"
    },
    "hints": {
      "ko": [
        "169.254.x.x 대역(링크-로컬).",
        "끝이 .169.254 로 끝납니다."
      ],
      "en": [
        "169.254.x.x (link-local) range.",
        "Ends with .169.254."
      ]
    }
  },
  {
    "id": "t0_reverse",
    "tier": 0,
    "cat": "crypto",
    "track": "crypto",
    "points": 50,
    "ci": false,
    "hash": "61c05ea1dabd40b8b5429da703790e3deedc8252d8e88471d9dd014b3d04c21d",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "거꾸로 읽기",
      "en": "Read it backwards"
    },
    "prompt": {
      "ko": "문자열을 통째로 뒤집으면 플래그가 됩니다:\n\n`}gnirts_eht_esrever{GALF`",
      "en": "Reverse the whole string to get the flag:\n\n`}gnirts_eht_esrever{GALF`"
    },
    "hints": {
      "ko": [
        "끝에서부터 한 글자씩 읽어 보세요.",
        "JS 콘솔: `\"...\".split(\"\").reverse().join(\"\")`"
      ],
      "en": [
        "Read it from the end.",
        "JS console: `\"...\".split(\"\").reverse().join(\"\")`"
      ]
    }
  },
  {
    "id": "t0_decimal",
    "tier": 0,
    "cat": "crypto",
    "track": "crypto",
    "points": 50,
    "ci": true,
    "hash": "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b",
    "fmt": "단어 / word",
    "title": {
      "ko": "ASCII 십진수",
      "en": "ASCII decimal"
    },
    "prompt": {
      "ko": "각 숫자는 한 글자의 ASCII 코드입니다. 디코딩하세요:\n\n`115 101 99 114 101 116`",
      "en": "Each number is one character's ASCII code. Decode it:\n\n`115 101 99 114 101 116`"
    },
    "hints": {
      "ko": [
        "115 = 0x73 = 's'.",
        "공백으로 나뉜 십진수를 문자로."
      ],
      "en": [
        "115 = 0x73 = 's'.",
        "Space-separated decimals → chars."
      ]
    }
  },
  {
    "id": "t0_urlenc",
    "tier": 0,
    "cat": "web",
    "track": "web",
    "points": 50,
    "ci": false,
    "hash": "2d8175b670d102d981337025ba9f81d95a880e2131967907715dd5d18197338f",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "퍼센트 인코딩",
      "en": "Percent-encoding"
    },
    "prompt": {
      "ko": "URL 디코딩하면 플래그입니다:\n\n`%46%4C%41%47%7B%75%72%6C%5F%65%6E%63%6F%64%65%64%7D`",
      "en": "URL-decode to reveal the flag:\n\n`%46%4C%41%47%7B%75%72%6C%5F%65%6E%63%6F%64%65%64%7D`"
    },
    "hints": {
      "ko": [
        "`%46` = 'F' 입니다.",
        "JS 콘솔: `decodeURIComponent(\"...\")`"
      ],
      "en": [
        "`%46` = 'F'.",
        "JS console: `decodeURIComponent(\"...\")`"
      ]
    }
  },
  {
    "id": "t0_meta",
    "tier": 0,
    "cat": "web",
    "track": "web",
    "points": 40,
    "ci": false,
    "hash": "b36d9b661bac670467701a72f7c0c77fb9a965dcc6cf2bad0b73c456c4fa3728",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "숨은 메타 태그",
      "en": "The hidden meta tag"
    },
    "prompt": {
      "ko": "HTML `<meta>` 태그 중 `name` 이 `ctf-flag` 인 것의 `content` 값을 찾으세요. (소스 보기 또는 개발자도구)",
      "en": "Find the `content` of the `<meta>` tag whose `name` is `ctf-flag`. (View Source or DevTools)"
    },
    "hints": {
      "ko": [
        "`Ctrl+U` 로 소스를 열고 `meta` 를 검색.",
        "`<meta name=\"ctf-flag\" content=\"...\">`"
      ],
      "en": [
        "Open source with `Ctrl+U`, search `meta`.",
        "`<meta name=\"ctf-flag\" content=\"...\">`"
      ]
    }
  },
  {
    "id": "t0_nato",
    "tier": 0,
    "cat": "crypto",
    "track": "crypto",
    "points": 40,
    "ci": true,
    "hash": "807d0fbcae7c4b20518d4d85664f6820aafdf936104122c5073e7744c46c4b87",
    "fmt": "단어 / word",
    "title": {
      "ko": "NATO 음성 알파벳",
      "en": "NATO phonetic alphabet"
    },
    "prompt": {
      "ko": "각 단어의 첫 글자를 모으세요:\n\n`Foxtrot Lima Alpha Golf`",
      "en": "Take the first letter of each word:\n\n`Foxtrot Lima Alpha Golf`"
    },
    "hints": {
      "ko": [
        "Foxtrot=F, Lima=L ...",
        "네 글자 단어입니다."
      ],
      "en": [
        "Foxtrot=F, Lima=L ...",
        "It is a four-letter word."
      ]
    }
  },
  {
    "id": "t1_atbash",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
    "points": 70,
    "ci": false,
    "hash": "3607df71397b068e947b788bdf856c24556e861917a3de1c065320d9e7975087",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "아트바시 암호",
      "en": "Atbash cipher"
    },
    "prompt": {
      "ko": "알파벳을 거울처럼 뒤집은(A↔Z, B↔Y) 암호입니다. 복호화하세요:\n\n`UOZT{zgyzhs_nriili}`",
      "en": "The alphabet is mirrored (A↔Z, B↔Y). Decrypt:\n\n`UOZT{zgyzhs_nriili}`"
    },
    "hints": {
      "ko": [
        "아트바시는 자기역원 — 한 번 더 적용.",
        "a→z, b→y, c→x ..."
      ],
      "en": [
        "Atbash is its own inverse — apply again.",
        "a→z, b→y, c→x ..."
      ]
    }
  },
  {
    "id": "t1_a1z26",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
    "points": 60,
    "ci": true,
    "hash": "051375546db9782e3debc25e0241edf1d5e5e2ec0f183dd8634ca5b2c8968bb8",
    "fmt": "단어 / word",
    "title": {
      "ko": "A1Z26 암호",
      "en": "A1Z26 cipher"
    },
    "prompt": {
      "ko": "a=1, b=2 … z=26 입니다. 숫자를 글자로:\n\n`8-1-3-11`",
      "en": "a=1, b=2 … z=26. Convert numbers to letters:\n\n`8-1-3-11`"
    },
    "hints": {
      "ko": [
        "8=h, 1=a ...",
        "하이픈으로 글자가 구분됩니다."
      ],
      "en": [
        "8=h, 1=a ...",
        "Hyphens separate letters."
      ]
    }
  },
  {
    "id": "t1_basicauth",
    "tier": 1,
    "cat": "web",
    "track": "web",
    "points": 60,
    "ci": true,
    "hash": "371a286d5872a3730d644327581546ec3e658bbf1a3c7f7f0de2bc19905d4402",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "Basic 인증의 인코딩",
      "en": "Basic auth encoding"
    },
    "prompt": {
      "ko": "HTTP Basic 인증은 `사용자:비밀번호` 를 어떤 인코딩으로 변환해 `Authorization` 헤더에 담나요? (암호화가 아닙니다, 한 단어)",
      "en": "HTTP Basic auth puts `user:password` into the `Authorization` header using which encoding? (not encryption — one word)"
    },
    "hints": {
      "ko": [
        "= 로 끝나곤 합니다.",
        "`Authorization: Basic <____>`"
      ],
      "en": [
        "Often ends with =.",
        "`Authorization: Basic <____>`"
      ]
    }
  },
  {
    "id": "t1_redirect",
    "tier": 1,
    "cat": "web",
    "track": "web",
    "points": 60,
    "ci": true,
    "hash": "c3ea99f86b2f8a74ef4145bb245155ff5f91cd856f287523481c15a1959d5fd1",
    "fmt": "숫자 / number",
    "title": {
      "ko": "영구 리다이렉트 코드",
      "en": "Permanent redirect code"
    },
    "prompt": {
      "ko": "자원이 영구적으로 다른 URL로 옮겨졌음을 의미하는 HTTP 상태 코드는? (숫자)",
      "en": "Which HTTP status code means a resource has permanently moved to a new URL? (number)"
    },
    "hints": {
      "ko": [
        "임시 이동은 302입니다.",
        "3 으로 시작하는 세 자리."
      ],
      "en": [
        "Temporary move is 302.",
        "Three digits starting with 3."
      ]
    }
  },
  {
    "id": "t1_creds",
    "tier": 1,
    "cat": "web",
    "track": "web",
    "points": 70,
    "ci": true,
    "hash": "854f23f151c958aefead79d83a8078f145f906f9e769dd6face8989040b162d5",
    "fmt": "사용자:비밀번호 / user:pass",
    "title": {
      "ko": "가로챈 자격증명",
      "en": "Intercepted credentials"
    },
    "prompt": {
      "ko": "`Authorization: Basic YWRtaW46czNjcjN0` 헤더를 보았습니다. 디코딩하면 자격증명은?",
      "en": "You saw `Authorization: Basic YWRtaW46czNjcjN0`. Decode it — what are the credentials?"
    },
    "hints": {
      "ko": [
        "Base64 디코드: `atob(\"...\")`.",
        "형식은 `사용자:비밀번호`."
      ],
      "en": [
        "Base64-decode: `atob(\"...\")`.",
        "Format is `user:password`."
      ]
    }
  },
  {
    "id": "t2_vigenere",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 100,
    "ci": false,
    "hash": "5f1e51f0d5c864d1933e7dbf22a4d729f015606fdfc72da81a2d718b463898d0",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "비제네르 암호",
      "en": "Vigenère cipher"
    },
    "prompt": {
      "ko": "키 `KEY` 로 암호화된 비제네르 암호문입니다. 복호화하세요:\n\n`PPYQ{zgqilovc_uiwoh_astfov}`",
      "en": "Vigenère ciphertext encrypted with key `KEY`. Decrypt:\n\n`PPYQ{zgqilovc_uiwoh_astfov}`"
    },
    "hints": {
      "ko": [
        "키를 반복해 글자별로 빼세요(비-알파벳은 건너뜀).",
        "CyberChef 'Vigenère Decode', key=KEY."
      ],
      "en": [
        "Subtract the repeating key per letter (skip non-letters).",
        "CyberChef 'Vigenère Decode', key=KEY."
      ]
    }
  },
  {
    "id": "t2_base58",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 100,
    "ci": false,
    "hash": "0bad4078aae00b415bada62c82f1b4c2e5458232ddcd30f555f08d76893f0f48",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "Base58 인코딩",
      "en": "Base58 encoding"
    },
    "prompt": {
      "ko": "비트코인 주소에 쓰이는 Base58(헷갈리는 0,O,I,l 제외)입니다. 디코딩하세요:\n\n`39rKM3yGEZE4C6b8Tfo1WqhwgtVkrqSu4kex`",
      "en": "Base58 as used by Bitcoin addresses (no 0,O,I,l). Decode:\n\n`39rKM3yGEZE4C6b8Tfo1WqhwgtVkrqSu4kex`"
    },
    "hints": {
      "ko": [
        "Base64 와 다른 문자셋입니다.",
        "CyberChef 'From Base58'."
      ],
      "en": [
        "Different alphabet from Base64.",
        "CyberChef 'From Base58'."
      ]
    }
  },
  {
    "id": "t2_unicode",
    "tier": 2,
    "cat": "web",
    "track": "web",
    "points": 90,
    "ci": false,
    "hash": "84df3ede1622103b20713a96f08f338b13d12913889438227c1cda314505bfff",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "유니코드 이스케이프",
      "en": "Unicode escapes"
    },
    "prompt": {
      "ko": "자바스크립트 유니코드 이스케이프 시퀀스입니다. 디코딩하세요:\n\n`\\u0046\\u004c\\u0041\\u0047\\u007b\\u0075\\u006e\\u0069\\u0063\\u006f\\u0064\\u0065\\u005f\\u0065\\u0073\\u0063\\u0061\\u0070\\u0065\\u005f\\u0073\\u0065\\u0071\\u007d`",
      "en": "JavaScript Unicode escape sequences. Decode:\n\n`\\u0046\\u004c\\u0041\\u0047\\u007b\\u0075\\u006e\\u0069\\u0063\\u006f\\u0064\\u0065\\u005f\\u0065\\u0073\\u0063\\u0061\\u0070\\u0065\\u005f\\u0073\\u0065\\u0071\\u007d`"
    },
    "hints": {
      "ko": [
        "`\\u0046` = 'F' 입니다.",
        "JS 콘솔: 따옴표로 감싸 출력해 보세요."
      ],
      "en": [
        "`\\u0046` = 'F'.",
        "JS console: wrap in quotes and print."
      ]
    }
  },
  {
    "id": "t2_sqlcomment",
    "tier": 2,
    "cat": "web",
    "track": "web",
    "points": 80,
    "ci": true,
    "hash": "d8156bae0c4243d3742fc4e9774d8aceabe0410249d720c855f98afc88ff846c",
    "fmt": "기호 / symbol",
    "title": {
      "ko": "SQL 한 줄 주석",
      "en": "SQL line comment"
    },
    "prompt": {
      "ko": "SQL 인젝션에서 쿼리의 나머지 부분을 주석 처리해 무력화할 때 쓰는, 한 줄 주석을 시작하는 두 글자 기호는? (MySQL/표준)",
      "en": "In SQL injection, which two-character sequence starts a line comment to neutralize the rest of the query? (standard SQL)"
    },
    "hints": {
      "ko": [
        "하이픈 두 개.",
        "`' OR 1=1 __`"
      ],
      "en": [
        "Two hyphens.",
        "`' OR 1=1 __`"
      ]
    }
  },
  {
    "id": "t2_idor",
    "tier": 2,
    "cat": "web",
    "track": "web",
    "points": 80,
    "ci": true,
    "hash": "0b5a52cdc4f5481343077f16476c5afde78732e28c9c5eafbf7f9a9a54a0540d",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "직접 객체 참조 취약점",
      "en": "Insecure direct object reference"
    },
    "prompt": {
      "ko": "권한 검증 없이 `?id=123` 같은 식별자만 바꿔 남의 자원에 접근하는 취약점의 약자(4글자)는?",
      "en": "What 4-letter abbreviation names the bug where changing an identifier like `?id=123` accesses another user's resource without authorization?"
    },
    "hints": {
      "ko": [
        "Insecure Direct Object Reference.",
        "OWASP 접근통제 항목."
      ],
      "en": [
        "Insecure Direct Object Reference.",
        "An OWASP access-control issue."
      ]
    }
  },
  {
    "id": "t3_xormulti",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 130,
    "ci": false,
    "hash": "4d7f3a95a516778bbf022e50f43434bc1fbb2087fa72b7f8590bb81ac4b897bf",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "반복 키 XOR",
      "en": "Repeating-key XOR"
    },
    "prompt": {
      "ko": "반복 키 `key` 로 XOR된 16진 바이트열입니다. 복호화하세요:\n\n`2d29382c1e0b0e151c0a1110050226000000341d161918`",
      "en": "Hex bytes XORed with the repeating key `key`. Decrypt:\n\n`2d29382c1e0b0e151c0a1110050226000000341d161918`"
    },
    "hints": {
      "ko": [
        "키가 3바이트라 3바이트마다 반복됩니다.",
        "`bytes[i] ^ \"key\"[i % 3]`"
      ],
      "en": [
        "Key is 3 bytes, repeats every 3.",
        "`bytes[i] ^ \"key\"[i % 3]`"
      ]
    }
  },
  {
    "id": "t3_base85",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 130,
    "ci": false,
    "hash": "35c414948080bf4d04c3531bc1407b234e87910ee4aff2f74d21f4998f252d8a",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "ASCII85 (Base85)",
      "en": "ASCII85 (Base85)"
    },
    "prompt": {
      "ko": "Base85(ASCII85, Adobe 방식, 구분자 없음)로 인코딩됐습니다. 디코딩하세요:\n\n`7SH*<HXUu*Bk]Oa?X[_Y?XdGbAN2Pq`",
      "en": "Encoded with Base85 (ASCII85, Adobe variant, no delimiters). Decode:\n\n`7SH*<HXUu*Bk]Oa?X[_Y?XdGbAN2Pq`"
    },
    "hints": {
      "ko": [
        "Base64보다 조밀합니다(4바이트→5문자).",
        "CyberChef 'From Base85' (alphabet !-u)."
      ],
      "en": [
        "Denser than Base64 (4 bytes→5 chars).",
        "CyberChef 'From Base85' (alphabet !-u)."
      ]
    }
  },
  {
    "id": "t3_elfmagic",
    "tier": 3,
    "cat": "forensics",
    "track": "forensics",
    "points": 110,
    "ci": true,
    "hash": "8f328025f36e3709031daf47458e790a90af6c3a75e7b3b9883b7192ed56d987",
    "fmt": "16진수 / hex",
    "title": {
      "ko": "ELF 매직 넘버",
      "en": "ELF magic number"
    },
    "prompt": {
      "ko": "리눅스 ELF 실행 파일의 첫 4바이트(매직 넘버)를 16진수로 입력하세요. (공백 없이, 소문자)",
      "en": "Enter the first 4 bytes (magic number) of a Linux ELF executable in hex. (no spaces, lowercase)"
    },
    "hints": {
      "ko": [
        "두 번째 바이트부터는 ASCII 'ELF'.",
        "`7f` 다음 `45 4c 46`."
      ],
      "en": [
        "Bytes 2-4 are ASCII 'ELF'.",
        "`7f` then `45 4c 46`."
      ]
    }
  },
  {
    "id": "t3_hmac",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 110,
    "ci": true,
    "hash": "f9ccd92bb6af4cb45e43113867e61dab39a4e7a2a0a88980a940250637773199",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "키 기반 메시지 인증",
      "en": "Keyed message authentication"
    },
    "prompt": {
      "ko": "JWT의 `HS256` 서명에 쓰이는, 해시 함수와 비밀 키를 결합한 메시지 인증 코드의 약자(4글자)는?",
      "en": "What 4-letter abbreviation is the keyed-hash message authentication code used by JWT `HS256`?"
    },
    "hints": {
      "ko": [
        "Hash-based Message Authentication Code.",
        "`____-SHA256`"
      ],
      "en": [
        "Hash-based Message Authentication Code.",
        "`____-SHA256`"
      ]
    }
  },
  {
    "id": "t3_jwtdecode",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 120,
    "ci": false,
    "hash": "41b3f5ba65ff6e30608a08ee8b353cad57562fbe7ed41486e72b6ad74e8381bd",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "JWT는 암호화가 아니다",
      "en": "JWT is not encryption"
    },
    "prompt": {
      "ko": "JWT의 payload는 Base64URL로 인코딩될 뿐 암호화가 아닙니다. 다음 payload를 디코딩해 `flag` 값을 찾으세요:\n\n`eyJmbGFnIjoiRkxBR3tqd3RfcGF5bG9hZF9pc19ub3RfZW5jcnlwdGVkfSJ9`",
      "en": "A JWT payload is only Base64URL-encoded, not encrypted. Decode this payload and read the `flag` value:\n\n`eyJmbGFnIjoiRkxBR3tqd3RfcGF5bG9hZF9pc19ub3RfZW5jcnlwdGVkfSJ9`"
    },
    "hints": {
      "ko": [
        "Base64URL 디코드 → JSON.",
        "`atob` 전에 `-`→`+`, `_`→`/` 치환."
      ],
      "en": [
        "Base64URL-decode → JSON.",
        "Before `atob`, swap `-`→`+`, `_`→`/`."
      ]
    }
  },
  {
    "id": "t4_triple",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 190,
    "ci": false,
    "hash": "d8f1ab639e9c7877747b5825382feaed6b51ea3c0d5f81a90d9ccb0c3b984bcd",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "3중 인코딩",
      "en": "Triple encoding"
    },
    "prompt": {
      "ko": "ROT13 → Base64 → Hex 순서로 풀면 플래그가 나옵니다:\n\n`AQL0LmDkAQp3Lwp0Awt3ZwL1AwH1MwMwAwR3BGL1AmV3ZmIzAwD2AGL1AmN3MN==`",
      "en": "Undo in order ROT13 → Base64 → Hex to get the flag:\n\n`AQL0LmDkAQp3Lwp0Awt3ZwL1AwH1MwMwAwR3BGL1AmV3ZmIzAwD2AGL1AmN3MN==`"
    },
    "hints": {
      "ko": [
        "1) ROT13 해제 → Base64 문자열.",
        "2) Base64 디코드 → 16진 문자열 → Hex 디코드."
      ],
      "en": [
        "1) Undo ROT13 → a Base64 string.",
        "2) Base64-decode → a hex string → hex-decode."
      ]
    }
  },
  {
    "id": "t4_vigenere",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 170,
    "ci": false,
    "hash": "cf7605469817d11a1dc936926136f51e1852fe1c98b6d5ad6779215ea8af56a1",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "비제네르 — 금고 열쇠",
      "en": "Vigenère — the vault key"
    },
    "prompt": {
      "ko": "키 `VAULT` 로 암호화된 비제네르 암호문입니다. 복호화하세요:\n\n`ALUR{mce_plngt_cd_hkeh}`",
      "en": "Vigenère ciphertext encrypted with key `VAULT`. Decrypt:\n\n`ALUR{mce_plngt_cd_hkeh}`"
    },
    "hints": {
      "ko": [
        "키가 더 길어졌을 뿐, 방식은 같습니다.",
        "key=VAULT 로 Vigenère 복호화."
      ],
      "en": [
        "Longer key, same method.",
        "Vigenère-decode with key=VAULT."
      ]
    }
  },
  {
    "id": "t4_xorcore",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 160,
    "ci": false,
    "hash": "4fe235bfac29a6809e5f013f34afd71c3ae29d879ed3da3806f3b8a93064023b",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "코어 키 XOR",
      "en": "Core-key XOR"
    },
    "prompt": {
      "ko": "반복 키 `core` 로 XOR된 16진 바이트열입니다. 복호화하세요:\n\n`2523332218171d173c181b110b30110a110a2d0e06160f`",
      "en": "Hex bytes XORed with the repeating key `core`. Decrypt:\n\n`2523332218171d173c181b110b30110a110a2d0e06160f`"
    },
    "hints": {
      "ko": [
        "4바이트 키가 반복됩니다.",
        "`bytes[i] ^ \"core\"[i % 4]`"
      ],
      "en": [
        "A 4-byte key repeats.",
        "`bytes[i] ^ \"core\"[i % 4]`"
      ]
    }
  },
  {
    "id": "t4_k8ssecret",
    "tier": 4,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": false,
    "hash": "05863231fff72c94d36adaa599b06f72c398e574a753c53f5ff1d79d770fe214",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "쿠버네티스 Secret",
      "en": "Kubernetes Secret"
    },
    "prompt": {
      "ko": "쿠버네티스 Secret의 `data` 값은 암호화가 아니라 Base64일 뿐입니다. 다음 값을 디코딩하세요:\n\n`RkxBR3trOHNfc2VjcmV0X29ubHlfYmFzZTY0fQ==`",
      "en": "A Kubernetes Secret `data` value is only Base64, not encrypted. Decode this value:\n\n`RkxBR3trOHNfc2VjcmV0X29ubHlfYmFzZTY0fQ==`"
    },
    "hints": {
      "ko": [
        "`kubectl get secret -o yaml` 로 보이는 그 값.",
        "Base64 디코드 한 번."
      ],
      "en": [
        "The value you see in `kubectl get secret -o yaml`.",
        "One Base64 decode."
      ]
    }
  },
  {
    "id": "t4_doubleb64",
    "tier": 4,
    "cat": "crypto",
    "track": "crypto",
    "points": 140,
    "ci": false,
    "hash": "ef2e0a4e4f05b322720c231e530590f86bbc349b6ff5d4651ff1c32cbf7bb360",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "이중 Base64",
      "en": "Double Base64"
    },
    "prompt": {
      "ko": "Base64로 두 번 감쌌습니다. 두 번 디코딩하세요:\n\n`Umt4QlIzdGtiM1ZpYkdWZlltRnpaVFkwWDNkeVlYQjk=`",
      "en": "Wrapped in Base64 twice. Decode twice:\n\n`Umt4QlIzdGtiM1ZpYkdWZlltRnpaVFkwWDNkeVlYQjk=`"
    },
    "hints": {
      "ko": [
        "디코드 결과가 또 Base64처럼 보입니다.",
        "`atob(atob(\"...\"))`"
      ],
      "en": [
        "The first decode looks like Base64 again.",
        "`atob(atob(\"...\"))`"
      ]
    }
  },
  {
    "id": "t0_md5",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 40,
    "ci": true,
    "hash": "3ebff31b62c0637c54d4ffa990d5c100ea359994b35f4b342ff49797542148cd",
    "fmt": "알고리즘명 / algorithm",
    "title": {
      "ko": "파일의 지문",
      "en": "The File's Fingerprint"
    },
    "prompt": {
      "ko": "증거 원본과 사본이 동일함을 증명하기 위해 파일의 '지문'을 계산하는 데 쓰이는, 128비트(32자 16진수) 값을 만드는 대표적인 (오늘날 충돌 공격에 취약하다고 알려진) 해시 알고리즘은?",
      "en": "Which classic hash algorithm (now known to be vulnerable to collision attacks), producing a 128-bit / 32-hex-digit value, is used to prove a forensic copy matches the original?"
    },
    "hints": {
      "ko": [
        "Message Digest 의 약자.",
        "결과값이 128비트(32자 16진수)."
      ],
      "en": [
        "Stands for Message Digest.",
        "128-bit output = 32 hex chars."
      ]
    }
  },
  {
    "id": "t0_hexdump",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 50,
    "ci": true,
    "hash": "b2d7da50ce9ad432c1ac5febf709d834a84db529b7acf0fa69d7d3f8ae6b7e81",
    "fmt": "명령어 / command",
    "title": {
      "ko": "바이트를 있는 그대로",
      "en": "Bytes As They Are"
    },
    "prompt": {
      "ko": "파일의 원본 바이트를 16진수와 ASCII를 나란히 보여주는 형태로 덤프하는 리눅스 명령어는? (`-C` 옵션으로 정규 형식 출력, 세 글자)",
      "en": "Which three-letter Linux command dumps a file's raw bytes as hex next to ASCII (canonical format with `-C`)?"
    },
    "hints": {
      "ko": [
        "vim 에도 내장되어 있는 도구입니다.",
        "`___ -C file | less`"
      ],
      "en": [
        "Also bundled with vim.",
        "`___ -C file | less`"
      ]
    }
  },
  {
    "id": "t4_prefetch",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 150,
    "ci": true,
    "hash": "4653c580b63bba1b5cd175c99bd2f3dbc73ec41694bc304be2e41e1f05bb81cd",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "실행의 흔적",
      "en": "Trace of Execution"
    },
    "prompt": {
      "ko": "Windows에서 프로그램의 실행 횟수·마지막 실행 시각·로드된 DLL 목록을 담아 `.pf` 파일로 저장되어, 악성코드 실행 흔적 조사의 핵심 아티팩트가 되는 기능의 이름은? (한 단어)",
      "en": "Which Windows feature stores `.pf` files recording a program's run count, last-run time, and loaded DLLs — a key artifact for proving malware execution?"
    },
    "hints": {
      "ko": [
        "`C:\\Windows\\Prefetch\\` 경로에 저장됩니다.",
        "파일명 예: NOTEPAD.EXE-1234ABCD.pf"
      ],
      "en": [
        "Stored under `C:\\Windows\\Prefetch\\`.",
        "Filenames look like NOTEPAD.EXE-1234ABCD.pf."
      ]
    }
  },
  {
    "id": "t4_volatility",
    "tier": 4,
    "cat": "malware",
    "track": "forensics",
    "points": 160,
    "ci": false,
    "hash": "b6166140437944900b8b211e213905931ce1c8ed0ace53320b40c17d4a721da1",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "메모리 속 단서",
      "en": "Clue in Memory"
    },
    "prompt": {
      "ko": "메모리 덤프를 분석하는 대표 오픈소스 프레임워크로 `strings`와 플러그인을 이용해 프로세스 목록·네트워크 연결을 복구하던 중, 수상한 Base64 문자열을 찾았습니다. 디코딩하세요:\n\n`RkxBR3ttZW1vcnlfZm9yZW5zaWNzX3dpbnN9`",
      "en": "While recovering process lists and network connections from a memory dump with the standard open-source memory forensics framework, you find a suspicious Base64 string. Decode it:\n\n`RkxBR3ttZW1vcnlfZm9yZW5zaWNzX3dpbnN9`"
    },
    "hints": {
      "ko": [
        "그 프레임워크의 이름은 'Volatility' 입니다(힌트일 뿐, 답 아님).",
        "`echo '...' | base64 -d` 또는 `atob('...')`"
      ],
      "en": [
        "The framework is called 'Volatility' (that's just a hint, not the answer).",
        "`echo '...' | base64 -d` or `atob('...')`"
      ]
    }
  },
  {
    "id": "t0_iam",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 40,
    "ci": true,
    "hash": "d457e3a99392a03f47057f50ac1cbc5d0365131575477971bf85177a0c0fed22",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "누가 무엇을 할 수 있는가",
      "en": "Who Can Do What"
    },
    "prompt": {
      "ko": "AWS·Azure·GCP 등 클라우드에서 사용자·역할(Role)·정책(Policy)을 통해 '누가 무엇을 할 수 있는지'를 관리하는 서비스의 공통 약자는?",
      "en": "What abbreviation names the cloud service (common across AWS/Azure/GCP) that manages users, roles, and policies to control 'who can do what'?"
    },
    "hints": {
      "ko": [
        "Identity and Access Management 의 약자.",
        "세 글자."
      ],
      "en": [
        "Abbreviation for Identity and Access Management.",
        "Three letters."
      ]
    }
  },
  {
    "id": "t0_vpc",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 50,
    "ci": true,
    "hash": "38faba71b3a6cfc9e5f93fe6a17abe770093ba938baa488aa016fca907eadcaa",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "나만의 가상 네트워크",
      "en": "My Own Virtual Network"
    },
    "prompt": {
      "ko": "클라우드에서 논리적으로 격리된, 서브넷·라우팅테이블·보안그룹을 담는 나만의 가상 네트워크를 부르는 AWS 용어의 약자는?",
      "en": "What abbreviation names the logically isolated virtual network (containing subnets, route tables, security groups) an AWS account gets?"
    },
    "hints": {
      "ko": [
        "Virtual Private Cloud 의 약자.",
        "세 글자."
      ],
      "en": [
        "Abbreviation for Virtual Private Cloud.",
        "Three letters."
      ]
    }
  },
  {
    "id": "t1_arn",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 60,
    "ci": true,
    "hash": "42e7ab5b52beca9d20fbc05fa6b72c0a48755ada50d340472ab6f1832cbf42ac",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "리소스의 고유 이름표",
      "en": "The Resource's Unique Tag"
    },
    "prompt": {
      "ko": "AWS에서 모든 리소스(사용자·버킷·함수 등)를 `arn:aws:서비스:리전:계정ID:리소스` 형태로 고유하게 식별하는 문자열 형식의 약자는?",
      "en": "What abbreviation names the string format (`arn:aws:service:region:account-id:resource`) that uniquely identifies every AWS resource?"
    },
    "hints": {
      "ko": [
        "Amazon Resource Name 의 약자.",
        "세 글자."
      ],
      "en": [
        "Abbreviation for Amazon Resource Name.",
        "Three letters."
      ]
    }
  },
  {
    "id": "t1_snapshot",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 65,
    "ci": true,
    "hash": "16a0eeb0791b6c92451fd284dd9f599e0a7dbe7f6ebea6e2d2d06c7f74aec112",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "그 순간을 저장하다",
      "en": "Freeze That Moment"
    },
    "prompt": {
      "ko": "클라우드 스토리지/볼륨(EBS 등)의 특정 시점 상태를 통째로 백업해두는 기능을 부르는, 명사로도 동사로도 쓰이는 한 단어는?",
      "en": "What single word (used as both noun and verb) names a point-in-time backup of a cloud volume like EBS?"
    },
    "hints": {
      "ko": [
        "사진 찍듯 그 순간을 '찰칵' 저장합니다.",
        "카메라 관련 단어에서 유래."
      ],
      "en": [
        "Captures a moment like a photo.",
        "Borrowed from camera terminology."
      ]
    }
  },
  {
    "id": "t4_aslr",
    "tier": 4,
    "cat": "pwn",
    "track": "system",
    "points": 140,
    "ci": true,
    "hash": "738ab575cf55699b4b9eb6ef605a20282cf7363f4cf086867bd42da96ec22498",
    "fmt": "약자 / abbreviation",
    "title": {
      "ko": "매번 바뀌는 주소",
      "en": "The Address Keeps Moving"
    },
    "prompt": {
      "ko": "스택·힙·라이브러리의 메모리 주소를 매 실행마다 무작위화해 익스플로잇의 주소 하드코딩을 어렵게 만드는 OS 보호 기법의 약자는?",
      "en": "What abbreviation names the OS protection that randomizes stack/heap/library addresses on every run, defeating hardcoded exploit addresses?"
    },
    "hints": {
      "ko": [
        "Address Space Layout Randomization 의 약자.",
        "`/proc/sys/kernel/randomize_va_space` 로 리눅스에서 제어합니다."
      ],
      "en": [
        "Abbreviation for Address Space Layout Randomization.",
        "Controlled via `/proc/sys/kernel/randomize_va_space` on Linux."
      ]
    }
  },
  {
    "id": "t4_canary",
    "tier": 4,
    "cat": "pwn",
    "track": "system",
    "points": 150,
    "ci": true,
    "hash": "e100fbce008c04ec40637af0af91fb2f05aeedc23f856a2d3c0b1580625d755e",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "탄광 속의 그 새",
      "en": "The Bird in the Mine"
    },
    "prompt": {
      "ko": "함수 리턴 직전 스택에 심어둔 무작위 값이 변조되었는지 검사해 스택 버퍼 오버플로우를 탐지하는 보호 기법을, 탄광에서 유독가스를 미리 감지하던 새의 이름을 따서 부르는 한 단어는?",
      "en": "Which stack buffer overflow protection (checking a random value planted before return for tampering) is named after the bird once used to detect toxic gas in mines?"
    },
    "hints": {
      "ko": [
        "GCC의 `-fstack-protector` 가 이 값을 심습니다.",
        "'탄광 속 카나리아'라는 관용구에서 유래."
      ],
      "en": [
        "GCC's `-fstack-protector` inserts this value.",
        "From the idiom 'canary in a coal mine'."
      ]
    }
  }
];
