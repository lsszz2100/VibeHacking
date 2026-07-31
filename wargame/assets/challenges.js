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
,
  {
    "id": "ai",
    "icon": "🤖",
    "ko": "AI·LLM 보안",
    "en": "AI & LLM Security",
    "desc_ko": "프롬프트 인젝션·적대적 예제·모델 복제·도구 호출 권한.",
    "desc_en": "Prompt injection, adversarial examples, model copying, tool-calling privilege."
  },
  {
    "id": "network",
    "icon": "🛰️",
    "ko": "네트워크·프로토콜",
    "en": "Network & Protocols",
    "desc_ko": "TCP/IP·DNS·TLS·무선·라우팅과 그 위에서 벌어지는 공격과 방어.",
    "desc_en": "TCP/IP, DNS, TLS, wireless and routing — and the attacks and defenses on top of them."
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
    "fmt": "한 단어 / one word",
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
        "브라우저 콘솔에서 두 자리씩 잘라 `parseInt(b, 16)` 로 파싱해 보세요."
      ],
      "en": [
        "Every two digits is one byte.",
        "In the console, slice it two digits at a time and `parseInt(b, 16)`."
      ]
    }
  },
  {
    "id": "t1_railfence",
    "tier": 1,
    "cat": "crypto",
    "track": "crypto",
    "points": 70,
    "ci": true,
    "hash": "b6396bef6dbcaa4651dc4241ae88196d1e00dbd4a29cb8aad49c2941541fae4e",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "지그재그 울타리",
      "en": "The Zig-Zag Fence"
    },
    "prompt": {
      "ko": "메시지를 여러 행에 지그재그(위아래)로 적은 뒤 행 단위로 이어 읽는 고전 전치(transposition) 암호의 이름은? (영문 두 단어)",
      "en": "What classic transposition cipher writes the message in a zig-zag across several rows, then reads it off row by row? (two English words)"
    },
    "hints": {
      "ko": [
        "지그재그 울타리 모양에서 이름을 딴 전치 암호입니다.",
        "`rail ____` — 두 번째 단어는 '울타리/장벽'을 뜻합니다."
      ],
      "en": [
        "A transposition cipher named for its zig-zag, fence-like shape.",
        "`rail ____` — the second word means a barrier/enclosure."
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
    "fmt": "한 단어 / one word",
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
    "fmt": "파일 이름 / file name",
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
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "가장 흔한 비밀번호",
      "en": "The Most Common One"
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
    "fmt": "경로 표기 / path notation (3글자 / 3 chars)",
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
    "fmt": "알고리즘 이름 / algorithm name (4글자 / 4 chars, 하이픈 없이 / no hyphen)",
    "title": {
      "ko": "해시의 정체",
      "en": "Identify the Hash"
    },
    "prompt": {
      "ko": "40자리 16진수(160비트)로 출력되며, 충돌 공격이 발견되어 사용이 권장되지 않는 해시 알고리즘은? (이름을 하이픈 없이 붙여서 입력)",
      "en": "Which hash algorithm outputs 40 hex chars (160-bit) and is deprecated due to collision attacks? (write the name as one token, without a hyphen)"
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
    "id": "t2_rsa",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 100,
    "ci": true,
    "hash": "f5f69168bba3cfa1e2a80dff839b48db36df36fa876c1cd9d7d508f3ab308744",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "두 소수의 곱",
      "en": "Product of Two Primes"
    },
    "prompt": {
      "ko": "두 큰 소수의 곱을 인수분해하기 어렵다는 점에 안전성을 두는, 공개키/개인키 쌍을 사용하는 대표적 비대칭 암호 알고리즘의 약자는?",
      "en": "Which asymmetric algorithm — using a public/private key pair — bases its security on the difficulty of factoring the product of two large primes? (abbreviation)"
    },
    "hints": {
      "ko": [
        "발명자 세 사람 Rivest·Shamir·Adleman의 이니셜입니다.",
        "TLS·SSH·PGP에서 오래 쓰인 3글자 약자."
      ],
      "en": [
        "The initials of its inventors Rivest, Shamir, Adleman.",
        "A 3-letter abbreviation long used in TLS, SSH, PGP."
      ]
    }
  },
  {
    "id": "t2_polybius",
    "tier": 2,
    "cat": "crypto",
    "track": "crypto",
    "points": 90,
    "ci": true,
    "hash": "7d0d4704202c5ab87ab3ac01cdc9503b9b26a0fec933808f18e64e79e9d13992",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "5×5 좌표 암호",
      "en": "The 5×5 Grid Cipher"
    },
    "prompt": {
      "ko": "각 알파벳을 5×5 격자에서의 (행, 열) 좌표 숫자쌍으로 바꾸는 고전 암호(I/J는 한 칸을 공유)의 이름은? (영문 한 단어)",
      "en": "Which classic cipher replaces each letter with its (row, column) coordinate pair in a 5×5 grid (I and J share a cell)? (one English word)"
    },
    "hints": {
      "ko": [
        "고대 그리스 역사가의 이름에서 왔습니다.",
        "`poly____` — '정사각형(square)'과 함께 불리기도 합니다."
      ],
      "en": [
        "Named after an ancient Greek historian.",
        "`poly____` — often paired with the word 'square'."
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
    "fmt": "포맷 지정자 / format specifier (예: %x / e.g. %x)",
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
        "`50 4E 47` 세 바이트를 ASCII로 읽으면 형식 이름 세 글자가 됩니다.",
        "이미지 형식."
      ],
      "en": [
        "Read the bytes `50 4E 47` as ASCII and you get the three-letter format name.",
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
    "fmt": "도구 이름 / tool name",
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
    "fmt": "TCP 플래그 / TCP flag",
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
    "id": "t4_capsysadmin",
    "tier": 4,
    "cat": "cloud",
    "track": "cloud",
    "points": 140,
    "ci": true,
    "hash": "0e9c6d2741a7a8321561a79f94d71d4f5471f197cc2789701769cdcbf2554e39",
    "fmt": "리눅스 capability / Linux capability",
    "title": {
      "ko": "만능에 가까운 그 capability",
      "en": "The Near-Omnipotent Capability"
    },
    "prompt": {
      "ko": "컨테이너에 `--cap-add=______` 로 부여하면 파일시스템 마운트 등 광범위한 호스트 작업이 가능해져 컨테이너 탈출에 악용되는, 사실상 만능에 가까운 리눅스 커널 capability의 이름은?",
      "en": "Granting a container `--cap-add=______` unlocks broad host operations (like mounting filesystems) and is a common container-escape primitive — name this near-omnipotent Linux kernel capability."
    },
    "hints": {
      "ko": [
        "`SYS_____` — 이름 그대로 '시스템 관리자'급 권한 묶음.",
        "`CAP_` 접두사 뒤에 오는, 'system'과 'admin'을 합친 형태입니다."
      ],
      "en": [
        "`SYS_____` — literally the 'system administrator' capability.",
        "After the `CAP_` prefix, it's 'system' joined with 'admin'."
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
    "id": "t4_ssti_mro",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 170,
    "ci": true,
    "hash": "a9c495d34b02acf3b3936b062a8a9d775c6ac075131050fb4976b691b821f50d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "클래스 계층을 거슬러",
      "en": "Walk the Class Hierarchy"
    },
    "prompt": {
      "ko": "Jinja2 SSTI로 RCE까지 가는 표준 gadget 체인에서, `''.__class__` 다음에 이어 붙여 메서드 결정 순서(상속 계층 전체)를 튜플로 얻고 거기서 `object` 를 찾는 던더 속성은? (한 단어)",
      "en": "In the classic Jinja2 SSTI-to-RCE gadget chain, which dunder attribute do you append after `''.__class__` to get the full method resolution order (inheritance chain) as a tuple and locate `object`? (one word)"
    },
    "hints": {
      "ko": [
        "밑줄 두 개로 감싸인 던더 속성이며, 상속 순서 리스트를 줍니다.",
        "`__bases__` 는 한 단계만, 이것은 전체 순서를 줍니다: `__m__`."
      ],
      "en": [
        "A dunder attribute returning the ordered inheritance list.",
        "`__bases__` gives one level; this gives the whole order: `__m__`."
      ]
    }
  },
  {
    "id": "t4_graphql",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 160,
    "ci": true,
    "hash": "9abecc0128b99a8ff87b8fbe4cf4f683b129ae108ec4ee33c43d436b0d5c115c",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "스키마를 통째로",
      "en": "Dump the Whole Schema"
    },
    "prompt": {
      "ko": "운영 환경에서 비활성화해야 하지만 켜져 있으면 `__schema` 질의로 전체 타입·필드·뮤테이션을 덤프당하는, GraphQL의 이 내장 기능 이름은? (영문 한 단어)",
      "en": "Which built-in GraphQL feature — one that should be disabled in production — lets an attacker dump every type, field and mutation via a `__schema` query when left enabled? (one English word)"
    },
    "hints": {
      "ko": [
        "`__schema` / `__type` 같은 메타 질의를 가능하게 하는 기능입니다.",
        "'내성/자기관찰'을 뜻하는 영어 단어: intro________."
      ],
      "en": [
        "It powers meta-queries like `__schema` / `__type`.",
        "The English word for self-inspection: intro________."
      ]
    }
  },
  {
    "id": "t4_webchain",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 180,
    "ci": false,
    "hash": "ec4d0e6d24434d0509745b2e6193045627440a74645e5207bd3a3a6fe7074140",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "이중 인코딩 세션 토큰",
      "en": "Double-Encoded Session Token"
    },
    "prompt": {
      "ko": "탈취한 세션 토큰이 Base64로 두 번 감싸여 있습니다. 두 번 디코드해 플래그를 복구하세요:\n\n`Umt4QlIzdHNZWGxsY21Wa1gzZGxZbDkwYjJ0bGJsOWpjbUZqYTJWa2ZRPT0=`",
      "en": "A stolen session token is wrapped in Base64 twice. Decode it twice to recover the flag:\n\n`Umt4QlIzdHNZWGxsY21Wa1gzZGxZbDkwYjJ0bGJsOWpjbUZqYTJWa2ZRPT0=`"
    },
    "hints": {
      "ko": [
        "한 번 Base64 디코드하면 또 다른 Base64 문자열이 나옵니다.",
        "`echo '...' | base64 -d | base64 -d` 또는 `atob(atob('...'))`."
      ],
      "en": [
        "One Base64 decode yields another Base64 string.",
        "`echo '...' | base64 -d | base64 -d` or `atob(atob('...'))`."
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
    "fmt": "약어 / acronym",
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
      "ko": "마지막 도전입니다. 아래는 단일 바이트 키 `0x37` 로 XOR된 플래그입니다. 복호화하면 금고는 당신의 것:\n\n`717b76704c4e58426854585a475b5243525368435f5268415e55526840564550565a524a`",
      "en": "The final challenge. Below is a flag XOR-ed with the single-byte key `0x37`. Decrypt it and the vault is yours:\n\n`717b76704c4e58426854585a475b5243525368435f5268415e55526840564550565a524a`"
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
      "en": "Hidden Text"
    },
    "prompt": {
      "ko": "바이너리에서 사람이 읽을 수 있는 ASCII 문자열만 뽑아내는 고전 유닉스 명령은? (명령어 이름)",
      "en": "Which classic Unix command extracts the human-readable ASCII text out of a binary? (command name)"
    },
    "hints": {
      "ko": [
        "이름 그대로 '문자열들'.",
        "`____ ./malware.bin | grep FLAG`"
      ],
      "en": [
        "The command is named after exactly what it pulls out.",
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
    "fmt": "16진수 / hex (2글자 / 2 chars)",
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
    "id": "t0_whoami",
    "tier": 0,
    "cat": "linux",
    "track": "system",
    "points": 45,
    "ci": true,
    "hash": "f25297859cf0a70af5c053a5464a5fa647a35ceee1d91397331903846d79ffc1",
    "fmt": "명령어 / command",
    "title": {
      "ko": "나는 누구인가",
      "en": "Who Am I"
    },
    "prompt": {
      "ko": "리눅스 셸에서 현재 로그인한(유효 사용자) 계정 이름을 출력하는 한 단어짜리 명령은?",
      "en": "Which one-word Linux command prints the name of the currently logged-in (effective) user?"
    },
    "hints": {
      "ko": [
        "영어 의문문 'who am i' 를 붙여 쓴 이름입니다.",
        "권한 상승 후 root 로 바뀌었는지 확인할 때 자주 씁니다."
      ],
      "en": [
        "It is the words 'who am i' joined together.",
        "Often run after privesc to check if you became root."
      ]
    }
  },
  {
    "id": "t0_shebang",
    "tier": 0,
    "cat": "linux",
    "track": "system",
    "points": 50,
    "ci": true,
    "hash": "c8c91095817f0cf3a7bd74e5a0104431cde285d893acbfc3b3d73396ea8844be",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "샵-뱅 두 글자",
      "en": "The First Two Bytes"
    },
    "prompt": {
      "ko": "유닉스 스크립트의 첫 줄 맨 앞에 오는 `#!` 기호(예: `#!/bin/bash`)를 부르는 영어 이름은? 이 두 바이트가 어떤 인터프리터로 스크립트를 실행할지 정합니다. (한 단어)",
      "en": "What is the English name of the `#!` marker at the very start of a Unix script's first line (e.g. `#!/bin/bash`), whose two bytes select the interpreter used to run the script? (one word)"
    },
    "hints": {
      "ko": [
        "`#` (sharp/hash) 와 `!` (bang) 를 합친 속어입니다.",
        "파일의 매직 넘버 `0x23 0x21` 에 해당합니다."
      ],
      "en": [
        "A slang blend of `#` (sharp/hash) and `!` (bang).",
        "Corresponds to the file magic bytes `0x23 0x21`."
      ]
    }
  },
  {
    "id": "t1_ldd",
    "tier": 1,
    "cat": "linux",
    "track": "system",
    "points": 65,
    "ci": true,
    "hash": "fc8329924ddd4805793ff18ae0d87685f6717160db36eb22ca04e8a55130287b",
    "fmt": "명령어 / command",
    "title": {
      "ko": "무엇에 기대는가",
      "en": "What It Leans On"
    },
    "prompt": {
      "ko": "동적 링크된 실행 파일이 어떤 공유 라이브러리(`.so`)에 의존하는지 나열해 주는 리눅스 명령은? (한 단어, 소문자)",
      "en": "Which Linux command lists the shared libraries (`.so`) that a dynamically linked executable depends on? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "'List Dynamic Dependencies' 의 머리글자입니다.",
        "출력에 `libc.so.6 => ...` 같은 줄이 보입니다."
      ],
      "en": [
        "Initials of 'List Dynamic Dependencies'.",
        "Its output shows lines like `libc.so.6 => ...`."
      ]
    }
  },
  {
    "id": "t1_endian",
    "tier": 1,
    "cat": "reversing",
    "track": "system",
    "points": 65,
    "ci": true,
    "hash": "180ca01b95f0dfdd36fbb600e51cf6e46c8ef468de56b017847886fefaf7b6f9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "작은 쪽이 먼저",
      "en": "Smallest First"
    },
    "prompt": {
      "ko": "x86/x86-64 는 정수를 메모리에 저장할 때 **최하위 바이트를 낮은 주소에 먼저** 둡니다. 예를 들어 `0x11223344` 는 바이트열 `44 33 22 11` 로 쌓입니다. 이 바이트 순서의 이름은 '____ 엔디언'? (빈칸에 들어갈 영어 한 단어)",
      "en": "x86/x86-64 stores an integer with its **least-significant byte at the lowest address first** — e.g. `0x11223344` is laid out as bytes `44 33 22 11`. This byte order is called '____-endian'. (fill the blank, one English word)"
    },
    "hints": {
      "ko": [
        "네트워크 바이트 순서인 'big 엔디언' 의 반대말입니다.",
        "익스플로잇에서 주소를 `struct.pack('<Q', addr)` 처럼 이 순서로 패킹합니다."
      ],
      "en": [
        "The opposite of 'big-endian' (network byte order).",
        "In exploits you pack addresses this way, e.g. `struct.pack('<Q', addr)`."
      ]
    }
  },
  {
    "id": "t2_gdb",
    "tier": 2,
    "cat": "reversing",
    "track": "system",
    "points": 90,
    "ci": true,
    "hash": "a919007637abd504f123db0cbc8f290ab16db93adf24b1fc03c50e6131d2b98e",
    "fmt": "명령어 / command",
    "title": {
      "ko": "달리는 프로세스에 올라타라",
      "en": "Latch Onto a Running Process"
    },
    "prompt": {
      "ko": "이미 실행 중인 프로그램을 gdb 로 디버깅하려고 그 프로세스 ID 에 디버거를 연결(붙이기)할 때 쓰는 gdb 명령은? (한 단어, `gdb -p` 가 내부적으로 수행하는 동작의 이름)",
      "en": "To debug an already-running program, which gdb command attaches the debugger to its process ID? (one word — the action `gdb -p` performs under the hood)"
    },
    "hints": {
      "ko": [
        "반대 명령은 `detach` 입니다.",
        "`____ <PID>` 형태로 사용합니다."
      ],
      "en": [
        "The opposite command is `detach`.",
        "Used as `____ <PID>`."
      ]
    }
  },
  {
    "id": "t3_got",
    "tier": 3,
    "cat": "pwn",
    "track": "system",
    "points": 120,
    "ci": true,
    "hash": "0497db517ef058cb6d3672d5ffe8f062fddabc4bf56aa1d254b7f078e9a79e49",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "덮어쓰면 흐름을 뺏는 표",
      "en": "Overwrite It, Hijack the Flow"
    },
    "prompt": {
      "ko": "동적 링크 바이너리에서 외부 함수(예: `libc` 의 `puts`)의 실제 주소가 처음 호출 시 해석되어 채워지는 테이블입니다. 이 항목을 임의 쓰기로 덮어써 제어 흐름을 탈취하는 고전 pwn 기법의 표적이 되는 이 테이블의 3글자 약어는?",
      "en": "In a dynamically linked binary, this table is filled in — at first call — with the resolved real address of an external function (e.g. libc's `puts`). What is the 3-letter acronym of the table that a classic pwn technique overwrites to hijack control flow?"
    },
    "hints": {
      "ko": [
        "Global Offset Table 의 머리글자입니다.",
        "짝을 이루는 것은 `PLT`(Procedure Linkage Table) 입니다."
      ],
      "en": [
        "Initials of 'Global Offset Table'.",
        "Its counterpart is the `PLT` (Procedure Linkage Table)."
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
    "fmt": "도구 이름 / tool name",
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
    "fmt": "서비스 이름 / service name",
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
    "fmt": "약어 / acronym (2글자 / 2 chars)",
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
    "id": "t2_eks",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "6e884711fb5f5560386641ff08349621f67827bcfe69d8bd4b546a2bd5f00de2",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "관리형 쿠버네티스",
      "en": "Managed Kubernetes"
    },
    "prompt": {
      "ko": "AWS가 쿠버네티스 컨트롤 플레인을 대신 운영·관리해 주는 관리형 서비스의 약자는? (Elastic ______ Service)",
      "en": "What is the abbreviation for AWS's managed service that runs and maintains the Kubernetes control plane for you? (Elastic ______ Service)"
    },
    "hints": {
      "ko": [
        "`E_S` — 가운데 글자는 Kubernetes의 K.",
        "GCP의 GKE, Azure의 AKS에 대응됩니다."
      ],
      "en": [
        "`E_S` — the middle letter is the K in Kubernetes.",
        "Analogous to GCP's GKE and Azure's AKS."
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
        "고래가 무리 지어 다니는 그 무리를 뜻하는 영단어에서 따왔습니다.",
        "`kubectl get ____`"
      ],
      "en": [
        "Named after the English word for a group of whales.",
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
    "fmt": "IP 주소 / IP address",
    "title": {
      "ko": "메타데이터의 IP",
      "en": "The Metadata IP"
    },
    "prompt": {
      "ko": "SSRF로 클라우드 인스턴스의 임시 자격증명을 탈취할 때 노리는, 모든 주요 클라우드의 메타데이터 서비스 링크-로컬 IP 주소는?",
      "en": "Which link-local IP address (the metadata service across major clouds) do attackers target via SSRF to steal an instance's temporary keys?"
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
    "id": "t3_cryptojacking",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": true,
    "hash": "935ca8d5c7d15c4e3098a6e5fa3309e10e918d9139e3b09e0617151edbb52429",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "남의 계정으로 채굴",
      "en": "Mining on Someone Else's Dime"
    },
    "prompt": {
      "ko": "탈취한 클라우드 계정이나 컨테이너에서 공격자가 몰래 암호화폐를 채굴해 피해자에게 컴퓨팅 비용을 떠넘기는 공격을 가리키는 한 단어(영문)는?",
      "en": "What single English word names the attack in which an intruder secretly mines cryptocurrency on a compromised cloud account or container, sticking the victim with the compute bill?"
    },
    "hints": {
      "ko": [
        "'crypto' + 'hijacking'의 합성어입니다.",
        "`crypto______` — GPU 인스턴스가 갑자기 100% 사용률을 보이면 의심 신호."
      ],
      "en": [
        "A portmanteau of 'crypto' + 'hijacking'.",
        "`crypto______` — GPU instances suddenly at 100% usage is a red flag."
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
    "fmt": "한 단어 / one word",
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
    "id": "t0_octal",
    "tier": 0,
    "cat": "crypto",
    "track": "crypto",
    "points": 50,
    "ci": false,
    "hash": "33d7f97040980680e781fae0f62edd198094584b4935398b511aa3baa88f0bfe",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "8진법의 세계",
      "en": "Base-8 World"
    },
    "prompt": {
      "ko": "공백으로 구분된 8진법(옥탈) ASCII 코드입니다. 디코딩하면 플래그:\n\n`106 114 101 107 173 142 141 163 145 70 137 157 143 164 141 154 175`",
      "en": "Space-separated octal (base-8) ASCII codes. Decode to reveal the flag:\n\n`106 114 101 107 173 142 141 163 145 70 137 157 143 164 141 154 175`"
    },
    "hints": {
      "ko": [
        "각 숫자를 8진법으로 읽어 문자로: `106`(8진) = 70 = 'F'.",
        "16진(hex)·10진(decimal)이 아니라 8진입니다."
      ],
      "en": [
        "Read each number as base-8 → a char: `106`(oct) = 70 = 'F'.",
        "It's base-8, not hex or decimal."
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
    "fmt": "한 단어 / one word",
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
    "fmt": "한 단어 / one word",
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
      "en": "Intercepted Login"
    },
    "prompt": {
      "ko": "`Authorization: Basic YWRtaW46czNjcjN0` 헤더를 보았습니다. 디코딩하면 자격증명은?",
      "en": "You saw `Authorization: Basic YWRtaW46czNjcjN0`. Decode it — what is the `user:password` pair?"
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
    "fmt": "기호 / symbol (2글자 / 2 chars)",
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
    "fmt": "약어 / acronym",
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
    "fmt": "약어 / acronym",
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
    "id": "t3_cbc",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 120,
    "ci": true,
    "hash": "f1454f676ceb25587d73dec3e5f5e5bba4cb8f075d9478f87e66ae9f11068e2d",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "블록을 사슬로 엮다",
      "en": "Chaining the Blocks"
    },
    "prompt": {
      "ko": "각 평문 블록을 직전 암호문 블록과 결합(첫 블록은 IV 사용)해 사슬처럼 연쇄시키는 블록 암호 운용 모드의 3글자 약자는?",
      "en": "What 3-letter block-cipher mode of operation chains each plaintext block with the previous ciphertext block (using an IV for the first block)? (abbreviation)"
    },
    "hints": {
      "ko": [
        "Cipher Block Chaining.",
        "IV 재사용·패딩 오라클(padding oracle) 공격에 주의해야 하는 모드입니다."
      ],
      "en": [
        "Cipher Block Chaining.",
        "Watch out for IV reuse and padding-oracle attacks."
      ]
    }
  },
  {
    "id": "t3_salt",
    "tier": 3,
    "cat": "crypto",
    "track": "crypto",
    "points": 110,
    "ci": true,
    "hash": "63479ad69a090b258277ec8fba6f99419a2ffb248981510657c944ccd1148e97",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "레인보우 테이블 방어",
      "en": "Defeating Rainbow Tables"
    },
    "prompt": {
      "ko": "레인보우 테이블 공격을 막기 위해 비밀번호를 해싱하기 전에 사용자마다 덧붙이는 무작위 값을 가리키는 한 단어(영문)는?",
      "en": "What single English word names the random per-user value added to a password before hashing to defeat rainbow-table attacks?"
    },
    "hints": {
      "ko": [
        "요리에서 '간을 맞추는' 그 단어와 철자가 같습니다.",
        "같은 비밀번호라도 저장된 해시가 서로 달라지게 만듭니다."
      ],
      "en": [
        "Spelled like the seasoning you add to food.",
        "Makes identical passwords hash to different stored values."
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
    "id": "t3_proto",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "30e2af384186b57fda019524ade9f9afe48e815480b993d14ec8dc68251b592a",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "프로토타입을 오염시켜라",
      "en": "Pollute the Prototype"
    },
    "prompt": {
      "ko": "JavaScript 프로토타입 오염(prototype pollution) 공격에서, 병합·복사 로직을 속여 모든 객체의 상위 프로토타입에 속성을 심을 때 페이로드의 키로 사용하는 특수 속성 이름은? (한 단어)",
      "en": "In a JavaScript prototype pollution attack, which special property name is used as the payload key to inject onto every object's parent prototype via a vulnerable merge/copy? (one word)"
    },
    "hints": {
      "ko": [
        "밑줄 두 개로 감싸인 던더(dunder) 속성입니다.",
        "`obj.__?__.polluted = true` 형태로 접근합니다."
      ],
      "en": [
        "It is a double-underscore (dunder) property.",
        "Accessed as `obj.__?__.polluted = true`."
      ]
    }
  },
  {
    "id": "t3_jinjaconfig",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "b79606fb3afea5bd1609ed40b622142f1c98125abcfe89a76a661b0e8e343910",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "설정을 유출하라",
      "en": "Leak the App Settings"
    },
    "prompt": {
      "ko": "Flask/Jinja2 SSTI에서 `{{ ____ }}` 로 접근하면 앱의 SECRET_KEY 등 설정값이 통째로 노출되는, 템플릿 전역 객체의 이름은? (소문자 한 단어)",
      "en": "In Flask/Jinja2 SSTI, which template global object, accessed as `{{ ____ }}`, dumps the app's settings including SECRET_KEY? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "Flask 앱 설정을 담는 딕셔너리형 전역입니다.",
        "앱 객체에서 `app.____` 로 꺼내 쓰는 그 이름입니다."
      ],
      "en": [
        "A dict-like global holding the Flask app settings.",
        "Read off the app object as `app.____`."
      ]
    }
  },
  {
    "id": "t3_jwtnone",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 140,
    "ci": false,
    "hash": "283e5c828024eb91519475544f6bf59eae0da2a89310e5c94a460d7352802a8a",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "서명 없는 토큰",
      "en": "The Unsigned Token"
    },
    "prompt": {
      "ko": "다음 JWT는 `alg: none` 으로 서명 부분이 비어 있어 누구나 위조할 수 있습니다. payload를 Base64URL 디코드해 `flag` 값을 찾으세요:\n\n`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImZsYWciOiJGTEFHe2p3dF9ub25lX2FsZ19mb3JnZXJ5fSIsImFkbWluIjp0cnVlfQ.`",
      "en": "This JWT uses `alg: none` — the signature part is empty, so anyone can forge it. Base64URL-decode the payload and read the `flag` value:\n\n`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImZsYWciOiJGTEFHe2p3dF9ub25lX2FsZ19mb3JnZXJ5fSIsImFkbWluIjp0cnVlfQ.`"
    },
    "hints": {
      "ko": [
        "점(.)으로 나뉜 두 번째 조각이 payload 입니다.",
        "Base64URL 디코드 → JSON 의 `flag` 필드."
      ],
      "en": [
        "The second dot-separated part is the payload.",
        "Base64URL-decode → the `flag` field of the JSON."
      ]
    }
  },
  {
    "id": "t3_ssrf",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "9cc1ee455a3363ffc504f40006f70d0c8276648a5d3eb3f9524e94d1b7a83aef",
    "fmt": "스킴 이름 / scheme name",
    "title": {
      "ko": "프로토콜을 바꿔라",
      "en": "Switch the Protocol"
    },
    "prompt": {
      "ko": "SSRF 취약점으로 내부 서비스(예: 인증 없는 Redis)에 임의의 원시 바이트를 밀어 넣으려 합니다. `http://` 로는 원하는 명령을 못 보낼 때, `curl` 도 지원하는 오래된 프로토콜을 이용해 원시 TCP 페이로드를 실어 보내는 비-HTTP URI 스킴은? (한 단어)",
      "en": "Via an SSRF you want to push arbitrary raw bytes into an internal, auth-less service (e.g. Redis). Since `http://` can't carry the exact commands, which non-HTTP URI scheme — an old protocol that `curl` still supports — lets you smuggle a raw TCP payload? (one word)"
    },
    "hints": {
      "ko": [
        "`____://127.0.0.1:6379/_` 형태로 Redis 에 접근합니다.",
        "1991년경의 문서 검색 프로토콜에서 이름을 따왔습니다."
      ],
      "en": [
        "Used as `____://127.0.0.1:6379/_` to reach Redis.",
        "Named after a ~1991 document-retrieval protocol."
      ]
    }
  },
  {
    "id": "t3_nosql",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "5f664be5d489773c905edcf99b771251121c7c4539fe760305c424ebda69373a",
    "fmt": "연산자 / operator ($ 포함 / include $)",
    "title": {
      "ko": "같지 않으면 참",
      "en": "True When Not Equal"
    },
    "prompt": {
      "ko": "MongoDB 백엔드 로그인에서 JSON 본문을 보내면 필터에 그대로 들어갑니다. `{\"user\":\"admin\",\"password\":{\"$__\":\"\"}}` 처럼 비밀번호를 '어떤 값과도 같지 않음' 으로 만들어 항상 참이 되게 하는 MongoDB 쿼리 연산자는? (`$` 포함)",
      "en": "A MongoDB-backed login puts your JSON body straight into the query filter. Which MongoDB query operator makes the password field mean 'not equal to anything', so the check is always true — as in `{\"user\":\"admin\",\"password\":{\"$__\":\"\"}}`? (include the `$`)"
    },
    "hints": {
      "ko": [
        "영어 'not equal' 의 줄임말입니다.",
        "`$gt`, `$lt`, `$regex` 같은 비교 연산자 계열."
      ],
      "en": [
        "Short for 'not equal'.",
        "Same family as `$gt`, `$lt`, `$regex`."
      ]
    }
  },
  {
    "id": "t3_cors",
    "tier": 3,
    "cat": "web",
    "track": "web",
    "points": 130,
    "ci": true,
    "hash": "631aada47deaf488bb72eee0873a20472c8f43ff960f2188f66cc41eb3f35428",
    "fmt": "헤더 접미사 / header suffix",
    "title": {
      "ko": "출처를 반사하다",
      "en": "Reflected Origin"
    },
    "prompt": {
      "ko": "취약한 서버가 요청의 `Origin` 을 그대로 `Access-Control-Allow-Origin` 에 반사합니다. 여기에 더해 피해자의 인증 세션(자격증명)까지 실린 교차-출처 요청을 브라우저가 허용하게 하려면, 서버가 반드시 `true` 로 내보내야 하는 응답 헤더는? `Access-Control-Allow-________`",
      "en": "A vulnerable server reflects the request's `Origin` back into `Access-Control-Allow-Origin`. To also let the browser send the victim's authenticated session on that cross-origin request, which response header must the server set to `true`? `Access-Control-Allow-________`"
    },
    "hints": {
      "ko": [
        "자격증명(인증 세션) 전송 허용 여부를 정합니다.",
        "이 헤더가 `true` 이면 ACAO 는 와일드카드 `*` 를 쓸 수 없습니다."
      ],
      "en": [
        "It governs whether the authenticated session may be sent at all.",
        "When it is `true`, ACAO cannot use the wildcard `*`."
      ]
    }
  },
  {
    "id": "t4_smuggling",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 170,
    "ci": true,
    "hash": "1ecb76524bc07187f9be47535fc44a9dff07e6d525396d40b2a441c9a52ab523",
    "fmt": "약어 / acronym (예: AB.CD / e.g. AB.CD)",
    "title": {
      "ko": "두 서버의 엇갈린 셈",
      "en": "Two Servers Disagree"
    },
    "prompt": {
      "ko": "HTTP 요청 스머글링에서 프런트엔드 프록시는 `Content-Length` 헤더로 요청 경계를 판단하고, 백엔드 서버는 `Transfer-Encoding: chunked` 를 신뢰합니다. 이렇게 프런트=CL, 백엔드=TE 로 엇갈리는 고전적 스머글링 유형을 부르는 점(.) 포함 표준 약칭은? (예: `AB.CD` 형태)",
      "en": "In HTTP request smuggling the front-end proxy uses the `Content-Length` header to find the request boundary, while the back-end trusts `Transfer-Encoding: chunked`. What is the dotted standard abbreviation for this classic front-end=CL, back-end=TE mismatch? (form `AB.CD`)"
    },
    "hints": {
      "ko": [
        "프런트=Content-Length, 백엔드=Transfer-Encoding 순서 그대로 약칭이 됩니다.",
        "정반대 조합은 `TE.CL` 입니다."
      ],
      "en": [
        "The abbreviation follows the order front=Content-Length, back=Transfer-Encoding.",
        "The mirror-image variant is `TE.CL`."
      ]
    }
  },
  {
    "id": "t4_oauth",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 160,
    "ci": true,
    "hash": "ca74bea00c269f053d5ac8df6f09be5b1e86f973195de3fd98e4a1e9838ce8e0",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "가로챈 코드를 무력화하라",
      "en": "Neutralize the Stolen Code"
    },
    "prompt": {
      "ko": "모바일·SPA 같은 공개 클라이언트에서 OAuth 2.0 인가 코드가 가로채여도 재사용을 막기 위해, 클라이언트가 임의의 `code_verifier` 와 그 해시인 `code_challenge` 를 주고받도록 한 확장 규격의 4글자 약어는?",
      "en": "For public clients (mobile / SPA), which 4-letter OAuth 2.0 extension makes the client exchange a random `code_verifier` and its hash `code_challenge`, so a stolen authorization code cannot be replayed?"
    },
    "hints": {
      "ko": [
        "Proof Key for Code Exchange 의 약어입니다.",
        "흔히 '픽시' 라고 읽습니다. (RFC 7636)"
      ],
      "en": [
        "Acronym of 'Proof Key for Code Exchange'.",
        "Commonly pronounced 'pixy'. (RFC 7636)"
      ]
    }
  },
  {
    "id": "t4_cachepoison",
    "tier": 4,
    "cat": "web",
    "track": "web",
    "points": 160,
    "ci": true,
    "hash": "4740ae6347b0172c01254ff55bae5aff5199f4446e7f6d643d40185b3f475145",
    "fmt": "헤더 접미사 / header suffix",
    "title": {
      "ko": "캐시를 오염시키는 헤더",
      "en": "The Header That Poisons the Cache"
    },
    "prompt": {
      "ko": "웹 캐시 포이즈닝과 비밀번호 재설정 오염 공격에서, 앱이 절대 URL(예: 재설정 링크)을 만들 때 요청에서 그대로 신뢰하면 위험한 대표적 '언키드(캐시 키 미포함)' 요청 헤더는? `X-Forwarded-____`",
      "en": "In web cache poisoning and password-reset poisoning, which classic 'unkeyed' request header is dangerous when an app trusts it to build absolute URLs (e.g. a reset link)? `X-Forwarded-____`"
    },
    "hints": {
      "ko": [
        "리버스 프록시가 원래 요청의 호스트명을 뒤로 전달할 때 쓰는 헤더입니다.",
        "`X-Forwarded-For` 의 형제이지만, 이건 IP 가 아니라 호스트명을 담습니다."
      ],
      "en": [
        "The header a reverse proxy uses to pass the original hostname downstream.",
        "A sibling of `X-Forwarded-For`, but it carries the hostname, not the IP."
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
    "fmt": "알고리즘 이름 / algorithm name (3글자 / 3 chars)",
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
    "fmt": "약어 / acronym",
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
    "fmt": "약어 / acronym",
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
    "fmt": "약어 / acronym",
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
    "fmt": "약어 / acronym",
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
        "From the idiom about the bird kept in a coal mine."
      ]
    }
  },
  {
    "id": "t0_sigkill",
    "tier": 0,
    "cat": "linux",
    "track": "system",
    "points": 40,
    "ci": true,
    "hash": "19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7",
    "fmt": "숫자 / number",
    "title": {
      "ko": "프로세스를 강제 종료",
      "en": "Force Kill a Process"
    },
    "prompt": {
      "ko": "리눅스에서 `kill -9 <PID>` 처럼 프로세스를 즉시 강제 종료할 때 쓰이는 시그널 번호는? (숫자만)",
      "en": "Which signal number does `kill -9 <PID>` send to immediately force-kill a process on Linux? (number only)"
    },
    "hints": {
      "ko": [
        "절대 무시하거나 처리할 수 없는 시그널입니다.",
        "SIGKILL의 번호입니다."
      ],
      "en": [
        "A signal that can never be caught or ignored.",
        "It's the number for SIGKILL."
      ]
    }
  },
  {
    "id": "t1_symlink",
    "tier": 1,
    "cat": "linux",
    "track": "system",
    "points": 65,
    "ci": true,
    "hash": "660ea4d709cf6a4f8bd150f1c89c754d23aa0b1ea2c53e537141a466b092c2a5",
    "fmt": "명령어 / command",
    "title": {
      "ko": "가리키기만 하는 파일",
      "en": "A File That Just Points"
    },
    "prompt": {
      "ko": "원본 파일을 가리키기만 하는 심볼릭 링크(바로가기)를 만드는 명령은? (옵션 포함, 예: `cmd -o target link`)",
      "en": "Which command (with its flag) creates a symbolic link pointing to a target file? (e.g. `cmd -o target link`)"
    },
    "hints": {
      "ko": [
        "`ln` 명령에 옵션 하나를 더합니다.",
        "`-s` (symbolic)."
      ],
      "en": [
        "Add one flag to the `ln` command.",
        "`-s` for symbolic."
      ]
    }
  },
  {
    "id": "t2_procmon",
    "tier": 2,
    "cat": "windows",
    "track": "system",
    "points": 85,
    "ci": true,
    "hash": "d86580392e249926e944c40917377c0428bb1afc300fe31d4d321900da973495",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "실시간으로 훔쳐보기",
      "en": "Watching in Real Time"
    },
    "prompt": {
      "ko": "Windows에서 프로세스·파일·레지스트리 접근을 실시간으로 감시해 악성코드 행위 분석에 널리 쓰이는 Sysinternals 도구의 이름은?",
      "en": "Which Sysinternals tool monitors real-time process/file/registry activity on Windows and is widely used for malware behavior analysis?"
    },
    "hints": {
      "ko": [
        "Sysinternals Suite에 포함된 도구입니다.",
        "'Process'와 'Monitor'의 합성(줄임말)."
      ],
      "en": [
        "Part of the Sysinternals Suite.",
        "A blend of 'Process' and 'Monitor'."
      ]
    }
  },
  {
    "id": "t2_lsof",
    "tier": 2,
    "cat": "linux",
    "track": "system",
    "points": 85,
    "ci": true,
    "hash": "cb298bd94fae6f2f713a1108a16e0632f3a1e21820a288d7ea86c8b00a4d4fef",
    "fmt": "명령어 / command",
    "title": {
      "ko": "열린 파일 목록",
      "en": "List Open Files"
    },
    "prompt": {
      "ko": "리눅스에서 특정 프로세스가 열어둔 파일·소켓·라이브러리를 나열하는 명령은? (명령어만)",
      "en": "Which Linux command lists the open files, sockets, and libraries held by a process? (command only)"
    },
    "hints": {
      "ko": [
        "이름 자체가 'list open files'의 줄임말입니다.",
        "`____ -p <PID>`"
      ],
      "en": [
        "Its name is literally short for 'list open files'.",
        "`____ -p <PID>`"
      ]
    }
  },
  {
    "id": "t4_rop",
    "tier": 4,
    "cat": "pwn",
    "track": "system",
    "points": 150,
    "ci": true,
    "hash": "d1e909483b98bf9e8b8c2ae3e1688365ecb2e7b75286c9784646d3d76c1c0dc6",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "이미 있는 조각을 이어붙이다",
      "en": "Chaining What's Already There"
    },
    "prompt": {
      "ko": "DEP/NX로 스택 실행이 막혔을 때, 바이너리에 이미 존재하는 코드 조각(가젯)들을 이어붙여 임의 코드 실행을 흉내내는 익스플로잇 기법의 약자는?",
      "en": "When DEP/NX blocks stack execution, which exploitation technique's abbreviation names chaining existing code gadgets already in the binary to simulate arbitrary execution?"
    },
    "hints": {
      "ko": [
        "Return-Oriented Programming 의 약자.",
        "`ret` 명령으로 끝나는 가젯들을 이어붙입니다."
      ],
      "en": [
        "Abbreviation for Return-Oriented Programming.",
        "Chains gadgets that each end in a `ret`."
      ]
    }
  },
  {
    "id": "t4_uaf",
    "tier": 4,
    "cat": "pwn",
    "track": "system",
    "points": 160,
    "ci": true,
    "hash": "9e92f50f72fc1a740d5187ba781df8f89cf52b3085e6c49334945dca8a2f53db",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "이미 해제된 메모리",
      "en": "Memory After It's Freed"
    },
    "prompt": {
      "ko": "`free()`로 이미 해제된 힙 메모리에 남은 포인터로 계속 접근해 발생하는, 브라우저·커널 익스플로잇에서 흔한 취약점 유형의 약자는?",
      "en": "Which vulnerability class's abbreviation names accessing heap memory through a dangling pointer after it's already been `free()`'d — common in browser and kernel exploits?"
    },
    "hints": {
      "ko": [
        "Use-After-Free 의 약자.",
        "세 글자."
      ],
      "en": [
        "Abbreviation for Use-After-Free.",
        "Three letters."
      ]
    }
  },
  {
    "id": "t0_region",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 45,
    "ci": true,
    "hash": "c697d2981bf416569a16cfbcdec1542b5398f3cc77d2b905819aa99c46ecf6f6",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "데이터센터의 큰 단위",
      "en": "A Big Slice of Datacenters"
    },
    "prompt": {
      "ko": "AWS/GCP/Azure 등 클라우드에서 지리적으로 분리된 데이터센터 묶음(예: `ap-northeast-2`)을 부르는 한 단어는?",
      "en": "What single word names a geographically separate cluster of cloud datacenters (e.g. `ap-northeast-2`)?"
    },
    "hints": {
      "ko": [
        "가용영역(AZ)보다 더 큰 단위입니다.",
        "지역/지방을 뜻하는 영단어."
      ],
      "en": [
        "Bigger than an Availability Zone.",
        "The English word for a geographic area."
      ]
    }
  },
  {
    "id": "t0_cdn",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 45,
    "ci": true,
    "hash": "db9831b53a8574d33f3d7ce6820598c67224687dbe57cbbc10b6070e5aa57744",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "가까운 곳에서 전송",
      "en": "Served from Near You"
    },
    "prompt": {
      "ko": "전 세계 엣지 서버에 콘텐츠를 캐싱해 사용자와 가까운 곳에서 전송함으로써 지연을 줄이는 네트워크를 가리키는 3글자 약어는? (AWS의 CloudFront가 대표 예)",
      "en": "What 3-letter abbreviation names the network of globally distributed edge servers that caches content close to users to cut latency? (AWS CloudFront is one example)"
    },
    "hints": {
      "ko": [
        "Content Delivery Network.",
        "정적 파일(이미지·JS)을 엣지에서 제공합니다."
      ],
      "en": [
        "Content Delivery Network.",
        "Serves static assets (images, JS) from the edge."
      ]
    }
  },
  {
    "id": "t1_lb",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 65,
    "ci": true,
    "hash": "7a34bf90b5e9eecc91c3c8418a343ae9fba263400f7ae1e6ddb67abe0f7a453a",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "트래픽을 나눠주는 것",
      "en": "Splitting the Traffic"
    },
    "prompt": {
      "ko": "여러 서버 인스턴스에 들어오는 요청을 고르게 분산시켜주는 서비스를 부르는 두 단어(약자 아님)는?",
      "en": "What two-word term (not an abbreviation) names the service that distributes incoming requests evenly across multiple server instances?"
    },
    "hints": {
      "ko": [
        "AWS의 ELB/ALB가 이 역할을 합니다.",
        "'짐을 나누다'는 뜻의 영단어 두 개."
      ],
      "en": [
        "AWS's ELB/ALB serve this role.",
        "Two English words meaning 'to distribute weight evenly'."
      ]
    }
  },
  {
    "id": "t3_assumerole",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 125,
    "ci": true,
    "hash": "776a88039ef9efe803d63e13848afb8ea36d612d3fb5df9c364148e30ad9ca45",
    "fmt": "API 액션 / API action",
    "title": {
      "ko": "역할을 빌려쓰다",
      "en": "Borrowing a Role"
    },
    "prompt": {
      "ko": "AWS에서 다른 역할의 임시 자격 증명을 발급받기 위해 호출하는 STS API 액션의 이름은? (예: `sts:________`)",
      "en": "Which STS API action do you call in AWS to obtain temporary keys for another role? (e.g. `sts:________`)"
    },
    "hints": {
      "ko": [
        "역할을 '가정한다(assume)'는 뜻입니다.",
        "CamelCase 두 단어가 붙어 있습니다."
      ],
      "en": [
        "It means to 'assume' a role.",
        "Two CamelCase words joined together."
      ]
    }
  },
  {
    "id": "t3_cspm",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": true,
    "hash": "5d269f85e3e967c8a49655adcd5090ab75980245bcb66eba8e6f056413dc80e7",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "설정 실수를 계속 감시하다",
      "en": "Watching for Misconfigurations"
    },
    "prompt": {
      "ko": "클라우드 인프라의 오설정(퍼블릭 버킷, 과도한 권한 부여 등)을 지속적으로 스캔·경고하는 보안 도구 카테고리의 약자는?",
      "en": "What abbreviation names the security tool category that continuously scans and alerts on cloud misconfigurations (public buckets, excessive permissions, etc.)?"
    },
    "hints": {
      "ko": [
        "Cloud Security Posture Management 의 약자.",
        "네 글자."
      ],
      "en": [
        "Abbreviation for Cloud Security Posture Management.",
        "Four letters."
      ]
    }
  },
  {
    "id": "t4_coldstart",
    "tier": 4,
    "cat": "cloud",
    "track": "cloud",
    "points": 140,
    "ci": true,
    "hash": "2ab729086fade508b332db3792a12c723cc78cab48f5d1ec8f4a4245fd79d623",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "처음 깨어날 때는 느리다",
      "en": "Slow to Wake Up"
    },
    "prompt": {
      "ko": "서버리스 함수(AWS Lambda 등)가 한동안 호출되지 않아 새로 초기화되면서 지연이 발생하는 현상을 부르는 두 단어(예: `___ start`)는?",
      "en": "What two-word term (e.g. `___ start`) names the latency that occurs when a serverless function (like AWS Lambda) must initialize from scratch after being idle?"
    },
    "hints": {
      "ko": [
        "반대말은 'warm start'입니다.",
        "온도를 뜻하는 형용사 + start."
      ],
      "en": [
        "The opposite is a 'warm start'.",
        "A temperature adjective + start."
      ]
    }
  },
  {
    "id": "t0_forensicimage",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 50,
    "ci": true,
    "hash": "b75b0489f78a9bae128f5fb590705c68e6bd9110fbdfec40721575c177d38c86",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "원본을 건드리지 않는 사본",
      "en": "A Copy That Never Touches the Original"
    },
    "prompt": {
      "ko": "디지털 포렌식에서 원본 증거를 변경하지 않기 위해 비트 단위로 통째로 복제해두는 사본을 부르는 두 단어(예: `forensic ___`)는?",
      "en": "What two-word term (e.g. `forensic ___`) names a bit-for-bit copy made so the original evidence is never altered during digital forensics?"
    },
    "hints": {
      "ko": [
        "FTK Imager 같은 이미징 도구로 만듭니다.",
        "'그림/사본'을 뜻하는 영단어가 뒤에 옵니다."
      ],
      "en": [
        "Made with imaging tools such as FTK Imager.",
        "Ends with the word meaning 'a copy/picture'."
      ]
    }
  },
  {
    "id": "t1_pcap",
    "tier": 1,
    "cat": "network",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "ff3ed7cbf694b9da51b7617e827def2dfaf824596500228573f4cd5857793b33",
    "fmt": "확장자 / extension",
    "title": {
      "ko": "캡처한 패킷의 확장자",
      "en": "Extension for Captured Packets"
    },
    "prompt": {
      "ko": "Wireshark/tcpdump로 캡처한 네트워크 패킷 파일의 표준 확장자는? (점 없이, 소문자)",
      "en": "What is the standard file extension for a network packet capture from Wireshark/tcpdump? (no dot, lowercase)"
    },
    "hints": {
      "ko": [
        "'packet capture'의 줄임말입니다.",
        "네 글자."
      ],
      "en": [
        "Short for 'packet capture'.",
        "Four letters."
      ]
    }
  },
  {
    "id": "t1_custody",
    "tier": 1,
    "cat": "forensics",
    "track": "forensics",
    "points": 70,
    "ci": true,
    "hash": "5a77bdc97e1a5cdb8b99a3f6163306eb890f6b0c9b660c71b62fa9a176e75297",
    "fmt": "문구 / phrase",
    "title": {
      "ko": "증거가 거쳐온 손길의 기록",
      "en": "The Record of Every Hand It Passed Through"
    },
    "prompt": {
      "ko": "압수한 증거가 발견 시점부터 법정 제출까지 누구를 거쳤는지 문서로 남겨, 증거 무결성을 증명하는 절차를 부르는 세 단어(예: `chain of ___`)는?",
      "en": "What three-word term (e.g. `chain of ___`) names the documented trail of everyone who handled a piece of evidence, from seizure to court, proving its integrity?"
    },
    "hints": {
      "ko": [
        "'사슬'을 뜻하는 단어로 시작합니다.",
        "chain of ____."
      ],
      "en": [
        "Starts with the word for 'chain'.",
        "chain of ____."
      ]
    }
  },
  {
    "id": "t4_usbstor",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 155,
    "ci": true,
    "hash": "dd32fb1174150592a3cf077fad0c9542021b1b7833d82ad29de64f3cabc6ebe8",
    "fmt": "레지스트리 키 / registry key",
    "title": {
      "ko": "USB가 남기는 흔적",
      "en": "The Trace a USB Leaves Behind"
    },
    "prompt": {
      "ko": "Windows 레지스트리에서 과거에 연결됐던 USB 저장장치의 시리얼 번호·제조사 정보가 남는 대표 키 이름은? (한 단어)",
      "en": "Which Windows Registry key preserves the serial number and vendor info of previously connected USB storage devices? (one word)"
    },
    "hints": {
      "ko": [
        "`HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\` 아래에 있습니다.",
        "'USB'와 '저장소(storage)'의 합성입니다."
      ],
      "en": [
        "Found under `HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\`.",
        "A blend of 'USB' and 'storage'."
      ]
    }
  },
  {
    "id": "t0_dd",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 50,
    "ci": true,
    "hash": "9b7ecc6eeb83abf9ade10fe38865df4499be3568dcc507ae2ec3b44989cb0093",
    "fmt": "명령어 / command (2글자 / 2 chars)",
    "title": {
      "ko": "비트 단위 그대로 복제",
      "en": "Bit-for-Bit Copy"
    },
    "prompt": {
      "ko": "포렌식에서 원본 저장매체를 변경하지 않고 디스크나 파티션을 비트 단위로 그대로 복제(이미징)할 때 쓰는 고전적인 두 글자짜리 유닉스 명령은?",
      "en": "In forensics, which classic two-letter Unix command makes a bit-for-bit copy (image) of a disk or partition without altering the original media?"
    },
    "hints": {
      "ko": [
        "`____ if=/dev/sda of=disk.img bs=4M` 형태로 사용합니다.",
        "'data duplicator' 또는 'disk dump' 라고도 풀어 부릅니다."
      ],
      "en": [
        "Used as `____ if=/dev/sda of=disk.img bs=4M`.",
        "Sometimes expanded as 'data duplicator' or 'disk dump'."
      ]
    }
  },
  {
    "id": "t1_tcpdump",
    "tier": 1,
    "cat": "network",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "3096fd17ccf8ee00173d4d753aa67e476526b800ae6eff06b055d71fc4ce6dff",
    "fmt": "명령어 / command",
    "title": {
      "ko": "명령줄의 패킷 사냥꾼",
      "en": "The Command-Line Packet Hunter"
    },
    "prompt": {
      "ko": "GUI 없이 터미널에서 네트워크 패킷을 실시간 캡처하고 `.pcap` 로 저장하는 대표적인 명령줄 도구는? (GUI 패킷 분석기의 텍스트판 형제, 한 단어)",
      "en": "Which classic command-line tool captures network packets in real time from a terminal (no GUI) and can save them as `.pcap`? (the text-mode sibling of the well-known GUI analyzer, one word)"
    },
    "hints": {
      "ko": [
        "이름은 'TCP' + 'dump' 의 합성입니다.",
        "`____ -i eth0 -w out.pcap` 형태로 캡처합니다."
      ],
      "en": [
        "Its name blends 'TCP' + 'dump'.",
        "Capture with `____ -i eth0 -w out.pcap`."
      ]
    }
  },
  {
    "id": "t2_carving",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 85,
    "ci": true,
    "hash": "117b405eea833174250f59af5a817ab521ebafecc77441483223441a0ec4a890",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "메타데이터 없이 파일을 건지다",
      "en": "Recover Files With No Metadata"
    },
    "prompt": {
      "ko": "파일시스템 구조나 디렉터리 정보가 손상돼 없을 때, 원시 바이트 스트림에서 알려진 헤더·푸터 시그니처(예: JPEG 의 `FF D8 ... FF D9`)를 찾아 파일을 통째로 복원하는 포렌식 기법을 '파일 ______' 라 부릅니다. 빈칸에 들어갈 영어 한 단어는? (foremost·scalpel 같은 도구가 수행)",
      "en": "When filesystem structures or directory entries are gone, the forensic technique of scanning a raw byte stream for known header/footer signatures (e.g. JPEG's `FF D8 ... FF D9`) to reconstruct whole files is called 'file ______'. What one English word fills the blank? (tools like foremost / scalpel do this)"
    },
    "hints": {
      "ko": [
        "고기를 '발라내다' 라는 뜻의 영어 단어와 같습니다.",
        "`foremost`, `scalpel`, `photorec` 이 이 작업을 수행합니다."
      ],
      "en": [
        "Same English word as slicing/carving meat.",
        "`foremost`, `scalpel`, and `photorec` perform it."
      ]
    }
  },
  {
    "id": "t2_ads",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 90,
    "ci": true,
    "hash": "788eb2efc52660fe41472319f0d2c623be6540c956921b3632fcc934bf1be10d",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "파일 뒤에 숨은 흐름",
      "en": "The Stream Behind the File"
    },
    "prompt": {
      "ko": "NTFS 파일시스템에서 하나의 파일에 눈에 보이지 않는 별도의 데이터 흐름을 덧붙여 악성코드를 숨길 수 있습니다(`notepad file.txt:hidden.exe`). 이 '대체 데이터 스트림' 기능을 가리키는 3글자 영어 약어는?",
      "en": "On NTFS, a file can carry an invisible extra data stream used to hide malware (`notepad file.txt:hidden.exe`). What is the 3-letter English acronym for this 'alternate data stream' feature?"
    },
    "hints": {
      "ko": [
        "'Alternate Data Stream' 의 머리글자입니다.",
        "`dir /r` 또는 `Get-Item -Stream *` 로 탐지합니다."
      ],
      "en": [
        "Initials of 'Alternate Data Stream'.",
        "Detect with `dir /r` or `Get-Item -Stream *`."
      ]
    }
  },
  {
    "id": "t4_mft",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 150,
    "ci": true,
    "hash": "29a44d58cc6374a2e166bb1738c0ca4f012d7ba929f18365ff5f7e75ba99e6b7",
    "fmt": "약어 / acronym (3글자 / 3 chars, $ 제외 / no $)",
    "title": {
      "ko": "모든 파일의 장부",
      "en": "The Ledger of Every File"
    },
    "prompt": {
      "ko": "NTFS 볼륨에서 모든 파일·디렉터리의 이름·타임스탬프·클러스터 위치 등 레코드를 담아, 디스크 포렌식과 타임라인 분석의 핵심이 되는 메타데이터 구조가 있습니다. 이 구조의 3글자 약어는? (파일명에 붙는 `$` 접두사는 빼고 약어만 입력)",
      "en": "On an NTFS volume there is a metadata structure holding a record for every file and directory — names, timestamps, cluster locations — central to disk forensics and timeline analysis. What is its 3-letter acronym? (enter the acronym only, without the `$` prefix its filename carries)"
    },
    "hints": {
      "ko": [
        "'Master File Table' 의 머리글자입니다.",
        "`$` 접두사가 붙는 NTFS 메타파일이며, 각 레코드 크기는 보통 1024바이트."
      ],
      "en": [
        "Initials of 'Master File Table'.",
        "A `$`-prefixed NTFS metafile; each record is usually 1024 bytes."
      ]
    }
  },
  {
    "id": "t4_timestomp",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 155,
    "ci": true,
    "hash": "bd79d5302f5ec355456457038a0bf3fd630f6c0bf6364176acb5ccf878901d1c",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "시간을 지우는 자",
      "en": "The One Who Rewrites Time"
    },
    "prompt": {
      "ko": "공격자가 조사관의 타임라인 분석을 방해하려고 파일의 MACB(수정·접근·변경·생성) 타임스탬프를 위조하는 안티-포렌식 기법이 있습니다. Metasploit/Meterpreter 의 동명 도구로도 유명한, '시간(time)'과 '짓밟다(stomp)'를 합친 이 기법의 한 단어 이름은?",
      "en": "To disrupt an investigator's timeline analysis, attackers forge a file's MACB (Modified/Accessed/Changed/Born) timestamps. What is the one-word name of this anti-forensic technique — blending 'time' + 'stomp' and also the name of a Metasploit/Meterpreter tool?"
    },
    "hints": {
      "ko": [
        "'time' + 'stomp(짓밟다)' 의 합성어입니다.",
        "$STANDARD_INFORMATION 타임스탬프는 바꿔도 $FILE_NAME 은 못 바꾸는 경우가 많아 탐지 단서가 됩니다."
      ],
      "en": [
        "A blend of 'time' + 'stomp'.",
        "It often alters $STANDARD_INFORMATION timestamps but not $FILE_NAME — a detection clue."
      ]
    }
  },
  {
    "id": "t0_authfactor",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 45,
    "ci": true,
    "hash": "cb0356a0532e824bd17b1ad6f24af01a2d9bbdda8891918ab6b91d9835f7c3ec",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "비밀번호만으론 부족하다",
      "en": "A Password Is Not Enough"
    },
    "prompt": {
      "ko": "클라우드 계정 탈취를 막는 가장 기본적인 통제는, 비밀번호에 더해 서로 다른 종류의 인증 요소를 추가로 요구하는 것입니다. 이 통제를 가리키는 3글자 영어 약자는? (`2FA` 를 포함하는 상위 용어)",
      "en": "The most basic control against cloud account takeover is requiring an additional, different kind of authentication factor on top of the password. What is the 3-letter English acronym for this control? (the umbrella term that covers `2FA`)"
    },
    "hints": {
      "ko": [
        "'Multi-Factor Authentication' 의 머리글자입니다.",
        "루트 계정에 이것이 없으면 클라우드 설정 점검 도구가 가장 먼저 경고합니다."
      ],
      "en": [
        "Initials of 'Multi-Factor Authentication'.",
        "Missing it on the root account is the first thing a cloud posture scanner flags."
      ]
    }
  },
  {
    "id": "t1_dockerfile",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 60,
    "ci": true,
    "hash": "75857a45899985be4c4d941e90b6b396d6c92a4c7437aaf0bf102089fe21379d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "이미지의 출발점",
      "en": "Where the Image Starts"
    },
    "prompt": {
      "ko": "Dockerfile에서 베이스 이미지를 지정하는, 보통 파일의 첫 줄에 오는 명령어(instruction)는? (예: `____ ubuntu:22.04`)",
      "en": "Which Dockerfile instruction declares the base image and normally sits on the first line? (e.g. `____ ubuntu:22.04`)"
    },
    "hints": {
      "ko": [
        "'~에서 가져온다'는 뜻의 영어 전치사 4글자입니다.",
        "`FR__` — 태그를 `latest`로 두면 재현성·공급망 위험이 커집니다."
      ],
      "en": [
        "A 4-letter English preposition marking where something originates.",
        "`FR__` — pinning it to `latest` hurts reproducibility and supply-chain safety."
      ]
    }
  },
  {
    "id": "t1_iac",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 60,
    "ci": true,
    "hash": "e914d68f72dbeaa29a91a4c2f9f3108f4cc6f4630a3712982fee13cfb45169fe",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "인프라를 코드로",
      "en": "Infrastructure as Code"
    },
    "prompt": {
      "ko": "웹 UI에서 손으로 클릭하는 대신, 선언적 설정 파일(코드)로 인프라를 프로비저닝·관리하는 방식을 가리키는 3글자 약어는?",
      "en": "What 3-letter acronym names the practice of provisioning and managing infrastructure through declarative definition files (code) instead of clicking through a web UI by hand?"
    },
    "hints": {
      "ko": [
        "Infrastructure as Code.",
        "`I_C` — 변경 이력을 Git으로 추적할 수 있습니다."
      ],
      "en": [
        "Infrastructure as Code.",
        "`I_C` — changes get tracked in Git."
      ]
    }
  },
  {
    "id": "t1_terraform",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 65,
    "ci": true,
    "hash": "94dc3ea57721d541aae09b7bf2368c1e20d4c89996ff6df4349d86048877c0e7",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "선언적 프로비저닝 도구",
      "en": "Declarative Provisioning Tool"
    },
    "prompt": {
      "ko": "HashiCorp가 만든 오픈소스 인프라 자동화 도구로, HCL 언어와 `.tf` 파일로 클라우드 리소스를 선언적으로 프로비저닝하는 도구의 이름은? (한 단어)",
      "en": "Which open-source HashiCorp tool provisions cloud resources declaratively using the HCL language and `.tf` files? (one word)"
    },
    "hints": {
      "ko": [
        "`terra____` — 이름은 '지구'를 뜻합니다.",
        "`.tf` 파일과 `plan`/`apply` 명령을 씁니다."
      ],
      "en": [
        "`terra____` — its name evokes 'earth'.",
        "Uses `.tf` files with `plan`/`apply` commands."
      ]
    }
  },
  {
    "id": "t2_k8sauthz",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "2552b1c0272ab701af519fff4e4299f03720e72a3e3b57f7214b81d13c7eceff",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "역할로 권한을 묶다",
      "en": "Permissions by Role"
    },
    "prompt": {
      "ko": "쿠버네티스와 대부분의 클라우드에서, 권한을 사용자에게 직접 주지 않고 역할에 묶은 뒤 사용자를 그 역할에 바인딩하는 접근 제어 모델의 4글자 영어 약자는?",
      "en": "In Kubernetes and most clouds, permissions are attached to a role and users are bound to that role instead of being granted directly. What is the 4-letter English acronym for this access-control model?"
    },
    "hints": {
      "ko": [
        "'Role-Based Access Control' 의 머리글자입니다.",
        "K8s에서는 `Role`/`ClusterRole` 과 `RoleBinding` 으로 구현합니다."
      ],
      "en": [
        "Initials of 'Role-Based Access Control'.",
        "K8s implements it with `Role`/`ClusterRole` plus `RoleBinding`."
      ]
    }
  },
  {
    "id": "t2_sg",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "b42e18366abaf7d25debe1765391f2a4b1f3a16708045d2e6642a14fc4c93144",
    "fmt": "CIDR 표기 / CIDR notation",
    "title": {
      "ko": "전 세계에 열린 문",
      "en": "Open to the World"
    },
    "prompt": {
      "ko": "보안그룹·방화벽 규칙 감사에서 가장 흔히 지적되는 오설정은 SSH(22번) 포트를 인터넷 전체에 열어두는 것입니다. 이때 소스로 설정된, **모든 IPv4 주소**를 뜻하는 CIDR 표기를 그대로 입력하세요.",
      "en": "The most common finding in security-group/firewall audits is leaving SSH (port 22) open to the entire internet. Enter the CIDR notation used as that source — the one meaning **any IPv4 address**."
    },
    "hints": {
      "ko": [
        "`x.x.x.x/y` 형태이며, 프리픽스 길이가 0이면 주소 전체를 포함합니다.",
        "IPv6에서 이에 대응하는 표기는 `::/0` 입니다."
      ],
      "en": [
        "Form `x.x.x.x/y`; a prefix length of 0 covers every address.",
        "The IPv6 counterpart is `::/0`."
      ]
    }
  },
  {
    "id": "t3_dockersock",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": true,
    "hash": "71329c4cc6e32171553fa81d044eb31d1a3aac52ba9376c4a99f4505c494cf5b",
    "fmt": "절대 경로 / absolute path",
    "title": {
      "ko": "소켓 하나면 호스트가 열린다",
      "en": "One Socket to Own the Host"
    },
    "prompt": {
      "ko": "컨테이너 안에 호스트의 Docker 데몬 유닉스 소켓을 마운트하면 그 컨테이너는 사실상 호스트 root가 됩니다(원하는 특권 컨테이너를 새로 띄울 수 있으므로). 이 소켓의 기본 절대 경로는?",
      "en": "Mounting the host's Docker daemon Unix socket into a container effectively hands it host root (it can spawn any container it likes, with full host access). What is that socket's default absolute path?"
    },
    "hints": {
      "ko": [
        "`/var/run/` 아래에 있는 소켓 파일입니다.",
        "`docker -H unix://<경로>` 의 기본값이며, 파일명은 `docker.____` 입니다."
      ],
      "en": [
        "A socket file under `/var/run/`.",
        "The default for `docker -H unix://<path>`; the file is named `docker.____`."
      ]
    }
  },
  {
    "id": "t3_imdsv2",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 125,
    "ci": true,
    "hash": "373cb2c6d4fe2778441d4f0266505b699fa518d002e5793b87f9b48836de3f62",
    "fmt": "HTTP 메서드 / HTTP method",
    "title": {
      "ko": "토큰 없이는 못 준다",
      "en": "No Token, No Metadata"
    },
    "prompt": {
      "ko": "IMDSv2는 SSRF로 인스턴스 자격증명이 새어나가는 것을 막기 위해, 메타데이터를 읽기 전에 먼저 세션 토큰을 발급받도록 요구합니다(`/latest/api/token`). 이 토큰 요청에 사용하는 HTTP 메서드는? — 평범한 SSRF로는 흉내내기 어려운 메서드라는 점이 방어의 핵심입니다.",
      "en": "IMDSv2 stops SSRF-based credential theft by requiring a session token before metadata can be read (`/latest/api/token`). Which HTTP method issues that token request? The defense works precisely because plain SSRF struggles to send it."
    },
    "hints": {
      "ko": [
        "GET도 POST도 아닙니다. REST에서 자원의 생성·교체에 쓰는 메서드입니다.",
        "3글자이며, `X-aws-ec2-metadata-token-ttl-seconds` 헤더와 함께 보냅니다."
      ],
      "en": [
        "Neither GET nor POST — the REST verb for create/replace.",
        "Three letters, sent with the `X-aws-ec2-metadata-token-ttl-seconds` header."
      ]
    }
  },
  {
    "id": "t0_writeblocker",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 50,
    "ci": true,
    "hash": "86769308ebb37d8caa407ecbcd1b314ea73428e47970f46d1d8828b2badda879",
    "fmt": "장비 이름 / device name (두 단어 / two words)",
    "title": {
      "ko": "증거를 지키는 한 방향 장치",
      "en": "The One-Way Guardian of Evidence"
    },
    "prompt": {
      "ko": "포렌식 이미징 중 원본 저장매체에 단 한 바이트도 기록되지 않도록, 쓰기 신호를 물리적으로 차단하고 읽기만 허용하는 하드웨어 장치를 무엇이라 부르나요? (영어 두 단어)",
      "en": "During forensic imaging, which hardware device physically blocks all write signals to the original media—allowing only reads—so not a single byte is altered? (two English words)"
    },
    "hints": {
      "ko": [
        "원본 무결성을 보장하는 '증거 보존'의 핵심 장비입니다.",
        "첫 단어는 'read'의 반대, 둘째 단어는 '막는 것/차단기'를 뜻합니다."
      ],
      "en": [
        "It is the key evidence-preservation device that guarantees original integrity.",
        "First word is the opposite of 'read'; the second means something that obstructs or stops."
      ]
    }
  },
  {
    "id": "t1_pemagic",
    "tier": 1,
    "cat": "forensics",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "3ed0256da8da5eabae7aa1680886a2aa394dd7c002eb2f3b02e9f0f9ec9daa2c",
    "fmt": "시그니처 / signature (2글자 / 2 chars)",
    "title": {
      "ko": "윈도우 실행파일의 서명",
      "en": "The Windows Executable's Signature"
    },
    "prompt": {
      "ko": "모든 Windows PE 실행파일(.exe/.dll)은 파일 맨 앞 2바이트가 항상 같은 ASCII 시그니처로 시작합니다. 헥스 에디터로 `.exe`를 열면 첫 두 글자로 보이는 이 매직 시그니처는 무엇인가요? (ELF의 `7F 45 4C 46`에 대응하는 PE의 매직)",
      "en": "Every Windows PE executable (.exe/.dll) begins with the same fixed 2-byte ASCII signature at the very start of the file. Opening a `.exe` in a hex editor, what two letters appear first? (the PE counterpart to ELF's `7F 45 4C 46`)"
    },
    "hints": {
      "ko": [
        "16진수로는 `4D 5A` 이며, 이를 ASCII로 읽으면 답이 됩니다.",
        "DOS 시절 설계자 Mark Zbikowski의 이니셜에서 유래했습니다."
      ],
      "en": [
        "In hex it is `4D 5A`; read those bytes as ASCII to get the answer.",
        "It comes from the initials of DOS designer Mark Zbikowski."
      ]
    }
  },
  {
    "id": "t1_dex",
    "tier": 1,
    "cat": "forensics",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "9d0fbf9349f646f1435072f2b0212084752ef4601bd6b012fbbe61b6c5e03930",
    "fmt": "확장자 / extension (3글자 / 3 chars)",
    "title": {
      "ko": "안드로이드가 실행하는 바이트코드",
      "en": "The Bytecode Android Runs"
    },
    "prompt": {
      "ko": "안드로이드 앱을 리버싱할 때, 자바 소스가 컴파일된 뒤 Dalvik/ART 가상머신이 실행하는 바이트코드는 APK 내부의 `classes.___` 파일에 담깁니다. 이 3글자 확장자는 무엇인가요?",
      "en": "When reversing an Android app, the bytecode executed by the Dalvik/ART VM (after Java is compiled) lives inside the APK as a `classes.___` file. What is this three-letter extension?"
    },
    "hints": {
      "ko": [
        "'Dalvik EXecutable'의 약자입니다.",
        "`apktool`이나 `jadx`로 이 파일을 열어 스마트폰 악성코드를 분석합니다."
      ],
      "en": [
        "It is short for 'Dalvik EXecutable'.",
        "You open this file with `apktool` or `jadx` to analyze mobile malware."
      ]
    }
  },
  {
    "id": "t2_packing",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 85,
    "ci": true,
    "hash": "7c6e059c91d86331d06879929b56905cb02d57df32d4c491744e7b3e7eb9918a",
    "fmt": "한 단어 / one word (-ing으로 끝남 / ends in -ing)",
    "title": {
      "ko": "정적 분석을 무력화하는 압축",
      "en": "The Compression That Blinds Static Analysis"
    },
    "prompt": {
      "ko": "악성코드가 실제 코드를 압축·암호화해 껍데기(stub) 속에 숨기고, 실행 시점에만 메모리에서 원본을 복원해 정적 분석과 시그니처 탐지를 회피하는 기법을 무엇이라 하나요? (UPX가 대표 도구, 영어 한 단어의 -ing 형태)",
      "en": "What is the technique where malware compresses/encrypts its real code inside a stub and restores the original only in memory at runtime—evading static analysis and signature detection? (UPX is the classic tool; one English word, the '-ing' form)"
    },
    "hints": {
      "ko": [
        "실행파일을 이 상태로 만드는 도구를 'packer'라고 부릅니다.",
        "이 기법이 적용된 바이너리는 원본 코드가 숨겨져 문자열 추출이 거의 되지 않습니다."
      ],
      "en": [
        "The tool that puts an executable into this state is called a 'packer'.",
        "A binary in this state hides its real code, so string extraction yields almost nothing."
      ]
    }
  },
  {
    "id": "t2_entropy",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 85,
    "ci": true,
    "hash": "67671a2f53dd910a8b35840edb6a0a1e751ae5532178ca7f025b823eee317992",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "무질서도로 숨긴 것을 찾다",
      "en": "Finding the Hidden by Its Disorder"
    },
    "prompt": {
      "ko": "파일이나 PE 섹션의 바이트가 얼마나 무작위·무질서한지를 0~8 사이 수치로 측정해, 값이 8에 가까우면 압축·암호화되었다고 판단하는 정보이론 지표는 무엇인가요? (섀넌이 정의, 영어 한 단어)",
      "en": "Which information-theory metric scores how random/disordered the bytes of a file or PE section are on a 0–8 scale—so a value near 8 signals compression or encryption? (defined by Shannon; one English word)"
    },
    "hints": {
      "ko": [
        "열역학에서 '무질서도'를 뜻하는 바로 그 단어입니다.",
        "`ent`, `binwalk -E`, PEStudio가 이 값을 계산해 줍니다."
      ],
      "en": [
        "It is the very word thermodynamics uses for 'disorder'.",
        "`ent`, `binwalk -E`, and PEStudio all compute this value for you."
      ]
    }
  },
  {
    "id": "t3_hollowing",
    "tier": 3,
    "cat": "forensics",
    "track": "forensics",
    "points": 105,
    "ci": true,
    "hash": "34e36214d1921828dd0bb0ed46fdf64a14d0d33aa3757aee9e40acfe9df5711f",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "정상 프로세스의 껍데기를 빼앗다",
      "en": "Stealing a Legit Process's Shell"
    },
    "prompt": {
      "ko": "악성코드가 정상 프로세스를 일시정지 상태로 생성한 뒤, 그 프로세스의 메모리 이미지를 통째로 비워내고(unmap) 악성 PE로 덮어쓴 다음 재개시켜 정상 프로세스로 위장하는 대표적 코드 인젝션 기법을 'process ______'라 부릅니다. 빈칸에 들어갈 영어 한 단어는? (속을 파낸다는 뜻)",
      "en": "Malware spawns a legitimate process in a suspended state, unmaps its entire memory image, overwrites it with a malicious PE, then resumes it to masquerade as the legit process. This classic code-injection technique is called 'process ______'. What one English word fills the blank? (it means to carve out the inside)"
    },
    "hints": {
      "ko": [
        "영어로 '속을 파내다/텅 비게 하다'라는 동사의 -ing 형태입니다.",
        "MITRE ATT&CK의 Process Injection(T1055) 하위 기법으로 분류됩니다."
      ],
      "en": [
        "It is the '-ing' form of an English verb meaning 'to carve out the inside / make empty'.",
        "It is classified under MITRE ATT&CK Process Injection (T1055)."
      ]
    }
  },
  {
    "id": "t0_uname",
    "tier": 0,
    "cat": "linux",
    "track": "system",
    "points": 45,
    "ci": true,
    "hash": "5c0be87ed7434d69005f8bbd84cad8ae6abfd49121b4aaeeb4c1f4a2e2987711",
    "fmt": "명령어 / command",
    "title": {
      "ko": "이 시스템의 정체를 물어라",
      "en": "Ask the System Who It Is"
    },
    "prompt": {
      "ko": "리눅스에서 실행 중인 커널의 이름·버전·머신 아키텍처 같은 시스템 정보를 출력하는 표준 명령은? (`-a` 옵션을 붙이면 전부 한 줄로 쏟아내는 그 명령, 한 단어)",
      "en": "Which standard Linux command prints system information such as the running kernel name, version, and machine architecture? (the one you run with `-a` to dump it all on one line — one word)"
    },
    "hints": {
      "ko": [
        "POSIX 표준 유틸리티이며, 이름은 'unix name' 을 줄인 것입니다.",
        "`____ -r` 은 커널 릴리스만, `____ -m` 은 머신 하드웨어 이름만 출력합니다."
      ],
      "en": [
        "A POSIX standard utility; its name is short for 'unix name'.",
        "`____ -r` prints just the kernel release; `____ -m` prints just the machine hardware name."
      ]
    }
  },
  {
    "id": "t1_readelf",
    "tier": 1,
    "cat": "reversing",
    "track": "system",
    "points": 65,
    "ci": true,
    "hash": "c06edbcb7bfdeb6bc176a30810bed1afd47feb85f65c2bbcf66853164f7515e4",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "ELF 헤더를 낱낱이 펼쳐라",
      "en": "Unfold Every ELF Header"
    },
    "prompt": {
      "ko": "리눅스 ELF 실행파일의 헤더·섹션 테이블·프로그램 헤더·심볼을 상세히 출력하는 binutils 전용 도구는? (`-h` 로 ELF 헤더, `-S` 로 섹션 목록을 보는 그 명령, 한 단어)",
      "en": "Which dedicated binutils tool prints an ELF executable's header, section table, program headers, and symbols in detail? (`-h` shows the ELF header, `-S` the section list — one word)"
    },
    "hints": {
      "ko": [
        "이름은 'read' + 실행파일 포맷 이름(ELF)의 조합입니다.",
        "역어셈블은 하지 않고 ELF 파일의 구조(헤더·섹션·심볼)를 해석해 보여주는 도구입니다."
      ],
      "en": [
        "Its name combines 'read' with the executable format's name (ELF).",
        "It does not disassemble — it parses and displays the ELF structure (headers, sections, symbols)."
      ]
    }
  },
  {
    "id": "t1_objdump",
    "tier": 1,
    "cat": "reversing",
    "track": "system",
    "points": 70,
    "ci": true,
    "hash": "306e2b4264b7dbf0107520e1823108bd5d17635be7742b6f9660a6c527cb4fd2",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "바이너리를 어셈블리로 풀어헤쳐라",
      "en": "Spill a Binary into Assembly"
    },
    "prompt": {
      "ko": "실행파일의 기계어를 역어셈블(`-d`)해 어셈블리로 보여 주는 대표적인 binutils 도구는? (오브젝트 파일을 통째로 덤프한다는 뜻의 이름, 한 단어)",
      "en": "Which classic binutils tool disassembles (`-d`) a binary's machine code into assembly? (its name means 'dump the object file' — one word)"
    },
    "hints": {
      "ko": [
        "이름은 'object' 와 'dump' 를 붙인 합성어입니다.",
        "`____ -d ./bin` 으로 .text 섹션을 역어셈블합니다."
      ],
      "en": [
        "Its name is 'object' joined with 'dump'.",
        "`____ -d ./bin` disassembles the .text section."
      ]
    }
  },
  {
    "id": "t2_strace",
    "tier": 2,
    "cat": "linux",
    "track": "system",
    "points": 90,
    "ci": true,
    "hash": "761f8a60b54fcf3965300ced84ed9a0db0eb70c89482e61f9e79a1a1ca251f18",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "커널을 두드리는 소리를 엿듣다",
      "en": "Eavesdrop on Every Kernel Call"
    },
    "prompt": {
      "ko": "실행 중인 프로그램이 커널에 요청하는 시스템 콜(open·read·write 등)을 실시간으로 가로채 순서대로 출력해 주는 리눅스 진단 도구는? (라이브러리 호출을 추적하는 `ltrace` 의 시스템 콜 짝, 한 단어)",
      "en": "Which Linux diagnostic tool intercepts and prints, in order, the system calls (open, read, write, …) a running program makes to the kernel? (the syscall counterpart of `ltrace`, which traces library calls — one word)"
    },
    "hints": {
      "ko": [
        "이름은 'system call' 을 뜻하는 한 글자 접두어 + 'trace' 입니다.",
        "`____ -f ./prog` 는 자식 프로세스까지 따라가며 시스템 콜을 기록합니다."
      ],
      "en": [
        "Its name is a one-letter prefix for 'system call' + 'trace'.",
        "`____ -f ./prog` follows child processes while logging syscalls."
      ]
    }
  },
  {
    "id": "t3_pie",
    "tier": 3,
    "cat": "pwn",
    "track": "system",
    "points": 120,
    "ci": true,
    "hash": "558211ed72b2d6967037419dff6f1e7cfd002d178c8fdeeb1239760d4e4c4059",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "실행파일마저 매번 자리를 바꾸게 하라",
      "en": "Even the Executable Won't Sit Still"
    },
    "prompt": {
      "ko": "로더의 주소 무작위화가 실행파일 본체(.text 등)의 로드 주소까지 매 실행마다 흩어놓을 수 있도록, 위치 독립적으로 컴파일된 실행파일을 가리키는 3글자 약어는? (`checksec` 이 이 항목을 enabled/disabled 로 보고하며, 이것이 없으면 실행파일의 코드 주소가 고정됩니다)",
      "en": "What 3-letter abbreviation names an executable compiled position-independently, so the loader's address randomization can cover even the main program's load address (.text, …) on every run? (`checksec` reports this field as enabled/disabled; without it the executable's code addresses stay fixed)"
    },
    "hints": {
      "ko": [
        "Position-______ Executable 세 단어의 머리글자입니다.",
        "checksec 출력에서 'No ___' 로 표시되면 코드 주소가 고정이라 가젯 주소가 예측 가능해집니다."
      ],
      "en": [
        "It is the initials of Position-______ Executable.",
        "checksec shows 'No ___' when code addresses are fixed, making gadget addresses predictable."
      ]
    }
  },
  {
    "id": "t4_tcache",
    "tier": 4,
    "cat": "pwn",
    "track": "system",
    "points": 155,
    "ci": true,
    "hash": "30bf9a328005656691e93a15d16168cee5fa58f1fe4ff4c2d9d1f9d8baf42253",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "해제된 청크의 은밀한 캐시를 노려라",
      "en": "Poison the Cache of Freed Chunks"
    },
    "prompt": {
      "ko": "glibc 2.26 이후 malloc 이 성능을 위해 도입한, 스레드마다 갓 해제된(free) 힙 청크를 단일 연결 리스트로 담아 두는 캐시 계층의 이름은? (공격자가 이 리스트의 next 포인터를 덮어써 임의 주소 할당을 얻는 'poisoning' 으로 악명 높은, 한 단어 소문자)",
      "en": "Since glibc 2.26, malloc keeps a per-thread cache layer that stores recently freed heap chunks in a singly-linked list for speed. Attackers overwrite that list's next pointer for an arbitrary allocation ('poisoning'). What is this layer's name? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "이름은 'thread' 의 머리글자 + 'cache' 를 붙인 것입니다.",
        "관련 익스플로잇 기법을 '____ poisoning' 이라 부릅니다."
      ],
      "en": [
        "Its name is the initial of 'thread' + 'cache'.",
        "The related exploit technique is called '____ poisoning'."
      ]
    }
  },
  {
    "id": "t0_pwd",
    "tier": 0,
    "cat": "system",
    "track": "system",
    "points": 40,
    "ci": true,
    "hash": "a1159e9df3670d549d04524532629f5477ceb7deec9b45e47e8c009506ecb2c8",
    "fmt": "명령어 / command",
    "title": {
      "ko": "현재 디렉터리 출력",
      "en": "Where Am I"
    },
    "prompt": {
      "ko": "리눅스에서 현재 작업 중인 디렉터리의 절대 경로를 출력하는 명령어는? (한 단어)",
      "en": "Which Linux command prints the absolute path of your current working directory? (one word)"
    },
    "hints": {
      "ko": [
        "'print working directory'의 약자입니다.",
        "`___` 를 치면 예: `/home/user` 가 출력됩니다."
      ],
      "en": [
        "Short for 'print working directory'.",
        "Typing `___` prints e.g. `/home/user`."
      ]
    }
  },
  {
    "id": "t0_ps",
    "tier": 0,
    "cat": "system",
    "track": "system",
    "points": 45,
    "ci": true,
    "hash": "6527c9361a2f469c5275afcb5d06e53013367cd231995de13dc7218711388382",
    "fmt": "명령어 / command",
    "title": {
      "ko": "실행 중인 프로세스",
      "en": "Running Processes"
    },
    "prompt": {
      "ko": "현재 실행 중인 프로세스 목록을 그 시점의 상태로 한 번에 보여 주는 리눅스 명령어는? (한 단어, 흔히 `aux` 옵션과 함께 씀)",
      "en": "Which Linux command lists the currently running processes as they are at that moment? (one word, often used with `aux`)"
    },
    "hints": {
      "ko": [
        "'process status'의 약자입니다.",
        "`__ aux` 로 모든 사용자의 프로세스를 봅니다."
      ],
      "en": [
        "Short for 'process status'.",
        "`__ aux` lists every user's processes."
      ]
    }
  },
  {
    "id": "t1_chown",
    "tier": 1,
    "cat": "system",
    "track": "system",
    "points": 65,
    "ci": true,
    "hash": "f92b5215aa322cc1e02f2d805b390d62d5ff942c8fa66e53f417a10abbb959cd",
    "fmt": "명령어 / command",
    "title": {
      "ko": "소유자 바꾸기",
      "en": "Change the Owner"
    },
    "prompt": {
      "ko": "파일이나 디렉터리의 소유자(owner)를 변경하는 리눅스 명령어는? (한 단어)",
      "en": "Which Linux command changes the owner of a file or directory? (one word)"
    },
    "hints": {
      "ko": [
        "'change owner'를 줄인 이름입니다.",
        "`____ root:root file` 처럼 그룹까지 함께 바꿀 수 있습니다."
      ],
      "en": [
        "Its name shortens 'change owner'.",
        "`____ root:root file` can set the group too."
      ]
    }
  },
  {
    "id": "t2_nm",
    "tier": 2,
    "cat": "system",
    "track": "system",
    "points": 90,
    "ci": true,
    "hash": "2ca7289b5248632c8fe5386b972e8fde6585068c5cb8e2948489e10e7be6d4d8",
    "fmt": "도구 이름 / tool name (2글자 / 2 chars)",
    "title": {
      "ko": "심볼 테이블 나열",
      "en": "List the Symbols"
    },
    "prompt": {
      "ko": "오브젝트 파일이나 실행 파일의 심볼 테이블(함수·전역변수 이름과 주소)을 나열하는 binutils 도구는? (두 글자 명령어)",
      "en": "Which binutils tool lists the symbol table (function/global names and addresses) of an object or executable? (two-letter command)"
    },
    "hints": {
      "ko": [
        "'name'의 앞 두 글자와 같은 두 글자 이름입니다.",
        "`__ -C a.out` 로 C++ 심볼을 디맹글해 봅니다."
      ],
      "en": [
        "A two-letter name, like the first two letters of 'name'.",
        "`__ -C a.out` demangles C++ symbols."
      ]
    }
  },
  {
    "id": "t3_ptrace",
    "tier": 3,
    "cat": "system",
    "track": "system",
    "points": 115,
    "ci": true,
    "hash": "160ec8e507f2527b4de8f753c43de80b5aca90d0918e709d88c5519d6b122e34",
    "fmt": "시스템 콜 / syscall",
    "title": {
      "ko": "프로세스를 붙잡는 콜",
      "en": "The Call Behind Debuggers"
    },
    "prompt": {
      "ko": "디버거가 다른 프로세스의 제어권을 얻어 메모리·레지스터를 읽고 제어할 때 내부적으로 호출하는 리눅스 시스템 콜의 이름은? (한 단어)",
      "en": "What Linux system call do debuggers use under the hood to hook into another process and read/control its memory and registers? (one word)"
    },
    "hints": {
      "ko": [
        "이름은 'process' + 'trace'의 축약입니다.",
        "안티디버깅 기법은 이 콜이 이미 걸려 있으면 두 번째 호출이 실패하는 점을 악용합니다."
      ],
      "en": [
        "Its name is 'process' + 'trace'.",
        "Anti-debugging tricks abuse that a second call fails if one is already attached."
      ]
    }
  },
  {
    "id": "t4_ret2libc",
    "tier": 4,
    "cat": "system",
    "track": "system",
    "points": 155,
    "ci": true,
    "hash": "c57eaf6530a6ac809ae16cc9062eb65bab051b73b6a2f5fa2202d7c3debb5cb7",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "이미 있는 함수로 리턴",
      "en": "Return Into Existing Code"
    },
    "prompt": {
      "ko": "NX(스택 실행 방지)를 우회하려고, 스택에 셸코드를 넣는 대신 libc의 기존 함수(예: system)로 리턴 주소를 덮어써 실행 흐름을 넘기는 고전 익스플로잇 기법의 이름은? (숫자 포함 한 단어)",
      "en": "To bypass NX (non-executable stack), instead of injecting shellcode you overwrite the return address to jump into an existing libc function (e.g. system). Name this classic exploit technique. (one token, contains a digit)"
    },
    "hints": {
      "ko": [
        "'return to libc'에서 to 를 숫자 2로 씁니다.",
        "`ret___libc` — 보통 libc의 `system(\"/bin/sh\")` 로 점프합니다."
      ],
      "en": [
        "'return to libc', with 'to' written as the digit 2.",
        "`ret___libc` — typically jumps into libc's `system(\"/bin/sh\")`."
      ]
    }
  },
  {
    "id": "t4_seccomp",
    "tier": 4,
    "cat": "system",
    "track": "system",
    "points": 150,
    "ci": true,
    "hash": "b10f708e69418485dbf6225020bf24204fd32b2a50c17e4fd16a76e09558a5f9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "시스템 콜 화이트리스트",
      "en": "Filter the Syscalls"
    },
    "prompt": {
      "ko": "프로세스나 컨테이너가 호출할 수 있는 시스템 콜을 화이트리스트로 제한해 공격 표면을 줄이는 리눅스 커널 보안 기능의 이름은? (한 단어)",
      "en": "What Linux kernel security feature restricts which system calls a process/container may make (via a whitelist), shrinking the attack surface? (one word)"
    },
    "hints": {
      "ko": [
        "'secure computing mode'를 줄인 이름입니다.",
        "Docker는 기본 `sec____` 프로파일로 위험한 syscall을 막습니다."
      ],
      "en": [
        "Short for 'secure computing mode'.",
        "Docker ships a default `sec____` profile blocking dangerous syscalls."
      ]
    }
  },
  {
    "id": "t0_ioc",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 45,
    "ci": true,
    "hash": "7354a0024740d89096dc6137ff3bb47df328ab8ea22f20e88c059d387e58aeae",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "침해의 흔적",
      "en": "Traces of a Breach"
    },
    "prompt": {
      "ko": "침해가 발생했음을 알려 주는 관찰 가능한 흔적(악성 IP·해시·도메인 등)을 통칭하는 3글자 약어는?",
      "en": "What 3-letter acronym collectively names the observable artifacts (malicious IPs, hashes, domains) that signal a compromise has occurred?"
    },
    "hints": {
      "ko": [
        "Indicator Of Compromise.",
        "위협 인텔리전스 피드가 이 값들을 공유합니다."
      ],
      "en": [
        "Indicator Of Compromise.",
        "Threat-intel feeds share these values."
      ]
    }
  },
  {
    "id": "t0_ram",
    "tier": 0,
    "cat": "forensics",
    "track": "forensics",
    "points": 45,
    "ci": true,
    "hash": "a631f4488a457da27b4a64dc8f2d85085b50ff568be99125cf6f8f45c759878e",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "가장 먼저 수집",
      "en": "Grab It First"
    },
    "prompt": {
      "ko": "휘발성이 높아 전원을 끄면 사라지므로 포렌식에서 가장 먼저 수집해야 하는 주기억장치의 3글자 약자는? (수집 순서상 최우선)",
      "en": "What 3-letter abbreviation names the volatile main memory that must be collected first in forensics because it is lost on power-off? (top of the order of volatility)"
    },
    "hints": {
      "ko": [
        "Random Access Memory.",
        "이 영역을 통째로 저장한 것을 '메모리 덤프'라고 합니다."
      ],
      "en": [
        "Random Access Memory.",
        "A full capture of it is called a 'memory dump'."
      ]
    }
  },
  {
    "id": "t1_netstat",
    "tier": 1,
    "cat": "forensics",
    "track": "forensics",
    "points": 60,
    "ci": true,
    "hash": "9a990e354cd9648e4a6371a05999dbd45da5831e866917f41b0f966f07bfea86",
    "fmt": "명령어 / command",
    "title": {
      "ko": "열린 연결 보기",
      "en": "Open Connections"
    },
    "prompt": {
      "ko": "호스트의 열린 포트와 활성 네트워크 연결(TCP/UDP)을 보여 주는 고전 명령어는? (한 단어)",
      "en": "Which classic command shows a host open ports and active network connections (TCP/UDP)? (one word)"
    },
    "hints": {
      "ko": [
        "'network statistics'의 축약입니다.",
        "`____ -ano` 로 연결과 PID를 함께 봅니다(요즘은 `ss` 로 대체)."
      ],
      "en": [
        "Short for 'network statistics'.",
        "`____ -ano` shows connections with PIDs (modern `ss` replaces it)."
      ]
    }
  },
  {
    "id": "t2_steghide",
    "tier": 2,
    "cat": "forensics",
    "track": "forensics",
    "points": 85,
    "ci": true,
    "hash": "cb4acd2b3839eea32ef807b243408ba3be1bbe74006bdf696f498cb966c688fe",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "그림 속 데이터",
      "en": "Data Concealed in a Picture"
    },
    "prompt": {
      "ko": "이미지·오디오 파일 안에 데이터를 숨기거나(임베드) 추출하는 대표적인 스테가노그래피 CLI 도구의 이름은? (한 단어)",
      "en": "Which popular steganography CLI tool embeds or extracts data concealed within image/audio files? (one word)"
    },
    "hints": {
      "ko": [
        "'steganography' + 'hide'를 합친 이름입니다.",
        "`____ extract -sf cover.jpg` 로 숨긴 데이터를 꺼냅니다."
      ],
      "en": [
        "Its name blends 'steganography' + 'hide'.",
        "`____ extract -sf cover.jpg` pulls out the concealed data."
      ]
    }
  },
  {
    "id": "t3_c2",
    "tier": 3,
    "cat": "forensics",
    "track": "forensics",
    "points": 110,
    "ci": true,
    "hash": "9c0abe51c6e6655d81de2d044d4fb194931f058c0426c67c7285d8f5657ed64a",
    "fmt": "약어 / acronym (2글자 / 2 chars)",
    "title": {
      "ko": "좀비의 사령탑",
      "en": "The Attacker Command Post"
    },
    "prompt": {
      "ko": "감염된 좀비 호스트가 지시를 받고 탈취 데이터를 보내는, 공격자가 운영하는 명령·제어 서버를 가리키는 2글자 약어는? (C&C 라고도 함)",
      "en": "What 2-character abbreviation names the attacker-run command-and-control server that infected hosts beacon to for orders and data exfiltration? (also written C&C)"
    },
    "hints": {
      "ko": [
        "'Command and Control'에서 두 번째 C를 숫자 2로 줄입니다.",
        "비콘 주기(beacon interval)를 분석해 이 트래픽을 탐지합니다."
      ],
      "en": [
        "'Command and Control', the second C written as the digit 2.",
        "Analysts spot it by its beacon interval."
      ]
    }
  },
  {
    "id": "t4_rootkit",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 155,
    "ci": true,
    "hash": "189ca7f3ff5335190ea4ecedaaad8e9613c8165bf99d563a82b1033af59c0e37",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "스스로를 숨기는 것",
      "en": "Hiding Its Own Tracks"
    },
    "prompt": {
      "ko": "커널이나 시스템 깊숙이 숨어 자신의 존재(프로세스·파일·연결)를 은폐하며 지속적 관리자 권한을 유지하는 악성코드 유형의 이름은? (한 단어)",
      "en": "What single word names malware that hides deep in the kernel/system, concealing its own presence (processes, files, connections) to keep persistent admin access?"
    },
    "hints": {
      "ko": [
        "'root'(관리자) + 'kit'(도구모음)의 합성어입니다.",
        "커널 모드 변종은 API를 후킹(SSDT 등)해 결과를 조작합니다."
      ],
      "en": [
        "A blend of 'root' (admin) + 'kit' (toolset).",
        "Kernel-mode variants hook APIs (e.g. SSDT) to falsify results."
      ]
    }
  },
  {
    "id": "t4_shimcache",
    "tier": 4,
    "cat": "forensics",
    "track": "forensics",
    "points": 150,
    "ci": true,
    "hash": "513eecf62e066a0b3ac8a9e09a2a1ed5006d690351897f6db49def663656ef99",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "호환성 캐시의 흔적",
      "en": "The Compatibility Cache"
    },
    "prompt": {
      "ko": "윈도우 애플리케이션 호환성 데이터베이스(AppCompatCache)에 남아 프로그램 실행·존재 흔적을 보여 주는 포렌식 아티팩트의 통칭은? (한 단어)",
      "en": "What single word names the Windows forensic artifact stored in the Application Compatibility database (AppCompatCache) that evidences program execution/presence?"
    },
    "hints": {
      "ko": [
        "'shim'(호환성 계층) + 'cache'의 합성어입니다.",
        "레지스트리 `...\\\\AppCompatCache` 값에서 파싱합니다."
      ],
      "en": [
        "A blend of 'shim' (compat layer) + 'cache'.",
        "Parsed from the registry `...\\\\AppCompatCache` value."
      ]
    }
  },
  {
    "id": "t0_saas",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 45,
    "ci": true,
    "hash": "98650c35cd5ea2afde8468b6d1866d3de00c715eb34044136bc3aad5c9b7b3db",
    "fmt": "약어 / acronym",
    "title": {
      "ko": "설치 없는 소프트웨어",
      "en": "Software, Just Use It"
    },
    "prompt": {
      "ko": "사용자가 설치·인프라 관리 없이 웹으로 바로 쓰는 완성형 소프트웨어 제공 모델(예: Gmail, Salesforce)을 가리키는 약어는?",
      "en": "What abbreviation names the model that delivers ready-to-use software over the web with no install or infra management (e.g. Gmail, Salesforce)?"
    },
    "hints": {
      "ko": [
        "Software as a Service.",
        "`S__S` — 4글자 약어입니다."
      ],
      "en": [
        "Software as a Service.",
        "`S__S` — a 4-character abbreviation."
      ]
    }
  },
  {
    "id": "t0_sharedresp",
    "tier": 0,
    "cat": "cloud",
    "track": "cloud",
    "points": 50,
    "ci": true,
    "hash": "2dbab7a48de51f5c2cbc3e0d6a9a9d6d2a6be0581df0789db88ec55154ba239d",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "누가 무엇을 책임지나",
      "en": "Who Secures What"
    },
    "prompt": {
      "ko": "클라우드 보안에서 '클라우드 자체(of the cloud)는 제공업체가, 클라우드 안(in the cloud)의 데이터·설정은 고객이 책임진다'는 원칙을 가리키는 두 단어(영문) 모델 이름은? (`____ ____ model`)",
      "en": "In cloud security, what two-word model states the provider secures the cloud itself while the customer secures their data/configuration in the cloud? (`____ ____ model`)"
    },
    "hints": {
      "ko": [
        "'공유된 책임'을 영어 두 단어로 옮긴 것입니다.",
        "`shared ______________` — 오설정에 의한 데이터 유출은 대개 고객 책임 영역."
      ],
      "en": [
        "Two English words for '공유된 책임'.",
        "`shared ______________` — misconfig breaches usually fall on the customer side."
      ]
    }
  },
  {
    "id": "t1_helm",
    "tier": 1,
    "cat": "cloud",
    "track": "cloud",
    "points": 65,
    "ci": true,
    "hash": "ab14d3faa25e917efe6e7135d4ecca197866738885a88b9b95d1a16d2bb5b323",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "차트로 배포",
      "en": "Deploy by Chart"
    },
    "prompt": {
      "ko": "쿠버네티스 애플리케이션을 'chart'라는 패키지 단위로 배포·관리하는 대표적인 패키지 매니저의 이름은? (한 단어)",
      "en": "What is the name of the popular package manager that deploys and manages Kubernetes apps as packages called 'charts'? (one word)"
    },
    "hints": {
      "ko": [
        "배의 '키(방향타)'를 뜻하는 영어 단어입니다(쿠버네티스=키잡이 테마).",
        "`____ install myrelease ./chart` 로 배포합니다."
      ],
      "en": [
        "The English word for a ship steering wheel (fits the Kubernetes helmsman theme).",
        "`____ install myrelease ./chart` deploys it."
      ]
    }
  },
  {
    "id": "t2_ingress",
    "tier": 2,
    "cat": "cloud",
    "track": "cloud",
    "points": 90,
    "ci": true,
    "hash": "487a0a9a39038de9767bdcbc6f81bf46cd7dcedb81be97d41dd6079d35bd922e",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "외부 트래픽 라우팅",
      "en": "Routing Traffic In"
    },
    "prompt": {
      "ko": "쿠버네티스에서 외부 HTTP(S) 트래픽을 클러스터 내부 서비스로 라우팅하는 규칙(호스트/경로 기반)을 정의하는 리소스의 이름은? (한 단어)",
      "en": "In Kubernetes, what resource defines rules (host/path-based) that route external HTTP(S) traffic to internal services? (one word)"
    },
    "hints": {
      "ko": [
        "'들어오는 트래픽(inbound)'을 뜻하는 영어 단어이며, 반대말은 egress 입니다.",
        "보통 nginx/traefik 컨트롤러가 이 리소스를 구현합니다."
      ],
      "en": [
        "The English word for 'inbound', the opposite of egress.",
        "An nginx/traefik controller usually implements it."
      ]
    }
  },
  {
    "id": "t3_privesc",
    "tier": 3,
    "cat": "cloud",
    "track": "cloud",
    "points": 130,
    "ci": true,
    "hash": "d3fa9e1e93989d0b1b266c8f4a5eafad0d0b3ff1db8c6136a9b8fcbf30a29b5e",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "권한을 끌어올리다",
      "en": "Climbing the Privileges"
    },
    "prompt": {
      "ko": "낮은 권한으로 침투한 뒤, 과도한 권한 정책이나 취약점을 악용해 더 높은 권한(관리자/root)을 획득하는 공격 단계를 가리키는 두 단어(영문)는?",
      "en": "What two-word term names the attack stage where a low-privilege foothold is leveraged (via over-permissive policies or a vuln) to gain higher (admin/root) privileges?"
    },
    "hints": {
      "ko": [
        "'권한 상승'을 영어 두 단어로 옮긴 것입니다.",
        "`privilege ____________` — 수직(vertical)/수평(horizontal)으로 나뉩니다."
      ],
      "en": [
        "Two English words for '권한 상승'.",
        "`privilege ____________` — split into vertical and horizontal."
      ]
    }
  },
  {
    "id": "t4_datapoisoning",
    "tier": 4,
    "cat": "ai",
    "track": "cloud",
    "points": 140,
    "ci": true,
    "hash": "8523305e90d58767dc73336f41bf038b80c9a9823f9bd3ea010594bcc5abd2e8",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "학습 데이터 오염",
      "en": "Corrupting the Training Set"
    },
    "prompt": {
      "ko": "공격자가 머신러닝/LLM의 학습 데이터에 악의적 샘플을 몰래 주입해 모델의 판단이나 출력을 왜곡시키는, OWASP LLM Top 10에 포함된 공격을 가리키는 두 단어(영문)는?",
      "en": "What two-word attack (in the OWASP LLM Top 10) secretly injects malicious samples into an ML/LLM's training data to skew the model's behavior or output?"
    },
    "hints": {
      "ko": [
        "학습 '데이터'를 '오염'시킨다는 뜻의 두 단어입니다.",
        "`data ________` — 백도어(트리거) 삽입에도 쓰입니다."
      ],
      "en": [
        "Two words meaning to contaminate the training data.",
        "`data ________` — also used to plant backdoor triggers."
      ]
    }
  },
  {
    "id": "t4_gvisor",
    "tier": 4,
    "cat": "cloud",
    "track": "cloud",
    "points": 140,
    "ci": true,
    "hash": "1f6d325084c7647bcd2a0352753a861a30a972c5ad6b75f6c2f1092961bb98f8",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "유저공간 커널 샌드박스",
      "en": "A Kernel in User Space"
    },
    "prompt": {
      "ko": "구글이 만든, 컨테이너와 호스트 커널 사이에서 시스템 콜을 가로채 사용자공간 커널로 처리함으로써 강한 격리를 제공하는 샌드박스 런타임의 이름은? (한 단어)",
      "en": "What is the name of Google's sandbox runtime that intercepts container syscalls and services them in a user-space kernel for stronger isolation? (one word)"
    },
    "hints": {
      "ko": [
        "소문자 g 로 시작하며 뒤에 'Visor(면갑)'가 붙습니다.",
        "`runsc` 런타임으로 구현되어 Docker/K8s 에 연결됩니다."
      ],
      "en": [
        "Starts with a lowercase g, followed by 'Visor'.",
        "Implemented as the `runsc` runtime, plugged into Docker/K8s."
      ]
    }
  },
  {
    "id": "t0_hallucination",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 45,
    "ci": true,
    "hash": "2c229d9fff93795f5e6a9d9b9ac19d6d1211b7c82c052a0aac3c95e7449137a0",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "자신 있게 틀리기",
      "en": "Confidently Wrong"
    },
    "prompt": {
      "ko": "언어 모델이 근거가 없는데도 사실인 양 매끄럽게 지어내는 출력을 부르는 말은? (영어 한 단어)",
      "en": "What do we call output a language model invents with no grounding, yet states as smoothly as fact? (one English word)"
    },
    "hints": {
      "ko": [
        "사람이 없는 것을 보거나 듣는 증상에서 따온 이름입니다.",
        "모델은 \"모른다\"가 아니라 그럴듯한 문장을 만들어 냅니다."
      ],
      "en": [
        "Named after perceiving something that is not there.",
        "The model does not say \"I do not know\" — it produces something plausible."
      ]
    }
  },
  {
    "id": "t0_guardrail",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 40,
    "ci": true,
    "hash": "2f0a9e4fec74e596ad09c1ed0f7b77efd01d2149acc4d492e06a87a0da365b1f",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "난간을 세워라",
      "en": "A Rail Along the Edge"
    },
    "prompt": {
      "ko": "모델의 입력과 출력을 정책에 따라 검사·차단해 위험한 응답이 나가지 않게 막는 보호 장치를 통칭하는 영어 한 단어는?",
      "en": "What single English word names the protective layer that inspects and blocks a model's inputs and outputs against policy so unsafe responses never leave?"
    },
    "hints": {
      "ko": [
        "도로 갓길에 세워 차가 벼랑으로 떨어지지 않게 막는 그 시설의 이름입니다.",
        "모델 자체를 고치는 것이 아니라 바깥에 두르는 층입니다."
      ],
      "en": [
        "Named after the barrier on a road that keeps a car from going over the edge.",
        "It wraps around the model rather than changing it."
      ]
    }
  },
  {
    "id": "t0_inference",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 45,
    "ci": true,
    "hash": "925733dafd743699fa17409329abdb2728da89ba5736e44ad0fd4a67836e9f9c",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "학습은 끝났다",
      "en": "Training Is Over"
    },
    "prompt": {
      "ko": "학습이 모두 끝난 모델이 실제 요청을 받아 응답을 만들어 내는 실행 단계를 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What is the runtime stage called, where a fully trained model takes a real request and produces a response? (one English word)"
    },
    "hints": {
      "ko": [
        "학습(training)과 짝을 이루는 반대편 단계입니다.",
        "이 단계의 비용이 서비스 운영비의 대부분을 차지합니다."
      ],
      "en": [
        "The counterpart stage to training.",
        "Its cost dominates what it takes to run the service."
      ]
    }
  },
  {
    "id": "t0_dataset",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 40,
    "ci": true,
    "hash": "b277fd623676a525c29b9eb155afc8c9010681814ceafb2d7627f47b9a232576",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "재료 창고",
      "en": "The Pantry"
    },
    "prompt": {
      "ko": "모델을 학습시킬 때 먹이는 자료 묶음 전체를 가리키는 영어 한 단어는?",
      "en": "What single English word names the whole body of material a model is trained on?"
    },
    "hints": {
      "ko": [
        "자료(data)와 묶음(set)을 합친 낱말입니다.",
        "여기에 손을 대는 공격이 오염(poisoning)입니다."
      ],
      "en": [
        "A compound of data and set.",
        "Tampering with it is what poisoning attacks do."
      ]
    }
  },
  {
    "id": "t0_tokenizer",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 50,
    "ci": true,
    "hash": "5f97e3774c51edd1d63706c2ec3826c564a067794770cdab0f8c4797971cacf9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "글자를 조각내는 것",
      "en": "The Chopper"
    },
    "prompt": {
      "ko": "사람이 쓴 문장을 모델이 실제로 다루는 작은 조각들로 잘라 번호를 매기는 구성요소의 이름은? (영어 한 단어)",
      "en": "What is the component called that cuts human text into the small numbered pieces a model actually consumes? (one English word)"
    },
    "hints": {
      "ko": [
        "잘라낸 조각 하나하나를 \"토큰\"이라 부릅니다 — 그 일을 하는 주체의 이름을 답하세요.",
        "같은 문장이라도 이것이 다르면 조각 수가 달라집니다."
      ],
      "en": [
        "Each piece it produces is called a token — name the thing that does the cutting.",
        "Change it and the same sentence costs a different number of pieces."
      ]
    }
  },
  {
    "id": "t0_seed",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 50,
    "ci": true,
    "hash": "19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "같은 답을 두 번",
      "en": "The Same Answer Twice"
    },
    "prompt": {
      "ko": "난수 생성을 고정해 같은 입력에 같은 출력이 재현되도록 만들 때 지정하는 값의 이름은? (영어 한 단어)",
      "en": "What is the value called that you pin down so a random generator repeats itself and the same input yields the same output? (one English word)"
    },
    "hints": {
      "ko": [
        "땅에 심는 그 낱말과 같은 단어입니다.",
        "실험을 재현하거나 버그를 다시 만들어 낼 때 반드시 기록해 둡니다."
      ],
      "en": [
        "The same word as the thing you plant in soil.",
        "You record it when you need an experiment or a bug to reproduce."
      ]
    }
  },
  {
    "id": "t0_alignment",
    "tier": 0,
    "cat": "ai",
    "track": "ai",
    "points": 60,
    "ci": true,
    "hash": "47ccb97a79f5a2bff2713968c83bbbea9cd53d2edf6b0a47439910e111c95fe9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "의도를 맞추다",
      "en": "Matching Intent"
    },
    "prompt": {
      "ko": "모델이 사람의 의도와 운영 정책을 따르도록 학습·조정하는 작업 전반을 가리키는 영어 한 단어는?",
      "en": "What single English word covers the work of training and tuning a model so it follows human intent and operator policy?"
    },
    "hints": {
      "ko": [
        "바퀴 정렬을 맞춘다고 할 때 쓰는 그 단어입니다.",
        "이것을 무너뜨려 금지된 응답을 끌어내려는 시도가 안전장치 우회 공격입니다."
      ],
      "en": [
        "The same word used for lining up a car's wheels.",
        "Attacks that pull forbidden output are attempts to break exactly this."
      ]
    }
  },
  {
    "id": "t1_rag",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 65,
    "ci": true,
    "hash": "a3e690053061793bb12ad4c32aace5856f57f1694d3608df1379d240ce1bbc5b",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "찾아서 붙여주기",
      "en": "Fetch, Then Answer"
    },
    "prompt": {
      "ko": "모델이 답하기 전에 외부 문서를 먼저 검색해 그 내용을 프롬프트에 끼워 넣어 주는 구조의 3글자 약어는?",
      "en": "What 3-letter abbreviation names the design where documents are searched first and pasted into the prompt before the model answers?"
    },
    "hints": {
      "ko": [
        "Retrieval-Augmented Generation의 머리글자입니다.",
        "검색된 문서에 공격 문구가 심겨 있으면 그것이 그대로 모델 입력이 됩니다."
      ],
      "en": [
        "The initials of Retrieval-Augmented Generation.",
        "If the fetched document carries planted instructions, they become model input verbatim."
      ]
    }
  },
  {
    "id": "t1_embedding",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 70,
    "ci": true,
    "hash": "aa580156f36e357b5bfb0dcd869a026c7b0a244e7b01cba17d5da1dc1e7039cd",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "의미를 숫자로",
      "en": "Meaning as Numbers"
    },
    "prompt": {
      "ko": "단어나 문서의 의미를 고정 길이의 실수 벡터로 바꾼 표현을 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What do we call the representation that turns a word or document's meaning into a fixed-length vector of numbers? (one English word)"
    },
    "hints": {
      "ko": [
        "비슷한 뜻일수록 벡터 사이 거리가 가깝습니다.",
        "이 벡터만 있어도 원문을 상당 부분 되살릴 수 있어 그 자체가 민감 정보입니다."
      ],
      "en": [
        "Closer vectors mean closer meanings.",
        "The vectors alone can reconstruct much of the original text, so they are sensitive on their own."
      ]
    }
  },
  {
    "id": "t1_mcp",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 70,
    "ci": true,
    "hash": "10182ab855ff772753c05b2fea333666b5f312835d32936b6b03e08ef2cbd6d3",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "도구를 꽂는 규격",
      "en": "The Socket for Tools"
    },
    "prompt": {
      "ko": "모델에 외부 도구와 자원을 표준화된 방식으로 연결하기 위해 Anthropic이 공개한 개방형 프로토콜의 3글자 약어는?",
      "en": "What 3-letter abbreviation names the open protocol Anthropic published for connecting external tools and resources to a model in a standard way?"
    },
    "hints": {
      "ko": [
        "Model Context Protocol의 머리글자입니다.",
        "연결한 서버가 신뢰할 수 없으면 그 서버의 응답이 곧 모델 입력이 됩니다."
      ],
      "en": [
        "The initials of Model Context Protocol.",
        "If a connected server is untrusted, its responses become model input."
      ]
    }
  },
  {
    "id": "t1_lora",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 70,
    "ci": true,
    "hash": "d339f720de1fd92a672df9ef19a8cdbda6171cbf33fcd35ad95c46f8aebaf628",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "가볍게 갈아끼우기",
      "en": "Swap In, Stay Light"
    },
    "prompt": {
      "ko": "원본 가중치는 얼려 둔 채 작은 저계수 행렬만 학습해 덧붙이는 경량 미세조정 기법의 4글자 약어는?",
      "en": "What 4-letter abbreviation names the lightweight tuning method that freezes the original weights and trains only small low-rank matrices to add on top?"
    },
    "hints": {
      "ko": [
        "Low-Rank Adaptation의 머리글자입니다.",
        "결과물이 작은 파일이라 배포가 쉽고, 그래서 출처가 불분명한 것을 받아 붙이는 위험도 큽니다."
      ],
      "en": [
        "The initials of Low-Rank Adaptation.",
        "The result is a small file — easy to share, and just as easy to accept from an unknown source."
      ]
    }
  },
  {
    "id": "t1_safetensors",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 65,
    "ci": true,
    "hash": "54f843a33581bf0d9ae8bd35563b3e93d6439e0fe198199b1b52107ae628e3b2",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "열어도 안전하게",
      "en": "Safe to Open"
    },
    "prompt": {
      "ko": "가중치를 불러오는 것만으로 임의 코드가 실행되지 않도록, 실행 가능한 객체 없이 순수 수치와 메타데이터만 담게 설계된 모델 저장 포맷의 이름은? (영어 한 단어)",
      "en": "What single English word names the model file format designed to hold only raw numbers and metadata — no executable objects — so that merely loading weights cannot run code?"
    },
    "hints": {
      "ko": [
        "이름 자체가 \"안전한 텐서\"라는 뜻의 합성어입니다.",
        "이 포맷이 대체하려는 쪽은 파이썬 객체를 통째로 복원하는 방식입니다."
      ],
      "en": [
        "The name itself is a compound meaning \"safe tensors\".",
        "It exists to replace a format that restores whole Python objects."
      ]
    }
  },
  {
    "id": "t1_logit",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 60,
    "ci": true,
    "hash": "76eee315ea0140598642eafd3a69dae02d07e140c90da4971b09a9601e6a8bf1",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "확률이 되기 직전",
      "en": "Just Before Probability"
    },
    "prompt": {
      "ko": "모델의 마지막 층이 내놓는, 아직 확률로 정규화되지 않은 각 후보의 원시 점수를 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What do we call the raw per-candidate score a model's final layer emits, before it is normalized into a probability? (one English word)"
    },
    "hints": {
      "ko": [
        "이 값들을 지수화해 합이 1이 되도록 나누면 확률이 됩니다.",
        "API가 이 값을 그대로 돌려주면 모델을 베껴 가기가 훨씬 쉬워집니다."
      ],
      "en": [
        "Exponentiate them and divide by their sum and you get probabilities.",
        "An API that hands these back makes copying the model far easier."
      ]
    }
  },
  {
    "id": "t1_quantization",
    "tier": 1,
    "cat": "ai",
    "track": "ai",
    "points": 60,
    "ci": true,
    "hash": "00337646bb399b2abd588064f50b7de7cca824b6598885681211cf09ec41de3d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "정밀도를 깎다",
      "en": "Trading Precision for Room"
    },
    "prompt": {
      "ko": "가중치를 더 낮은 비트 정밀도로 표현해 메모리와 연산량을 줄이는 모델 경량화 기법을 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What single English word names the technique of representing weights at lower bit precision to cut memory and compute?"
    },
    "hints": {
      "ko": [
        "32비트를 8비트나 4비트로 줄이는 그 작업입니다.",
        "값을 구간으로 몰아 넣는다는 뜻의 낱말입니다."
      ],
      "en": [
        "Going from 32-bit down to 8- or 4-bit.",
        "The word means forcing values into discrete steps."
      ]
    }
  },
  {
    "id": "t2_indirect",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 90,
    "ci": true,
    "hash": "fdbf5bfd03fbfa1453c3e55ff5ec913e444b2fe5c7529be42aac8965b0290770",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "내가 쓰지 않은 명령",
      "en": "An Instruction I Never Typed"
    },
    "prompt": {
      "ko": "공격자가 사용자에게 직접 입력시키는 대신, 모델이 나중에 읽게 될 웹페이지나 문서에 지시문을 미리 심어 두는 공격 유형을 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What single English word describes the kind of attack where the adversary plants instructions in a page or document the model will later read, instead of having the user type them?"
    },
    "hints": {
      "ko": [
        "사용자가 직접 넣는 쪽과 대비되는 낱말입니다.",
        "요약을 시킨 웹페이지, 붙여넣은 이력서, 받은 메일 본문이 모두 통로가 됩니다."
      ],
      "en": [
        "The opposite word to what the user types in themselves.",
        "A page you asked it to summarize, a pasted résumé, the body of an email — all are carriers."
      ]
    }
  },
  {
    "id": "t2_spotlighting",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 100,
    "ci": true,
    "hash": "29a47755539232c8f6272ae7f29947c37e3275d305d90520a612906cd222c4d3",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "조명을 비춰 구분하라",
      "en": "Shine a Light on It"
    },
    "prompt": {
      "ko": "모델에게 건네는 외부 데이터를 표시·인코딩·구획으로 명확히 티나게 만들어, 그 안의 문장을 지시로 오해하지 않게 하는 방어 기법의 이름은? (영어 한 단어)",
      "en": "What single English word names the defense that marks, encodes, or fences external data so visibly that the model will not mistake sentences inside it for instructions?"
    },
    "hints": {
      "ko": [
        "무대에서 한 사람에게만 빛을 쏘는 그 장치의 이름에서 왔습니다.",
        "\"이 대목은 자료일 뿐 명령이 아니다\"를 모델이 알아보게 만드는 것이 목적입니다."
      ],
      "en": [
        "Named after the stage light that picks out one person.",
        "The point is to let the model see \"this block is data, not orders\"."
      ]
    }
  },
  {
    "id": "t2_delimiter",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 80,
    "ci": true,
    "hash": "c4b3f42c1c768312aed1d1af8bdbcbc70096a9de3140b990a36db384f1799791",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "여기부터는 남의 말",
      "en": "Where Their Words Begin"
    },
    "prompt": {
      "ko": "사용자 입력이 어디서 시작하고 끝나는지 모델에게 알려 주려고 프롬프트에 끼워 넣는 경계 표시 문자열을 통칭하는 영어 한 단어는?",
      "en": "What single English word names the boundary marker inserted into a prompt to tell the model where user input starts and stops?"
    },
    "hints": {
      "ko": [
        "CSV의 쉼표, 문장의 따옴표가 하는 역할과 같은 이름입니다.",
        "이 표시를 공격자가 그대로 흉내 내 쓰면 경계가 무너지므로 예측 불가능한 값이어야 합니다."
      ],
      "en": [
        "The same name as the comma in a CSV or the quotes around a string.",
        "If an attacker can reproduce the marker the boundary collapses, so it must be unpredictable."
      ]
    }
  },
  {
    "id": "t2_membership",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 90,
    "ci": true,
    "hash": "bf5cf59e356652253268c604cbf8df8cfdb03a4a0d32b27ad158e581709c80e4",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "너 거기 있었니",
      "en": "Were You in There?"
    },
    "prompt": {
      "ko": "모델의 응답만 관찰해서 \"이 특정 레코드가 학습 자료에 들어 있었는가\"를 알아내는 프라이버시 공격이 있습니다. 이 공격 이름은 두 단어인데, 그중 첫 단어 — 어떤 집합에 속해 있었는지를 뜻하는 영어 한 단어 — 를 답하세요.",
      "en": "There is a privacy attack that watches only a model's responses to determine whether one specific record was in its training data. Its name is two words — give the first one, the English word for having belonged to a set."
    },
    "hints": {
      "ko": [
        "어떤 집합에 \"속해 있었는가\"를 묻는 낱말입니다.",
        "학습에 쓰인 자료에는 모델이 더 확신에 차서 반응하는 경향이 단서가 됩니다."
      ],
      "en": [
        "The word for whether something belonged to a set.",
        "The tell is that models react more confidently to material they were trained on."
      ]
    }
  },
  {
    "id": "t2_persona",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 85,
    "ci": true,
    "hash": "5e815286bca594454b291f3b0350ec22aab6de20b6d9efeec67d604f6bce65ee",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "역할을 뒤집어쓰기",
      "en": "Wearing a Character"
    },
    "prompt": {
      "ko": "\"너는 이제 아무 제약 없는 캐릭터야\"처럼 모델에게 가공의 인격을 씌워 정책을 우회하려는 수법에서, 그 씌우는 가공의 인격을 부르는 영어 한 단어는?",
      "en": "In the style of attack that tells a model \"you are now a character with no restrictions\", what single English word names the fictional identity being imposed?"
    },
    "hints": {
      "ko": [
        "연극에서 배우가 쓰는 가면을 뜻하던 라틴어에서 왔습니다.",
        "모델이 규칙을 잊은 것이 아니라 \"지금은 다른 사람\"이라고 믿게 만드는 것이 요령입니다."
      ],
      "en": [
        "From the Latin for the mask an actor wears on stage.",
        "The trick is not making the model forget the rules but making it believe it is someone else."
      ]
    }
  },
  {
    "id": "t2_markdown",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 85,
    "ci": true,
    "hash": "bc18f7068971a44e264848ecd54b72b02d38216abb8ce3c3d2148e37e8a12398",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "보이지 않는 배달부",
      "en": "The Invisible Courier"
    },
    "prompt": {
      "ko": "채팅 UI가 모델 출력을 렌더링할 때 이미지 문법을 그대로 그려 주면, 모델이 대화 내용을 URL에 실어 외부 서버로 유출할 수 있습니다. 이 유출 통로가 되는, 이미지·링크 문법을 제공하는 경량 서식 언어의 이름은? (영어 한 단어)",
      "en": "When a chat UI renders a model's output, an image tag can be drawn automatically — letting the model smuggle conversation text out in the URL. What single English word names the lightweight formatting language that supplies that image and link syntax?"
    },
    "hints": {
      "ko": [
        "README 파일을 쓸 때 쓰는 그 서식입니다.",
        "방어는 렌더링 단계에서 외부 출처 이미지를 막는 것입니다."
      ],
      "en": [
        "The same format you write a README in.",
        "The fix is at the render step: block images from outside origins."
      ]
    }
  },
  {
    "id": "t2_agency",
    "tier": 2,
    "cat": "ai",
    "track": "ai",
    "points": 100,
    "ci": true,
    "hash": "c4b2af4722ee54e317672875b2d8cf49aa884bf5820ec6091114fea5ec6560e4",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "너무 많이 할 수 있다",
      "en": "Allowed to Do Too Much"
    },
    "prompt": {
      "ko": "OWASP LLM Top 10에는 모델에 붙인 도구·권한·자율성이 필요 이상으로 커서, 인젝션 한 번이 곧 실제 행동으로 이어지는 위험을 가리키는 항목이 있습니다. \"Excessive ____\"의 빈칸에 들어갈 영어 한 단어는?",
      "en": "OWASP LLM Top 10 has an entry for giving a model more tools, permissions, and autonomy than it needs, so that a single injection turns straight into real-world action. What single English word completes \"Excessive ____\"?"
    },
    "hints": {
      "ko": [
        "\"행위 주체로서 스스로 할 수 있는 정도\"를 뜻하는 낱말입니다.",
        "완화책은 도구를 읽기 전용으로 줄이고 사람 승인을 끼워 넣는 것입니다."
      ],
      "en": [
        "The noun for how much a thing can act on its own behalf.",
        "The mitigation is read-only tools and a human approval step."
      ]
    }
  },
  {
    "id": "t3_fgsm",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 110,
    "ci": true,
    "hash": "0803943eb2beae79b08298d94cdeabf6623ec58886b5cc68409b713619e3c89c",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "한 걸음이면 충분하다",
      "en": "One Step Is Enough"
    },
    "prompt": {
      "ko": "손실의 기울기 부호만 보고 입력에 아주 작은 섭동을 한 번에 더해 오분류를 유도하는, 가장 고전적인 적대적 예제 생성 기법의 4글자 약어는?",
      "en": "What 4-letter abbreviation names the classic adversarial-example method that reads only the sign of the loss gradient and adds one tiny perturbation to the input in a single step?"
    },
    "hints": {
      "ko": [
        "Fast Gradient Sign Method의 머리글자입니다.",
        "반복 없이 한 번에 끝나기 때문에 빠르지만 그만큼 약합니다."
      ],
      "en": [
        "The initials of Fast Gradient Sign Method.",
        "One shot, no iteration — fast, and correspondingly weak."
      ]
    }
  },
  {
    "id": "t3_pgd",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 120,
    "ci": true,
    "hash": "4be678262bd5d9ecaa03661f1d11374d7ac5ceeb6d28d1f6a77dc68c0cd6473c",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "경계 안으로 되밀며",
      "en": "Pushed Back Inside"
    },
    "prompt": {
      "ko": "작은 걸음을 여러 번 반복하되 매 걸음마다 허용된 섭동 범위 안으로 다시 투영해 넣는, 반복형 적대적 예제 공격의 3글자 약어는?",
      "en": "What 3-letter abbreviation names the iterative adversarial attack that takes many small steps, projecting back inside the allowed perturbation ball after each one?"
    },
    "hints": {
      "ko": [
        "Projected Gradient Descent의 머리글자입니다.",
        "강건성을 주장하려면 최소한 이 공격은 견뎌야 한다고 여겨집니다."
      ],
      "en": [
        "The initials of Projected Gradient Descent.",
        "Surviving it is treated as the minimum bar for claiming robustness."
      ]
    }
  },
  {
    "id": "t3_epsilon",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 105,
    "ci": true,
    "hash": "6ebf3c8d63ef6b217bcee69e31f77f3634bbbef1346de27e229c17122974e27b",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "얼마나 흔들 수 있나",
      "en": "How Far You May Push"
    },
    "prompt": {
      "ko": "적대적 예제를 만들 때 \"원본에서 이만큼까지만 바꿀 수 있다\"는 섭동 크기의 상한을 나타내는 그리스 문자의 이름을 영어로 쓰면? (한 단어)",
      "en": "When crafting adversarial examples, a Greek letter denotes the budget — how far from the original you may move. Write that letter's name in English. (one word)"
    },
    "hints": {
      "ko": [
        "그리스 알파벳의 다섯 번째 글자이고, 수학에서 \"아주 작은 양\"의 대명사입니다.",
        "이 값이 커질수록 공격은 쉬워지지만 변형이 사람 눈에 띄기 시작합니다."
      ],
      "en": [
        "The fifth letter of the Greek alphabet, mathematics' byword for a very small quantity.",
        "Raise it and the attack gets easier — and visible."
      ]
    }
  },
  {
    "id": "t3_inversion",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 125,
    "ci": true,
    "hash": "418df28d06f462b0eb70db5b82e164c9ed72b4992b8eac275d344a83600ea4e9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "거꾸로 되짚기",
      "en": "Running It Backwards"
    },
    "prompt": {
      "ko": "모델의 출력이나 신뢰도만 반복 관찰해 학습에 쓰인 원본 데이터(예: 얼굴 이미지)를 되살려 내는 공격을 \"model ____\"이라 부릅니다. 빈칸의 영어 한 단어는?",
      "en": "Repeatedly probing a model's outputs or confidences to reconstruct the original training data — a face image, say — is called \"model ____\". What single English word fills the blank?"
    },
    "hints": {
      "ko": [
        "함수를 거꾸로 푸는 연산의 이름과 같습니다.",
        "출력에 담긴 정보가 많을수록(확률 전체를 돌려줄수록) 잘 통합니다."
      ],
      "en": [
        "The same word as the operation that undoes a function.",
        "The more the output reveals — full probabilities, say — the better it works."
      ]
    }
  },
  {
    "id": "t3_surrogate",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 130,
    "ci": true,
    "hash": "8dc7e1ff18ccb788b377a80ce80a30294bdddbbfa696856cb6e3d49c7eac4b83",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "대신 세우는 모델",
      "en": "A Stand-In Model"
    },
    "prompt": {
      "ko": "표적 모델에 질의를 퍼부어 그 응답으로 대신 학습시킨 복제 모델 — 이후 이 모델을 놓고 마음껏 공격을 설계한 뒤 원본에 옮겨 붙입니다 — 을 부르는 영어 한 단어는?",
      "en": "You flood a target model with queries and train a copy on its answers, then design attacks freely against the copy before carrying them over. What single English word names that copy?"
    },
    "hints": {
      "ko": [
        "본인 대신 역할을 떠맡는 사람을 가리키는 낱말입니다.",
        "흰 상자 공격을 검은 상자 표적에 쓰기 위한 다리 역할을 합니다."
      ],
      "en": [
        "The word for someone who stands in for another.",
        "It is the bridge that lets white-box attacks reach a black-box target."
      ]
    }
  },
  {
    "id": "t3_suffix",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 115,
    "ci": true,
    "hash": "a1b7c6f1aa933f882745c9a905739790931b7fb9a01e49b44d2b4d19e1bf8e39",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "뒤에 붙는 헛소리",
      "en": "Gibberish on the End"
    },
    "prompt": {
      "ko": "사람에게는 의미 없는 문자열처럼 보이지만 프롬프트 끝에 덧붙이면 모델의 거절을 무너뜨리도록 최적화로 찾아낸 토큰 뭉치를 \"adversarial ____\"라고 부릅니다. 빈칸의 영어 한 단어는?",
      "en": "A string that looks like nonsense to a human but is optimized so that appending it to a prompt collapses the model's refusal is called an \"adversarial ____\". What single English word fills the blank?"
    },
    "hints": {
      "ko": [
        "낱말 뒤에 붙는 어미를 가리키는 문법 용어와 같은 단어입니다.",
        "앞에 붙이는 접두사(prefix)와 짝을 이룹니다."
      ],
      "en": [
        "The same word as the grammatical ending attached after a stem.",
        "It pairs with prefix, which goes on the front."
      ]
    }
  },
  {
    "id": "t3_transferability",
    "tier": 3,
    "cat": "ai",
    "track": "ai",
    "points": 140,
    "ci": true,
    "hash": "105b4e5c58919ec9d0b4359cd5274e42ab6668b534de0bae6466df01784f95fd",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "옮겨 붙는 성질",
      "en": "It Carries Over"
    },
    "prompt": {
      "ko": "한 모델을 겨냥해 만든 적대적 예제가 구조도 학습 데이터도 다른 별개의 모델에서까지 그대로 통하는 성질을 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What single English word names the property whereby an adversarial example crafted against one model still works on a different model with another architecture and another training set?"
    },
    "hints": {
      "ko": [
        "\"옮기다(transfer)\"에 성질을 뜻하는 어미를 붙인 낱말입니다.",
        "이 성질 덕분에 표적의 내부를 몰라도 대리 모델만으로 공격이 성립합니다."
      ],
      "en": [
        "The verb transfer plus the ending that turns it into a property.",
        "It is why an attacker never needs the target's internals — a stand-in model suffices."
      ]
    }
  },
  {
    "id": "t4_smoothing",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 170,
    "ci": true,
    "hash": "3637a614cb738f813fb7c3b401e83c1c700bf3e97e5add3269d818cf73f0175d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "증명된 반경",
      "en": "A Radius You Can Prove"
    },
    "prompt": {
      "ko": "입력에 무작위 잡음을 섞어 여러 번 추론한 뒤 다수결로 답을 내면, 일정 반경 안의 어떤 섭동에도 예측이 바뀌지 않음을 수학적으로 보장할 수 있습니다. 이 인증된(certified) 방어의 이름 \"randomized ____\"의 빈칸에 들어갈 영어 한 단어는?",
      "en": "Adding random noise to the input, running the model many times, and taking a majority vote yields a mathematical guarantee that no perturbation within some radius can change the prediction. This certified defense is called \"randomized ____\". What single English word fills the blank?"
    },
    "hints": {
      "ko": [
        "거친 표면을 문질러 매끈하게 만드는 동작을 뜻하는 낱말입니다.",
        "경험적 방어와 달리 \"이 반경 안에서는 절대 안 뚫린다\"를 증명해 줍니다."
      ],
      "en": [
        "The word for rubbing a rough surface flat.",
        "Unlike empirical defenses it proves a radius inside which nothing can break it."
      ]
    }
  },
  {
    "id": "t4_distillation",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 160,
    "ci": true,
    "hash": "b862b5591f08e64c551dd311fb916b8ed02978398a677535eb8c903fd4cae827",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "증류해서 옮기기",
      "en": "Boiled Down and Poured Over"
    },
    "prompt": {
      "ko": "큰 교사 모델의 부드러운 출력 분포를 작은 학생 모델에게 학습시켜 능력을 옮기는 기법의 이름은? (영어 한 단어) — 방어 기법으로도, 모델을 훔치는 수단으로도 쓰입니다.",
      "en": "Training a small student model on a large teacher model's soft output distribution to carry its ability over — what is that technique called? (one English word) It serves as a defense and as a way to steal a model alike."
    },
    "hints": {
      "ko": [
        "술을 내리거나 물을 정제할 때 쓰는 그 공정의 이름입니다.",
        "방어로 쓰면 기울기를 뭉개고, 공격으로 쓰면 남의 모델을 베껴 옵니다."
      ],
      "en": [
        "Named after the process used to refine spirits or purify water.",
        "As a defense it blunts gradients; as an attack it copies someone else's model."
      ]
    }
  },
  {
    "id": "t4_pickle",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 180,
    "ci": true,
    "hash": "6d08a4e630e4aa0d5cd873e65aea0a23df42de61073ecb49ef17158fe6a9dcea",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "불러오는 순간 실행된다",
      "en": "Loading Is Executing"
    },
    "prompt": {
      "ko": "파이썬 객체를 통째로 직렬화하는 이 표준 포맷은 복원 과정에서 임의 코드를 실행할 수 있어, 공개 저장소에서 받은 모델 가중치 파일이 곧 실행 파일이 되는 공급망 위험을 만듭니다. 이 포맷의 이름은? (영어 한 단어)",
      "en": "This standard Python format serializes whole objects and can execute arbitrary code while restoring them — which makes a weights file downloaded from a public hub effectively an executable, and a supply-chain risk. What is the format called? (one English word)"
    },
    "hints": {
      "ko": [
        "오이를 식초에 절여 두는 그 음식과 같은 이름입니다.",
        "이 위험 때문에 나온 대안이 순수 수치만 담는 저장 포맷입니다."
      ],
      "en": [
        "The same word as the cucumber preserved in vinegar.",
        "The alternative format that holds only raw numbers exists because of this risk."
      ]
    }
  },
  {
    "id": "t4_gcg",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 190,
    "ci": true,
    "hash": "432dfd9c30ad50adec635fc2813fde786455c0110998d93528a5b3744fab4cf3",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "토큰을 좌표처럼",
      "en": "Tokens as Coordinates"
    },
    "prompt": {
      "ko": "기울기 정보를 이용해 매 단계 한 토큰 자리씩 후보를 골라 탐욕적으로 교체하며, 거절을 뚫는 문자열을 자동으로 찾아내는 — 공개 모델에서 널리 재현된 — 안전장치 우회 자동화 기법의 3글자 약어는?",
      "en": "What 3-letter abbreviation names the automated method — widely reproduced on open models — that uses gradient information to greedily swap one token position at a time until it finds a string that defeats refusal?"
    },
    "hints": {
      "ko": [
        "Greedy Coordinate Gradient의 머리글자입니다.",
        "찾아낸 문자열이 다른 모델에도 그대로 옮겨 붙는다는 점이 이 연구의 충격이었습니다."
      ],
      "en": [
        "The initials of Greedy Coordinate Gradient.",
        "The shock of the paper was that what it found carried over to other models."
      ]
    }
  },
  {
    "id": "t4_crescendo",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 150,
    "ci": true,
    "hash": "eedc28b678375cc1e2a7ab92f0588674249376eea7d369dfd440af8b5fbec3d5",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "점점 세게",
      "en": "Louder, Gradually"
    },
    "prompt": {
      "ko": "한 번에 위험한 요청을 하지 않고, 무해한 질문에서 시작해 여러 차례에 걸쳐 조금씩 수위를 올려 결국 정책을 넘게 만드는 다중 턴 우회 기법의 이름은? (음악 용어에서 온 영어 한 단어)",
      "en": "Rather than asking for the dangerous thing outright, this multi-turn attack opens with something harmless and escalates by one step each turn until the policy is crossed. What is it called? (one English word, borrowed from music)"
    },
    "hints": {
      "ko": [
        "악보에서 소리를 점점 크게 하라는 그 지시어입니다.",
        "턴 하나만 떼어 놓고 보면 어느 것도 위반이 아니라는 점이 탐지를 어렵게 합니다."
      ],
      "en": [
        "The score marking that tells a player to grow steadily louder.",
        "Detection is hard because no single turn, taken alone, violates anything."
      ]
    }
  },
  {
    "id": "t4_deputy",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 155,
    "ci": true,
    "hash": "00652261d8f5e7a4521daae4c82d601c42ac334acafc208438ebc9fc384f725b",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "권한을 빌려 쓴 심부름꾼",
      "en": "The Errand Boy's Badge"
    },
    "prompt": {
      "ko": "자신보다 높은 권한을 가진 구성요소를 꾀어 그 권한으로 대신 행동하게 만드는 고전적 보안 문제를 \"confused ____ problem\"이라 부릅니다. 도구를 붙인 모델이 사용자 권한을 넘어 행동할 때 정확히 이 문제가 재현됩니다. 빈칸의 영어 한 단어는?",
      "en": "Tricking a component that holds more authority than you into acting with that authority on your behalf is the classic \"confused ____ problem\" — reproduced exactly when a tool-wielding model acts beyond the user's own permissions. What single English word fills the blank?"
    },
    "hints": {
      "ko": [
        "보안관을 대신해 일하는 사람을 가리키는 낱말입니다.",
        "1988년 Norm Hardy가 붙인 이름으로, 대리 권한을 다루는 모든 시스템에 되풀이됩니다."
      ],
      "en": [
        "The word for the one who acts on the sheriff's behalf.",
        "Named by Norm Hardy in 1988; it recurs in every system that delegates authority."
      ]
    }
  },
  {
    "id": "t4_unlearning",
    "tier": 4,
    "cat": "ai",
    "track": "ai",
    "points": 130,
    "ci": true,
    "hash": "4d9b7c1f73c9748596f1a93d7ce6224ed651b19aee8ca6406d86285d49945789",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "배운 것을 지우기",
      "en": "Making It Forget"
    },
    "prompt": {
      "ko": "이미 학습이 끝난 모델에서 특정 데이터가 남긴 영향만 골라 제거해, 처음부터 그 데이터 없이 학습한 것과 사실상 같은 상태로 만들려는 연구 분야를 뭐라고 부릅니까? (영어 한 단어)",
      "en": "What single English word names the research area that removes one specific data point's influence from an already-trained model, aiming for a state indistinguishable from having trained without it?"
    },
    "hints": {
      "ko": [
        "learning 앞에 부정 접두사를 붙인 낱말입니다.",
        "삭제 요구권(잊힐 권리)을 모델에 적용하려면 반드시 필요한 기술입니다."
      ],
      "en": [
        "The word learning with a negating prefix on the front.",
        "It is what the right to erasure would require if it is to reach a model."
      ]
    }
  },
  {
    "id": "t0_ping",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 40,
    "ci": true,
    "hash": "758d61f26a44448384e5c4468a0dcb7a2abe456067b0f7b505bc28b9411fe931",
    "fmt": "명령어 / command",
    "title": {
      "ko": "살아 있나요?",
      "en": "Are You There?"
    },
    "prompt": {
      "ko": "원격 장비가 응답하는지 확인하려고 에코 요청을 보내고 왕복 시간을 알려 주는 한 단어짜리 명령은?",
      "en": "Which one-word command sends an echo request to see whether a remote machine answers, and reports the round-trip time?"
    },
    "hints": {
      "ko": [
        "잠수함 음파 탐지기가 내는 소리에서 이름을 따왔습니다.",
        "`____ -c 4 example.com` 처럼 네 번만 보낼 수도 있습니다."
      ],
      "en": [
        "Named after the sound sonar makes.",
        "`____ -c 4 example.com` sends just four of them."
      ]
    }
  },
  {
    "id": "t0_httpsport",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 45,
    "ci": true,
    "hash": "6d05621ab7cb7b4fb796ca2ffbe1a141e0d4319d3deb6a05322b9de85d69b923",
    "fmt": "숫자 / number",
    "title": {
      "ko": "자물쇠가 걸린 포트",
      "en": "The Locked Port"
    },
    "prompt": {
      "ko": "HTTPS가 기본으로 사용하는 TCP 포트 번호는? (숫자만)",
      "en": "Which TCP port number does HTTPS use by default? (number only)"
    },
    "hints": {
      "ko": [
        "암호화하지 않는 HTTP는 80번을 씁니다.",
        "세 자리이고 4로 시작합니다."
      ],
      "en": [
        "Plain HTTP uses 80.",
        "Three digits, starting with a 4."
      ]
    }
  },
  {
    "id": "t0_dhcp",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 45,
    "ci": true,
    "hash": "6f89bddf8582a8d223e132d10c9436e788687f159fbbf5ac36a6eb14d307a3fa",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "주소를 나눠 주는 쪽",
      "en": "Who Hands Out Addresses"
    },
    "prompt": {
      "ko": "네트워크에 막 접속한 장비에 IP 주소·서브넷 마스크·기본 경로를 자동으로 임대해 주는 프로토콜의 4글자 약자는?",
      "en": "What 4-letter acronym names the protocol that automatically leases an IP address, a subnet mask and a default route to a machine that just joined the network?"
    },
    "hints": {
      "ko": [
        "Dynamic Host Configuration Protocol 의 머리글자입니다.",
        "가짜 서버가 이 요청에 먼저 답해 버리면 서브넷 전체의 통신을 원하는 쪽으로 유도할 수 있습니다."
      ],
      "en": [
        "Initials of Dynamic Host Configuration Protocol.",
        "A rogue server that answers these requests first can steer a whole subnet."
      ]
    }
  },
  {
    "id": "t0_gateway",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 50,
    "ci": true,
    "hash": "4ea5ee68fea05586106890ded5733820bb77d919cda27bc4b8139b7cd33b8889",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "밖으로 나가는 문",
      "en": "The Way Out"
    },
    "prompt": {
      "ko": "목적지가 로컬 서브넷 밖이면 장비는 패킷을 LAN 안의 특정 주소로 넘깁니다. 나가는 패킷이 가장 먼저 거치는 이 라우터 인터페이스를 가리키는 '기본 ____' 의 영어 한 단어는?",
      "en": "When a packet's destination sits outside the local subnet, the machine hands it to one particular address on the LAN. What single English word names that 'default ____' — the router interface every outbound packet meets first?"
    },
    "hints": {
      "ko": [
        "통과해 지나가는 '문' 을 뜻하는 영어 단어입니다.",
        "`ip route` 출력에서 `default via ...` 줄이 이것을 가리킵니다."
      ],
      "en": [
        "The English word for a gate you pass through.",
        "`ip route` points at it on the `default via ...` line."
      ]
    }
  },
  {
    "id": "t0_mtu",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 50,
    "ci": true,
    "hash": "49be6e401e7f8b9844afb969dcbc96e78205ed86ec1e5a46150bd4ab4fdd5686",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "이보다 크면 쪼갠다",
      "en": "Bigger Than This Gets Split"
    },
    "prompt": {
      "ko": "한 프레임에 실을 수 있는 최대 페이로드 크기(보통 이더넷에서 1500바이트)로, 이보다 크면 패킷을 조각내야 하는 값을 가리키는 3글자 약자는?",
      "en": "What 3-letter acronym names the largest payload a link will carry in one frame — 1500 bytes on ordinary Ethernet — above which a packet must be fragmented?"
    },
    "hints": {
      "ko": [
        "Maximum Transmission Unit 의 머리글자입니다.",
        "터널은 헤더를 덧붙이므로 그 안에서는 이 값을 보통 낮춰 잡습니다."
      ],
      "en": [
        "Initials of Maximum Transmission Unit.",
        "A tunnel adds headers, so this value is usually lowered inside one."
      ]
    }
  },
  {
    "id": "t0_loopback",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 60,
    "ci": true,
    "hash": "64edaa3fb9310e98cdb183cddbf156d9964a05c017fa7f8ee3c262909fa36759",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "자기 자신에게",
      "en": "Back to Itself"
    },
    "prompt": {
      "ko": "모든 장비에는 트래픽이 밖으로 나가지 않고 자기 자신에게 되돌아오는 가상 인터페이스가 있습니다 — 리눅스의 `lo`, IPv4의 `127.0.0.1`, IPv6의 `::1`. 이 인터페이스를 부르는 영어 한 단어는?",
      "en": "Every machine has a virtual interface whose traffic never leaves it — `lo` on Linux, `127.0.0.1` on IPv4, `::1` on IPv6. What single English word names it?"
    },
    "hints": {
      "ko": [
        "'고리' 를 뜻하는 단어와 '되돌아옴' 을 뜻하는 단어를 붙인 합성어입니다.",
        "여기에만 바인딩한 서비스는 다른 장비에서 접근할 수 없습니다."
      ],
      "en": [
        "A compound of 'loop' and the word for coming back.",
        "A service bound only to it cannot be reached from another machine."
      ]
    }
  },
  {
    "id": "t0_osi",
    "tier": 0,
    "cat": "network",
    "track": "network",
    "points": 60,
    "ci": true,
    "hash": "75e07ef9bcaa8fd530089f7d81a3da7eda54a1cae0ebf0dbc72d0657deea2ae7",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "일곱 층",
      "en": "Seven Layers"
    },
    "prompt": {
      "ko": "물리·데이터링크·네트워크·전송·세션·표현·응용의 일곱 계층으로 나눈, 문제가 어느 계층에 있는지 말할 때 지금도 쓰는 참조 모델의 3글자 약자는?",
      "en": "What 3-letter acronym names the seven-layer reference model — physical, data link, network, transport, session, presentation, application — engineers still use to say which layer a problem lives on?"
    },
    "hints": {
      "ko": [
        "Open Systems Interconnection 의 머리글자입니다.",
        "일상적으로 말하는 L7·L3 가 이 모델의 계층 번호입니다."
      ],
      "en": [
        "Initials of Open Systems Interconnection.",
        "Everyday talk of 'L7' and 'L3' means this model's layers."
      ]
    }
  },
  {
    "id": "t1_arp",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 60,
    "ci": true,
    "hash": "cf835fc094349f22c2214fc8256cb895fcbcc01c77083c0f94114703d9e79a29",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "그 IP는 누구 것?",
      "en": "Who Has That IP?"
    },
    "prompt": {
      "ko": "같은 LAN 안에서 IPv4 주소만 아는 장비가 프레임에 들어갈 하드웨어 주소를 알아내야 합니다. 세그먼트 전체에 '10.0.0.5 를 가진 쪽?' 하고 물은 뒤 응답을 캐시에 담아 두는 이 프로토콜의 3글자 약자는?",
      "en": "Inside one LAN segment a machine that knows only an IPv4 address still needs the hardware address that belongs in the frame. What 3-letter acronym names the protocol that asks the whole segment 'who has 10.0.0.5?' and caches the reply?"
    },
    "hints": {
      "ko": [
        "Address Resolution Protocol 의 머리글자입니다.",
        "`____ -a` 로 캐시 표를 볼 수 있습니다. 응답에 인증이 없어 위조가 쉽습니다."
      ],
      "en": [
        "Initials of Address Resolution Protocol.",
        "`____ -a` prints the cached table; the replies are unauthenticated, so they are easy to forge."
      ]
    }
  },
  {
    "id": "t1_icmp",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 60,
    "ci": true,
    "hash": "c3eac7105ca647900c32b5eced7a6ccb56cded0790ef0bc08614a5ad31e54025",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "오류를 알려 주는 전령",
      "en": "The Messenger for Errors"
    },
    "prompt": {
      "ko": "사용자 데이터가 아니라 IP 자체의 제어·오류 메시지('목적지 도달 불가', '시간 초과', 에코 요청/응답)를 실어 나르는 프로토콜의 4글자 약자는?",
      "en": "Which 4-letter protocol acronym carries IP's own control and error messages — 'destination unreachable', 'time exceeded', the echo request/reply pair — rather than user data?"
    },
    "hints": {
      "ko": [
        "Internet Control Message Protocol 의 머리글자입니다.",
        "방화벽이 통째로 막아 두는 일이 많아, 조용한 장비가 곧 꺼진 장비는 아닙니다."
      ],
      "en": [
        "Initials of Internet Control Message Protocol.",
        "Firewalls often drop it wholesale, so a silent machine is not proof it is down."
      ]
    }
  },
  {
    "id": "t1_mx",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 65,
    "ci": true,
    "hash": "d7f890c4f72a3d49b69870b2dc2850c698e7b841eb2dd7cd21e4de551a29f4c4",
    "fmt": "약어 / acronym (2글자 / 2 chars)",
    "title": {
      "ko": "편지는 어디로",
      "en": "Where the Mail Goes"
    },
    "prompt": {
      "ko": "어떤 도메인의 메일을 어느 서버가 받는지 알려 주고, 여러 개일 때는 우선순위 숫자로 고르게 하는 DNS 레코드 종류의 2글자 약자는?",
      "en": "Which 2-letter DNS record type tells a sender which server accepts email for a domain, using a preference number to choose among several?"
    },
    "hints": {
      "ko": [
        "Mail eXchanger 의 줄임입니다.",
        "`dig example.com __` 로 조회합니다. 방치된 항목은 남의 서버로 메일을 넘길 수 있습니다."
      ],
      "en": [
        "Short for Mail eXchanger.",
        "`dig example.com __` lists them; a stale entry can hand mail to someone else."
      ]
    }
  },
  {
    "id": "t1_vlan",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 65,
    "ci": true,
    "hash": "c3b258168c41c0bce97616716bef315eeed33eb1142904bfe7f32eb392c7cf80",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "한 스위치, 여러 네트워크",
      "en": "One Switch, Many Networks"
    },
    "prompt": {
      "ko": "물리 스위치 한 대가 12비트 ID(802.1Q)로 구분되는 여러 개의 독립된 도메인을 나르게 해 주는 논리적 분할의 4글자 약자는?",
      "en": "What 4-letter acronym names the logical segmentation that lets one physical switch carry several separate domains, each tagged with its own 12-bit id (802.1Q)?"
    },
    "hints": {
      "ko": [
        "Virtual Local Area Network 의 머리글자입니다.",
        "포트를 트렁크 자동 협상 상태로 두면 그 사이를 건너뛰는 공격이 가능합니다."
      ],
      "en": [
        "Initials of Virtual Local Area Network.",
        "Leaving a port negotiating trunk mode lets an attacker hop between them."
      ]
    }
  },
  {
    "id": "t1_traceroute",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 70,
    "ci": true,
    "hash": "261063ce089e84d540c499ef21de9486c2be4ee6c79142a2dca537262239e6a5",
    "fmt": "명령어 / command",
    "title": {
      "ko": "어디를 거쳐 가나",
      "en": "Which Way Did It Go"
    },
    "prompt": {
      "ko": "TTL 을 1, 2, 3 으로 늘려 가며 탐침을 보내고 돌아오는 '시간 초과' 응답을 읽어, 패킷이 거쳐 가는 라우터를 하나씩 밝혀내는 고전 명령은? (한 단어, 유닉스 표기)",
      "en": "Which classic command reveals every router a packet passes through by sending probes with a time-to-live of 1, then 2, then 3, and reading each 'time exceeded' reply? (one word, the Unix spelling)"
    },
    "hints": {
      "ko": [
        "'추적' 을 뜻하는 단어에 '경로' 를 뜻하는 단어를 붙였습니다.",
        "윈도우에서는 `tracert` 라고 씁니다. 여기서 묻는 것은 유닉스 쪽 이름입니다."
      ],
      "en": [
        "The word for tracing joined with the word for a route.",
        "Windows spells it `tracert`; this asks for the Unix name."
      ]
    }
  },
  {
    "id": "t1_nat",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 70,
    "ci": true,
    "hash": "d919a100ce6b45524d415d52d088d5817587c6dd8c3691b03b8063c44d043523",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "하나의 공인 주소 뒤에",
      "en": "Behind One Public Address"
    },
    "prompt": {
      "ko": "사설 출발지 주소를 공인 주소 하나로 바꿔 쓰고(응답이 돌아올 수 있도록 포트를 기억하며), 가정 네트워크 전체가 IPv4 주소 하나를 나눠 쓰게 해 주는 라우터 기능의 3글자 약자는?",
      "en": "What 3-letter acronym names the router function that rewrites private source addresses into one public address — tracking ports so replies find their way back — letting a whole home network share a single IPv4 address?"
    },
    "hints": {
      "ko": [
        "Network Address Translation 의 머리글자입니다.",
        "그래서 이 뒤에 있는 장비는 포워딩 규칙 없이는 밖에서 먼저 접속할 수 없습니다."
      ],
      "en": [
        "Initials of Network Address Translation.",
        "It is why a machine behind it cannot be reached from outside without a forwarding rule."
      ]
    }
  },
  {
    "id": "t1_whois",
    "tier": 1,
    "cat": "network",
    "track": "network",
    "points": 65,
    "ci": true,
    "hash": "b1140742ba42ab97d3e8b01c0cbb29d4de2c347d735e20160f00468af5b2b021",
    "fmt": "명령어 / command",
    "title": {
      "ko": "이 도메인 주인은",
      "en": "Who Owns This Domain"
    },
    "prompt": {
      "ko": "정찰 단계에서 레지스트리에 질의해 도메인의 등록자·등록기관·네임서버·만료일을 가져오는 한 단어짜리 명령(그리고 그 뒤의 프로토콜)의 이름은?",
      "en": "In reconnaissance, which one-word command — and the protocol behind it — asks a registry for a domain's registrant, registrar, name servers and expiry date?"
    },
    "hints": {
      "ko": [
        "'who is' 라는 물음에서 빈칸을 뺀 형태입니다.",
        "요즘은 등록기관이 개인정보 보호를 이유로 상당 부분을 가려서 내보냅니다."
      ],
      "en": [
        "The question 'who is' with the space taken out.",
        "Registrars now redact much of the output for privacy."
      ]
    }
  },
  {
    "id": "t2_sni",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 80,
    "ci": true,
    "hash": "a97c5f2dd3d5023df257f9b37f1922f92a1aa1248b2eb082200c838724b51e2b",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "암호화 전에 새어 나가는 이름",
      "en": "The Name That Leaks First"
    },
    "prompt": {
      "ko": "TLS 핸드셰이크에서 ClientHello 는 암호화가 시작되기 전에 요청 대상의 이름을 평문으로 실어 보냅니다. HTTPS 인데도 중간 장비가 어느 사이트에 접속하는지 알 수 있는 이유이죠. 이 확장의 3글자 약자는?",
      "en": "In a TLS handshake the ClientHello carries the requested name in the clear, before any encryption begins — which is how a middlebox can tell which site you are visiting even over HTTPS. What 3-letter acronym names that extension?"
    },
    "hints": {
      "ko": [
        "Server Name Indication 의 머리글자입니다.",
        "IP 하나가 여러 인증서를 서비스할 수 있는 것도 서버가 이 값을 이렇게 일찍 알기 때문입니다."
      ],
      "en": [
        "Initials of Server Name Indication.",
        "One IP can serve many certificates only because the server learns the name this early."
      ]
    }
  },
  {
    "id": "t2_ipsec",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 85,
    "ci": true,
    "hash": "be9f13bdf5f5b56126d09f0489cf3f8464ae4b68e8787a8b9e68f5fa73aa8202",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "IP 계층의 터널",
      "en": "A Tunnel at the IP Layer"
    },
    "prompt": {
      "ko": "AH·ESP 로 무결성과 암호화를, IKE 로 키 교환을 담당하며 네트워크 계층 자체에서 트래픽을 보호해 대부분의 사이트 간 VPN 의 바탕이 되는 프로토콜 모음의 이름은? (붙여서 한 덩어리로)",
      "en": "Which protocol suite secures traffic at the network layer itself — AH and ESP for integrity and encryption, IKE for key exchange — and underpins most site-to-site VPNs? (one token, no space)"
    },
    "hints": {
      "ko": [
        "'IP' 뒤에 'security' 의 앞 세 글자를 붙인 이름입니다.",
        "전송 모드는 페이로드만, 터널 모드는 원본 패킷 전체를 감쌉니다."
      ],
      "en": [
        "'IP' joined with the first three letters of 'security'.",
        "Transport mode protects the payload; tunnel mode wraps the entire original packet."
      ]
    }
  },
  {
    "id": "t2_eviltwin",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 85,
    "ci": true,
    "hash": "35a53abb01f049ed49f551625c5c1fc45f2381c7804aa0e13c239b1b60ceceb0",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "똑같은 이름의 가짜",
      "en": "The Fake With the Same Name"
    },
    "prompt": {
      "ko": "공격자가 진짜와 똑같은 네트워크 이름을 더 강한 신호로 내보내는 무선 AP 를 세워, 단말이 그쪽에 붙게 만들고 오가는 트래픽을 가로챕니다. 이 가짜 AP 를 부르는 영어 두 단어는?",
      "en": "An attacker stands up an access point announcing the same network name as the real one, with a stronger signal, so clients associate with it and hand over their traffic. What two-word English term names this rogue access point?"
    },
    "hints": {
      "ko": [
        "'사악한' 을 뜻하는 형용사와 '쌍둥이' 를 뜻하는 명사, 두 단어입니다.",
        "가짜 로그인 페이지까지 붙이면 비밀번호도 함께 수집됩니다."
      ],
      "en": [
        "Two words: a wicked adjective plus the noun for an identical sibling.",
        "Pair it with a fake login page and it collects the password too."
      ]
    }
  },
  {
    "id": "t2_deauth",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 90,
    "ci": true,
    "hash": "da26748823899561eb2a55fd5a9d867d39a9d00a942e15828438fcf9e8de3804",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "잠깐 끊어라",
      "en": "Knock Them Off"
    },
    "prompt": {
      "ko": "802.11 관리 프레임은 오랫동안 인증되지 않아, 단말에게 연결을 끊으라고 알리는 프레임을 누구나 위조할 수 있었습니다. 가짜 AP 로 유도할 때도, 재접속 순간의 핸드셰이크를 잡을 때도 쓰였죠. 이 프레임과 공격을 부르는 짧은 이름은? (한 단어, 줄인 형태)",
      "en": "802.11 management frames went unauthenticated for years, so anyone could forge the one telling a client to disconnect — used both to push a client onto a rogue AP and to capture the handshake on reconnect. What is the common short name for that frame and attack? (one word, the abbreviated form)"
    },
    "hints": {
      "ko": [
        "'되돌리다' 를 뜻하는 접두사 뒤에 'authentication' 의 줄임을 붙인 형태입니다.",
        "802.11w 의 보호된 관리 프레임이 이 문제의 해결책입니다."
      ],
      "en": [
        "The prefix meaning 'undo' in front of the shortened form of 'authentication'.",
        "802.11w (protected management frames) is the fix."
      ]
    }
  },
  {
    "id": "t2_wep",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 90,
    "ci": true,
    "hash": "e5b3d61431b57b959f330ed5c6a6285ed52a86b3da8205ca175e5198e014f3c1",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "24비트짜리 실수",
      "en": "A 24-Bit Mistake"
    },
    "prompt": {
      "ko": "최초의 802.11 암호화 방식은 24비트 초기화 벡터와 RC4 를 썼는데, 이 값이 몇 시간이면 반복되어 수집한 트래픽만으로 몇 분 만에 키가 복구되었습니다. 이 방식의 3글자 약자는?",
      "en": "The original 802.11 encryption scheme paired RC4 with a 24-bit initialization vector that repeats within hours, letting the key be recovered from captured traffic in minutes. What is its 3-letter acronym?"
    },
    "hints": {
      "ko": [
        "Wired Equivalent Privacy 의 머리글자 — 이름이 약속한 것보다 훨씬 못했습니다.",
        "뒤이어 WPA, 그다음 WPA2 가 이것을 대체했습니다."
      ],
      "en": [
        "Initials of Wired Equivalent Privacy — a name that promised more than it delivered.",
        "WPA, and then WPA2, replaced it."
      ]
    }
  },
  {
    "id": "t2_snmp",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 100,
    "ci": true,
    "hash": "9e7f55c19ed75b9bb3bfcc7c65182fdeac0236803c4bf26ed437824b7338956a",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "열려 있는 관리 통로",
      "en": "The Management Door Left Open"
    },
    "prompt": {
      "ko": "라우터·스위치·프린터는 UDP 기반 관리 프로토콜로 상태 값과 설정을 노출합니다. 버전 1 과 2c 는 공유 문자열 하나만으로 인증하는데, 수많은 장비가 그 값을 `public` 그대로 두고 있죠. 이 프로토콜의 4글자 약자는?",
      "en": "Routers, switches and printers expose their counters and settings over a UDP management protocol whose versions 1 and 2c authenticate with nothing but a shared string — left at `public` on countless devices. What is its 4-letter acronym?"
    },
    "hints": {
      "ko": [
        "Simple Network Management Protocol 의 머리글자입니다.",
        "버전 3 에 와서야 제대로 된 인증과 암호화가 붙었습니다."
      ],
      "en": [
        "Initials of Simple Network Management Protocol.",
        "Version 3 was the first to add real authentication and encryption."
      ]
    }
  },
  {
    "id": "t2_promiscuous",
    "tier": 2,
    "cat": "network",
    "track": "network",
    "points": 80,
    "ci": true,
    "hash": "85f5d2e0be9805a29999c2226a417e555c9c442870d4e745a522483db17f80d9",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "내 것이 아닌 프레임까지",
      "en": "Frames That Are Not Yours"
    },
    "prompt": {
      "ko": "네트워크 카드는 보통 자기 하드웨어 주소로 오지 않은 프레임을 버립니다. 세그먼트의 모든 것을 잡으려는 스니퍼는 카드를 어떤 모드로 바꿀까요? (영어 한 단어)",
      "en": "A network card normally discards frames not addressed to its own hardware address. To capture everything on the segment, a sniffer puts the card into which mode? (one English word)"
    },
    "hints": {
      "ko": [
        "'가리지 않는' 을 뜻하는 영어 형용사입니다.",
        "스위치 환경에서는 이것만으로 부족해 미러 포트나 탭이 함께 필요합니다."
      ],
      "en": [
        "The English adjective for 'indiscriminate'.",
        "On a switched network it is not enough by itself — you also need a mirror port or a tap."
      ]
    }
  },
  {
    "id": "t3_rebinding",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 105,
    "ci": true,
    "hash": "0807d29b7231e5549c90e5dfccbd5f545aecad98b7530890abf4e4a1a0280bb9",
    "fmt": "한 단어 / one word (-ing으로 끝남 / ends in -ing)",
    "title": {
      "ko": "같은 이름, 다른 주소",
      "en": "Same Name, New Address"
    },
    "prompt": {
      "ko": "공격자의 도메인이 처음에는 공인 주소로 응답해 페이지를 띄우고, 레코드 수명을 1초로 둔 채 다시 물으면 `192.168.0.1` 로 응답합니다. 이미 로드된 스크립트가 같은 출처 자격으로 피해자의 공유기와 통신할 수 있게 되죠. 이 공격을 'DNS ____' 이라 부릅니다. 빈칸의 영어 한 단어는?",
      "en": "An attacker's domain first answers with a public address so the page loads, then — with a one-second record lifetime — answers again with `192.168.0.1`, so the already-loaded script may talk to the victim's router under the same origin. This attack is called 'DNS ____'. What one English word fills the blank?"
    },
    "hints": {
      "ko": [
        "'다시 묶는다' 는 뜻의 동사에 -ing 를 붙인 형태입니다.",
        "해석된 주소를 고정하거나, 목적지에서 요청이 자칭하는 이름을 검증하면 막힙니다."
      ],
      "en": [
        "The '-ing' form of a verb meaning to bind again, to something else.",
        "Pinning the resolved address, or checking at the target which name the request claims, defeats it."
      ]
    }
  },
  {
    "id": "t3_amplification",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 110,
    "ci": true,
    "hash": "ccc52fa33c390d49c7971ec7a3cce9de2d5dc8a40a2d34532644f576dd3a5c42",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "작게 묻고 크게 받는다",
      "en": "Small Question, Huge Answer"
    },
    "prompt": {
      "ko": "공격자가 출발지 주소를 피해자로 위조해 개방 리졸버나 NTP 서버에 작은 UDP 질의를 보내면, 훨씬 큰 응답이 전부 피해자에게 쏟아집니다. 공격자가 쓴 대역폭의 수십 배가 되기도 하죠. 이 효과를 가리키는 영어 한 단어는? ('DNS ____ 공격' 의 그 단어)",
      "en": "A DDoS technique forges the victim's address as the source of small UDP queries to open resolvers or NTP servers, whose far larger replies all land on the victim — dozens of times the attacker's own bandwidth. What single English word names that multiplying effect (as in 'DNS ____ attack')?"
    },
    "hints": {
      "ko": [
        "소리나 크기를 키운다는 뜻의 명사입니다.",
        "응답 크기와 질의 크기의 비를 이것의 '계수' 라고 부릅니다."
      ],
      "en": [
        "The noun for making something louder or larger.",
        "The ratio of reply size to query size is called the factor of this."
      ]
    }
  },
  {
    "id": "t3_slowloris",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 115,
    "ci": true,
    "hash": "1f2aff657741018a68ef7540764440d4387176bdf4eb0ffd7d7798d8a3d674f2",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "느리게 목을 조른다",
      "en": "Slow Strangulation"
    },
    "prompt": {
      "ko": "이 서비스 거부 공격은 웹 서버에 연결을 잔뜩 열어 두고 몇 초에 한 번씩 헤더 한 줄만 흘려보내 연결을 간신히 살려 둡니다. 대역폭을 거의 쓰지 않고도 연결 풀이 고갈되죠. 느리게 움직이는 영장류의 이름을 딴 이 공격의 이름은? (한 단어)",
      "en": "This denial of service opens many connections to a web server and keeps each barely alive by dribbling out a single partial header every few seconds, exhausting the connection pool on almost no bandwidth. It is named after a slow-moving primate. What is it called? (one word)"
    },
    "hints": {
      "ko": [
        "'느린' 을 뜻하는 단어에, 눈이 큰 야행성 영장류의 이름을 붙였습니다.",
        "요청을 전부 받아 두었다가 넘기는 리버스 프록시를 앞에 두면 무력화됩니다."
      ],
      "en": [
        "'slow' joined with the name of a big-eyed nocturnal primate.",
        "A reverse proxy that buffers the whole request before forwarding defeats it."
      ]
    }
  },
  {
    "id": "t3_pivoting",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 120,
    "ci": true,
    "hash": "230bb2b52c70291db9127a0dea376a56a037af5057ed7ca08918985e2db2875d",
    "fmt": "한 단어 / one word (-ing으로 끝남 / ends in -ing)",
    "title": {
      "ko": "발판을 딛고 안쪽으로",
      "en": "Using the Foothold to Go Deeper"
    },
    "prompt": {
      "ko": "인터넷에 노출된 장비 한 대를 장악한 공격자가 그 장비를 통해 트래픽을 흘려보내, 외부에 열린 적 없는 내부 서브넷까지 닿습니다 — SSH 터널·포트 포워딩·SOCKS 프록시로요. 이렇게 네트워크 안쪽으로 옮겨 가는 행위를 가리키는 영어 한 단어(-ing 형)는?",
      "en": "Having taken one internet-facing machine, the attacker routes traffic through it to reach the internal subnet that was never exposed — with SSH tunnels, port forwards, a SOCKS proxy. What single English word, in its -ing form, names moving deeper into a network this way?"
    },
    "hints": {
      "ko": [
        "한 발을 축으로 삼아 도는 동작을 뜻하는 동사의 -ing 형입니다.",
        "네트워크 분할(세그멘테이션)은 바로 이 비용을 올리려고 존재합니다."
      ],
      "en": [
        "The -ing form of the verb for turning on a fixed point, the way a basketball player does.",
        "Network segmentation exists precisely to make this expensive."
      ]
    }
  },
  {
    "id": "t3_portknock",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 125,
    "ci": true,
    "hash": "d2e949a46902f80a82c919b99f035c9d0d29cada38b12ccac42d88d3c9aa0ebb",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "정해진 순서로 두드려라",
      "en": "Knock in the Right Order"
    },
    "prompt": {
      "ko": "서비스를 방화벽 뒤에 숨겨 두고, 클라이언트가 닫힌 포트들을 미리 약속한 순서대로 두드렸을 때만 해당 포트를 열어 주는 방식이 있습니다. 올바른 리듬으로 두드린 사람에게만 문이 열리는 셈이죠. 이 기법을 부르는 영어 두 단어는?",
      "en": "A service can hide behind a firewall that opens its port only after the client has attempted connections to a prearranged sequence of closed ports — the door opens only for whoever taps the right rhythm. What two-word English term names this technique?"
    },
    "hints": {
      "ko": [
        "두 번째 단어는 문 앞에서 하는 동작의 -ing 형입니다.",
        "인증이 아니라 은닉입니다 — 순서를 엿본 사람은 그대로 따라 할 수 있습니다."
      ],
      "en": [
        "The second word is the -ing form of what you do at a door.",
        "It is obscurity, not authentication — anyone who watches the sequence can replay it."
      ]
    }
  },
  {
    "id": "t3_ja3",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 130,
    "ci": true,
    "hash": "d823ade9182081d884b7e1b914e89bbdb03a8ea0e6a393a4596ad940c7b44bee",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "손을 어떻게 흔드는가",
      "en": "How You Shake Hands"
    },
    "prompt": {
      "ko": "TLS 를 복호화하지 않고도, ClientHello 에 실린 암호 스위트·확장·곡선 목록을 순서 그대로 해시하면 클라이언트 라이브러리를 식별하는 지문이 나옵니다. HTTPS 위에서도 특정 악성코드 계열이 드러나죠. Salesforce 가 공개한 이 지문의 3글자 이름은?",
      "en": "Without decrypting TLS at all, a defender can hash the ordered list of cipher suites, extensions and curves in the ClientHello to get a fingerprint identifying the client library — so a malware family stands out even over HTTPS. What is the 3-character name of this fingerprint, published by Salesforce?"
    },
    "hints": {
      "ko": [
        "이니셜 두 글자 뒤에 숫자 3 이 붙습니다. 후속 규격은 같은 방식으로 4 가 붙습니다.",
        "서버 쪽에도 짝이 되는 지문이 있고, 이름 끝에 S 가 붙습니다."
      ],
      "en": [
        "Two initials followed by the digit 3; its successor is named the same way with a 4.",
        "Servers have a counterpart fingerprint whose name ends in an S."
      ]
    }
  },
  {
    "id": "t3_bgp",
    "tier": 3,
    "cat": "network",
    "track": "network",
    "points": 140,
    "ci": true,
    "hash": "5ed8c466a446c1f9802271d7393e807a8470b936cff34f05bc617cf4d5a7dd72",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "인터넷은 신뢰로 굴러간다",
      "en": "The Internet Runs on Trust"
    },
    "prompt": {
      "ko": "자율 시스템(AS)들이 자기가 닿을 수 있는 주소 대역을 서로 알리는 이 프로토콜에는 소유권을 증명하는 장치가 없습니다. 그래서 남의 대역을 자기 것이라 광고하면 그 네트워크로 갈 트래픽을 끌어올 수 있죠. 이 라우팅 프로토콜의 3글자 약자는?",
      "en": "The protocol autonomous systems use to advertise which address blocks they can reach has no built-in proof of ownership — so an operator announcing a prefix it does not hold can pull another network's traffic to itself. What is this routing protocol's 3-letter acronym?"
    },
    "hints": {
      "ko": [
        "자율 시스템 사이에서 TCP 179 번 위로 동작합니다.",
        "2008년 유튜브 접속 장애와 여러 건의 암호화폐 거래소 탈취가 거짓 광고 하나에서 시작됐습니다."
      ],
      "en": [
        "It runs between autonomous systems over TCP port 179.",
        "The 2008 YouTube outage and several crypto-exchange thefts began with one false announcement here."
      ]
    }
  },
  {
    "id": "t4_quic",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 140,
    "ci": true,
    "hash": "387166e8d5e3d12859c7b18a34dae7f4337e6a8039347f8d5279e6f7f854c40d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "UDP 위에 올라탄 전송",
      "en": "Transport on Top of UDP"
    },
    "prompt": {
      "ko": "HTTP/3 는 TCP 위에서 동작하지 않습니다. 이 전송 프로토콜은 UDP 위에서 스트림을 다중화하고 핸드셰이크와 암호화를 안에 품고 있어, 별도의 TLS 계층이 없고 패킷 하나를 잃어도 해당 스트림만 멈춥니다. 이 프로토콜의 이름은? (붙여서 한 덩어리로)",
      "en": "HTTP/3 does not run on TCP at all. Its transport multiplexes streams over UDP with the handshake and encryption built in, so there is no separate TLS layer and a lost packet stalls only its own stream. What is this transport protocol called? (one token)"
    },
    "hints": {
      "ko": [
        "네 글자입니다. 구글에서 처음엔 약자로 읽혔지만 지금은 그냥 프로토콜 이름입니다.",
        "UDP 위에 있으므로 TCP 만 이해하는 중간 장비는 내용을 들여다볼 수 없습니다."
      ],
      "en": [
        "Four letters; first read as an acronym at Google, now simply the protocol's name.",
        "Because it rides UDP, middleboxes that only understand TCP cannot inspect it."
      ]
    }
  },
  {
    "id": "t4_doh",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 150,
    "ci": true,
    "hash": "30ba046924427f14548567adbd8f9e36ca530c6d5b9b81ab1d767a1278e9491b",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "질의까지 숨긴다",
      "en": "Hiding the Lookup Too"
    },
    "prompt": {
      "ko": "이름 해석은 원래 UDP 53 번을 평문으로 오갔기 때문에 경로상의 누구나 보고 바꿀 수 있었습니다. 이 질의를 리졸버로 향하는 평범한 HTTPS 요청 안에 감싸 넣는 방식의 3글자 약자는? — 기업 방화벽에서 웹 트래픽과 구분되지 않는다는 부작용도 함께 옵니다.",
      "en": "Name resolution used to travel in the clear over UDP 53, so anyone on the path could read and rewrite it. What 3-letter acronym names the scheme that wraps those queries inside an ordinary HTTPS request to a resolver — which also makes them indistinguishable from web traffic at the enterprise firewall?"
    },
    "hints": {
      "ko": [
        "프로토콜 이름, 'over', 그리고 보안 웹 프로토콜 — 각각의 첫 글자만 땄습니다.",
        "전용 포트를 그대로 쓰는 형제 규격도 있는데, 그쪽은 HTTPS 안에 숨지 않습니다."
      ],
      "en": [
        "The protocol's name, the word 'over', and the secure web protocol — first letters only.",
        "A sibling scheme keeps a dedicated port instead of hiding inside HTTPS."
      ]
    }
  },
  {
    "id": "t4_rpki",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 160,
    "ci": true,
    "hash": "9dd287895fae6b057f80e8e7a17d5f53f373f27aed24718b493cc63e45cd82f4",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "이 대역이 정말 네 것인가",
      "en": "Prove the Prefix Is Yours"
    },
    "prompt": {
      "ko": "자기 것이 아닌 주소 대역을 광고하지 못하도록, 각 대역과 그것을 광고해도 되는 AS 를 묶은 서명 객체를 공개하고 라우터가 어긋나는 광고를 거부하게 합니다. 이 인증서 기반 구조의 4글자 약자는?",
      "en": "To stop a network from announcing address space it does not hold, operators publish signed objects binding each prefix to the autonomous system allowed to originate it, and routers reject announcements that contradict them. What 4-letter acronym names this certificate infrastructure?"
    },
    "hints": {
      "ko": [
        "Resource Public Key Infrastructure 의 머리글자입니다.",
        "서명된 객체 자체는 ROA 라고 부릅니다."
      ],
      "en": [
        "Initials of Resource Public Key Infrastructure.",
        "The signed object itself is called a ROA."
      ]
    }
  },
  {
    "id": "t4_ocsp",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 170,
    "ci": true,
    "hash": "b913067f07fd41354ac64402bf7b5b5d3b2862ed567dbf77eb52db9277db5be5",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "이 인증서 아직 살아 있나",
      "en": "Is This Certificate Still Good"
    },
    "prompt": {
      "ko": "브라우저가 폐기 목록 전체를 내려받는 대신, 특정 인증서 하나가 폐기되었는지 발급 CA 에 실시간으로 물어볼 수 있습니다. 다만 서버가 그 응답을 대신 첨부(stapling)하지 않으면 CA 에게 접속 사이트를 알려 주는 셈이 되죠. 이 프로토콜의 4글자 약자는?",
      "en": "A browser can ask the issuing CA in real time whether one specific certificate has been revoked, instead of downloading an entire revocation list — at the cost of telling the CA which site you are visiting, unless the server staples the answer itself. What 4-letter acronym names this protocol?"
    },
    "hints": {
      "ko": [
        "Online Certificate Status Protocol 의 머리글자입니다.",
        "이것이 대체한 목록 기반 방식은 CRL 입니다."
      ],
      "en": [
        "Initials of Online Certificate Status Protocol.",
        "The list-based alternative it replaced is the CRL."
      ]
    }
  },
  {
    "id": "t4_krack",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 180,
    "ci": true,
    "hash": "f7c1cc0ee77f3053be6032dfaa32913d9af58a7f64b06e352d2d7f4df5c11699",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "핸드셰이크를 되감다",
      "en": "Rewinding the Handshake"
    },
    "prompt": {
      "ko": "2017년 WPA2 의 4-way 핸드셰이크 결함으로, 공격자가 세 번째 메시지를 재전송해 단말이 이미 쓴 키를 다시 설치하고 카운터를 되돌리게 만들 수 있었습니다. 암호를 몰라도 트래픽이 복호화되었죠. 이 키 재설치 공격에 붙은 한 단어짜리 이름은?",
      "en": "In 2017 a flaw in the WPA2 four-way handshake let an attacker replay message three, forcing the client to reinstall an already-used key and reset its counter — decrypting traffic without ever learning the passphrase. What one-word name was given to this key reinstallation attack?"
    },
    "hints": {
      "ko": [
        "'Key Reinstallation AttaCK' 에서 뽑아낸, 균열을 뜻하는 단어의 일부러 틀린 철자입니다.",
        "해결은 새 비밀번호가 아니라 단말 쪽 패치였습니다."
      ],
      "en": [
        "A deliberate misspelling of the word for a crack or flaw, drawn out of 'Key Reinstallation AttaCK'.",
        "The fix was a client-side patch, not a new passphrase."
      ]
    }
  },
  {
    "id": "t4_netflow",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 190,
    "ci": true,
    "hash": "fc9c32a4bcde53e93edee75376691f5192b33ca4f197c78805ce9d748ae0cdf5",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "패킷 대신 대화 기록",
      "en": "Conversations, Not Packets"
    },
    "prompt": {
      "ko": "규모가 커지면 모든 패킷을 저장할 수 없으므로, 라우터는 대화 단위로 출발지·목적지·포트·프로토콜·바이트/패킷 수를 담은 레코드를 내보냅니다. 몇 달 뒤에도 주기적 통신이나 대용량 전송을 찾아내기에 충분하죠. 지금은 IPFIX 로 표준화된 이 흐름 레코드에 시스코가 붙인 이름은? (붙여서 한 덩어리로)",
      "en": "Storing every packet is impossible at scale, so routers export one record per conversation — source, destination, ports, protocol, byte and packet counts — enough to spot a periodic call-home or a large transfer months later. What is Cisco's name for these flow records, now generalized as IPFIX? (one token)"
    },
    "hints": {
      "ko": [
        "'net' 뒤에 '흐름' 을 뜻하는 영어 단어를 붙였습니다.",
        "템플릿은 아홉 번째 버전에서 도입되었고, 이를 바탕으로 만든 IETF 표준이 IPFIX 입니다."
      ],
      "en": [
        "'net' joined with the English word for a stream of movement.",
        "Templates arrived in its ninth version; the IETF standard built on it is IPFIX."
      ]
    }
  },
  {
    "id": "t4_wireguard",
    "tier": 4,
    "cat": "network",
    "track": "network",
    "points": 200,
    "ci": true,
    "hash": "28387a164997aec602d65711a6a74d4ee162d8fb5987702e7962031a61262887",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "4천 줄짜리 VPN",
      "en": "A VPN in Four Thousand Lines"
    },
    "prompt": {
      "ko": "이 VPN 은 리눅스 커널 안에 수천 줄로 구현되어 있고, 암호 협상을 아예 제공하지 않으며(고정된 현대 알고리즘 한 벌), SSH 처럼 공개키로 상대를 식별하고, UDP 위에서 동작합니다. 이름은? (붙여서 한 덩어리로)",
      "en": "This VPN lives in the Linux kernel in a few thousand lines, offers no cipher negotiation at all (one fixed modern suite), identifies peers by public key the way SSH does, and runs over UDP. What is it called? (one token)"
    },
    "hints": {
      "ko": [
        "'선(wire)' 뒤에 '지키는 사람' 을 뜻하는 영어 단어를 붙였습니다.",
        "코드가 작아 감사하기 쉽다는 점이 강점이었고, 리눅스 5.6 에 병합되었습니다."
      ],
      "en": [
        "'wire' joined with the English word for one who protects.",
        "Its small codebase was the argument for auditability; it merged into Linux 5.6."
      ]
    }
  }
];
