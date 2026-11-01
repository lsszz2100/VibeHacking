#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function computeHash(id) {
  const ident = id.replace(/^t\d_/, '') + "_v1";
  const flag = "FLAG{" + crypto.createHash('sha256').update(ident).digest('hex').substring(0, 20) + "}";
  return crypto.createHash('sha256').update(flag).digest('hex');
}

const challengesDef = [
  // Tier 0 (2)
  {
    id: "t0_c2tunnel_fundamentals_covert_channels",
    tier: 0, cat: "covert", track: "c2tunnel", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "C2 네트워크 터널링과 정규 프로토콜 은닉 채널 원리", en: "C2 Network Tunneling & Covert Channel Principles" },
    prompt: {
      ko: "엄격한 경계 방화벽 환경에서 DNS, HTTP, ICMP 등 허용된 프로토콜 페이로드 내부에 임의의 명령과 데이터를 캡슐화하는 은닉 채널 원리를 분석합니다.\n지정된 식별자 `c2tunnel_fundamentals_covert_channels_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_fundamentals_covert_channels_v1\") 앞 20자리}`",
      en: "Examine covert channel mechanisms encapsulating unauthorized C2 commands inside legitimate protocol payloads.\nCompute the first 20 hex characters of SHA256(\"c2tunnel_fundamentals_covert_channels_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_fundamentals_covert_channels_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["은닉 채널은 방화벽의 비인가 아웃바운드 포트 차단을 우회하기 위해 정규 프로토콜을 터널로 악용합니다.", "식별자 `c2tunnel_fundamentals_covert_channels_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Covert channels bypass perimeter egress filters by tunneling inside permitted protocols.", "Extract first 20 hex chars of SHA256(\"c2tunnel_fundamentals_covert_channels_v1\")."]
    }
  },
  {
    id: "t0_c2tunnel_egress_firewall_bypass_principles",
    tier: 0, cat: "egress", track: "c2tunnel", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "경계 방화벽 아웃바운드 통제와 포트 터널링 우회 매커니즘", en: "Perimeter Egress Controls & Port Tunneling Bypass Mechanisms" },
    prompt: {
      ko: "외향 트래픽 포트 차단을 우회하기 위해 표준 80(HTTP), 443(HTTPS), 53(DNS) 포트로 위장하여 외부 C2 서버와 연결을 수립하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_egress_firewall_bypass_principles_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_egress_firewall_bypass_principles_v1\") 앞 20자리}`",
      en: "Analyze how adversaries disguise C2 connections as outbound traffic on ports 80, 443, or 53 to circumvent perimeter firewalls.\nCompute the first 20 hex characters of SHA256(\"c2tunnel_egress_firewall_bypass_principles_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_egress_firewall_bypass_principles_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["단순 포트 기반 필터링은 페이로드 내용까지 검사하지 못하므로 터널링 공격에 취약합니다.", "식별자 `c2tunnel_egress_firewall_bypass_principles_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Port-based packet filtering alone fails to detect encapsulated covert traffic.", "Extract first 20 hex chars of SHA256(\"c2tunnel_egress_firewall_bypass_principles_v1\")."]
    }
  },

  // Tier 1 (8)
  {
    id: "t1_c2tunnel_dns_protocol_recursion_rfc1035",
    tier: 1, cat: "dnstunnel", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "DNS 재귀 질의(Recursive Query)를 통한 폐쇄망 외부 통신 원리", en: "Isolated Network Communication via Recursive DNS Resolution" },
    prompt: {
      ko: "인터넷 직접 접속이 차단된 내부 호스트가 사내 DNS 캐시 서버의 재귀 질의를 경유하여 공격자의 권한 있는 네임서버와 통신하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_dns_protocol_recursion_rfc1035_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_dns_protocol_recursion_rfc1035_v1\") 앞 20자리}`",
      en: "Analyze how internal hosts without direct internet access reach attacker authoritative nameservers via recursive resolvers.\nCompute first 20 hex chars of SHA256(\"c2tunnel_dns_protocol_recursion_rfc1035_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_dns_protocol_recursion_rfc1035_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["재귀 리졸버는 권한 있는 네임서버의 응답을 클라이언트에게 중계하므로 간접 C2 프록시 역할을 수행하게 됩니다.", "식별자 `c2tunnel_dns_protocol_recursion_rfc1035_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Recursive resolvers act as accidental intermediaries forwarding requests to malicious authoritative servers.", "Extract first 20 hex chars of SHA256(\"c2tunnel_dns_protocol_recursion_rfc1035_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_dns_txt_null_record_exfiltration",
    tier: 1, cat: "dnstunnel", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "DNS TXT/NULL/CNAME 레코드를 활용한 데이터 청킹 및 양방향 전송", en: "Data Chunking & Bidirectional Transfer via TXT/NULL Records" },
    prompt: {
      ko: "서브도메인 라벨로 데이터를 분할 업링크하고, TXT/NULL 레코드 응답 페이로드로 C2 명령을 수신하는 양방향 터널 구조를 분석합니다.\n지정된 식별자 `c2tunnel_dns_txt_null_record_exfiltration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_dns_txt_null_record_exfiltration_v1\") 앞 20자리}`",
      en: "Examine bidirectional DNS tunneling chunking encoded data into subdomains and receiving downstream commands via TXT payloads.\nCompute first 20 hex chars of SHA256(\"c2tunnel_dns_txt_null_record_exfiltration_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_dns_txt_null_record_exfiltration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TXT 레코드는 임의의 바이너리 또는 Base64 문자열을 대용량으로 반환할 수 있어 C2 다운링크에 널리 악용됩니다.", "식별자 `c2tunnel_dns_txt_null_record_exfiltration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["TXT records carry large text responses ideal for delivering staged payloads.", "Extract first 20 hex chars of SHA256(\"c2tunnel_dns_txt_null_record_exfiltration_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_iodine_dnscat2_tunnel_architecture",
    tier: 1, cat: "dnstunnel", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "iodine 및 dnscat2 오픈소스 DNS 터널링 도구 내부 구조", en: "Internal Architecture of iodine & dnscat2 DNS Tunneling Tools" },
    prompt: {
      ko: "가상 TUN/TAP 인터페이스를 생성하여 완전한 IP-over-DNS 터널을 수립하는 iodine과 애플리케이션 계층 명령 셸을 중계하는 dnscat2 구조를 비교 분석합니다.\n지정된 식별자 `c2tunnel_iodine_dnscat2_tunnel_architecture_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_iodine_dnscat2_tunnel_architecture_v1\") 앞 20자리}`",
      en: "Compare iodine creating virtual TUN devices for IP-over-DNS and dnscat2 providing application-layer command shells.\nCompute first 20 hex chars of SHA256(\"c2tunnel_iodine_dnscat2_tunnel_architecture_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_iodine_dnscat2_tunnel_architecture_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["iodine은 OS 네트워크 스택에 가상 IP를 할당하여 브라우징 및 SSH 접속을 DNS 터널로 라우팅합니다.", "식별자 `c2tunnel_iodine_dnscat2_tunnel_architecture_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["iodine operates at Layer 3 by allocating a virtual TUN subnet over DNS.", "Extract first 20 hex chars of SHA256(\"c2tunnel_iodine_dnscat2_tunnel_architecture_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_ssh_dynamic_port_forwarding",
    tier: 1, cat: "reversepivot", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "SSH -D 동적 포트 포워딩과 로컬 SOCKS5 인터페이스 생성", en: "SSH -D Dynamic Forwarding & Local SOCKS5 Interface Creation" },
    prompt: {
      ko: "SSH 클라이언트의 `-D [port]` 옵션을 활용하여 로컬 호스트에 다이나믹 애플리케이션 프록시(SOCKS5)를 바인딩하고 트래픽을 중계하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_ssh_dynamic_port_forwarding_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_ssh_dynamic_port_forwarding_v1\") 앞 20자리}`",
      en: "Analyze SSH dynamic port forwarding (`ssh -D 1080`) creating a local SOCKS5 proxy to tunnel arbitrary TCP connections.\nCompute first 20 hex chars of SHA256(\"c2tunnel_ssh_dynamic_port_forwarding_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_ssh_dynamic_port_forwarding_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["동적 포트 포워딩은 대상 목적지 포트가 가변적인 웹 브라우징이나 nmap 스캔 트래픽을 라우팅할 때 필수적입니다.", "식별자 `c2tunnel_ssh_dynamic_port_forwarding_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Dynamic forwarding delegates application destination routing to the local SOCKS listener.", "Extract first 20 hex chars of SHA256(\"c2tunnel_ssh_dynamic_port_forwarding_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_chisel_websocket_http2_tunneling",
    tier: 1, cat: "reversepivot", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Chisel의 HTTP/2 및 WebSocket 기반 단일 스트림 암호화 터널링", en: "Chisel Single-Stream Encrypted Tunneling over HTTP/2 & WebSocket" },
    prompt: {
      ko: "Chisel이 TCP 연결을 다중화하여 단일 WebSocket/HTTP2 스트림으로 캡슐화함으로써 기업 프록시의 심층 패킷 검사를 무력화하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_chisel_websocket_http2_tunneling_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_chisel_websocket_http2_tunneling_v1\") 앞 20자리}`",
      en: "Investigate how Chisel multiplexes TCP connections inside encrypted WebSocket streams to bypass corporate DPI proxies.\nCompute first 20 hex chars of SHA256(\"c2tunnel_chisel_websocket_http2_tunneling_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_chisel_websocket_http2_tunneling_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Chisel은 TLS 암호화 및 업그레이드 헤더를 통해 일반적인 웹 트래픽으로 완벽히 위장합니다.", "식별자 `c2tunnel_chisel_websocket_http2_tunneling_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Chisel mimics regular HTTPS WebSocket upgrades to defeat layer 7 filters.", "Extract first 20 hex chars of SHA256(\"c2tunnel_chisel_websocket_http2_tunneling_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_icmp_tunneling_ptunnel_mechanics",
    tier: 1, cat: "covert", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "ICMP Echo Request/Reply 페이로드를 악용한 ping 터널링 원리", en: "ICMP Echo Request/Reply Payload Tunneling Mechanics" },
    prompt: {
      ko: "보안 관리자가 방심하기 쉬운 ICMP Echo Request/Reply 패킷의 데이터 필드에 임의의 TCP 바이트 스트림을 실어 나르는 ptunnel 기법을 분석합니다.\n지정된 식별자 `c2tunnel_icmp_tunneling_ptunnel_mechanics_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_icmp_tunneling_ptunnel_mechanics_v1\") 앞 20자리}`",
      en: "Analyze ptunnel encapsulating full TCP connections into ICMP Echo Request and Reply data fields.\nCompute first 20 hex chars of SHA256(\"c2tunnel_icmp_tunneling_ptunnel_mechanics_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_icmp_tunneling_ptunnel_mechanics_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["일반적인 ping 패킷 페이로드는 알파벳 패턴을 가지지만 터널링 패킷은 압축/암호화된 비정형 데이터가 포함됩니다.", "식별자 `c2tunnel_icmp_tunneling_ptunnel_mechanics_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Standard ping packets have static padding, unlike encrypted binary payloads in ICMP tunnels.", "Extract first 20 hex chars of SHA256(\"c2tunnel_icmp_tunneling_ptunnel_mechanics_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_http_chunked_transfer_encoding_covert",
    tier: 1, cat: "c2profile", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "HTTP 청크 전송 인코딩을 악용한 비동기 C2 데이터 유출", en: "Asynchronous C2 Data Exfiltration via HTTP Chunked Transfer" },
    prompt: {
      ko: "Content-Length 없이 연결을 유지하며 잘게 쪼갠 청크 단위로 C2 명령과 데이터를 연속 송수신하는 HTTP/1.1 청크 터널링 구조를 분석합니다.\n지정된 식별자 `c2tunnel_http_chunked_transfer_encoding_covert_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_http_chunked_transfer_encoding_covert_v1\") 앞 20자리}`",
      en: "Examine HTTP chunked transfer encoding (`Transfer-Encoding: chunked`) streaming exfiltration without explicit Content-Length headers.\nCompute first 20 hex chars of SHA256(\"c2tunnel_http_chunked_transfer_encoding_covert_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_http_chunked_transfer_encoding_covert_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["청크 전송은 데이터 버퍼링 없이 즉시 패킷을 스트리밍할 수 있어 실시간 대화형 셸을 모방합니다.", "식별자 `c2tunnel_http_chunked_transfer_encoding_covert_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Chunked encoding allows real-time interactive terminal streaming without buffering.", "Extract first 20 hex chars of SHA256(\"c2tunnel_http_chunked_transfer_encoding_covert_v1\")."]
    }
  },
  {
    id: "t1_c2tunnel_reverse_port_forwarding_inbound_pivot",
    tier: 1, cat: "reversepivot", track: "c2tunnel", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "SSH -R 및 외부 릴레이를 통한 내부망 인바운드 역방향 진입점", en: "Inbound Lateral Pivoting via SSH Reverse Port Forwarding" },
    prompt: {
      ko: "내부 감염 호스트에서 외부 C2 서버로 아웃바운드 SSH 연결을 맺고, 외부 서버의 특정 포트를 내부망 서비스로 바인딩하는 역방향 터널 구조를 분석합니다.\n지정된 식별자 `c2tunnel_reverse_port_forwarding_inbound_pivot_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_reverse_port_forwarding_inbound_pivot_v1\") 앞 20자리}`",
      en: "Analyze SSH reverse forwarding (`ssh -R 8080:localhost:80`) exposing internal resources to external attackers.\nCompute first 20 hex chars of SHA256(\"c2tunnel_reverse_port_forwarding_inbound_pivot_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_reverse_port_forwarding_inbound_pivot_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["역방향 포트 포워딩은 방화벽 인바운드 차단 정책을 완벽하게 우회하여 침투 경로를 개방합니다.", "식별자 `c2tunnel_reverse_port_forwarding_inbound_pivot_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Reverse forwarding turns outbound client connections into inbound entry gateways.", "Extract first 20 hex chars of SHA256(\"c2tunnel_reverse_port_forwarding_inbound_pivot_v1\")."]
    }
  },

  // Tier 2 (12)
  {
    id: "t2_c2tunnel_shannon_entropy_mathematical_model",
    tier: 2, cat: "dnstunnel", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "FQDN 라벨의 Shannon 정보 엔트로피(H >= 3.8) 계산 및 판정", en: "Shannon Entropy Calculation & Thresholding on FQDN Labels" },
    prompt: {
      ko: "서브도메인 라벨의 문자열 무작위성을 Shannon 엔트로피 공식 $H(X) = -\\sum P(x)\\log_2 P(x)$로 수치화하여 임계값 3.8 이상을 탐지하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_shannon_entropy_mathematical_model_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_shannon_entropy_mathematical_model_v1\") 앞 20자리}`",
      en: "Model Shannon entropy calculations ($H \\ge 3.8$) detecting encoded malicious DNS exfiltration subdomains.\nCompute first 20 hex chars of SHA256(\"c2tunnel_shannon_entropy_mathematical_model_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_shannon_entropy_mathematical_model_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["인코딩되거나 암호화된 데이터는 균등한 문자 분포를 가져 일반 도메인명보다 월등히 높은 엔트로피를 보입니다.", "식별자 `c2tunnel_shannon_entropy_mathematical_model_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Encrypted or base-encoded payloads yield uniform character distributions with higher entropy.", "Extract first 20 hex chars of SHA256(\"c2tunnel_shannon_entropy_mathematical_model_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_base32_subdomain_encoding_detection",
    tier: 2, cat: "dnstunnel", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "대소문자 무관 DNS 규격에 맞춘 Base32 인코딩 청크 식별", en: "Detection of Case-Insensitive Base32 Subdomain Chunks" },
    prompt: {
      ko: "DNS 프로토콜이 대소문자를 구분하지 않는 점을 감안하여 Base64 대신 Base32(A-Z, 2-7) 알파벳을 사용하는 터널링 페이로드를 식별하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_base32_subdomain_encoding_detection_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_base32_subdomain_encoding_detection_v1\") 앞 20자리}`",
      en: "Identify Base32 (A-Z, 2-7) encoded chunks in DNS subdomains designed for case-insensitive resolver compatibility.\nCompute first 20 hex chars of SHA256(\"c2tunnel_base32_subdomain_encoding_detection_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_base32_subdomain_encoding_detection_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Base32는 특수문자나 소문자 왜곡 없이 DNS 캐시 계층을 안전하게 통과할 수 있습니다.", "식별자 `c2tunnel_base32_subdomain_encoding_detection_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Base32 alphabet prevents corruption when intermediate DNS caches lower-case query names.", "Extract first 20 hex chars of SHA256(\"c2tunnel_base32_subdomain_encoding_detection_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_chisel_reverse_socks5_proxy_chain",
    tier: 2, cat: "reversepivot", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Chisel R:socks 명령을 통한 역방향 프록시 체이닝 기법", en: "Reverse Proxy Chaining via Chisel R:socks Architecture" },
    prompt: {
      ko: "공격자가 C2 서버에 `./chisel client [c2_ip]:8443 R:1080:socks` 명령을 전송하여 외부 공격 머신에 내부망 접근 SOCKS5 인터페이스를 활성화하는 과정을 분석합니다.\n지정된 식별자 `c2tunnel_chisel_reverse_socks5_proxy_chain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_chisel_reverse_socks5_proxy_chain_v1\") 앞 20자리}`",
      en: "Analyze Chisel reverse SOCKS5 proxy chains enabling attackers to traverse segmented internal IP ranges.\nCompute first 20 hex chars of SHA256(\"c2tunnel_chisel_reverse_socks5_proxy_chain_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_chisel_reverse_socks5_proxy_chain_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["R:1080:socks는 공격자 머신의 1080 포트를 원격 클라이언트의 내부망 프록시 엔드포인트로 바인딩합니다.", "식별자 `c2tunnel_chisel_reverse_socks5_proxy_chain_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The R:socks directive establishes an inbound SOCKS listener on the remote server host.", "Extract first 20 hex chars of SHA256(\"c2tunnel_chisel_reverse_socks5_proxy_chain_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_ligolo_ng_tun_interface_pivoting",
    tier: 2, cat: "reversepivot", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Ligolo-ng 가상 TUN 인터페이스 기반 라우팅 피보팅", en: "Routing-Based Pivoting via Ligolo-ng Virtual TUN Interfaces" },
    prompt: {
      ko: "SOCKS 프록시의 속도 한계와 도구 호환성 문제를 극복하기 위해 가상 TUN 디바이스를 생성하고 IP 라우팅 테이블을 조작하는 Ligolo-ng 기법을 분석합니다.\n지정된 식별자 `c2tunnel_ligolo_ng_tun_interface_pivoting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_ligolo_ng_tun_interface_pivoting_v1\") 앞 20자리}`",
      en: "Examine Ligolo-ng creating virtual TUN devices to route arbitrary Layer 3 subnet traffic without proxychains overhead.\nCompute first 20 hex chars of SHA256(\"c2tunnel_ligolo_ng_tun_interface_pivoting_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_ligolo_ng_tun_interface_pivoting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["TUN 인터페이스 기반 피보팅은 ICMP ping 및 SYN 스캔 등 일반 L3/L4 네트워크 도구를 그대로 사용할 수 있습니다.", "식별자 `c2tunnel_ligolo_ng_tun_interface_pivoting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["TUN routing enables raw socket tools like nmap SYN scan directly against target subnets.", "Extract first 20 hex chars of SHA256(\"c2tunnel_ligolo_ng_tun_interface_pivoting_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_malleable_c2_profile_http_customization",
    tier: 2, cat: "c2profile", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Cobalt Strike Malleable C2 HTTP GET/POST 메타데이터 변조", en: "Cobalt Strike Malleable C2 HTTP Metadata Customization" },
    prompt: {
      ko: "Malleable C2 프로필을 통해 User-Agent, URI 경로, 쿠키 헤더 및 Base64Url 인코딩 변환을 구성하여 정상 웹 서비스로 위장하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_malleable_c2_profile_http_customization_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_malleable_c2_profile_http_customization_v1\") 앞 20자리}`",
      en: "Analyze Malleable C2 profiles altering HTTP headers, URIs, and cookie parameters to masquerade as benign CDNs.\nCompute first 20 hex chars of SHA256(\"c2tunnel_malleable_c2_profile_http_customization_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_malleable_c2_profile_http_customization_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자는 jQuery, Amazon, Microsoft Office 등의 정상 업데이트 요청 구조를 Malleable 프로필로 모방합니다.", "식별자 `c2tunnel_malleable_c2_profile_http_customization_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Attackers craft profiles mimicking popular jQuery or cloud API telemetry endpoints.", "Extract first 20 hex chars of SHA256(\"c2tunnel_malleable_c2_profile_http_customization_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_beacon_sleep_jitter_variance_model",
    tier: 2, cat: "c2profile", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "수면 지터(Jitter) 비율에 따른 비콘 패킷 간격(IAT) 분산 모델링", en: "Beacon Sleep Jitter Variance Modeling & IAT Statistical Analysis" },
    prompt: {
      ko: "기본 수면 주기(Sleep)에 무작위 오차 비율(Jitter)을 적용하여 $T \\in [T(1-J), T(1+J)]$ 범위의 균등 확률 분포를 형성하는 수학적 모델을 분석합니다.\n지정된 식별자 `c2tunnel_beacon_sleep_jitter_variance_model_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_beacon_sleep_jitter_variance_model_v1\") 앞 20자리}`",
      en: "Model beacon inter-arrival times across uniform random jitter intervals $T \\in [T(1-J), T(1+J)]$.\nCompute first 20 hex chars of SHA256(\"c2tunnel_beacon_sleep_jitter_variance_model_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_beacon_sleep_jitter_variance_model_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["지터가 적용되더라도 반복된 비콘 측정값들의 평균과 분산은 여전히 고유한 통계적 경계를 형성합니다.", "식별자 `c2tunnel_beacon_sleep_jitter_variance_model_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Even jittered beacons exhibit bounded variance distinct from erratic human browsing behavior.", "Extract first 20 hex chars of SHA256(\"c2tunnel_beacon_sleep_jitter_variance_model_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_domain_fronting_cdn_sni_obfuscation",
    tier: 2, cat: "covert", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "CDN Host 헤더 변조를 통한 도메인 프론팅(Domain Fronting)", en: "Domain Fronting & TLS SNI / HTTP Host Header Discrepancy" },
    prompt: {
      ko: "TLS ClientHello의 SNI 필드에는 신뢰할 수 있는 도메인을 기재하고, 암호화된 내부 HTTP Host 헤더에는 악성 C2 도메인을 지정하는 도메인 프론팅 원리를 분석합니다.\n지정된 식별자 `c2tunnel_domain_fronting_cdn_sni_obfuscation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_domain_fronting_cdn_sni_obfuscation_v1\") 앞 20자리}`",
      en: "Examine domain fronting exploiting discrepancies between plaintext TLS SNI and encrypted HTTP Host headers on CDNs.\nCompute first 20 hex chars of SHA256(\"c2tunnel_domain_fronting_cdn_sni_obfuscation_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_domain_fronting_cdn_sni_obfuscation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["방화벽은 SNI만 보고 허용하지만, CDN 에지 서버는 내부 Host 헤더를 보고 악성 오리진 서버로 트래픽을 라우팅합니다.", "식별자 `c2tunnel_domain_fronting_cdn_sni_obfuscation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Egress filters inspect SNI, while shared CDN edges dispatch requests based on inner Host headers.", "Extract first 20 hex chars of SHA256(\"c2tunnel_domain_fronting_cdn_sni_obfuscation_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_sysmon_eventid3_network_bind_telemetry",
    tier: 2, cat: "inlinedpi", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Sysmon Event ID 3 네트워크 연결 이그레스 이상 징후 분석", en: "Sysmon Event ID 3 Network Connection Telemetry Triage" },
    prompt: {
      ko: "비인가 프로세스(rundll32, powershell, spoolsv)가 외부 의심 IP(포트 8443, 1080)로 아웃바운드 소켓을 개설하는 행위를 Sysmon Event 3으로 감지하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_sysmon_eventid3_network_bind_telemetry_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_sysmon_eventid3_network_bind_telemetry_v1\") 앞 20자리}`",
      en: "Hunt anomalous outbound socket initiation from non-network binaries using Windows Sysmon Event ID 3 telemetry.\nCompute first 20 hex chars of SHA256(\"c2tunnel_sysmon_eventid3_network_bind_telemetry_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_sysmon_eventid3_network_bind_telemetry_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["정상적으로 네트워크 통신을 하지 않는 시스템 프로세스의 외향 연결은 C2 침투의 강력한 징후입니다.", "식별자 `c2tunnel_sysmon_eventid3_network_bind_telemetry_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Network connections established by trusted utilities often point to process injection or reverse shells.", "Extract first 20 hex chars of SHA256(\"c2tunnel_sysmon_eventid3_network_bind_telemetry_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_ebpf_socket_connect_tracing",
    tier: 2, cat: "inlinedpi", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "eBPF sys_enter_connect 시스템콜 추적을 통한 비인가 C2 IP 탐지", en: "eBPF sys_enter_connect Probing for Unauthorized C2 Outbound Sockets" },
    prompt: {
      ko: "리눅스 커널 수준에서 `sys_enter_connect` 인자를 실시간 계측하여 호스트 내부에서 시작되는 리버스 C2 연결의 목적지 IP/포트를 추출하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_ebpf_socket_connect_tracing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_ebpf_socket_connect_tracing_v1\") 앞 20자리}`",
      en: "Capture outbound connection parameters at kernel level by tracing sys_enter_connect arguments via eBPF.\nCompute first 20 hex chars of SHA256(\"c2tunnel_ebpf_socket_connect_tracing_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_ebpf_socket_connect_tracing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["eBPF는 사용자 공간의 로그 삭제나 안티포렌식 조작에 영향을 받지 않고 커널 경계에서 연결을 기록합니다.", "식별자 `c2tunnel_ebpf_socket_connect_tracing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["eBPF captures raw kernel socket parameters immune to userland log scrubbing.", "Extract first 20 hex chars of SHA256(\"c2tunnel_ebpf_socket_connect_tracing_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_suricata_flowbits_covert_tracking",
    tier: 2, cat: "inlinedpi", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Suricata NIDS Flowbits 상태 태그를 활용한 다단계 터널 추적", en: "Stateful Covert Tunnel Tracking via Suricata NIDS Flowbits" },
    prompt: {
      ko: "Suricata NIDS에서 `flowbits:set` 및 `flowbits:isset` 키워드를 활용하여 단일 패킷이 아닌 다단계 핸드셰이크 세션 전체를 추적하고 차단하는 규칙 구조를 분석합니다.\n지정된 식별자 `c2tunnel_suricata_flowbits_covert_tracking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_suricata_flowbits_covert_tracking_v1\") 앞 20자리}`",
      en: "Analyze multi-packet state tracking in Suricata using flowbits to flag initial handshakes and terminate subsequent tunnels.\nCompute first 20 hex chars of SHA256(\"c2tunnel_suricata_flowbits_covert_tracking_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_suricata_flowbits_covert_tracking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Flowbits는 단일 세션 내에서 발생한 선행 위협 이벤트를 기억하여 후속 데이터 스트림 차단 조건으로 활용합니다.", "식별자 `c2tunnel_suricata_flowbits_covert_tracking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Flowbits maintain session context across multiple packets to trigger stateful mitigation rules.", "Extract first 20 hex chars of SHA256(\"c2tunnel_suricata_flowbits_covert_tracking_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_zeek_dns_request_entropy_heuristics",
    tier: 2, cat: "inlinedpi", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Zeek dns_request 이벤트 기반 고엔트로피 서브도메인 실시간 경보", en: "Zeek Real-Time High-Entropy DNS Subdomain Heuristic Scripting" },
    prompt: {
      ko: "Zeek 네트워크 보안 모니터링 엔진에서 `dns_request` 이벤트를 후킹하여 FQDN 라벨 길이와 Shannon 엔트로피를 실시간 계산하는 스크립트 작성 원리를 분석합니다.\n지정된 식별자 `c2tunnel_zeek_dns_request_entropy_heuristics_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_zeek_dns_request_entropy_heuristics_v1\") 앞 20자리}`",
      en: "Examine Zeek scripts intercepting dns_request events to evaluate subdomain length and entropy thresholds in real time.\nCompute first 20 hex chars of SHA256(\"c2tunnel_zeek_dns_request_entropy_heuristics_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_zeek_dns_request_entropy_heuristics_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Zeek의 강력한 이벤트 기반 아키텍처는 기가비트급 네트워크 트래픽에서도 전수 DNS 메타데이터를 정밀 분석합니다.", "식별자 `c2tunnel_zeek_dns_request_entropy_heuristics_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Zeek event handlers parse and evaluate high-throughput DNS flows with minimal overhead.", "Extract first 20 hex chars of SHA256(\"c2tunnel_zeek_dns_request_entropy_heuristics_v1\")."]
    }
  },
  {
    id: "t2_c2tunnel_inline_ips_stream_drop_mitigation",
    tier: 2, cat: "inlinedpi", track: "c2tunnel", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "침입 방지 시스템(IPS) 인라인 모드에서 C2 세션 즉시 RST/Drop", en: "Inline IPS Real-Time Session Termination & TCP Reset Drops" },
    prompt: {
      ko: "수동 감시(IDS) 모드를 넘어 인라인(IPS) 계측 지점에서 악성 C2 터널 트래픽 감지 즉시 패킷을 Drop하고 TCP RST 플래그를 주입하는 방어 원리를 분석합니다.\n지정된 식별자 `c2tunnel_inline_ips_stream_drop_mitigation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_inline_ips_stream_drop_mitigation_v1\") 앞 20자리}`",
      en: "Analyze inline IPS architectures synchronously dropping packets and injecting TCP RST packets upon covert channel detection.\nCompute first 20 hex chars of SHA256(\"c2tunnel_inline_ips_stream_drop_mitigation_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_inline_ips_stream_drop_mitigation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["인라인 차단은 데이터가 기업 경계를 벗어나기 전에 물리/가상 인터페이스 수준에서 통신을 단절합니다.", "식별자 `c2tunnel_inline_ips_stream_drop_mitigation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inline IPS intercepts prevent payload egress by enforcing synchronous packet drops at the wire.", "Extract first 20 hex chars of SHA256(\"c2tunnel_inline_ips_stream_drop_mitigation_v1\")."]
    }
  },

  // Tier 3 (8)
  {
    id: "t3_c2tunnel_poisson_arrival_beacon_statistical_anomaly",
    tier: 3, cat: "c2profile", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "푸아송 프로세스 기반 비콘 도착 시간 간격(IAT) 통계적 이상 탐지", en: "Poisson Arrival Process & Inter-Arrival Time Anomaly Detection" },
    prompt: {
      ko: "일정 주기에 지터가 혼합된 비콘 신호를 모델링하기 위해 연속된 패킷 수신 간격의 평균과 분산, 왜도를 분석하여 정상 인간 트래픽과 통계적으로 분리하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1\") 앞 20자리}`",
      en: "Apply statistical modeling to inter-arrival time distributions to isolate jittered automated beacons from human burst traffic.\nCompute first 20 hex chars of SHA256(\"c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["인간의 브라우징은 긴 유휴 시간과 집중적 버스트가 교차하지만, C2 비콘은 일정한 수면 간격을 중심으로 군집을 이룹니다.", "식별자 `c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Human browsing exhibits heavy-tailed burstiness, unlike synthetic beacons clustering around mean sleep intervals.", "Extract first 20 hex chars of SHA256(\"c2tunnel_poisson_arrival_beacon_statistical_anomaly_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting",
    tier: 3, cat: "covert", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "C2 에이전트 TLS 클라이언트 핸드셰이크 JA3/JA4 해시 핑거프린팅", en: "TLS ClientHello Fingerprinting with JA3/JA4 for C2 Hunting" },
    prompt: {
      ko: "TLS 핸드셰이크 시 클라이언트가 전송하는 암호화 스위트 순서, 확장 필드, 타원 곡선 파라미터를 해싱(JA3/JA4)하여 악성 C2 바이너리를 식별하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1\") 앞 20자리}`",
      en: "Profile malicious C2 agent TLS handshakes via JA3 and JA4 hashes derived from ClientHello cipher suites and extensions.\nCompute first 20 hex chars of SHA256(\"c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["표준 웹 브라우저와 공격용 C2 에이전트(Sliver, Go, Python 기반)는 서로 다른 고유한 JA3 해시 시그니처를 가집니다.", "식별자 `c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Custom implants built in Go or C compiled with static TLS libraries present distinct JA3 signatures.", "Extract first 20 hex chars of SHA256(\"c2tunnel_tls_fingerprinting_ja3_ja4_c2_hunting_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_egress_firewall_strict_whitelisting",
    tier: 3, cat: "egress", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "기본 차단(Default-Deny) 아웃바운드 이그레스 방화벽 정책 수립", en: "Default-Deny Outbound Egress Firewall Architecture & Policy" },
    prompt: {
      ko: "모든 내부 워크스테이션과 서버의 외향 직접 연결을 차단하고, 오직 사내 포워드 프록시와 공인 DNS 캐시 서버만 경유하도록 강제하는 제로 트러스트 경계 방어를 분석합니다.\n지정된 식별자 `c2tunnel_egress_firewall_strict_whitelisting_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_egress_firewall_strict_whitelisting_v1\") 앞 20자리}`",
      en: "Establish default-deny outbound perimeter firewalls forcing all traffic through inspected forward proxies and internal DNS caches.\nCompute first 20 hex chars of SHA256(\"c2tunnel_egress_firewall_strict_whitelisting_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_egress_firewall_strict_whitelisting_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["비인가 포트 및 임의의 외부 공인 IP로의 직접적인 TCP/UDP 3-way handshake를 경계에서 무조건 거부합니다.", "식별자 `c2tunnel_egress_firewall_strict_whitelisting_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Strict egress filters prohibit workstations from initiating direct socket connections to external endpoints.", "Extract first 20 hex chars of SHA256(\"c2tunnel_egress_firewall_strict_whitelisting_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_socks5_authentication_mandate_hardening",
    tier: 3, cat: "reversepivot", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "기업 내부 SOCKS5 프록시 사용자 인증 및 ACL 인가 강화", en: "Mandatory Authentication & ACL Hardening on Internal SOCKS Proxies" },
    prompt: {
      ko: "무인증 SOCKS5 프록시의 익명 트래픽 전송 위험을 제거하기 위해 RFC 1929 사용자명/패스워드 인증 및 소스 IP 기반 서브넷 ACL을 강제하는 하드닝을 분석합니다.\n지정된 식별자 `c2tunnel_socks5_authentication_mandate_hardening_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_socks5_authentication_mandate_hardening_v1\") 앞 20자리}`",
      en: "Harden corporate proxy infrastructure by enforcing RFC 1929 username/password authentication and source subnet ACLs on SOCKS5 gateways.\nCompute first 20 hex chars of SHA256(\"c2tunnel_socks5_authentication_mandate_hardening_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_socks5_authentication_mandate_hardening_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["인증 없는 SOCKS 프록시는 공격자가 내부망에 생성한 터널을 통해 누구나 자유롭게 피보팅할 수 있는 통로가 됩니다.", "식별자 `c2tunnel_socks5_authentication_mandate_hardening_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unauthenticated proxy daemons allow unauthorized lateral movement across all reachable internal subnets.", "Extract first 20 hex chars of SHA256(\"c2tunnel_socks5_authentication_mandate_hardening_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_mtls_service_mesh_isolation",
    tier: 3, cat: "reversepivot", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "Istio/Linkerd mTLS 마이크로서비스 메시를 통한 피보팅 무력화", en: "Pivoting Neutralization via Istio/Linkerd mTLS Service Mesh" },
    prompt: {
      ko: "네트워크 수준에서 공격자가 프록시 터널을 수립하더라도, 서비스 간 암호화 상호 인증(mTLS)과 SPIFFE ID 검증을 통해 무인가 측면 이동을 원천 차단하는 기법을 분석합니다.\n지정된 식별자 `c2tunnel_mtls_service_mesh_isolation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_mtls_service_mesh_isolation_v1\") 앞 20자리}`",
      en: "Neutralize proxy pivoting in cloud-native workloads by enforcing mutual TLS (mTLS) and cryptographic SPIFFE identities across service meshes.\nCompute first 20 hex chars of SHA256(\"c2tunnel_mtls_service_mesh_isolation_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_mtls_service_mesh_isolation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자가 네트워크 패킷을 전달할 수 있더라도 유효한 mTLS 클라이언트 인증서가 없으면 애플리케이션 계층 연결이 즉시 거부됩니다.", "식별자 `c2tunnel_mtls_service_mesh_isolation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Even when network packets are routed, services reject requests lacking valid cryptographic client certificates.", "Extract first 20 hex chars of SHA256(\"c2tunnel_mtls_service_mesh_isolation_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_c2_header_watermark_threat_attribution",
    tier: 3, cat: "c2profile", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "C2 프로필 헤더 워터마크(0xcafe) 대조를 통한 위협 행위자 귀속", en: "Threat Actor Attribution via Malleable C2 Header Watermarks" },
    prompt: {
      ko: "Cobalt Strike 라이선스 키나 프레임워크 빌더가 패킷 헤더 또는 스테이저 바이트에 남기는 고유한 워터마크(Watermark)를 추출하여 침투 공격자를 추적하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_c2_header_watermark_threat_attribution_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_c2_header_watermark_threat_attribution_v1\") 앞 20자리}`",
      en: "Extract embedded watermarks and build artifacts inside C2 beacon headers to attribute campaigns to specific adversary tooling.\nCompute first 20 hex chars of SHA256(\"c2tunnel_c2_header_watermark_threat_attribution_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_c2_header_watermark_threat_attribution_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["워터마크 정수 값은 공격자가 사용하는 C2 라이선스 인스턴스에 고유하게 매핑되어 위협 인텔리전스 상관분석을 가능하게 합니다.", "식별자 `c2tunnel_c2_header_watermark_threat_attribution_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Beacon watermarks uniquely identify license fingerprints across disparate intrusion campaigns.", "Extract first 20 hex chars of SHA256(\"c2tunnel_c2_header_watermark_threat_attribution_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_soar_automated_host_isolation_playbook",
    tier: 3, cat: "inlinedpi", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "침해 지표(IoC) 탐지 시 SOAR 기반 호스트 방화벽 즉시 격리", en: "Automated Host Isolation via SOAR Playbook upon IoC Trigger" },
    prompt: {
      ko: "NIDS/EDR에서 C2 터널링 확정 판정 시 보안 오케스트레이션(SOAR) 플레이북을 실행하여 감염 단말의 네트워크 스위치 포트 셧다운 및 EDR 호스트 격리를 자동 수행하는 파이프라인을 분석합니다.\n지정된 식별자 `c2tunnel_soar_automated_host_isolation_playbook_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_soar_automated_host_isolation_playbook_v1\") 앞 20자리}`",
      en: "Orchestrate automated SOAR playbooks isolating compromised endpoints via network access control and EDR APIs upon C2 detection.\nCompute first 20 hex chars of SHA256(\"c2tunnel_soar_automated_host_isolation_playbook_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_soar_automated_host_isolation_playbook_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["자동화된 격리 조치는 관제 요원의 수동 대응 지연 시간(MTTR)을 단 몇 초 이내로 단축하여 대규모 데이터 유출을 방지합니다.", "식별자 `c2tunnel_soar_automated_host_isolation_playbook_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["SOAR automations drastically reduce Mean Time to Remediate (MTTR) by severing active tunnels instantly.", "Extract first 20 hex chars of SHA256(\"c2tunnel_soar_automated_host_isolation_playbook_v1\")."]
    }
  },
  {
    id: "t3_c2tunnel_mitre_attck_c2_technique_matrix",
    tier: 3, cat: "covert", track: "c2tunnel", points: 150, ci: false, fmt: "FLAG{...}",
    title: { ko: "MITRE ATT&CK T1071.004, T1572, T1090 다계층 매핑 감사", en: "MITRE ATT&CK Matrix Mapping for C2 Tunneling (T1071, T1572, T1090)" },
    prompt: {
      ko: "DNS 프로토콜 터널링(T1071.004), 프로토콜 터널링(T1572), 프록시 피보팅(T1090) 등 공격 전술을 MITRE ATT&CK 매트릭스에 매핑하고 방어 커버리지를 검증하는 원리를 분석합니다.\n지정된 식별자 `c2tunnel_mitre_attck_c2_technique_matrix_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_mitre_attck_c2_technique_matrix_v1\") 앞 20자리}`",
      en: "Map covert channel vectors against MITRE ATT&CK techniques T1071.004 (DNS), T1572 (Protocol Tunneling), and T1090 (Proxy).\nCompute first 20 hex chars of SHA256(\"c2tunnel_mitre_attck_c2_technique_matrix_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_mitre_attck_c2_technique_matrix_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["ATT&CK 매핑은 기업의 방어 탐지 룰이 공격자의 실제 TTP 전술을 빈틈없이 커버하고 있는지 계량화합니다.", "식별자 `c2tunnel_mitre_attck_c2_technique_matrix_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Technique mapping ensures defensive posture comprehensively covers adversary command and control behaviors.", "Extract first 20 hex chars of SHA256(\"c2tunnel_mitre_attck_c2_technique_matrix_v1\")."]
    }
  },

  // Tier 4 (5)
  {
    id: "t4_c2tunnel_full_spectrum_dns_exfil_defense_pipeline",
    tier: 4, cat: "dnstunnel", track: "c2tunnel", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "엔터프라이즈 DNS 방화벽 + Shannon 엔트로피 전수 검증 파이프라인", en: "Enterprise DNS Firewall & Shannon Entropy Full Pipeline" },
    prompt: {
      ko: "초당 수만 건의 재귀 DNS 쿼리를 처리하는 엔터프라이즈 환경에서 FQDN 길이, Shannon 엔트로피, 서브도메인 라벨 개수를 전수 검사하고 악성 유출을 실시간 차단하는 파이프라인을 구축합니다.\n지정된 식별자 `c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1\") 앞 20자리}`",
      en: "Architect high-throughput DNS firewalls combining Shannon entropy filters and query frequency analysis to block exfiltration.\nCompute first 20 hex chars of SHA256(\"c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["RPZ(Response Policy Zone)와 결합하여 고엔트로피 도메인에 대해 NXDOMAIN 응답을 강제 반환합니다.", "식별자 `c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Integrate Response Policy Zones (RPZ) to synthesize NXDOMAIN replies against anomalous subdomains.", "Extract first 20 hex chars of SHA256(\"c2tunnel_full_spectrum_dns_exfil_defense_pipeline_v1\")."]
    }
  },
  {
    id: "t4_c2tunnel_enterprise_reverse_pivoting_containment",
    tier: 4, cat: "reversepivot", track: "c2tunnel", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "다중 홉 Chisel/SSH 리버스 터널 전수 차단 및 VFS 포렌식", en: "Multi-Hop Reverse Pivoting Containment & VFS Tunnel Forensics" },
    prompt: {
      ko: "복수의 내부 서브넷을 관통하는 다중 홉(Multi-Hop) Chisel/SSH 역방향 터널을 적출하고, 네트워크 소켓과 연계된 프로세스 메모리 아티팩트를 포렌식 수사하는 종합 대응을 분석합니다.\n지정된 식별자 `c2tunnel_enterprise_reverse_pivoting_containment_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_enterprise_reverse_pivoting_containment_v1\") 앞 20자리}`",
      en: "Triage and dismantle multi-hop reverse Chisel/SSH proxy chains across isolated VLAN boundaries using endpoint forensics.\nCompute first 20 hex chars of SHA256(\"c2tunnel_enterprise_reverse_pivoting_containment_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_enterprise_reverse_pivoting_containment_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공격자는 다단계 리버스 프록시를 직렬로 연결하여 최초 침투지로부터 핵심 망 깊숙이 피보팅을 전개합니다.", "식별자 `c2tunnel_enterprise_reverse_pivoting_containment_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Adversaries daisy-chain reverse tunnels across VLAN boundaries to reach isolated core database enclaves.", "Extract first 20 hex chars of SHA256(\"c2tunnel_enterprise_reverse_pivoting_containment_v1\")."]
    }
  },
  {
    id: "t4_c2tunnel_advanced_statistical_beacon_unmasking",
    tier: 4, cat: "c2profile", track: "c2tunnel", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "지터가 은닉된 Malleable C2 트래픽의 기계학습/통계적 디옵터 판정", en: "Machine Learning & Advanced Statistical Unmasking of Jittered Beacons" },
    prompt: {
      ko: "랜덤 지터가 적용된 C2 비콘 트래픽을 탐지하기 위해 패킷 간격 IAT의 오토코릴레이션(Autocorrelation) 및 스펙트럼 밀도 분석을 결합한 지능형 탐지 모델을 구축합니다.\n지정된 식별자 `c2tunnel_advanced_statistical_beacon_unmasking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_advanced_statistical_beacon_unmasking_v1\") 앞 20자리}`",
      en: "Deploy autocorrelation and spectral density modeling to distinguish jittered C2 beacons from stochastic web traffic.\nCompute first 20 hex chars of SHA256(\"c2tunnel_advanced_statistical_beacon_unmasking_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_advanced_statistical_beacon_unmasking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["지터가 아무리 커도 비콘 생성 알고리즘의 의사 난수 생성기(PRNG) 패턴과 장시간 주파수 응답에서 통계적 주기성이 검출됩니다.", "식별자 `c2tunnel_advanced_statistical_beacon_unmasking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Spectral power density uncovers periodicity even under aggressive jitter configurations.", "Extract first 20 hex chars of SHA256(\"c2tunnel_advanced_statistical_beacon_unmasking_v1\")."]
    }
  },
  {
    id: "t4_c2tunnel_inline_stateful_dpi_orchestration",
    tier: 4, cat: "inlinedpi", track: "c2tunnel", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "Suricata + Zeek 융합 인라인 침입 방지 아키텍처 구축", en: "Converged Suricata & Zeek Inline Deep Packet Inspection Architecture" },
    prompt: {
      ko: "Suricata의 고속 인라인 패킷 필터링 능력과 Zeek의 심층 프로토콜 트랜잭션 분석을 연계하여 은닉 C2 통신을 0.1초 내 차단하는 융합 방어 아키텍처를 설계합니다.\n지정된 식별자 `c2tunnel_inline_stateful_dpi_orchestration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_inline_stateful_dpi_orchestration_v1\") 앞 20자리}`",
      en: "Orchestrate dual-layer inspection merging Suricata wire-speed inline dropping with Zeek stateful protocol behavioral analysis.\nCompute first 20 hex chars of SHA256(\"c2tunnel_inline_stateful_dpi_orchestration_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_inline_stateful_dpi_orchestration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Zeek이 이상 징후를 발견하여 동적 차단 룰을 생성하고 Suricata가 커널 XDP/AF_PACKET 수준에서 패킷을 폐기합니다.", "식별자 `c2tunnel_inline_stateful_dpi_orchestration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Zeek triggers programmatic mitigation rules enforced synchronously by Suricata AF_PACKET drops.", "Extract first 20 hex chars of SHA256(\"c2tunnel_inline_stateful_dpi_orchestration_v1\")."]
    }
  },
  {
    id: "t4_c2tunnel_capstone_full_spectrum_c2_covert_defense",
    tier: 4, cat: "covert", track: "c2tunnel", points: 250, ci: false, fmt: "FLAG{...}",
    title: { ko: "C2 터널링·SOCKS 피보팅·Malleable 지터·인라인 DPI 전주기 캡스톤", en: "Full-Spectrum C2 Tunneling, Pivoting & Covert Channel Defense Capstone" },
    prompt: {
      ko: "DNS 엔트로피 분석, Chisel 역방향 SOCKS5 차단, Malleable C2 지터 비콘 핑거프린팅, Zeek/Suricata 인라인 DPI 방어를 통합 수행하여 기업망 은닉 채널을 완벽 무력화하는 캡스톤 과정을 완료합니다.\n지정된 식별자 `c2tunnel_capstone_full_spectrum_c2_covert_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"c2tunnel_capstone_full_spectrum_c2_covert_defense_v1\") 앞 20자리}`",
      en: "Achieve capstone mastery defending against DNS exfiltration, reverse SOCKS5 tunneling, jittered C2 beacons, and inline DPI enforcement.\nCompute first 20 hex chars of SHA256(\"c2tunnel_capstone_full_spectrum_c2_covert_defense_v1\").\n\nFormat: `FLAG{SHA256(\"c2tunnel_capstone_full_spectrum_c2_covert_defense_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["축하합니다! 64개 전 트랙 2,240개 챌린지 및 52대 실습 랩의 네트워크 침해 방어 마스터 마일스톤에 도달했습니다.", "식별자 `c2tunnel_capstone_full_spectrum_c2_covert_defense_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Capstone milestone celebrating comprehensive mastery across 64 wargame tracks and 2,240 challenges.", "Extract first 20 hex chars of SHA256(\"c2tunnel_capstone_full_spectrum_c2_covert_defense_v1\")."]
    }
  }
];

// Add hash to each challenge
const processedChallenges = challengesDef.map(ch => {
  return {
    ...ch,
    hash: computeHash(ch.id)
  };
});

fs.writeFileSync(path.join(__dirname, 'track64_challenges.json'), JSON.stringify(processedChallenges, null, 2), 'utf8');
console.log(`Successfully generated ${processedChallenges.length} challenges in tools/track64_challenges.json`);
