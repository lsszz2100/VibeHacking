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
    id: "t0_extsec_manifest_v3_security_paradigm_shift",
    tier: 0, cat: "manifest", track: "extsec", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "Manifest V3 보안 패러다임 전환과 기본 원리", en: "Manifest V3 Security Paradigm Shift & Fundamentals" },
    prompt: {
      ko: "Chromium 생태계가 백그라운드 페이지를 비동기 서비스 워커로 대체하고 차단형 webRequest 대신 선언적 규칙을 강제하는 MV3 보안 철학을 분석합니다.\n지정된 식별자 `extsec_manifest_v3_security_paradigm_shift_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_manifest_v3_security_paradigm_shift_v1\") 앞 20자리}`",
      en: "Analyze Chromium's architectural pivot in Manifest V3 replacing persistent background pages with ephemeral service workers and declarative request filtering.\nCompute the first 20 hex characters of SHA256(\"extsec_manifest_v3_security_paradigm_shift_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_manifest_v3_security_paradigm_shift_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Manifest V3는 원격 코드 실행(eval)을 전면 차단하고 선언적 네트워크 제어를 도입했습니다.", "식별자 `extsec_manifest_v3_security_paradigm_shift_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Manifest V3 eliminates remotely hosted code execution while enforcing declarative rulesets.", "Extract first 20 hex chars of SHA256(\"extsec_manifest_v3_security_paradigm_shift_v1\")."]
    }
  },
  {
    id: "t0_extsec_browser_extension_least_privilege",
    tier: 0, cat: "manifest", track: "extsec", points: 25, ci: false, fmt: "FLAG{...}",
    title: { ko: "브라우저 확장 프로그램 최소 권한 원칙", en: "Browser Extension Principle of Least Privilege" },
    prompt: {
      ko: "과도한 host_permissions 대신 activeTab 권한을 활용하여 사용자 명시적 상호작용 시에만 탭에 접근하는 최소 권한 설계 원칙을 분석합니다.\n지정된 식별자 `extsec_browser_extension_least_privilege_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_browser_extension_least_privilege_v1\") 앞 20자리}`",
      en: "Evaluate the principle of least privilege utilizing activeTab permissions to minimize broad host access across user navigation.\nCompute the first 20 hex characters of SHA256(\"extsec_browser_extension_least_privilege_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_browser_extension_least_privilege_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["activeTab은 사용자가 확장 프로그램 아이콘을 클릭했을 때만 현재 탭의 일시적 접근 권한을 부여합니다.", "식별자 `extsec_browser_extension_least_privilege_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The activeTab permission grants temporary access to the active tab upon explicit user invocation.", "Extract first 20 hex chars of SHA256(\"extsec_browser_extension_least_privilege_v1\")."]
    }
  },

  // Tier 1 (6)
  {
    id: "t1_extsec_manifest_json_permissions_audit",
    tier: 1, cat: "manifest", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "manifest.json 위험 권한 항목 정밀 감사", en: "manifest.json High-Risk Permission Deep Audit" },
    prompt: {
      ko: "manifest.json에서 `<all_urls>`, `webRequestBlocking`, `cookies`, `nativeMessaging` 등 과도한 고위험 권한 명세를 식별하는 감사 절차를 분석합니다.\n지정된 식별자 `extsec_manifest_json_permissions_audit_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_manifest_json_permissions_audit_v1\") 앞 20자리}`",
      en: "Audit high-risk manifest capabilities including <all_urls>, webRequestBlocking, cookies, and nativeMessaging.\nCompute the first 20 hex characters of SHA256(\"extsec_manifest_json_permissions_audit_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_manifest_json_permissions_audit_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["광범위한 호스트 권한은 사용자가 방문하는 모든 웹페이지의 DOM과 쿠키를 침해할 수 있습니다.", "식별자 `extsec_manifest_json_permissions_audit_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Broad host patterns permit arbitrary DOM tampering and silent credential harvesting across sites.", "Extract first 20 hex chars of SHA256(\"extsec_manifest_json_permissions_audit_v1\")."]
    }
  },
  {
    id: "t1_extsec_service_worker_ephemeral_lifecycle",
    tier: 1, cat: "manifest", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "서비스 워커의 비동기 수명주기 및 메모리 관리", en: "Service Worker Ephemeral Lifecycle & Memory Governance" },
    prompt: {
      ko: "유휴 상태 시 자동 언로드되는 Manifest V3 백그라운드 서비스 워커의 특성과 전역 상태 캐싱 부작용을 분석합니다.\n지정된 식별자 `extsec_service_worker_ephemeral_lifecycle_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_service_worker_ephemeral_lifecycle_v1\") 앞 20자리}`",
      en: "Analyze event-driven execution models in MV3 background service workers and address state evaporation risks.\nCompute the first 20 hex characters of SHA256(\"extsec_service_worker_ephemeral_lifecycle_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_service_worker_ephemeral_lifecycle_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["서비스 워커는 약 30초 유휴 시 종료되므로 영속 상태는 반드시 chrome.storage API를 통해 보존해야 합니다.", "식별자 `extsec_service_worker_ephemeral_lifecycle_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Service workers terminate upon inactivity, requiring persistent state to reside in chrome.storage.", "Extract first 20 hex chars of SHA256(\"extsec_service_worker_ephemeral_lifecycle_v1\")."]
    }
  },
  {
    id: "t1_extsec_content_scripts_vs_page_scripts",
    tier: 1, cat: "dom", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "콘텐츠 스크립트와 호스트 페이지 스크립트의 격리 모델", en: "Content Scripts vs Host Page Execution Isolation" },
    prompt: {
      ko: "웹페이지에 주입된 content.js와 메인 월드 웹페이지 스크립트 간의 실행 컨텍스트 차이와 접근 가능한 브라우저 API 범위를 비교 분석합니다.\n지정된 식별자 `extsec_content_scripts_vs_page_scripts_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_content_scripts_vs_page_scripts_v1\") 앞 20자리}`",
      en: "Compare execution boundaries and accessible Chrome API subsets between injected content scripts and main world page scripts.\nCompute the first 20 hex characters of SHA256(\"extsec_content_scripts_vs_page_scripts_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_content_scripts_vs_page_scripts_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["콘텐츠 스크립트는 chrome.runtime 등 제한된 확장 API만 사용할 수 있으며 페이지 전역 변수와 분리됩니다.", "식별자 `extsec_content_scripts_vs_page_scripts_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Content scripts access a restricted subset of extension APIs while remaining isolated from page JS variables.", "Extract first 20 hex chars of SHA256(\"extsec_content_scripts_vs_page_scripts_v1\")."]
    }
  },
  {
    id: "t1_extsec_isolated_world_shared_dom_concept",
    tier: 1, cat: "dom", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "격리 월드(Isolated World)의 JS 힙 분리와 공유 DOM 특성", en: "Isolated World JS Heap Separation & Shared DOM Dynamics" },
    prompt: {
      ko: "Isolated World가 자바스크립트 객체 프로토타입은 분리하지만 단일 DOM 트리를 직접 공유함으로써 발생하는 보안 취약점을 분석합니다.\n지정된 식별자 `extsec_isolated_world_shared_dom_concept_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_isolated_world_shared_dom_concept_v1\") 앞 20자리}`",
      en: "Investigate Isolated World security mechanics where JS execution heaps are decoupled yet the underlying DOM tree is shared.\nCompute the first 20 hex characters of SHA256(\"extsec_isolated_world_shared_dom_concept_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_isolated_world_shared_dom_concept_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["공유 DOM 트리는 호스트 페이지가 변조한 DOM 속성을 콘텐츠 스크립트가 신뢰할 때 XSS로 이어질 수 있습니다.", "식별자 `extsec_isolated_world_shared_dom_concept_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The shared DOM allows untrusted page elements to influence content script logic through unsafe sinks.", "Extract first 20 hex chars of SHA256(\"extsec_isolated_world_shared_dom_concept_v1\")."]
    }
  },
  {
    id: "t1_extsec_web_accessible_resources_wildcard_risk",
    tier: 1, cat: "war", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "Web Accessible Resources 와일드카드 매칭의 보안 위협", en: "Web Accessible Resources Wildcard Matching Risks" },
    prompt: {
      ko: "web_accessible_resources에 `<all_urls>` 또는 광범위한 와일드카드를 설정할 경우 임의의 외부 웹페이지가 확장 내부 자산에 접근하는 위험을 분석합니다.\n지정된 식별자 `extsec_web_accessible_resources_wildcard_risk_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_web_accessible_resources_wildcard_risk_v1\") 앞 20자리}`",
      en: "Analyze exposure of internal extension assets to arbitrary web origins caused by unrestricted wildcard matches.\nCompute the first 20 hex characters of SHA256(\"extsec_web_accessible_resources_wildcard_risk_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_web_accessible_resources_wildcard_risk_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["외부 웹페이지는 fetch(`chrome-extension://${id}/...`) 호출을 통해 노출된 파일을 내려받을 수 있습니다.", "식별자 `extsec_web_accessible_resources_wildcard_risk_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Untrusted origins can fetch exposed resources via chrome-extension protocol if matches are unconstrained.", "Extract first 20 hex chars of SHA256(\"extsec_web_accessible_resources_wildcard_risk_v1\")."]
    }
  },
  {
    id: "t1_extsec_extension_storage_local_vs_session",
    tier: 1, cat: "storage", track: "extsec", points: 50, ci: false, fmt: "FLAG{...}",
    title: { ko: "chrome.storage.local 및 session 보안 비교", en: "chrome.storage.local vs session Security Architecture" },
    prompt: {
      ko: "디스크에 영구 보존되는 chrome.storage.local과 브라우저 세션 동안 인메모리에만 유지되는 chrome.storage.session의 보안 차이를 분석합니다.\n지정된 식별자 `extsec_extension_storage_local_vs_session_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_extension_storage_local_vs_session_v1\") 앞 20자리}`",
      en: "Differentiate persistent on-disk chrome.storage.local from ephemeral in-memory chrome.storage.session for secret caching.\nCompute the first 20 hex characters of SHA256(\"extsec_extension_storage_local_vs_session_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_extension_storage_local_vs_session_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["임시 인증 토큰이나 키는 브라우저 종료 시 증발하는 chrome.storage.session에 저장하는 것이 안전합니다.", "식별자 `extsec_extension_storage_local_vs_session_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Sensitive transient session tokens benefit from chrome.storage.session to prevent cold disk exposure.", "Extract first 20 hex chars of SHA256(\"extsec_extension_storage_local_vs_session_v1\")."]
    }
  },

  // Tier 2 (8)
  {
    id: "t2_extsec_cross_origin_war_secret_exfiltration",
    tier: 2, cat: "war", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "WAR 자산 직접 fetch를 통한 내부 설정 및 마스터 토큰 탈취", en: "Cross-Origin WAR Asset Fetching & Master Secret Exfiltration" },
    prompt: {
      ko: "외부 악성 웹페이지에서 web_accessible_resources로 개방된 auth_config.json에 접근하여 내부 마스터 인증 토큰을 탈취하는 공격을 분석합니다.\n지정된 식별자 `extsec_cross_origin_war_secret_exfiltration_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_cross_origin_war_secret_exfiltration_v1\") 앞 20자리}`",
      en: "Exfiltrate master authentication tokens from exposed configuration files declared under permissive WAR matches.\nCompute the first 20 hex characters of SHA256(\"extsec_cross_origin_war_secret_exfiltration_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_cross_origin_war_secret_exfiltration_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["정적 리소스에 하드코딩된 API 키는 WAR 와일드카드 선언 시 누구나 추출할 수 있습니다.", "식별자 `extsec_cross_origin_war_secret_exfiltration_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Hardcoded configuration secrets in WAR bundles are easily retrieved by any web origin.", "Extract first 20 hex chars of SHA256(\"extsec_cross_origin_war_secret_exfiltration_v1\")."]
    }
  },
  {
    id: "t2_extsec_dynamic_url_extension_fingerprinting_defense",
    tier: 2, cat: "war", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "use_dynamic_url을 활용한 확장 프로그램 핑거프린팅 방어", en: "use_dynamic_url Defense Against Extension Fingerprinting" },
    prompt: {
      ko: "브라우저에 설치된 확장의 ID를 무단 감지하는 핑거프린팅 기법을 차단하기 위해 세션별 동적 GUID URL을 생성하는 방어 메커니즘을 분석합니다.\n지정된 식별자 `extsec_dynamic_url_extension_fingerprinting_defense_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_dynamic_url_extension_fingerprinting_defense_v1\") 앞 20자리}`",
      en: "Prevent cross-site extension tracking and browser fingerprinting by mandating use_dynamic_url session GUIDs.\nCompute the first 20 hex characters of SHA256(\"extsec_dynamic_url_extension_fingerprinting_defense_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_dynamic_url_extension_fingerprinting_defense_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["use_dynamic_url: true를 설정하면 정적 확장 ID 대신 임의의 세션 GUID가 부여되어 외부 추적을 차단합니다.", "식별자 `extsec_dynamic_url_extension_fingerprinting_defense_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The use_dynamic_url directive randomizes resource URLs per installation session, blocking enumeration.", "Extract first 20 hex chars of SHA256(\"extsec_dynamic_url_extension_fingerprinting_defense_v1\")."]
    }
  },
  {
    id: "t2_extsec_content_script_innerhtml_dom_xss",
    tier: 2, cat: "dom", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "content.js postMessage 수신부의 innerHTML DOM XSS 익스플로잇", en: "content.js postMessage Handling & innerHTML DOM XSS" },
    prompt: {
      ko: "웹페이지의 window.postMessage 페이로드를 출처 검증 없이 innerHTML 싱크로 직접 렌더링할 때 발생하는 DOM XSS 취약점을 분석합니다.\n지정된 식별자 `extsec_content_script_innerhtml_dom_xss_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_content_script_innerhtml_dom_xss_v1\") 앞 20자리}`",
      en: "Exploit DOM-based XSS when content scripts consume unverified window.postMessage payloads into innerHTML sinks.\nCompute the first 20 hex characters of SHA256(\"extsec_content_script_innerhtml_dom_xss_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_content_script_innerhtml_dom_xss_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["event.origin 검증이 누락된 postMessage 이벤트 핸들러는 임의 사이트의 스크립트 주입 벡터가 됩니다.", "식별자 `extsec_content_script_innerhtml_dom_xss_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Unfiltered postMessage handlers lacking origin validation allow external pages to trigger DOM sinks.", "Extract first 20 hex chars of SHA256(\"extsec_content_script_innerhtml_dom_xss_v1\")."]
    }
  },
  {
    id: "t2_extsec_keystroke_and_password_sniffing",
    tier: 2, cat: "dom", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "폼 입력 이벤트 리스너를 통한 비밀번호 스니핑 진단", en: "Form Input Event Keystroke & Password Sniffing Triage" },
    prompt: {
      ko: "콘텐츠 스크립트가 DOM 상의 `input[type='password']` 요소에 이벤트 리스너를 부착하여 사용자 자격증명을 무단 수집하는 악성 패턴을 진단합니다.\n지정된 식별자 `extsec_keystroke_and_password_sniffing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_keystroke_and_password_sniffing_v1\") 앞 20자리}`",
      en: "Triage malicious content scripts attaching input event listeners to password fields to harvest credentials.\nCompute the first 20 hex characters of SHA256(\"extsec_keystroke_and_password_sniffing_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_keystroke_and_password_sniffing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["악성 확장은 비밀번호 필드의 input 및 change 이벤트를 모니터링하여 chrome.storage에 저장합니다.", "식별자 `extsec_keystroke_and_password_sniffing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Credential sniffing extensions hook input/change events on password elements to record user inputs.", "Extract first 20 hex chars of SHA256(\"extsec_keystroke_and_password_sniffing_v1\")."]
    }
  },
  {
    id: "t2_extsec_cross_context_message_passing_validation",
    tier: 2, cat: "dom", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "크로스 컨텍스트 메시지 송수신 오리진 검증 기법", en: "Cross-Context Message Passing Origin Validation" },
    prompt: {
      ko: "콘텐츠 스크립트와 백그라운드 서비스 워커, 웹페이지 간 통신 시 sender.id 및 event.origin을 엄격히 검증하는 방어 체계를 분석합니다.\n지정된 식별자 `extsec_cross_context_message_passing_validation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_cross_context_message_passing_validation_v1\") 앞 20자리}`",
      en: "Enforce strict sender.id and event.origin validation across content scripts, service workers, and host origins.\nCompute the first 20 hex characters of SHA256(\"extsec_cross_context_message_passing_validation_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_cross_context_message_passing_validation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["chrome.runtime.onMessageExternal 리스너는 sender.url과 sender.id를 반드시 인가 화이트리스트와 대조해야 합니다.", "식별자 `extsec_cross_context_message_passing_validation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["External message handlers must check sender.id and origin against explicit trust lists.", "Extract first 20 hex chars of SHA256(\"extsec_cross_context_message_passing_validation_v1\")."]
    }
  },
  {
    id: "t2_extsec_declarative_net_request_rule_structure",
    tier: 2, cat: "dnr", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Declarative Net Request (DNR) 규칙 구조 및 문법", en: "Declarative Net Request (DNR) Rule Structure & Grammar" },
    prompt: {
      ko: "Manifest V3에서 네트워크 요청 차단 및 수정을 선언적으로 정의하는 DNR rules.json의 action, condition, urlFilter 구조를 분석합니다.\n지정된 식별자 `extsec_declarative_net_request_rule_structure_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_declarative_net_request_rule_structure_v1\") 앞 20자리}`",
      en: "Analyze DNR declarative syntax including rule action, condition, resourceTypes, and urlFilter criteria.\nCompute the first 20 hex characters of SHA256(\"extsec_declarative_net_request_rule_structure_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_declarative_net_request_rule_structure_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["DNR은 브라우저 커널 레벨에서 비동기 차단을 수행하여 성능 저하와 트래픽 도청을 방지합니다.", "식별자 `extsec_declarative_net_request_rule_structure_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["DNR delegates network filtering directly to the browser core, preventing synchronous JS traffic snooping.", "Extract first 20 hex chars of SHA256(\"extsec_declarative_net_request_rule_structure_v1\")."]
    }
  },
  {
    id: "t2_extsec_extension_csp_eval_disallowance",
    tier: 2, cat: "csp", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Manifest V3 확장 프로그램 CSP의 unsafe-eval 원천 차단", en: "Manifest V3 Extension CSP Zero-Eval Enforcement" },
    prompt: {
      ko: "확장 프로그램 컨텍스트에서 `eval()`, `new Function()`, 외부 CDN 스크립트 로딩을 전면 불허하는 엄격한 CSP 정책을 분석합니다.\n지정된 식별자 `extsec_extension_csp_eval_disallowance_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_extension_csp_eval_disallowance_v1\") 앞 20자리}`",
      en: "Examine strict Extension CSP restrictions prohibiting eval(), new Function(), and remotely hosted code.\nCompute the first 20 hex characters of SHA256(\"extsec_extension_csp_eval_disallowance_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_extension_csp_eval_disallowance_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["MV3에서는 content_security_policy에 unsafe-eval 또는 외부 호스트 URL을 허용할 수 없습니다.", "식별자 `extsec_extension_csp_eval_disallowance_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["MV3 extension policy rejects unsafe-eval directives and forbids remote origin script loading.", "Extract first 20 hex chars of SHA256(\"extsec_extension_csp_eval_disallowance_v1\")."]
    }
  },
  {
    id: "t2_extsec_native_messaging_host_privilege_escalation",
    tier: 2, cat: "manifest", track: "extsec", points: 100, ci: false, fmt: "FLAG{...}",
    title: { ko: "Native Messaging Host 연동과 로컬 바이너리 권한 상승 방어", en: "Native Messaging Host Binding & Local RCE Mitigation" },
    prompt: {
      ko: "브라우저 확장이 로컬 OS 바이너리와 표준 입출력(stdio)으로 통신하는 Native Messaging의 공격 표면과 화이트리스트 방어를 분석합니다.\n지정된 식별자 `extsec_native_messaging_host_privilege_escalation_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_native_messaging_host_privilege_escalation_v1\") 앞 20자리}`",
      en: "Assess native messaging host manifest definitions and prevent command execution escalation via malicious stdio messages.\nCompute the first 20 hex characters of SHA256(\"extsec_native_messaging_host_privilege_escalation_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_native_messaging_host_privilege_escalation_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["호스트 매니페스트의 allowed_origins에 신뢰할 수 있는 확장 ID만 정확히 등록되어야 합니다.", "식별자 `extsec_native_messaging_host_privilege_escalation_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Native host manifests must restrict allowed_origins exclusively to authorized extension identities.", "Extract first 20 hex chars of SHA256(\"extsec_native_messaging_host_privilege_escalation_v1\")."]
    }
  },

  // Tier 3 (9)
  {
    id: "t3_extsec_cookie_theft_and_session_hijacking",
    tier: 3, cat: "manifest", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "과도한 cookies 권한을 악용한 크로스 도메인 세션 탈취", en: "Overprivileged Cookies Permission & Cross-Site Session Theft" },
    prompt: {
      ko: "확장 프로그램이 `chrome.cookies.getAll()`을 호출하여 금융, 클라우드 콘솔의 HttpOnly 세션 쿠키를 탈취하는 시나리오와 방어를 분석합니다.\n지정된 식별자 `extsec_cookie_theft_and_session_hijacking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_cookie_theft_and_session_hijacking_v1\") 앞 20자리}`",
      en: "Simulate and mitigate cross-origin cookie harvesting via chrome.cookies.getAll() targeting HttpOnly session tokens.\nCompute the first 20 hex characters of SHA256(\"extsec_cookie_theft_and_session_hijacking_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_cookie_theft_and_session_hijacking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["확장 프로그램의 cookies 권한은 웹페이지의 자바스크립트와 달리 HttpOnly 쿠키까지 직접 읽을 수 있습니다.", "식별자 `extsec_cookie_theft_and_session_hijacking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The extension cookies API bypasses document.cookie HttpOnly safeguards, requiring strict domain scoping.", "Extract first 20 hex chars of SHA256(\"extsec_cookie_theft_and_session_hijacking_v1\")."]
    }
  },
  {
    id: "t3_extsec_stealthy_iframe_injection_and_clickjacking",
    tier: 3, cat: "dom", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "취약 확장을 통한 비인가 iframe 주입 및 클릭재킹", en: "Stealthy Iframe Injection & Clickjacking via Extension DOM" },
    prompt: {
      ko: "콘텐츠 스크립트가 DOM에 투명 iframe을 주입하여 사용자의 의도하지 않은 금융 결제나 승인을 유도하는 클릭재킹 공격을 분석합니다.\n지정된 식별자 `extsec_stealthy_iframe_injection_and_clickjacking_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_stealthy_iframe_injection_and_clickjacking_v1\") 앞 20자리}`",
      en: "Analyze transparent iframe overlay injection by rogue extensions orchestrating clickjacking attacks.\nCompute the first 20 hex characters of SHA256(\"extsec_stealthy_iframe_injection_and_clickjacking_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_stealthy_iframe_injection_and_clickjacking_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["확장 프로그램은 웹페이지의 X-Frame-Options나 frame-ancestors 정책을 우회하여 iframe을 삽입할 수 있습니다.", "식별자 `extsec_stealthy_iframe_injection_and_clickjacking_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Privileged extensions can synthesize DOM overlays overriding standard frame embedding protections.", "Extract first 20 hex chars of SHA256(\"extsec_stealthy_iframe_injection_and_clickjacking_v1\")."]
    }
  },
  {
    id: "t3_extsec_dompurify_and_trusted_types_enforcement",
    tier: 3, cat: "csp", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "Trusted Types 및 DOMPurify를 활용한 DOM 싱크 원천 봉쇄", en: "Trusted Types & DOMPurify Enforcement Against DOM Sinks" },
    prompt: {
      ko: "W3C Trusted Types 정책과 DOMPurify 새니타이징 파이프라인을 구축하여 문자열 기반 innerHTML 할당을 원천 차단하는 기법을 분석합니다.\n지정된 식별자 `extsec_dompurify_and_trusted_types_enforcement_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_dompurify_and_trusted_types_enforcement_v1\") 앞 20자리}`",
      en: "Implement W3C Trusted Types policies and DOMPurify sanitization to systematically neutralize DOM XSS sinks.\nCompute the first 20 hex characters of SHA256(\"extsec_dompurify_and_trusted_types_enforcement_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_dompurify_and_trusted_types_enforcement_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["require-trusted-types-for 'script' 지시문을 통해 원시 문자열의 위험한 싱크 전달을 브라우저 엔진 레벨에서 거부합니다.", "식별자 `extsec_dompurify_and_trusted_types_enforcement_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Trusted Types enforce type checking on DOM sinks, preventing raw string execution at the engine tier.", "Extract first 20 hex chars of SHA256(\"extsec_dompurify_and_trusted_types_enforcement_v1\")."]
    }
  },
  {
    id: "t3_extsec_dnr_regex_rules_and_performance_budget",
    tier: 3, cat: "dnr", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "DNR 정규식 규칙 및 규칙 할당량(Ruleset Quota) 거버넌스", en: "DNR Regex Rulesets & Rule Quota Performance Governance" },
    prompt: {
      ko: "브라우저 정규표현식 DoS를 방지하기 위해 Chromium이 제한하는 DNR regexFilter 복잡도 한계 및 정적/동적 규칙 할당량을 분석합니다.\n지정된 식별자 `extsec_dnr_regex_rules_and_performance_budget_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_dnr_regex_rules_and_performance_budget_v1\") 앞 20자리}`",
      en: "Evaluate DNR regexFilter complexity constraints and memory budgets preventing ReDoS in declarative network engines.\nCompute the first 20 hex characters of SHA256(\"extsec_dnr_regex_rules_and_performance_budget_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_dnr_regex_rules_and_performance_budget_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["DNR은 re2 문법을 준수하며 정규식당 최대 복잡도 한계(regexFilter memory budget)를 강제합니다.", "식별자 `extsec_dnr_regex_rules_and_performance_budget_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["DNR utilizes RE2 linear-time regex matching and enforces strict memory budgets per ruleset.", "Extract first 20 hex chars of SHA256(\"extsec_dnr_regex_rules_and_performance_budget_v1\")."]
    }
  },
  {
    id: "t3_extsec_service_worker_state_persistence_race_conditions",
    tier: 3, cat: "manifest", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "서비스 워커 언로드 시 비동기 상태 유실 및 레이스 컨디션", en: "Service Worker Inactivity Unload & Asynchronous Race Mitigation" },
    prompt: {
      ko: "서비스 워커 수명주기 중 이벤트 처리 도중 프로세스가 종료되거나 재시작될 때 발생하는 비동기 상태 불일치를 방어하는 아키텍처를 분석합니다.\n지정된 식별자 `extsec_service_worker_state_persistence_race_conditions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_service_worker_state_persistence_race_conditions_v1\") 앞 20자리}`",
      en: "Design transactional state persistence models mitigating race conditions caused by abrupt worker evictions.\nCompute the first 20 hex characters of SHA256(\"extsec_service_worker_state_persistence_race_conditions_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_service_worker_state_persistence_race_conditions_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["이벤트 리스너는 항상 최상위 동기 스코프에 등록하고, 상태 복원은 비동기 storage 락으로 보호해야 합니다.", "식별자 `extsec_service_worker_state_persistence_race_conditions_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Listeners must be declared in top-level synchronous scope with storage-backed state locks.", "Extract first 20 hex chars of SHA256(\"extsec_service_worker_state_persistence_race_conditions_v1\")."]
    }
  },
  {
    id: "t3_extsec_crx_package_decompilation_and_static_analysis",
    tier: 3, cat: "forensics", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "CRX3 패키지 언팩 및 AST 기반 위험 API 정적 분석 자동화", en: "CRX3 Package Unpacking & AST Static Security Analysis" },
    prompt: {
      ko: "Chromium CRX3 헤더를 언패킹하고 Babel/ESLint AST 파서를 통해 난독화된 위험 API 호출(chrome.cookies, eval)을 탐지하는 기법을 분석합니다.\n지정된 식별자 `extsec_crx_package_decompilation_and_static_analysis_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_crx_package_decompilation_and_static_analysis_v1\") 앞 20자리}`",
      en: "Unpack CRX3 extension archives and leverage AST visitors to detect obfuscated Chrome API calls and evasion tricks.\nCompute the first 20 hex characters of SHA256(\"extsec_crx_package_decompilation_and_static_analysis_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_crx_package_decompilation_and_static_analysis_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["CRX3는 공개키 서명 헤더와 ZIP 압축 페이로드로 구성되어 있어 정적 언패킹 후 AST 분석이 가능합니다.", "식별자 `extsec_crx_package_decompilation_and_static_analysis_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["CRX3 contains RSA/Ed25519 signatures wrapping a zip payload susceptible to automated AST analysis.", "Extract first 20 hex chars of SHA256(\"extsec_crx_package_decompilation_and_static_analysis_v1\")."]
    }
  },
  {
    id: "t3_extsec_developer_mode_sideloading_attack_vectors",
    tier: 3, cat: "manifest", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "개발자 모드 로컬 언팩 확장 주입(Sideloading) 탐지", en: "Developer Mode Sideloading Detection & Local Persistence" },
    prompt: {
      ko: "공격자가 엔드포인트에 로컬 언팩 확장(Unpacked Extension)을 주입하여 브라우저 재시작 시 자동 실행시키는 사이드로딩 지속성 기법을 분석합니다.\n지정된 식별자 `extsec_developer_mode_sideloading_attack_vectors_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_developer_mode_sideloading_attack_vectors_v1\") 앞 20자리}`",
      en: "Investigate unpacked extension sideloading tactics establishing persistent C2 footholds across browser restarts.\nCompute the first 20 hex characters of SHA256(\"extsec_developer_mode_sideloading_attack_vectors_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_developer_mode_sideloading_attack_vectors_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["--load-extension CLI 플래그 및 Preferences 파일의 extensions.settings 변조는 사이드로딩의 핵심 지표입니다.", "식별자 `extsec_developer_mode_sideloading_attack_vectors_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Check command-line switches like --load-extension and monitor Secure Preferences integrity.", "Extract first 20 hex chars of SHA256(\"extsec_developer_mode_sideloading_attack_vectors_v1\")."]
    }
  },
  {
    id: "t3_extsec_browser_tab_manipulation_and_phishing",
    tier: 3, cat: "manifest", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "chrome.tabs API를 악용한 스텔스 피싱 탭 리다이렉션 방어", en: "chrome.tabs Manipulation & Covert Phishing Redirection Defense" },
    prompt: {
      ko: "사용자가 장시간 열어둔 탭을 백그라운드에서 chrome.tabs.update로 가짜 로그인 페이지로 리다이렉션(Tabnabbing)하는 공격과 방어를 분석합니다.\n지정된 식별자 `extsec_browser_tab_manipulation_and_phishing_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_browser_tab_manipulation_and_phishing_v1\") 앞 20자리}`",
      en: "Defend against Tabnabbing where inactive tabs are covertly redirected to credential harvesting clones.\nCompute the first 20 hex characters of SHA256(\"extsec_browser_tab_manipulation_and_phishing_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_browser_tab_manipulation_and_phishing_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["사용자가 다른 탭에 집중하고 있을 때 비활성 탭의 URL을 변경하는 기법을 Reverse Tabnabbing이라고 부릅니다.", "식별자 `extsec_browser_tab_manipulation_and_phishing_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Reverse tabnabbing swaps dormant tab URLs while users interact elsewhere, requiring URL change auditing.", "Extract first 20 hex chars of SHA256(\"extsec_browser_tab_manipulation_and_phishing_v1\")."]
    }
  },
  {
    id: "t3_extsec_runtime_external_connectable_whitelist",
    tier: 3, cat: "manifest", track: "extsec", points: 200, ci: false, fmt: "FLAG{...}",
    title: { ko: "externally_connectable 화이트리스트를 통한 웹 오리진 직접 통신 제한", en: "externally_connectable Web Origin Whitelist Hardening" },
    prompt: {
      ko: "웹페이지가 확장 프로그램과 직접 통신할 수 있는 범위를 정의하는 externally_connectable의 matches 화이트리스트 구성 및 보안 검증을 분석합니다.\n지정된 식별자 `extsec_runtime_external_connectable_whitelist_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_runtime_external_connectable_whitelist_v1\") 앞 20자리}`",
      en: "Restrict direct web-to-extension communication channels using strictly scoped externally_connectable whitelists.\nCompute the first 20 hex characters of SHA256(\"extsec_runtime_external_connectable_whitelist_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_runtime_external_connectable_whitelist_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["matches에 특정 신뢰 FQDN만 명시하지 않으면 모든 웹페이지가 chrome.runtime.sendMessage를 호출할 수 있습니다.", "식별자 `extsec_runtime_external_connectable_whitelist_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Without strict matches patterns, arbitrary origins can trigger internal extension message handlers.", "Extract first 20 hex chars of SHA256(\"extsec_runtime_external_connectable_whitelist_v1\")."]
    }
  },

  // Tier 4 (10)
  {
    id: "t4_extsec_enterprise_extension_allowlist_and_gpo_governance",
    tier: 4, cat: "manifest", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "엔터프라이즈 GPO ExtensionInstallAllowlist 및 거버넌스 통제", en: "Enterprise GPO ExtensionInstallAllowlist Governance" },
    prompt: {
      ko: "Active Directory GPO 또는 Chrome Browser Cloud Management(CBCM)를 통해 승인되지 않은 확장의 설치를 전면 차단하는 거버넌스 설정을 분석합니다.\n지정된 식별자 `extsec_enterprise_extension_allowlist_and_gpo_governance_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_enterprise_extension_allowlist_and_gpo_governance_v1\") 앞 20자리}`",
      en: "Enforce zero-trust extension policies via ExtensionInstallBlocklist: ['*'] and explicit ExtensionInstallAllowlist GPOs.\nCompute the first 20 hex characters of SHA256(\"extsec_enterprise_extension_allowlist_and_gpo_governance_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_enterprise_extension_allowlist_and_gpo_governance_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["와일드카드 차단(*) 후 사전 심사된 확장 ID만 허용하는 화이트리스트 정책이 기업 환경의 표준입니다.", "식별자 `extsec_enterprise_extension_allowlist_and_gpo_governance_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["The standard enterprise baseline blocks all extensions by default, whitelisting audited extensions.", "Extract first 20 hex chars of SHA256(\"extsec_enterprise_extension_allowlist_and_gpo_governance_v1\")."]
    }
  },
  {
    id: "t4_extsec_c2_covert_channel_via_extension_telemetry",
    tier: 4, cat: "forensics", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "확장 프로그램 텔레메트리를 위장한 은닉 C2 통신 식별", en: "Covert C2 Communications Masked as Extension Telemetry" },
    prompt: {
      ko: "분석/통계 전송 API를 위장하여 암호화된 사용자 입력과 토큰을 공격자 C2 서버로 주기적으로 비콘 통신하는 이상 행위를 추적합니다.\n지정된 식별자 `extsec_c2_covert_channel_via_extension_telemetry_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_c2_covert_channel_via_extension_telemetry_v1\") 앞 20자리}`",
      en: "Detect exfiltration channels camouflaged as legitimate diagnostic telemetry beaconing encrypted credentials to C2 nodes.\nCompute the first 20 hex characters of SHA256(\"extsec_c2_covert_channel_via_extension_telemetry_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_c2_covert_channel_via_extension_telemetry_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["주기적 핑 신호와 비정상적으로 큰 POST 바디(Base64 인코딩)를 분석하여 C2 채널을 분리합니다.", "식별자 `extsec_c2_covert_channel_via_extension_telemetry_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Inspect regular POST beacon payloads containing encrypted JSON structures directed at untrusted IPs.", "Extract first 20 hex chars of SHA256(\"extsec_c2_covert_channel_via_extension_telemetry_v1\")."]
    }
  },
  {
    id: "t4_extsec_supply_chain_extension_store_takeover",
    tier: 4, cat: "manifest", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "크롬 웹스토어 개발자 계정 탈취 및 악성 업데이트 공급망 공격", en: "Chrome Web Store Developer Account Hijacking & Malicious Updates" },
    prompt: {
      ko: "피싱으로 탈취된 합법 개발자 계정에서 백도어가 포함된 신규 버전을 배포하여 수백만 사용자에게 자동 업데이트되는 공급망 공격을 분석합니다.\n지정된 식별자 `extsec_supply_chain_extension_store_takeover_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_supply_chain_extension_store_takeover_v1\") 앞 20자리}`",
      en: "Analyze software supply chain compromises where hijacked publisher credentials deploy trojanized auto-updates.\nCompute the first 20 hex characters of SHA256(\"extsec_supply_chain_extension_store_takeover_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_supply_chain_extension_store_takeover_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["자동 업데이트 메커니즘을 악용하는 공급망 공격은 기업 엔드포인트의 버전 고정(Version Pinning)으로 방어합니다.", "식별자 `extsec_supply_chain_extension_store_takeover_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Mitigate web store supply chain attacks by enforcing version pinning and delta diff inspection.", "Extract first 20 hex chars of SHA256(\"extsec_supply_chain_extension_store_takeover_v1\")."]
    }
  },
  {
    id: "t4_extsec_multi_extension_privilege_escalation_chain",
    tier: 4, cat: "manifest", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "다중 확장 프로그램 간 메시지 포워딩을 통한 권한 상승 공격 체인", en: "Multi-Extension Cross-Messaging Privilege Escalation Chains" },
    prompt: {
      ko: "저권한 확장이 고권한(all_urls, cookies) 확장의 취약한 onMessageExternal 리스너를 호출하여 중간 대리인(Confused Deputy)으로 악용하는 체인을 분석합니다.\n지정된 식별자 `extsec_multi_extension_privilege_escalation_chain_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_multi_extension_privilege_escalation_chain_v1\") 앞 20자리}`",
      en: "Trace confused deputy attack chains where low-privilege extensions abuse unauthenticated handlers in high-privilege extensions.\nCompute the first 20 hex characters of SHA256(\"extsec_multi_extension_privilege_escalation_chain_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_multi_extension_privilege_escalation_chain_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["수신 확장은 발신 확장의 ID를 검증하지 않고 쿠키 읽기나 다운로드 작업을 대행할 때 탈취됩니다.", "식별자 `extsec_multi_extension_privilege_escalation_chain_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Target extensions acting as confused deputies execute privileged commands without validating sender IDs.", "Extract first 20 hex chars of SHA256(\"extsec_multi_extension_privilege_escalation_chain_v1\")."]
    }
  },
  {
    id: "t4_extsec_memory_forensics_on_v8_service_worker_heap",
    tier: 4, cat: "forensics", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "Chromium V8 서비스 워커 인메모리 힙 덤프 및 잔존 자격증명 포렌식", en: "Chromium V8 Service Worker Memory Forensics & Key Recovery" },
    prompt: {
      ko: "브라우저 렌더러 프로세스 메모리에서 V8 JS 힙 세그먼트를 덤프하여 서비스 워커 메모리에 잔존하는 JWT 토큰과 암호화 키를 복원합니다.\n지정된 식별자 `extsec_memory_forensics_on_v8_service_worker_heap_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_memory_forensics_on_v8_service_worker_heap_v1\") 앞 20자리}`",
      en: "Carve live V8 isolate heap dumps from browser renderer processes to recover transient tokens and decrypted secrets.\nCompute the first 20 hex characters of SHA256(\"extsec_memory_forensics_on_v8_service_worker_heap_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_memory_forensics_on_v8_service_worker_heap_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["V8 힙 스냅샷(HeapSnapshot)을 분석하여 살아있는 클로저와 전역 스코프에 잔존하는 평문 키를 카빙합니다.", "식별자 `extsec_memory_forensics_on_v8_service_worker_heap_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["V8 heap snapshots reveal active closures and string tables holding unencrypted authentication tokens.", "Extract first 20 hex chars of SHA256(\"extsec_memory_forensics_on_v8_service_worker_heap_v1\")."]
    }
  },
  {
    id: "t4_extsec_side_channel_timing_attack_via_war",
    tier: 4, cat: "war", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "WAR 캐시 응답 시간을 악용한 브라우징 히스토리 사이드 채널 유출", en: "WAR Cache Timing Side-Channel & Navigation History Leakage" },
    prompt: {
      ko: "특정 도메인에만 조건부 노출되는 WAR 리소스의 브라우저 HTTP 캐시 로딩 시간을 정밀 측정하여 사용자의 방문 이력을 복원하는 부채널 공격을 분석합니다.\n지정된 식별자 `extsec_side_channel_timing_attack_via_war_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_side_channel_timing_attack_via_war_v1\") 앞 20자리}`",
      en: "Evaluate cross-origin resource timing side-channels against cached WAR assets to infer user browsing history.\nCompute the first 20 hex characters of SHA256(\"extsec_side_channel_timing_attack_via_war_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_side_channel_timing_attack_via_war_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["performance.now()를 이용해 캐시 히트(Hit)와 미스(Miss)의 미세한 시간 차이를 분석합니다.", "식별자 `extsec_side_channel_timing_attack_via_war_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["High-precision performance timers expose differential latency between cached and uncached WAR assets.", "Extract first 20 hex chars of SHA256(\"extsec_side_channel_timing_attack_via_war_v1\")."]
    }
  },
  {
    id: "t4_extsec_webgpu_and_wasm_in_isolated_world",
    tier: 4, cat: "dom", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "격리 월드 내 WebAssembly/WebGPU 연산 악용 암호화폐 채굴 차단", en: "WebAssembly & WebGPU Abuse in Isolated Worlds Mitigation" },
    prompt: {
      ko: "콘텐츠 스크립트가 WebAssembly 컴파일 및 WebGPU 셰이더를 초기화하여 사용자 백그라운드 자원을 소모하는 스텔스 크립토재킹을 차단합니다.\n지정된 식별자 `extsec_webgpu_and_wasm_in_isolated_world_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_webgpu_and_wasm_in_isolated_world_v1\") 앞 20자리}`",
      en: "Neutralize covert cryptojacking operations executing parallel WebAssembly and WebGPU compute shaders inside isolated worlds.\nCompute the first 20 hex characters of SHA256(\"extsec_webgpu_and_wasm_in_isolated_world_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_webgpu_and_wasm_in_isolated_world_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["Wasm 인스턴스화 및 WebGPU 디바이스 요청을 가로채고 정책 기반으로 비활성화합니다.", "식별자 `extsec_webgpu_and_wasm_in_isolated_world_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Monitor and constrain WebAssembly.instantiate() and GPU compute pipeline allocations in extension contexts.", "Extract first 20 hex chars of SHA256(\"extsec_webgpu_and_wasm_in_isolated_world_v1\")."]
    }
  },
  {
    id: "t4_extsec_anti_analysis_techniques_in_malicious_extensions",
    tier: 4, cat: "forensics", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "악성 확장의 DevTools 디버거 탐지 및 동적 분석 회피 기법", en: "Anti-Analysis & DevTools Debugger Detection in Malicious Extensions" },
    prompt: {
      ko: "개발자 도구(DevTools) 개방 감지, 타이밍 지연 루프, 안티 디버깅 트랩을 구성하여 보안 분석가의 동적 진단을 방해하는 기법과 우회책을 분석합니다.\n지정된 식별자 `extsec_anti_analysis_techniques_in_malicious_extensions_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_anti_analysis_techniques_in_malicious_extensions_v1\") 앞 20자리}`",
      en: "Analyze evasion mechanisms detecting DevTools inspection and instrumenting debugger timing traps to thwart dynamic analysis.\nCompute the first 20 hex characters of SHA256(\"extsec_anti_analysis_techniques_in_malicious_extensions_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_anti_analysis_techniques_in_malicious_extensions_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["debugger 문과 window.outerWidth/innerWidth 차이 측정을 통한 DevTools 감지 코드를 패치해야 합니다.", "식별자 `extsec_anti_analysis_techniques_in_malicious_extensions_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Patch recursive debugger traps and window geometry checks used to identify analysis environments.", "Extract first 20 hex chars of SHA256(\"extsec_anti_analysis_techniques_in_malicious_extensions_v1\")."]
    }
  },
  {
    id: "t4_extsec_automated_manifest_v3_ci_linting_pipeline",
    tier: 4, cat: "csp", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "CI/CD 파이프라인에서의 Manifest V3 정적 보안 린팅 자동화", en: "Automated Manifest V3 Security Linting in CI/CD Pipelines" },
    prompt: {
      ko: "GitHub Actions 파이프라인에서 ESLint 확장 플러그인과 CSP/DNR 유효성 검사기를 연동하여 배포 전 취약한 권한을 자동 차단하는 체계를 분석합니다.\n지정된 식별자 `extsec_automated_manifest_v3_ci_linting_pipeline_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_automated_manifest_v3_ci_linting_pipeline_v1\") 앞 20자리}`",
      en: "Build automated CI security gates enforcing Manifest V3 schema validation, CSP purity, and permission least-privilege.\nCompute the first 20 hex characters of SHA256(\"extsec_automated_manifest_v3_ci_linting_pipeline_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_automated_manifest_v3_ci_linting_pipeline_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["빌드 단계에서 regexFilter 유효성 및 권한 차단 목록을 검사하여 보안 회귀를 원천 방지합니다.", "식별자 `extsec_automated_manifest_v3_ci_linting_pipeline_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Static AST linter rules block banned permissions and unvalidated innerHTML assignments prior to publication.", "Extract first 20 hex chars of SHA256(\"extsec_automated_manifest_v3_ci_linting_pipeline_v1\")."]
    }
  },
  {
    id: "t4_extsec_zero_trust_browser_architecture_and_extension_hardening",
    tier: 4, cat: "manifest", track: "extsec", points: 300, ci: false, fmt: "FLAG{...}",
    title: { ko: "제로 트러스트 엔터프라이즈 브라우저 아키텍처 및 종합 하드닝", en: "Zero-Trust Enterprise Browser Architecture & Extension Hardening" },
    prompt: {
      ko: "엔터프라이즈 환경에서 엔드포인트 브라우저의 확장 프로그램 권한, DNR 네트워크 정책, 격리 실행 환경, 감사 로깅을 아우르는 제로 트러스트 하드닝을 완성합니다.\n지정된 식별자 `extsec_zero_trust_browser_architecture_and_extension_hardening_v1`의 SHA-256 해시 앞 20자리를 추출하여 플래그를 제출하세요.\n\n형식: `FLAG{SHA256(\"extsec_zero_trust_browser_architecture_and_extension_hardening_v1\") 앞 20자리}`",
      en: "Synthesize enterprise zero-trust browser posture integrating strict extension allowlists, DNR policies, and telemetry audits.\nCompute the first 20 hex characters of SHA256(\"extsec_zero_trust_browser_architecture_and_extension_hardening_v1\").\n\nFormat: `FLAG{SHA256(\"extsec_zero_trust_browser_architecture_and_extension_hardening_v1\") first 20 hex}`"
    },
    hints: {
      ko: ["DNR 규칙, 최소 권한 매니페스트, 격리 월드 엄격화, 중앙 GPO 거버넌스를 결합하여 엔터프라이즈 보안을 달성합니다.", "식별자 `extsec_zero_trust_browser_architecture_and_extension_hardening_v1`의 해시 앞 20자리를 추출하세요."],
      en: ["Combine declarative filtering, minimal permissions, isolated execution, and enterprise cloud governance.", "Extract first 20 hex chars of SHA256(\"extsec_zero_trust_browser_architecture_and_extension_hardening_v1\")."]
    }
  }
];

const processed = challengesDef.map(c => {
  return {
    ...c,
    hash: computeHash(c.id)
  };
});

fs.writeFileSync(path.join(__dirname, 'track58_challenges.json'), JSON.stringify(processed, null, 2), 'utf8');
console.log(`Generated ${processed.length} challenges for Track 58 (extsec)!`);
