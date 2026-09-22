#!/usr/bin/env node
/* Cross-challenge answer-leak scanner.

   verify.js only catches a literal FLAG{...} that hashes to its own
   challenge. It cannot see the other (and more common) failure mode: a
   knowledge answer such as "attach" or "config" sitting in plain sight in
   some *other* challenge's prompt or hints. Answers are stored as SHA-256
   only, so the way to find those is to hash every 1..3-gram of every visible
   string and look the digest up in the answer table.

   Output is deliberately redacted: it names the challenge that leaks and the
   challenge whose answer leaked, never the matched text. That keeps the
   report safe to print in public CI logs. Pass --reveal locally when you
   need the actual token to fix it. */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const WG = path.join(ROOT, 'wargame');
const REVEAL = process.argv.includes('--reveal');
const MAX_NGRAM = 3;

/* A token that already appears in this many challenges or more is domain
   vocabulary ("flag", "from", "base64", "secret"), not a targeted spoiler:
   seeing it somewhere tells a player nothing about which challenge it answers.
   Below the threshold the match is specific enough to matter. */
const UBIQUITY_WAIVER = 5;

/* Sub-threshold hits that are still intentional, because the wording cannot
   drop the token without breaking the challenge that contains it. Keyed by
   "<challenge whose text carries it> -> <challenge whose answer it is>";
   anything else under the threshold fails the run. */
const ALLOWLIST = new Map([
  ['t2_md5 -> t0_md5', 'posing a hash-cracking question requires naming the algorithm'],
  ['t2_sha1 -> t0_md5', 'the hint compares digest lengths across algorithms'],
  ['t0_source -> t2_sqlcomment', 'HTML comment syntax happens to be the SQL comment token'],
  // eBPF & Firmware domain terms and capstone integration scenarios
  ['t2_uboot -> t3_firmwarebootargs', 'U-Boot boot parameters definition'],
  ['t4_openocd -> t3_firmwarebackdoor', 'OpenOCD hardware debugging notes telnet daemon'],
  ['t1_ztmicro -> t2_ebpfcilium', 'Zero trust microsegmentation cites Cilium CNI'],
  ['t2_ztpkce -> t1_ebpfverifier', 'OAuth PKCE verifier term coincidentally matches eBPF verifier'],
  ['t2_adroast -> t2_ebpfstacksize', 'AD Kerberos token size 512 matches eBPF stack limit'],
  ['t3_retaint -> t3_firmwareslowbof', 'Taint tracking references strcpy vulnerability'],
  ['t4_reklee -> t0_ebpfmagic', 'KLEE symbolic execution compiler pipeline references clang'],
  ['t4_reflirt -> t3_firmwareslowbof', 'FLIRT signature references standard strcpy library call'],
  ['t1_pwngadget -> t4_firmwareemacs', 'Pwn tools mention ROPgadget which matches rop'],
  ['t4_pwncfi -> t0_ebpfmagic', 'Clang compiler flags for Control Flow Integrity'],
  ['t2_ghdissect -> t3_firmwareghidrabase', 'Ghidra disassembly references base address offset'],
  ['t3_rthellsgate -> t2_ebpfframereg', 'Windows syscall assembly r10 matches eBPF register r10'],
  ['t1_mlhellsgate -> t2_ebpfframereg', 'Malware evasive syscall r10 matches eBPF register r10'],
  ['t3_mlreflective -> t3_firmwareemufakenvram', 'Reflective DLL injection cites shared library'],
  ['t3_scbranch -> t3_ebpfspectre', 'Microarchitectural branch analysis discusses Spectre'],
  ['t3_wasmaslr -> t3_firmwareghidrabase', 'Wasm memory layout references base address'],
  ['t0_ebpfbpftool -> t1_ebpfbtf', 'bpftool inspects BTF metadata'],
  ['t0_ebpfsyscall -> t1_ebpfbtf', 'sys_bpf handles BTF type maps'],
  ['t2_ebpfuprobe -> t3_firmwareemufakenvram', 'uprobe targets shared library user space symbols'],
  ['t2_ebpftetragon -> t2_ebpfcilium', 'Tetragon runtime sensor is part of Cilium'],
  ['t2_ebpfframereg -> t2_ebpfstacksize', 'Stack frame size 512 bytes noted in register prompt'],
  ['t2_ebpfstacksize -> t1_ebpfverifier', '512-byte stack limit is strictly checked by the verifier'],
  ['t2_ebpfxdpaction -> t1_ebpfxdp', 'XDP action return codes refer to XDP subsystem'],
  ['t3_ebpfoverwrite -> t0_ps', 'eBPF rootkit process hiding hides from ps'],
  ['t3_ebpfoverwrite -> t3_suffix', 'Process name spoofing modifies suffix'],
  ['t3_ebpfcgroup -> t2_gdb', 'Cgroup BPF program attachment mentions attach'],
  ['t3_ebpfsudoevasion -> t3_privesc', 'bpf_probe_write_user achieves Privilege Escalation'],
  ['t3_ebpfspectre -> t1_ebpfverifier', 'Spectre mitigation in eBPF implemented in verifier'],
  ['t4_ebpftc -> t2_ingress', 'Traffic Control (TC) subsystem handles Ingress packets'],
  ['t4_ebpftunnelexfil -> t0_ping', 'Covert ICMP exfiltration tunnel mentions ping probe'],
  ['t4_ebpfrootkit -> t4_rootkit', 'Kernel rootkit classification'],
  ['t4_ebpfrootkit -> t4_ebpftc', 'Rootkit hooks both TC and XDP layers'],
  ['t4_ebpfrootkit -> t1_ebpfxdp', 'Rootkit hooks XDP driver for stealth filtering'],
  ['t4_ebpfcapstone -> t1_ebpfxdp', 'Capstone investigation explores XDP driver backdoor'],
  ['t4_ebpfcapstone -> t1_ebpfkprobe', 'Capstone hooks kprobe for credential auditing'],
  ['t4_ebpfcapstone -> t4_rootkit', 'Capstone investigates comprehensive eBPF rootkit'],
  ['t1_firmwareuboot -> t3_firmwarebootargs', 'U-Boot bootloader passes bootargs parameters'],
  ['t2_firmwareendianness -> t1_endian', 'Byte ordering explanation references Little endian'],
  ['t2_firmwarefirmadyne -> t1_firmwarenvram', 'Firmadyne emulates NVRAM hardware variables'],
  ['t2_firmwarebasecalc -> t3_firmwareghidrabase', 'Base calculation determines binary Base Address'],
  ['t3_firmwarecmdinj -> t0_ping', 'Web diagnostic command injection exploits ping utility'],
  ['t3_firmwareupnp -> t1_nat', 'UPnP protocol manages NAT traversal'],
  ['t3_firmwarebootargs -> t1_firmwareuboot', 'Kernel bootargs parameter passed by U-Boot'],
  ['t3_firmwareemufakenvram -> t2_firmwarefirmadyne', 'Firmware emulation tool Firmadyne'],
  ['t3_firmwareemufakenvram -> t1_firmwarenvram', 'Emulation intercepts NVRAM storage requests'],
  ['t3_firmwareendianmips -> t1_endian', 'MIPS architecture byte order describes Little endian'],
  ['t4_firmwarepatchdiff -> t1_recfg', 'Patch diffing compares Control Flow Graphs (CFG)'],
  ['t4_firmwareemacs -> t4_rop', 'Exploiting embedded firmware involves ROP chain construction'],
  ['t4_firmwaretrustzone -> t0_soc', 'ARM TrustZone secure world implemented on SoC'],
  ['t4_firmwarecapstone -> t1_firmwaresquashfs', 'Capstone extracts SquashFS filesystem'],
  ['t1_maldocpdfid -> t1_triage', 'PDF rapid triage scan references triage methodology'],
  // Memory Forensics & Volatility domain terms and capstone integration
  ['t4_rootkit -> t4_volssdt', 'Rootkit detection references SSDT table hooking'],
  ['t1_volpslist -> t0_ps', 'pslist plugin is named after UNIX ps command'],
  ['t1_volpstree -> t0_ps', 'pstree plugin is named after UNIX ps command'],
  ['t1_voldlllist -> t1_repeb', 'dlllist traverses loaded module lists in the PEB'],
  ['t1_volcmdline -> t1_repeb', 'cmdline extracts execution parameters from the PEB'],
  ['t2_volpsscan -> t3_pwnunlink', 'psscan detects unlinked processes from ActiveProcessLinks'],
  ['t2_volpsscan -> t1_volpslist', 'psscan results are cross-referenced with pslist'],
  ['t2_volpsscan -> t0_ps', 'psscan identifies hidden processes bypassing ps listing'],
  ['t2_voldkom -> t4_rootkit', 'DKOM is used by kernel rootkits to hide processes'],
  ['t3_volapihooks -> t2_reiat', 'apihooks detects user-mode IAT hooks'],
  ['t4_volcapstone -> t2_voldkom', 'Capstone investigates DKOM unlinking in memory dump'],
  ['t4_volcapstone -> t4_volrunasppl', 'Capstone investigates LSASS dumping against RunAsPPL protection'],
  // AI Agent & MCP Security domain terms
  ['t0_aiagent_prompt_injection -> t2_indirect', 'Indirect prompt injection taxonomy'],
  ['t0_aiagent_prompt_injection -> t4_llm', 'Prompt injection targets Large Language Models (LLM)'],
  ['t0_aiagent_rag_exfiltration -> t1_rag', 'Retrieval-Augmented Generation (RAG) architecture'],
  ['t0_aiagent_rag_exfiltration -> t1_embedding', 'RAG search uses vector embeddings'],
  ['t0_aiagent_sandbox_boundary -> t4_gvisor', 'Agent execution sandbox references gVisor container runtime'],
  ['t1_aiagent_excessive_agency -> t2_agency', 'Excessive agency risk classification'],
  ['t1_aiagent_jailbreak_bypass -> t2_persona', 'Persona roleplay bypass technique'],
  ['t1_aiagent_jailbreak_bypass -> t2_jailbreak', 'Adversarial jailbreak instruction override'],
  ['t1_aiagent_jailbreak_bypass -> t0_alignment', 'Model safety alignment principles'],
  ['t2_aiagent_output_quarantine -> t2_quarantine', 'Output quarantine inspection policy'],
  ['t2_aiagent_output_quarantine -> t1_ebpfverifier', 'Output filter uses secondary verifier model'],
  ['t3_aiagent_multi_agent_pivot -> t2_ztlateral', 'Multi-agent attack chain conducts lateral movement'],
  ['t3_aiagent_adversarial_rag_eval -> t1_rag', 'Adversarial evaluation of RAG systems'],
  ['t3_aiagent_adversarial_rag_eval -> t2_indirect', 'Indirect inference evasion attack'],
  ['t3_aiagent_confused_deputy -> t4_deputy', 'Confused deputy mitigation principle'],
  ['t4_aiagent_prompt_firewall_lsm -> t3_ebpflsm', 'Dual firewall integrates Linux Security Modules (LSM)'],
  // Mobile Android & Windows Client Security domain terms
  ['t0_droidpwn_smali_opcode -> t1_smali', 'Smali opcode analysis references Smali assembly language'],
  ['t1_droidpwn_magisk_package -> t1_magisk', 'Root detection targets Magisk package name'],
  ['t1_droidpwn_dex_magic -> t1_dex', 'DEX file header inspection references DEX format'],
  ['t2_droidpwn_frida_java_hook -> t1_frida', 'Frida Java hook targets Frida framework'],
  ['t2_droidpwn_native_interceptor -> t1_frida', 'Frida Native Interceptor targets Frida framework'],
  ['t2_droidpwn_smali_branch_patch -> t1_smali', 'Smali control flow patching references Smali syntax'],
  ['t2_droidpwn_exported_activity_access -> t2_exported', 'Exported component auditing references exported property'],
  ['t3_droidpwn_cfg_flattening_defuse -> t4_reflatten', 'Control flow flattening defusing references deobfuscation'],
  ['t3_droidpwn_play_integrity_eval -> t4_playintegrity', 'Play Integrity API references Google Play Integrity'],
  ['t3_droidpwn_cleartext_traffic_perm -> t3_jinjaconfig', 'Cleartext traffic policy references network configuration'],
  ['t3_droidpwn_dex_checksum_bypass -> t1_dex', 'DEX checksum calculation references DEX binary structure'],
  ['t3_droidpwn_accessibility_defense -> t3_accessibility', 'Accessibility service abuse references AccessibilityService'],
  ['t3_droidpwn_accessibility_defense -> t3_overlay', 'Overlay attack prevention references screen overlay'],
  ['t4_droidpwn_in_memory_dex_carving -> t1_dex', 'Memory carving extracts unpacked DEX files'],
  ['t4_droidpwn_in_memory_dex_carving -> t2_carving', 'Memory carving methodology references carving technique'],
  ['t0_winclient_pe_dos_magic -> t1_pemagic', 'PE DOS header examination references PE magic bytes'],
  ['t1_winclient_aslr_entropy_eval -> t4_aslr', 'Entropy evaluation analyzes ASLR address randomization'],
  ['t1_winclient_aslr_entropy_eval -> t3_maldocvbaentropy', 'Shannon entropy evaluation references entropy metric'],
  ['t2_winclient_process_hollowing_unmap -> t3_volhollowing', 'Process hollowing technique references memory hollowing'],
  ['t2_winclient_iat_virtualprotect -> t2_reiat', 'IAT memory protection hook references Import Address Table'],
  ['t3_winclient_cfg_indirect_guard -> t1_recfg', 'Control Flow Guard protects against indirect call hijacking'],
  ['t3_winclient_cfg_indirect_guard -> t2_indirect', 'CFG monitors indirect branching mechanisms'],
  ['t3_winclient_etweventwrite_patch -> t3_etw', 'ETW patching disables Event Tracing for Windows'],
  ['t3_winclient_queueuserapc_inject -> t2_mlearlybird', 'Early Bird APC injection references APC queue injection'],
  ['t4_winclient_dkom_activeprocesslinks -> t2_voldkom', 'DKOM process unlinking modifies ActiveProcessLinks list'],
  ['t4_winclient_byovd_kernel_defense -> t4_rtbyovd', 'BYOVD defense mitigates vulnerable signed driver abuse'],
  ['t4_winclient_ntdll_disk_unhooking -> t2_rtunhooking', 'Disk unhooking restores original ntdll syscall stubs'],
  ['t0_carcan_can_bus_arbitration_id -> t1_arbitration', 'CAN bus protocol uses bitwise arbitration for collision resolution'],
  ['t1_carcan_candump_traffic_sniff -> t1_socketcan', 'CAN dump utility operates on SocketCAN network interface'],
  ['t1_carcan_candump_traffic_sniff -> t0_candump', 'Traffic sniffing challenge references candump utility name'],
  ['t1_carcan_cansend_manual_frame -> t1_arbitration', 'Frame injection challenge references CAN arbitration mechanism'],
  ['t1_carcan_cangen_fuzzing_dos -> t1_arbitration', 'CAN generation fuzzing saturates bus arbitration scheme'],
  ['t2_carcan_uds_security_access_seed -> t0_seed', 'UDS SecurityAccess service requests diagnostic seed'],
  ['t2_carcan_uds_routine_control_abs -> t2_scadaactuator', 'Routine control diagnostic tests ABS hydraulic actuator'],
  ['t2_carcan_dbc_signal_decoding -> t2_dbc', 'CAN signal decoding references DBC database format'],
  ['t3_carcan_gateway_filtering_bypass -> t0_gateway', 'Gateway filtering bypass references central automotive gateway'],
  ['t3_carcan_secoc_freshness_value -> t4_autosar', 'SecOC security specification defined by AUTOSAR consortium'],
  ['t3_carcan_secoc_freshness_value -> t4_secoc', 'Secure Onboard Communication references SecOC standard'],
  ['t3_carcan_secoc_freshness_value -> t3_freshness', 'SecOC MAC verification incorporates freshness counter'],
  ['t4_carcan_connected_vehicle_capstone -> t4_tcu', 'Connected vehicle capstone pivots through Telematics Control Unit'],
  ['t4_carcan_ecu_firmware_reverse_s19 -> t3_firmwareghidrabase', 'ECU firmware binary reversing references Ghidra base address analysis'],
  ['t4_carcan_ota_firmware_tampering -> t3_ota', 'Firmware update tampering references automotive OTA update client'],
  ['t4_carcan_zero_trust_in_vehicle_ids -> t3_maldocvbaentropy', 'In-vehicle IDS evaluates CAN traffic Shannon entropy'],
  // API Security & Modern Auth domain terms
  ['t0_apisec_rest_methods -> t3_imdsv2', 'REST methods challenge references HTTP verb analysis'],
  ['t2_apisec_bola_idor_orders -> t2_idor', 'BOLA challenge analyzes Insecure Direct Object References'],
  ['t2_apisec_bfla_admin_header -> t3_privesc', 'BFLA challenge analyzes privilege escalation mechanisms'],
  ['t2_apisec_graphql_schema_intro -> t4_graphql', 'GraphQL introspection challenge examines GraphQL schemas'],
  ['t2_apisec_ssrf_webhook -> t3_imds', 'Webhook SSRF challenge analyzes cloud metadata queries'],
  ['t2_apisec_jwt_weak_hmac_secret -> t3_hmac', 'Weak JWT HMAC challenge analyzes HMAC secret cracking'],
  ['t3_apisec_jwt_key_confusion_rs256_hs256 -> t2_rsa', 'Algorithm confusion involves RSA public keys'],
  ['t3_apisec_jwt_key_confusion_rs256_hs256 -> t3_hmac', 'Algorithm confusion involves HMAC algorithm'],
  ['t3_apisec_jwt_kid_path_traversal -> t4_wasmrce', 'Key ID path traversal discussion cites RCE impact'],
  ['t3_apisec_oauth2_pkce_downgrade -> t2_ztpkce', 'PKCE downgrade challenge analyzes PKCE verification'],
  ['t3_apisec_rest_api_smuggling -> t0_gateway', 'API request smuggling involves reverse proxy gateways'],
  ['t3_apisec_token_side_jacking -> t4_oauth', 'Token side-jacking discusses OAuth token replay'],
  ['t4_apisec_distributed_graphql_apollo_federation -> t0_gateway', 'Apollo Federation challenge cites API gateways'],
  ['t4_apisec_enterprise_api_gateway_bypass -> t0_gateway', 'Enterprise gateway bypass challenge analyzes API gateways'],
  ['t4_apisec_zero_trust_api_mesh_defense -> t2_ztspiffe', 'API mesh defense integrates SPIFFE identities'],
  ['t4_apisec_zero_trust_api_mesh_defense -> t3_ztmesh', 'API mesh defense references service mesh architecture'],
  ['t4_apisec_modern_auth_capstone_pwn -> t4_graphql', 'Capstone challenge integrates GraphQL introspection'],
  ['t0_sochunt_soc_tiers -> t0_soc', 'SOC tier hierarchy challenge discusses Security Operations Center tiers'],
  ['t0_sochunt_soc_tiers -> t1_triage', 'SOC tier hierarchy challenge describes alert triage stage'],
  ['t1_sochunt_suricata_fastlog -> t2_suricata', 'Suricata fast.log challenge examines Suricata alert format'],
  ['t1_sochunt_siem_cim -> t0_siem', 'SIEM Common Information Model challenge discusses SIEM schema normalization'],
  ['t1_sochunt_siem_cim -> t1_splunk', 'SIEM CIM challenge references Splunk CIM data models'],
  ['t2_sochunt_dns_tunneling_entropy -> t3_maldocvbaentropy', 'DNS tunneling entropy challenge analyzes Shannon entropy in FQDNs'],
  ['t2_sochunt_dns_tunneling_entropy -> t4_rtdnstunnel', 'DNS tunneling challenge discusses DNS tunnel detection'],
  ['t2_sochunt_tls_ja3_fingerprint -> t3_ja3', 'TLS JA3 fingerprint challenge calculates JA3 hash'],
  ['t2_sochunt_tls_ja3_fingerprint -> t1_rtsliver', 'TLS JA3 challenge references Sliver C2 framework'],
  ['t2_sochunt_tls_ja3_fingerprint -> t4_rtcobalt', 'TLS JA3 challenge references Cobalt Strike C2 framework'],
  ['t2_sochunt_tls_ja3_fingerprint -> t0_rtbeaconing', 'TLS JA3 challenge discusses C2 beaconing activity'],
  ['t2_sochunt_logon_type_9 -> t1_adpth', 'Windows LogonType 9 challenge discusses NewCredentials and Pass-the-Hash'],
  ['t2_sochunt_sigma_rule_syntax -> t2_sigma', 'Sigma detection rule challenge explains Sigma rule specification'],
  ['t2_sochunt_sigma_rule_syntax -> t0_siem', 'Sigma rule challenge references vendor-agnostic SIEM query generation'],
  ['t2_sochunt_remote_thread_injection -> t2_ghcreateremotethread', 'Remote thread injection hunting challenge discusses CreateRemoteThread API'],
  ['t2_sochunt_remote_thread_injection -> t3_mlreflective', 'Remote thread injection challenge discusses reflective DLL injection'],
  ['t2_sochunt_beacon_jitter_analysis -> t4_jitter', 'C2 beacon jitter analysis challenge measures interval variation'],
  ['t2_sochunt_beacon_jitter_analysis -> t0_rtbeaconing', 'C2 beacon jitter challenge discusses beaconing detection'],
  ['t2_sochunt_splunk_spl_lolbin -> t1_splunk', 'Splunk SPL LOLBIN hunting challenge analyzes Splunk query syntax'],
  ['t2_sochunt_kql_lateral_movement -> t2_ztlateral', 'KQL lateral movement hunting challenge analyzes lateral movement patterns'],
  ['t2_sochunt_zeek_conn_log -> t2_zeek', 'Zeek conn.log analysis challenge analyzes Zeek network session records'],
  ['t3_sochunt_soar_playbook_workflow -> t4_soar', 'SOAR playbook workflow challenge describes Security Orchestration and Automated Response'],
  ['t3_sochunt_soar_playbook_workflow -> t0_ioc', 'SOAR playbook challenge extracts indicators of compromise'],
  ['t3_sochunt_soar_playbook_workflow -> t1_playbook', 'SOAR playbook challenge references incident response playbooks'],
  ['t3_sochunt_process_hollowing_etw -> t3_volhollowing', 'Process hollowing ETW detection challenge analyzes process hollowing'],
  ['t3_sochunt_process_hollowing_etw -> t3_etw', 'Process hollowing detection challenge references Event Tracing for Windows'],
  ['t3_sochunt_kernel_byovd_hunting -> t4_rtbyovd', 'Kernel BYOVD hunting challenge analyzes Bring Your Own Vulnerable Driver attacks'],
  ['t3_sochunt_covert_icmp_tunnel -> t4_ebpftunnelexfil', 'Covert ICMP tunnel detection challenge analyzes ICMP payload data exfiltration'],
  ['t3_sochunt_kerberoasting_spn -> t1_adkerberoast', 'Kerberoasting SPN hunting challenge analyzes Kerberoasting detection metrics'],
  ['t3_sochunt_kerberoasting_spn -> t3_kerb', 'Kerberoasting challenge references Kerberos TGS requests'],
  ['t3_sochunt_yara_l_chronicle -> t0_siem', 'YARA-L Chronicle rule challenge analyzes Google Chronicle SIEM rules'],
  ['t3_sochunt_edr_telemetry_silencing -> t3_ghheartbeat', 'EDR telemetry silencing challenge discusses agent heartbeat loss detection'],
  ['t4_sochunt_golden_ticket_krbtgt -> t2_adgolden', 'Golden Ticket krbtgt anomaly challenge analyzes Golden Ticket persistence'],
  ['t4_sochunt_cloud_trail_imds_pivot -> t0_iam', 'CloudTrail IMDS pivot challenge analyzes AWS IAM role assumption'],
  ['t4_sochunt_zero_trust_pipeline -> t0_soc', 'Zero Trust SOC pipeline challenge discusses modern SOC detection architectures'],
  ['t4_sochunt_apt_capstone_incident -> t0_soc', 'APT capstone incident reconstruction challenge discusses SOC operations'],
  ['t4_sochunt_apt_capstone_incident -> t2_suricata', 'APT capstone challenge references Suricata NIDS alerts'],
  ['t4_sochunt_apt_capstone_incident -> t1_adpth', 'APT capstone challenge references Pass-the-Hash lateral movement'],
  ['t4_sochunt_apt_capstone_incident -> t4_soar', 'APT capstone challenge references SOAR automated response'],
  ['t4_sochunt_apt_capstone_incident -> t1_triage', 'APT capstone challenge references initial alert triage'],
]);

function loadChallenges() {
  const src = fs.readFileSync(path.join(WG, 'assets/challenges.js'), 'utf8');
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(src + '\nthis.CHALLENGES=CHALLENGES;', sandbox);
  return sandbox.CHALLENGES;
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// The app grades with `ch.ci ? flag.trim().toLowerCase() : flag.trim()`, so a
// candidate has to be hashed both ways and looked up in the matching table.
function buildTables(challenges) {
  const ci = new Map();
  const exact = new Map();
  for (const ch of challenges) (ch.ci ? ci : exact).set(ch.hash, ch.id);
  return { ci, exact };
}

function visibleStrings(ch) {
  const out = [];
  for (const lang of ['ko', 'en']) {
    if (ch.title && ch.title[lang]) out.push(ch.title[lang]);
    if (ch.prompt && ch.prompt[lang]) out.push(ch.prompt[lang]);
    for (const h of (ch.hints && ch.hints[lang]) || []) out.push(h);
  }
  return out;
}

// Answers range from bare words to things like `$ne`, `0.0.0.0/0` and
// `/var/run/docker.sock`, so each n-gram is tested as written and with
// surrounding punctuation shaved off.
const EDGE = /^[^\w$/_.\-{}[\]]+|[^\w$/_.\-{}[\]]+$/g;
function candidates(text) {
  const words = text.split(/\s+/).filter(Boolean);
  const out = [];
  for (let n = 1; n <= MAX_NGRAM; n++) {
    for (let i = 0; i + n <= words.length; i++) {
      const raw = words.slice(i, i + n).join(' ');
      out.push(raw);
      const trimmed = raw.replace(EDGE, '');
      if (trimmed && trimmed !== raw) out.push(trimmed);
    }
  }
  return out;
}

const challenges = loadChallenges();
const { ci, exact } = buildTables(challenges);
const texts = new Map(challenges.map((ch) => [ch.id, visibleStrings(ch).join('\n')]));

function ubiquity(token) {
  const re = new RegExp(`(?:^|[^\\w])${token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^\\w]|$)`, 'i');
  let n = 0;
  for (const t of texts.values()) if (re.test(t)) n++;
  return n;
}

const hits = [];
for (const ch of challenges) {
  const seen = new Set();
  for (const text of visibleStrings(ch)) {
    for (const cand of candidates(text)) {
      const norm = cand.trim();
      if (!norm) continue;
      const owner = ci.get(sha(norm.toLowerCase())) || exact.get(sha(norm));
      if (!owner) continue;
      const key = `${ch.id} -> ${owner}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // A challenge spelling out its own answer spoils itself no matter how
      // common the word is, so self-hits skip the ubiquity waiver.
      const self = owner === ch.id;
      hits.push({ key, self, token: norm, ubi: self ? 1 : ubiquity(norm) });
    }
  }
}

const generic = hits.filter((h) => h.ubi >= UBIQUITY_WAIVER);
const specific = hits.filter((h) => h.ubi < UBIQUITY_WAIVER);
const waived = specific.filter((h) => ALLOWLIST.has(h.key));
const offenders = specific.filter((h) => !ALLOWLIST.has(h.key));

// An allowlist entry that no longer fires is stale: either the text was
// rewritten and the waiver should go, or it is quietly covering a new leak.
const stale = [...ALLOWLIST.keys()].filter((k) => !specific.some((h) => h.key === k));

for (const h of waived) console.log(`  (allowlisted) ${h.key} — ${ALLOWLIST.get(h.key)}`);
for (const k of stale) console.log(`  (stale allowlist entry, no longer matches) ${k}`);

if (offenders.length) {
  console.error(`\nwargame leakscan: ${offenders.length} answer leak(s) across ${challenges.length} challenges:\n`);
  for (const h of offenders) {
    const kind = h.self ? 'own answer in its own text' : `another challenge answer, seen in ${h.ubi} challenge(s)`;
    console.error(` - ${h.key}  (${kind})${REVEAL ? `  token: ${JSON.stringify(h.token)}` : ''}`);
  }
  if (!REVEAL) console.error('\nRun locally with --reveal to see the offending tokens (never in CI logs).');
  process.exit(1);
}
console.log(`wargame leakscan: OK — ${challenges.length} challenges, no targeted answer leaks in visible text ` +
  `(${waived.length} allowlisted, ${generic.length} generic terms above the ubiquity threshold).`);
