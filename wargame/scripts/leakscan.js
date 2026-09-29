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
  ['t4_reflirt -> t3_firmwareslowbof', 'FLIRT signature references standard strcpy library call'],
  ['t1_pwngadget -> t4_firmwareemacs', 'Pwn tools mention ROPgadget which matches rop'],
  ['t3_rthellsgate -> t2_ebpfframereg', 'Windows syscall assembly r10 matches eBPF register r10'],
  ['t1_mlhellsgate -> t2_ebpfframereg', 'Malware evasive syscall r10 matches eBPF register r10'],
  ['t3_mlreflective -> t3_firmwareemufakenvram', 'Reflective DLL injection cites shared library'],
  ['t3_scbranch -> t3_ebpfspectre', 'Microarchitectural branch analysis discusses Spectre'],
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
  ['t3_firmwarecmdinj -> t0_ping', 'Web diagnostic command injection exploits ping utility'],
  ['t3_firmwareupnp -> t1_nat', 'UPnP protocol manages NAT traversal'],
  ['t3_firmwarebootargs -> t1_firmwareuboot', 'Kernel bootargs parameter passed by U-Boot'],
  ['t3_firmwareemufakenvram -> t2_firmwarefirmadyne', 'Firmware emulation tool Firmadyne'],
  ['t3_firmwareemufakenvram -> t1_firmwarenvram', 'Emulation intercepts NVRAM storage requests'],
  ['t3_firmwareendianmips -> t1_endian', 'MIPS architecture byte order describes Little endian'],
  ['t4_firmwareemacs -> t4_rop', 'Exploiting embedded firmware involves ROP chain construction'],
  ['t4_firmwaretrustzone -> t0_soc', 'ARM TrustZone secure world implemented on SoC'],
  ['t4_firmwarecapstone -> t1_firmwaresquashfs', 'Capstone extracts SquashFS filesystem'],
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
  ['t4_volcapstone -> t2_voldkom', 'Capstone investigates DKOM unlinking in memory dump'],
  ['t4_volcapstone -> t4_volrunasppl', 'Capstone investigates LSASS dumping against RunAsPPL protection'],
  // AI Agent & MCP Security domain terms
  ['t0_aiagent_prompt_injection -> t4_llm', 'Prompt injection targets Large Language Models (LLM)'],
  ['t0_aiagent_rag_exfiltration -> t1_rag', 'Retrieval-Augmented Generation (RAG) architecture'],
  ['t0_aiagent_rag_exfiltration -> t1_embedding', 'RAG search uses vector embeddings'],
  ['t0_aiagent_sandbox_boundary -> t4_gvisor', 'Agent execution sandbox references gVisor container runtime'],
  ['t1_aiagent_excessive_agency -> t2_agency', 'Excessive agency risk classification'],
  ['t1_aiagent_jailbreak_bypass -> t2_persona', 'Persona roleplay bypass technique'],
  ['t1_aiagent_jailbreak_bypass -> t0_alignment', 'Model safety alignment principles'],
  ['t2_aiagent_output_quarantine -> t2_quarantine', 'Output quarantine inspection policy'],
  ['t2_aiagent_output_quarantine -> t1_ebpfverifier', 'Output filter uses secondary verifier model'],
  ['t3_aiagent_multi_agent_pivot -> t2_ztlateral', 'Multi-agent attack chain conducts lateral movement'],
  ['t3_aiagent_adversarial_rag_eval -> t1_rag', 'Adversarial evaluation of RAG systems'],
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
  ['t3_droidpwn_dex_checksum_bypass -> t1_dex', 'DEX checksum calculation references DEX binary structure'],
  ['t3_droidpwn_accessibility_defense -> t3_accessibility', 'Accessibility service abuse references AccessibilityService'],
  ['t3_droidpwn_accessibility_defense -> t3_overlay', 'Overlay attack prevention references screen overlay'],
  ['t4_droidpwn_in_memory_dex_carving -> t1_dex', 'Memory carving extracts unpacked DEX files'],
  ['t4_droidpwn_in_memory_dex_carving -> t2_carving', 'Memory carving methodology references carving technique'],
  ['t0_winclient_pe_dos_magic -> t1_pemagic', 'PE DOS header examination references PE magic bytes'],
  ['t1_winclient_aslr_entropy_eval -> t4_aslr', 'Entropy evaluation analyzes ASLR address randomization'],
  ['t2_winclient_process_hollowing_unmap -> t3_volhollowing', 'Process hollowing technique references memory hollowing'],
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
  ['t3_carcan_secoc_freshness_value -> t4_autosar', 'SecOC security specification defined by AUTOSAR consortium'],
  ['t3_carcan_secoc_freshness_value -> t4_secoc', 'Secure Onboard Communication references SecOC standard'],
  ['t3_carcan_secoc_freshness_value -> t3_freshness', 'SecOC MAC verification incorporates freshness counter'],
  ['t4_carcan_connected_vehicle_capstone -> t4_tcu', 'Connected vehicle capstone pivots through Telematics Control Unit'],
  ['t4_carcan_ota_firmware_tampering -> t3_ota', 'Firmware update tampering references automotive OTA update client'],
  // API Security & Modern Auth domain terms
  ['t0_apisec_rest_methods -> t3_imdsv2', 'REST methods challenge references HTTP verb analysis'],
  ['t2_apisec_bola_idor_orders -> t2_idor', 'BOLA challenge analyzes Insecure Direct Object References'],
  ['t2_apisec_bfla_admin_header -> t3_privesc', 'BFLA challenge analyzes privilege escalation mechanisms'],
  ['t2_apisec_graphql_schema_intro -> t4_graphql', 'GraphQL introspection challenge examines GraphQL schemas'],
  ['t2_apisec_ssrf_webhook -> t3_imds', 'Webhook SSRF challenge analyzes cloud metadata queries'],
  ['t3_apisec_jwt_key_confusion_rs256_hs256 -> t2_rsa', 'Algorithm confusion involves RSA public keys'],
  ['t3_apisec_jwt_kid_path_traversal -> t4_wasmrce', 'Key ID path traversal discussion cites RCE impact'],
  ['t3_apisec_oauth2_pkce_downgrade -> t2_ztpkce', 'PKCE downgrade challenge analyzes PKCE verification'],
  ['t3_apisec_token_side_jacking -> t4_oauth', 'Token side-jacking discusses OAuth token replay'],
  ['t4_apisec_zero_trust_api_mesh_defense -> t2_ztspiffe', 'API mesh defense integrates SPIFFE identities'],
  ['t4_apisec_zero_trust_api_mesh_defense -> t3_ztmesh', 'API mesh defense references service mesh architecture'],
  ['t4_apisec_modern_auth_capstone_pwn -> t4_graphql', 'Capstone challenge integrates GraphQL introspection'],
  ['t0_sochunt_soc_tiers -> t0_soc', 'SOC tier hierarchy challenge discusses Security Operations Center tiers'],
  ['t1_sochunt_suricata_fastlog -> t2_suricata', 'Suricata fast.log challenge examines Suricata alert format'],
  ['t1_sochunt_siem_cim -> t0_siem', 'SIEM Common Information Model challenge discusses SIEM schema normalization'],
  ['t1_sochunt_siem_cim -> t1_splunk', 'SIEM CIM challenge references Splunk CIM data models'],
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
  ['t1_fuzzing_seed_corpus -> t0_seed', 'Seed corpus challenge discusses initial seed files'],
  ['t1_fuzzing_mutation_havoc -> t4_rthavoc', 'Mutation havoc challenge analyzes havoc mutation stage'],
  ['t1_fuzzing_mutation_havoc -> t4_scbitflip', 'Mutation challenge discusses bitflip mutation strategies'],
  ['t1_fuzzing_crash_signals -> t0_pwnsigsegv', 'Crash signal challenge analyzes SIGSEGV signal 11'],
  ['t2_fuzzing_asan_heap_uaf -> t4_uaf', 'ASAN heap UAF challenge analyzes Use-After-Free defects'],
  ['t2_fuzzing_frida_mode -> t1_frida', 'Frida mode challenge references Frida DBI engine'],
  ['t3_fuzzing_deterministic_poc -> t0_pwnrip', 'Deterministic PoC challenge discusses RIP register reproduction'],
  ['t3_fuzzing_cfi_safe_stack -> t4_pwncfi', 'CFI challenge discusses Control Flow Integrity defenses'],
  ['t4_fuzzing_browser_dom_fuzzing -> t2_ebpfjit', 'Browser fuzzing challenge discusses JIT compiler fuzzing'],
  ['t4_fuzzing_smart_contract_echidna -> t0_web3evm', 'Smart contract fuzzing discusses EVM execution engine'],
  ['t4_fuzzing_concolic_symbolic -> t2_resmt', 'Concolic fuzzing discusses SMT solvers'],
  ['t4_fuzzing_concolic_symbolic -> t3_rez3', 'Concolic fuzzing discusses Z3 theorem prover'],
  ['t4_fuzzing_concolic_symbolic -> t3_reconcolic', 'Hybrid fuzzing analyzes concolic execution'],
  // AI Red Teaming & Jailbreak domain terms
  ['t0_airedteam_direct_jailbreak -> t4_llm', 'Direct jailbreak prompt discusses LLM target'],
  ['t1_airedteam_indirect_injection -> t4_llm', 'Indirect injection prompt discusses LLM agent'],
  ['t1_airedteam_delimiter_defense -> t2_delimiter', 'XML delimiter defense discusses delimiter tagging'],
  ['t1_airedteam_homoglyph_attack -> t4_oshomoglyph', 'Homoglyph substitution attack discusses homoglyphs'],
  ['t1_airedteam_pyrit_framework -> t0_rtredteam', 'PyRIT framework references red team automation'],
  ['t2_airedteam_multi_turn_crescendo -> t4_crescendo', 'Crescendo jailbreak discusses multi-turn crescendo attack'],
  ['t2_airedteam_token_splitting_bpe -> t0_guardrail', 'BPE token splitting analyzes guardrail evasion'],
  ['t2_airedteam_nfkc_normalization -> t4_oshomoglyph', 'NFKC normalization mitigates homoglyph substitution'],
  ['t2_airedteam_dual_llm_pattern -> t4_container', 'Dual LLM privileged isolation pattern'],
  ['t2_airedteam_prompt_leaking_canary -> t4_canary', 'Canary token discusses prompt leakage detection canary'],
  ['t2_airedteam_embedding_distance -> t0_guardrail', 'Embedding distance evaluates semantic guardrail'],
  ['t2_airedteam_embedding_distance -> t1_embedding', 'Embedding similarity analyzes vector embeddings'],
  ['t2_airedteam_excessive_agency -> t2_agency', 'OWASP excessive agency vulnerability discussion'],
  ['t3_airedteam_gcg_adversarial_suffix -> t4_gcg', 'Greedy Coordinate Gradient attack references GCG'],
  ['t3_airedteam_gcg_adversarial_suffix -> t3_suffix', 'GCG adversarial suffix appends tokens'],
  ['t3_airedteam_rag_chunk_poisoning -> t1_rag', 'RAG chunk poisoning evaluates RAG architectures'],
  ['t3_airedteam_multimodal_visual_injection -> t4_llm', 'Multimodal visual injection targets vision LLM models'],
  ['t4_airedteam_tool_namespace_isolation -> t3_scnamespace', 'Tool namespace isolation matches namespace term'],
  ['t4_airedteam_prompt_firewall_lsm -> t3_ebpflsm', 'LSM kernel-coupled prompt firewall references LSM hook'],
  ['t4_airedteam_semantic_integrity_attestation -> t0_inference', 'TEE remote attestation verifies agent inference integrity'],
  ['t4_airedteam_capstone_redteam_eval -> t0_rtredteam', 'Capstone AI red team evaluation references red team'],
  ['t4_airedteam_capstone_redteam_eval -> t0_guardrail', 'Capstone evaluation checks guardrail resilience'],
  // Malware Analysis & Dynamic Sandbox domain terms
  ['t0_malsandbox_mz_dos_header -> t0_mldosheader', 'MZ DOS header discusses DOS header'],
  ['t0_malsandbox_mz_dos_header -> t1_pemagic', 'DOS header mentions MZ magic'],
  ['t0_malsandbox_shannon_entropy_concept -> t2_packing', 'Entropy concept discusses packing'],
  ['t1_malsandbox_anti_debug_peb -> t1_repeb', 'Anti-debug discusses PEB BeingDebugged'],
  ['t1_malsandbox_hash_reputation -> t3_virustotal', 'Hash reputation discusses VirusTotal'],
  ['t2_malsandbox_upx_section_entropy -> t0_reupx', 'UPX entropy discusses UPX'],
  ['t2_malsandbox_tls_callbacks -> t1_reoep', 'TLS callbacks discuss OEP'],
  ['t2_malsandbox_tls_callbacks -> t1_mltls', 'TLS callbacks discuss TLS'],
  ['t2_malsandbox_process_hollowing -> t3_volhollowing', 'Process hollowing discusses hollowing'],
  ['t2_malsandbox_rdtsc_timing_check -> t1_rerdtsc', 'Timing check discusses RDTSC'],
  ['t2_malsandbox_rdtsc_timing_check -> t4_ghhypervisor', 'Timing check discusses hypervisor'],
  ['t3_malsandbox_cuckoomon_api_hooking -> t2_ghcreateremotethread', 'cuckoomon discusses CreateRemoteThread'],
  ['t3_malsandbox_sleep_fast_forward -> t4_mlntdelayexecution', 'Sleep fast forward discusses NtDelayExecution'],
  ['t3_malsandbox_network_beacon_dns -> t1_pcap', 'Network beacon discusses pcap'],
  ['t3_malsandbox_memory_dump_volatility -> t3_volmalfind', 'Memory dump discusses malfind'],
  ['t4_malsandbox_kernel_ebpf_sandbox -> t3_ebpflsm', 'eBPF sandbox discusses LSM'],
  ['t4_malsandbox_capev2_driver_unhook -> t4_volssdt', 'CAPEv2 driver discusses SSDT'],
  ['t4_malsandbox_capev2_driver_unhook -> t2_rtunhooking', 'CAPEv2 driver discusses unhooking'],
  ['t4_malsandbox_anti_vm_instruction_cpuid -> t2_mlcpuid', 'Anti-VM instruction discusses CPUID'],
  ['t4_malsandbox_anti_vm_instruction_cpuid -> t4_ghhypervisor', 'CPUID discusses hypervisor'],
  ['t4_malsandbox_stix_misp_export -> t3_stix', 'Threat export discusses STIX'],
  ['t4_malsandbox_stix_misp_export -> t3_misp', 'Threat export discusses MISP'],
  ['t4_malsandbox_stix_misp_export -> t0_ioc', 'Threat export discusses IOC'],
  ['t4_malsandbox_dynamic_unpacking_dump -> t1_reoep', 'Dynamic unpacking discusses OEP'],
  ['t4_malsandbox_capstone_pipeline_orchestration -> t3_misp', 'Capstone discusses MISP'],
  // Wireless Security & WPA3 SAE / PMKID domain terms
  ['t0_wifisec_bssid_essid -> t2_wlbssid', 'BSSID vs ESSID comparison references BSSID term'],
  ['t0_wifisec_monitor_mode -> t2_promiscuous', 'Monitor mode explanation discusses promiscuous frame capture'],
  ['t1_wifisec_probe_request_karma -> t4_wlkarma', 'Probe request rogue AP discussion cites Karma attack pattern'],
  ['t1_wifisec_aircrack_ng_suite -> t1_wlairmon', 'Aircrack-ng suite utilities cite airmon-ng tool'],
  ['t1_wifisec_deauth_frame_dos -> t2_deauth', '802.11 management deauthentication frame DOS discusses deauth'],
  ['t1_wifisec_wps_pin_pixie_dust -> t4_prng', 'WPS Pixie Dust offline attack exploits weak PRNG seed entropy'],
  ['t2_wifisec_sae_dragonfly_commit -> t3_wldragonfly', 'WPA3 SAE authentication commit exchange references Dragonfly protocol'],
  ['t2_wifisec_krack_key_reinstallation -> t4_krack', '4-Way Handshake Key Reinstallation vulnerability references KRACK'],
  ['t2_wifisec_evil_twin_rogue_ap -> t2_eviltwin', 'Rogue Access Point spoofing analysis references Evil Twin term'],
  ['t3_wifisec_dragonblood_timing_leak -> t3_wldragonfly', 'Dragonblood side-channel attack targets Dragonfly handshake'],
  ['t3_wifisec_sae_hunting_pecking_loop -> t3_wldragonfly', 'Hunting-and-pecking algorithm timing leak targets Dragonfly PWE'],
  ['t3_wifisec_80211w_pmf_bip_cmac -> t4_wlpmf', '802.11w Protected Management Frames defense references PMF standard'],
  ['t3_wifisec_pmf_deauth_dos_immunity -> t4_wlpmf', 'PMF deauth DOS immunity analysis references PMF protection'],
  ['t3_wifisec_pmf_deauth_dos_immunity -> t2_deauth', 'Deauthentication attack resistance discusses deauth vulnerability'],
  ['t3_wifisec_wips_rogue_containment -> t2_eviltwin', 'WIPS rogue AP containment analyzes Evil Twin mitigation'],
  ['t4_wifisec_wlan_client_isolation_bypass -> t1_arp', 'Client isolation bypass via gateway redirection discusses ARP inspection'],
  ['t4_wifisec_wlan_client_isolation_bypass -> t3_relay', 'Client isolation bypass discusses layer 2 packet relay'],
  ['t4_wifisec_capstone_wireless_audit -> t4_wlpmf', 'Capstone wireless audit evaluates PMF enforcement'],
  ['t4_wifisec_capstone_wireless_audit -> t2_eviltwin', 'Capstone wireless audit analyzes Evil Twin attack vectors'],
  // Cisco & Enterprise L2 Network Infrastructure domain terms
  ['t0_netinfra_cisco_ios_modes -> t4_container', 'Cisco IOS configuration modes discuss execution containers'],
  ['t0_netinfra_snmp_default_communities -> t2_snmp', 'Default community discussion cites SNMP protocol'],
  ['t0_netinfra_vlan_fundamentals -> t1_vlan', 'VLAN fundamentals discuss VLAN architecture'],
  ['t2_netinfra_ciscoconfigcopy_mib -> t2_snmp', 'Config copy MIB discusses SNMP management'],
  ['t2_netinfra_vlan_double_tagging -> t1_vlan', 'Double tagging discusses VLAN tagging'],
  ['t2_netinfra_dhcp_snooping_trust_port -> t0_dhcp', 'DHCP snooping discusses DHCP protocol'],
  ['t2_netinfra_dai_arp_inspection -> t1_arp', 'Dynamic ARP inspection discusses ARP protocol'],
  ['t2_netinfra_dai_arp_inspection -> t0_dhcp', 'Dynamic ARP inspection references DHCP snooping bindings'],
  ['t3_netinfra_cisco_type5_md5_hashcat -> t0_md5', 'Type 5 hash analysis discusses MD5 algorithm'],
  ['t3_netinfra_vlan_acl_vacl -> t1_vlan', 'VLAN ACL discusses VLAN security'],
  ['t3_netinfra_private_vlan_isolated -> t1_vlan', 'Private VLAN discusses VLAN segmentation'],
  ['t3_netinfra_private_vlan_isolated -> t2_promiscuous', 'Private VLAN discusses promiscuous ports'],
  ['t3_netinfra_ip_source_guard_ipsg -> t0_dhcp', 'IP source guard references DHCP snooping table'],
  ['t3_netinfra_router_bgp_route_hijacking -> t3_bgp', 'Route hijacking analyzes BGP routing'],
  ['t3_netinfra_router_bgp_route_hijacking -> t4_rpki', 'Route origin authorization references RPKI validation'],
  ['t4_netinfra_snmp_rce_copy_running_startup -> t2_snmp', 'Startup config persistence discusses SNMP set'],
  ['t4_netinfra_bgp_evil_twin_asn_spoof -> t3_bgp', 'BGP AS path spoofing discusses BGP protocol'],
  ['t4_netinfra_bgp_evil_twin_asn_spoof -> t0_md5', 'BGP peer protection discusses MD5 authentication'],
  ['t4_netinfra_cisco_ios_xe_webui_cve -> t3_privesc', 'Web UI privilege escalation discusses privilege escalation'],
  ['t4_netinfra_stp_tc_bpdu_topology_churn -> t4_ebpftc', 'STP topology change BPDU references TC notation'],
  ['t4_netinfra_capstone_enterprise_audit -> t2_snmp', 'Capstone network audit reviews SNMP hardening'],
  // AD CS & Kerberos Delegation domain terms
  ['t1_adcs_kerberos_delegation_types -> t3_adrbcd', 'Kerberos delegation types discusses RBCD architecture'],
  ['t2_adcs_esc1_enrollee_supplies_san -> t3_adesc1', 'ESC1 SAN injection discusses ESC1 vulnerability'],
  ['t2_adcs_unpac_the_hash -> t4_adpac', 'UnPAC-the-Hash extracts PAC credential info'],
  ['t2_adcs_rbcd_msds_allowedtoact -> t3_adrbcd', 'RBCD msDS-AllowedToAct discusses RBCD delegation'],
  ['t3_adcs_esc4_template_acl_overwrite -> t3_adesc1', 'ESC4 ACL modification converts template into ESC1'],
  ['t3_adcs_esc8_ntlm_relay_web_enroll -> t3_relay', 'ESC8 discusses NTLM relay attacks'],
  ['t3_adcs_esc8_ntlm_relay_web_enroll -> t2_adntlmrelay', 'ESC8 discusses AD NTLM relay vectors'],
  ['t3_adcs_esc13_issuance_policies_oid -> t4_container', 'Issuance policy discusses container security'],
  ['t3_adcs_protected_users_security -> t4_container', 'Protected users group discusses administrative containers'],
  ['t3_adcs_event_4887_4768_siem -> t0_siem', 'Event ID correlation discusses SIEM detection'],
  ['t4_adcs_shadow_credentials_keycredentiallink -> t3_adshadowcreds', 'Shadow credentials discusses msDS-KeyCredentialLink'],
  ['t4_adcs_esc8_relay_petitpotam_efs -> t3_adcoerce', 'PetitPotam discusses authentication coercion'],
  ['t4_adcs_esc8_relay_petitpotam_efs -> t3_relay', 'PetitPotam attack discusses NTLM relay'],
  ['t4_adcs_esc8_relay_petitpotam_efs -> t2_adntlmrelay', 'PetitPotam discusses AD NTLM relay chain'],
  ['t4_adcs_rbcd_coercion_cross_forest -> t3_adrbcd', 'Cross-forest coercion discusses RBCD chains'],
  // Ghidra Reverse Engineering & Deobfuscation domain terms
  ['t1_ghidra_opaque_predicate_math -> t2_reopaque', 'Opaque predicate discussion cites opaque term'],
  ['t1_ghidra_import_table_iat -> t3_got', 'GOT/PLT import analysis references GOT table'],
  ['t2_ghidra_pcode_nop_sled -> t2_reopaque', 'P-Code deobfuscation discusses opaque predicates'],
  ['t2_ghidra_binary_patch_nop -> t3_nop', 'Binary patching discussion references NOP opcode'],
  ['t2_ghidra_self_checksum_algorithm -> t3_wasmtrap', 'Integrity check discussion cites trap abort mechanism'],
  ['t3_ghidra_symbolic_execution_deflat -> t2_resmt', 'Symbolic execution discusses SMT solving'],
  ['t3_ghidra_symbolic_execution_deflat -> t3_rez3', 'SMT solving cites Z3 solver engine'],
  ['t3_ghidra_vm_interpreter_handler -> t0_vpc', 'VM obfuscation discusses virtual PC (VPC) pointer'],
  ['t4_ghidra_control_flow_integrity_cfi -> t4_pwncfi', 'CFI discussion references CFI standards'],
  ['t4_ghidra_control_flow_integrity_cfi -> t4_pwncet', 'Intel CET analysis discusses CET instructions'],
  ['t4_ghidra_secure_boot_remote_attestation -> t3_firmwaresecureboot', 'Secure boot attestation references Secure Boot'],
  // OAuth 2.0 & OIDC SSO Exploitation domain terms
  ['t0_oauth_pkce_rfc7636 -> t1_scspa', 'PKCE for public clients discusses SPA architecture'],
  ['t1_oauth_redirect_path_traversal -> t4_maldoccabtraversal', 'Redirect URI path traversal discusses directory traversal'],
  ['t1_oauth_scope_escalation -> t3_privesc', 'OAuth scope escalation discusses privilege escalation'],
  ['t2_oauth_key_confusion_rs256_hs256 -> t2_rsa', 'Key confusion attack discusses RS256 RSA public key'],
  ['t3_oauth_ssrf_token_endpoint -> t3_imds', 'Token endpoint SSRF discusses IMDS metadata access'],
  ['t3_oauth_ssrf_token_endpoint -> t3_pivoting', 'Token endpoint SSRF discusses internal network pivoting'],
  ['t3_oauth_dpop_proof_tampering -> t4_oauth', 'DPoP proof tampering discusses OAuth authorization framework'],
  ['t3_oauth_saml_oauth_bridge_flaw -> t1_ztsaml', 'SAML-OAuth bridge flaw discusses SAML federation'],
  ['t4_oauth_zero_trust_sso_hardening -> t3_ztcaep', 'Zero Trust SSO hardening discusses CAEP continuous evaluation'],
  ['t4_oauth_capstone_sso_exploitation_audit -> t4_oauth', 'Capstone SSO audit analyzes OAuth security architecture'],
  // BGP Routing & RPKI Security domain terms
  ['t0_bgp_peering_model -> t2_exported', 'Peering route model discusses exported routes to peers'],
  ['t2_bgp_communities_manipulation -> t2_ingress', 'Community manipulation discusses border ingress filter'],
  ['t3_rpki_rtr_cache_sync -> t2_ipsec', 'RTR cache sync transport security discusses IPsec encryption'],
  ['t3_bgp_evpn_vxlan_interas -> t3_overlay', 'EVPN VXLAN inter-as discusses overlay networking'],
  ['t4_bgp_tier1_transit_interception -> t2_ghdetour', 'Tier-1 route leak interception discusses traffic detour'],
  ['t4_bgp_zero_trust_peering_architecture -> t2_ptpipeline', 'Zero-trust peering discusses automated validation pipeline'],
  ['t4_bgp_zero_trust_peering_architecture -> t3_screpro', 'Automated route server policy ensures reproducible standards'],
  ['t4_bgp_quantum_resistant_bgpsec -> t4_nist', 'Post-quantum BGPsec discusses NIST PQC algorithms'],
  ['t4_bgp_quantum_resistant_bgpsec -> t0_mtu', 'Post-quantum BGPsec discusses MTU limitations'],
  ['t4_bgp_soar_automated_ir_isolation -> t4_soar', 'Automated incident response discusses SOAR playbooks'],
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
