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
  ['t3_jwtnone -> t2_jwt', "the JWT's own header decodes to it regardless of the prose"],
  ['t3_yara -> t2_strings', 'literal YARA rule section name'],
  ['t4_volatility -> t2_strings', 'names the tool used in the scenario'],
  ['t0_base64 -> t2_strings', 'ordinary English plural in the hint'],
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
  ['t3_scpin -> t4_ebpfsigndigest', 'Side-channel pin analysis references sha256 hash'],
  ['t3_rthellsgate -> t2_ebpfframereg', 'Windows syscall assembly r10 matches eBPF register r10'],
  ['t1_mlhellsgate -> t2_ebpfframereg', 'Malware evasive syscall r10 matches eBPF register r10'],
  ['t3_mlreflective -> t3_firmwareemufakenvram', 'Reflective DLL injection cites shared library'],
  ['t3_scbranch -> t3_ebpfspectre', 'Microarchitectural branch analysis discusses Spectre'],
  ['t3_wasmaslr -> t3_firmwareghidrabase', 'Wasm memory layout references base address'],
  ['t0_ebpfbpftool -> t1_ebpfbtf', 'bpftool inspects BTF metadata'],
  ['t0_ebpfsyscall -> t1_ebpfbtf', 'sys_bpf handles BTF type maps'],
  ['t1_ebpfverifier -> t0_ztverify', 'Verifier prompt references verify action'],
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
  ['t4_ebpfsigndigest -> t0_ztverify', 'Signature digest verification references verify'],
  ['t4_ebpfcapstone -> t1_ebpfxdp', 'Capstone investigation explores XDP driver backdoor'],
  ['t4_ebpfcapstone -> t1_ebpfkprobe', 'Capstone hooks kprobe for credential auditing'],
  ['t4_ebpfcapstone -> t4_rootkit', 'Capstone investigates comprehensive eBPF rootkit'],
  ['t1_firmwareuboot -> t3_firmwarebootargs', 'U-Boot bootloader passes bootargs parameters'],
  ['t1_firmwarenvram -> t0_ram', 'NVRAM stands for Non-Volatile RAM'],
  ['t1_firmwarenvram -> t3_cors', 'Firmware NVRAM references Flash memory'],
  ['t2_firmwareendianness -> t1_endian', 'Byte ordering explanation references Little endian'],
  ['t2_firmwarefirmadyne -> t1_firmwarenvram', 'Firmadyne emulates NVRAM hardware variables'],
  ['t2_firmwareinitrd -> t0_ram', 'initrd is the initial RAM disk'],
  ['t2_firmwarebasecalc -> t3_firmwareghidrabase', 'Base calculation determines binary Base Address'],
  ['t3_firmwarebackdoor -> t3_cors', 'Hardware backdoor dumped from Flash memory'],
  ['t3_firmwarecmdinj -> t0_ping', 'Web diagnostic command injection exploits ping utility'],
  ['t3_firmwareupnp -> t1_nat', 'UPnP protocol manages NAT traversal'],
  ['t3_firmwarebootargs -> t1_firmwareuboot', 'Kernel bootargs parameter passed by U-Boot'],
  ['t3_firmwareemufakenvram -> t2_firmwarefirmadyne', 'Firmware emulation tool Firmadyne'],
  ['t3_firmwareemufakenvram -> t1_firmwarenvram', 'Emulation intercepts NVRAM storage requests'],
  ['t3_firmwareendianmips -> t1_endian', 'MIPS architecture byte order describes Little endian'],
  ['t3_firmwareslowbof -> t2_strings', 'Buffer overflow in string copy references strings'],
  ['t4_firmwarepatchdiff -> t1_recfg', 'Patch diffing compares Control Flow Graphs (CFG)'],
  ['t4_firmwareemacs -> t4_rop', 'Exploiting embedded firmware involves ROP chain construction'],
  ['t4_firmwaretrustzone -> t0_soc', 'ARM TrustZone secure world implemented on SoC'],
  ['t4_firmwarespiundump -> t0_ztverify', 'SPI flash checksum check references verify'],
  ['t4_firmwarecapstone -> t1_firmwaresquashfs', 'Capstone extracts SquashFS filesystem'],
  ['t1_maldocpdfid -> t1_triage', 'PDF rapid triage scan references triage methodology'],
  ['t4_maldoccapstone -> t4_ebpfsigndigest', 'Maldoc capstone specifies sha256 hash formatting'],
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
