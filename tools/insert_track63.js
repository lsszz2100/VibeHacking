const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "ebpfruntime",
    "icon": "🐝",
    "ko": "eBPF 런타임 보안 & 옵저버빌리티",
    "en": "eBPF Runtime Security & Observability",
    "desc_ko": "eBPF kprobe/tracepoint 텔레메트리·eBPF LSM 네임스페이스 탈출 차단·Tetragon TracingPolicy 실시간 SIGKILL·Shadow BPF Rootkit 무결성 감사.",
    "desc_en": "eBPF kprobe/tracepoint telemetry, eBPF LSM namespace escape mitigation, Tetragon TracingPolicy in-kernel SIGKILL, and shadow BPF rootkit triage."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "ebpfruntime"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted ebpfruntime track into TRACKS array');
}

// 2. Load 35 challenges
const track63Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track63_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track63Challenges.map(ch => {
  return '  ' + JSON.stringify(ch, null, 2).replace(/\n/g, '\n  ');
}).join(',\n');

// Find the end of CHALLENGES: '  }\n];'
const challengeEndMarker = '  }\n];';
const lastIdx = content.lastIndexOf(challengeEndMarker);
if (lastIdx === -1) {
  console.error('Could not find challengeEndMarker at end of challenges.js');
  process.exit(1);
}

content = content.slice(0, lastIdx) + '  },\n' + formattedChallenges + '\n];\n';
fs.writeFileSync(challengesFile, content, 'utf8');
console.log('Successfully appended 35 challenges to wargame/assets/challenges.js');

// 3. Add IDs to solve-derivable.js
let solveDerivableContent = fs.readFileSync(solveDerivableFile, 'utf8');
const idList = track63Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 63rd Track: ebpfruntime (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
