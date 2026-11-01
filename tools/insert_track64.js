const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "c2tunnel",
    "icon": "📡",
    "ko": "C2 터널링 & 은닉 채널",
    "en": "C2 Tunneling & Covert Channels",
    "desc_ko": "DNS 터널링 Shannon 엔트로피 분석·Chisel/SSH 역방향 SOCKS5 피보팅·Malleable C2 지터 비콘 핑거프린팅·Zeek/Suricata Flowbits 인라인 DPI 방어.",
    "desc_en": "DNS tunneling Shannon entropy analysis, Chisel/SSH reverse SOCKS5 dynamic pivoting, Malleable C2 jitter beacon fingerprinting, and Zeek/Suricata flowbits inline DPI defense."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "c2tunnel"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted c2tunnel track into TRACKS array');
}

// 2. Load 35 challenges
const track64Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track64_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track64Challenges.map(ch => {
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
const idList = track64Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 64th Track: c2tunnel (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully updated wargame/scripts/solve-derivable.js with Track 64 IDs');
