const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "extsec",
    "icon": "🧩",
    "ko": "브라우저 확장 프로그램 보안 & Manifest V3",
    "en": "Browser Extension Security & Manifest V3",
    "desc_ko": "Manifest V3 권한 명세 및 백그라운드 서비스 워커 감사·Web Accessible Resources(WAR) 토큰 유출·Content Script DOM innerHTML XSS 및 패스워드 스니핑·Declarative Net Request(DNR) 및 확장 CSP 하드닝.",
    "desc_en": "Manifest V3 permission & service worker auditing, Web Accessible Resources (WAR) secret leakage, Content Script DOM innerHTML XSS & credential sniffing, and Declarative Net Request (DNR) CSP hardening."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "extsec"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted extsec track into TRACKS array');
}

// 2. Load 35 challenges
const track58Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track58_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track58Challenges.map(ch => {
  return '  ' + JSON.stringify(ch, null, 2).replace(/\n/g, '\n  ');
}).join(',\n');

// Find the end of CHALLENGES: '  }\n];\n' or '  }\n];'
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
const idList = track58Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 58th Track: extsec (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
