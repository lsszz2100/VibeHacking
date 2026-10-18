const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "pqc",
    "icon": "⚛️",
    "ko": "양자 내성 암호 & PQC 마이그레이션",
    "en": "Post-Quantum Cryptography & PQC Migration",
    "desc_ko": "쇼어 알고리즘 HNDL 위협·격자 기반 암호학(LWE/Module-LWE)·NIST FIPS 203(ML-KEM) 및 FIPS 204(ML-DSA)·TLS 1.3 하이브리드 KEM 및 부채널 공격 방어.",
    "desc_en": "Shor's algorithm HNDL threats, lattice cryptography (LWE/Module-LWE), NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA), TLS 1.3 hybrid KEM, and side-channel countermeasures."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "pqc"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted pqc track into TRACKS array');
}

// 2. Load 35 challenges
const track59Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track59_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track59Challenges.map(ch => {
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
const idList = track59Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 59th Track: pqc (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
