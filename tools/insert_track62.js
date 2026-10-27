const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "sansdfir",
    "icon": "🔍",
    "ko": "SANS DFIR 아티팩트 헌팅 & 타임라인",
    "en": "SANS DFIR Artifact Hunting & Timeline",
    "desc_ko": "SANS FOR508/572 실행 흔적(PECmd/ShimCache)·$MFT/USN 저널 카빙·Volatility 3 DKOM & VAD 인젝션 트리아지·Supertimeline SOAR 격리.",
    "desc_en": "SANS FOR508/572 Evidence of Execution (PECmd/ShimCache), $MFT/USN journal carving, Volatility 3 DKOM & VAD injection, and Supertimeline SOAR containment."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "sansdfir"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted sansdfir track into TRACKS array');
}

// 2. Load 35 challenges
const track62Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track62_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track62Challenges.map(ch => {
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
const idList = track62Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 62nd Track: sansdfir (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
