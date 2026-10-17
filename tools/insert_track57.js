const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "cloudir",
    "icon": "☁️",
    "ko": "클라우드 사고 대응 & 침해 위협 헌팅",
    "en": "Cloud Incident Response & Threat Hunting",
    "desc_ko": "CloudTrail 관리 감사 로그 분석·STS 임시 자격증명 유출 및 S3 포렌식·VPC Flow Logs C2 비콘 상관분석·GuardDuty 및 SOAR 자동 봉쇄.",
    "desc_en": "CloudTrail management audit analysis, STS temporary credential theft & S3 forensics, VPC Flow Logs C2 beacon correlation, and GuardDuty SOAR containment."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "cloudir"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted cloudir track into TRACKS array');
}

// 2. Load 35 challenges
const track57Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track57_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track57Challenges.map(ch => {
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
const idList = track57Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 57th Track: cloudir (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
