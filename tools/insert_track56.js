const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "serverless",
    "icon": "⚡",
    "ko": "서버리스 클라우드 보안 & 이벤트 인젝션",
    "en": "Serverless Security & Cloud Event Injection",
    "desc_ko": "S3 ObjectCreated 이벤트 인젝션 RCE·웜 컨테이너 /tmp 영속성 및 세션 토큰 탈취·과도한 IAM 실행 역할 sts:AssumeRole 권한 상승·불변 루트 FS 및 최소 권한 런타임 하드닝.",
    "desc_en": "S3 ObjectCreated event injection RCE, warm container /tmp persistence & session token carving, overprivileged IAM execution role sts:AssumeRole escalation, and immutable runtime hardening."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "serverless"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted serverless track into TRACKS array');
}

// 2. Load 35 challenges
const track56Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track56_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track56Challenges.map(ch => {
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
const idList = track56Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 56th Track: serverless (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
