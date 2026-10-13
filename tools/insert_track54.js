const fs = require('fs');
const path = require('path');

const challengesFile = path.join(__dirname, '../wargame/assets/challenges.js');
let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "dfir",
    "icon": "🚨",
    "ko": "엔터프라이즈 침해사고 대응 & DFIR",
    "en": "Enterprise Incident Response & DFIR",
    "desc_ko": "Sysmon 프로세스 계통·PPID 스푸핑 트리아지·NTFS $MFT 및 USN 저널 포렌식·랜섬웨어 카나리·C2 비콘 탐지 및 네트워크 격리·SOAR 불변 복구 플레이북.",
    "desc_en": "Sysmon process lineage, PPID spoofing triage, NTFS $MFT & USN journal forensics, ransomware canary analysis, C2 beacon network isolation, and SOAR immutable recovery playbooks."
  }`;

// Check if dfir track already present
if (!content.includes('"id": "dfir"')) {
  // Insert before '];\n\nconst CHALLENGES ='
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted dfir track into TRACKS array');
}

// Load 35 challenges
const newChallenges = JSON.parse(fs.readFileSync('/tmp/track54_challenges.json', 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = newChallenges.map(ch => {
  return '  ' + JSON.stringify(ch, null, 2).replace(/\n/g, '\n  ');
}).join(',\n');

// Find the end of CHALLENGES: '  }\n];\n'
const challengeEndMarker = '  }\n];';
const lastIdx = content.lastIndexOf(challengeEndMarker);
if (lastIdx === -1) {
  console.error('Could not find challengeEndMarker at end of file');
  process.exit(1);
}

content = content.slice(0, lastIdx) + '  },\n' + formattedChallenges + '\n];\n';
fs.writeFileSync(challengesFile, content, 'utf8');
console.log('Successfully appended 35 challenges to wargame/assets/challenges.js');
