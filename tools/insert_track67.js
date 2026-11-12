const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "pqcmigrate",
    "icon": "⚛️",
    "ko": "PQC 양자 내성 암호 마이그레이션 & FIPS 203/204",
    "en": "PQC Migration & FIPS 203/204",
    "desc_ko": "NIST FIPS 203 ML-KEM-768 격자 KEM·FIPS 204 ML-DSA-65 전자서명·SNDL 수집 도청 대응·하이브리드 TLS 1.3 다운그레이드 방어·암호 민첩성(Crypto-Agility) 검증.",
    "desc_en": "NIST FIPS 203 ML-KEM-768 Lattice KEM, FIPS 204 ML-DSA-65 digital signatures, SNDL eavesdropping defense, Hybrid TLS 1.3 anti-downgrade controls, and crypto-agility verification."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "pqcmigrate"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted pqcmigrate track into TRACKS array');
}

// 2. Load 35 challenges
const track67Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track67_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track67Challenges.map(ch => {
  return '  ' + JSON.stringify(ch, null, 2).replace(/\n/g, '\n  ');
}).join(',\n');

// 3. Append to CHALLENGES at the very end of file
content = content.trimEnd();
if (content.endsWith('];')) {
  content = content.slice(0, -2).trimEnd() + ',\n' + formattedChallenges + '\n];\n';
} else {
  console.error('File does not end with ];');
  process.exit(1);
}

fs.writeFileSync(challengesFile, content, 'utf8');
console.log('Successfully appended 35 challenges for Track 67 to wargame/assets/challenges.js');
