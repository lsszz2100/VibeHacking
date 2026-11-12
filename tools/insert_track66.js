const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "agentsandbox",
    "icon": "🤖",
    "ko": "AI 에이전트 탈출 & Landlock 샌드박스",
    "en": "AI Agent Sandbox Escape & Landlock LSM Defense",
    "desc_ko": "MCP 도구 포이즈닝·Confused Deputy 권한 탈취·서브프로세스 셸 탈출·Linux Landlock LSM 비특권 파일 격리·eBPF 듀얼 LLM 런타임 방어.",
    "desc_en": "MCP tool poisoning, Confused Deputy privilege hijacking, subprocess shell escape, Linux Landlock LSM unprivileged sandboxing, and eBPF dual-LLM runtime defense."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "agentsandbox"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted agentsandbox track into TRACKS array');
}

// 2. Load 35 challenges
const track66Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track66_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track66Challenges.map(ch => {
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
console.log('Successfully appended 35 challenges to wargame/assets/challenges.js');
