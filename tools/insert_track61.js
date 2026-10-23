const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const challengesFile = path.join(ROOT, 'wargame/assets/challenges.js');
const solveDerivableFile = path.join(ROOT, 'wargame/scripts/solve-derivable.js');

let content = fs.readFileSync(challengesFile, 'utf8');

const newTrack = `  {
    "id": "agentmcp",
    "icon": "🤖",
    "ko": "AI 에이전트 & MCP 보안",
    "en": "AI Agent & MCP Security",
    "desc_ko": "간접 프롬프트 주입(IPI)·MCP 툴 섀도잉 및 포이즈닝·Confused Deputy 권한 상승·Dual LLM 가드레일 및 Landlock 샌드박싱.",
    "desc_en": "Indirect Prompt Injection (IPI), MCP tool shadowing, Confused Deputy escalation, Dual LLM guardrails, and Landlock sandboxing."
  }`;

// 1. Insert Track into TRACKS array
if (!content.includes('"id": "agentmcp"')) {
  const trackEndMarker = '  }\n];\n\nconst CHALLENGES = [';
  if (!content.includes(trackEndMarker)) {
    console.error('Could not find trackEndMarker in challenges.js');
    process.exit(1);
  }
  content = content.replace(trackEndMarker, '  },\n' + newTrack + '\n];\n\nconst CHALLENGES = [');
  console.log('Inserted agentmcp track into TRACKS array');
}

// 2. Load 35 challenges
const track61Challenges = JSON.parse(fs.readFileSync(path.join(__dirname, 'track61_challenges.json'), 'utf8'));

// Format challenges nicely with 2 spaces indent
const formattedChallenges = track61Challenges.map(ch => {
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
const idList = track61Challenges.map(ch => `  "${ch.id}"`).join(',\n');
const insertBlock = `,\n  // 61st Track: agentmcp (35 challenges)\n${idList}\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;

const targetMarker = `\n];\n\nfor (const id of DROIDPWN_WINCLIENT_IDS)`;
if (!solveDerivableContent.includes(targetMarker)) {
  console.error('Could not find DROIDPWN_WINCLIENT_IDS targetMarker in solve-derivable.js');
  process.exit(1);
}

solveDerivableContent = solveDerivableContent.replace(targetMarker, insertBlock);
fs.writeFileSync(solveDerivableFile, solveDerivableContent, 'utf8');
console.log('Successfully appended 35 IDs to solve-derivable.js');
