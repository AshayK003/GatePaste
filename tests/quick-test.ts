import { detectSecrets } from '../utils/detector';
import { PATTERNS } from '../utils/patterns';

console.log(`Testing ${PATTERNS.length} patterns...`);

// Check s flag patterns
const sFlagPatterns = PATTERNS.filter(p => {
  const flags = p.regex.flags;
  return flags.includes('s');
});
console.log('s-flag patterns:', sFlagPatterns.map(p => `${p.id} (${p.regex.flags})`).join(', '));

const text = 'sk-pro...o345';
console.log('\nTesting:', JSON.stringify(text));
const start = performance.now();
const result = detectSecrets(text);
const elapsed = performance.now() - start;
console.log('Duration:', elapsed.toFixed(2), 'ms');
console.log('Matched:', result.matched);
console.log('Findings:', result.findings.length);
if (result.findings.length > 0) {
  console.log('First:', result.findings[0].patternId, result.findings[0].patternName);
}
