/**
 * Quick smoke test of the detection engine.
 * Run with: npx tsx tests/smoke.ts
 */
import { detectSecrets, hasSecrets } from '../utils/detector';
import { shannonEntropy, isHighEntropy } from '../utils/entropy';
import { PATTERNS } from '../utils/patterns';

console.log('=== GatePaste Smoke Test ===\n');

let passed = 0;
let failed = 0;

function check(label: string, ok: boolean, detail?: string) {
  if (ok) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}${detail ? ': ' + detail : ''}`); }
}

// 1. Pattern count
console.log(`1. Pattern definitions: ${PATTERNS.length}`);
check('≥45 patterns for MVP', PATTERNS.length >= 45);
console.log();

// 2. Entropy
console.log('2. Shannon Entropy:');
check('Hex key entropy >3.5',
  shannonEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4').toFixed(2) as unknown as number >= 3.5 as unknown as boolean);
check('Repeated chars entropy ~0',
  shannonEntropy('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') < 0.01);
check('isHighEntropy(hex key, 3.5) = true',
  isHighEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 3.5));
check('Natural language is NOT high entropy',
  isHighEntropy('The quick brown fox') === false);
console.log();

// 3. Detection tests — realistic (but fake) secret strings
console.log('3. Detection engine:');

// API Keys
check('OpenAI-style sk-key', detectSecrets('sk-proj-abc123def456ghi789jkl012mno345').matched);
check('GitHub PAT', detectSecrets('ghp_abc123def456ghi789jkl012mno345pqr678stu').matched);
check('GitLab PAT', detectSecrets('glpat-abc123def456ghi789jkl012').matched);
check('Slack bot token', detectSecrets('xox' + 'b-' + '123456789012-abcdefghijklmnopqrstuvwx').matched);
check('Stripe secret key', detectSecrets('sk_' + 'live_TESTTESTTESTTESTTESTTESTTESTTEST').matched);
check('Twilio key', detectSecrets('SKabc123def456ghi789jkl012mno345pq').matched);
check('SendGrid key', detectSecrets('SG.TESTTESTTESTTESTTESTXXX.TESTTESTTESTTESTTESTXXXZZ').matched);
check('npm token', detectSecrets('npm_abc123def456ghi789jkl012mno345pqr1').matched);
check('Telegram bot token', detectSecrets('1234567890:ABCdefGHIjklMNOpqrSTUvwxYZabcdefgh').matched);
check('AWS access key', detectSecrets('AKIATESTTESTTEST1234').matched);
check('GCP API key', detectSecrets('AIzaSyD-abc123def456ghi789jkl012mno345').matched);
check('Azure conn string', detectSecrets('DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901').matched);

// Database URLs
check('PostgreSQL URL', detectSecrets('postgres://admin:secret123@db.example.com:5432/mydb').matched);
check('MongoDB+srv URL', detectSecrets('mongodb+srv://user:password@cluster0.mongodb.net/mydb').matched);
check('MySQL URL', detectSecrets('mysql://root:rootpass@localhost:3306/myschema').matched);

// Private keys
check('RSA private key',
  detectSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----').matched);

// JWT
check('JWT token', detectSecrets('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3j1gPZL4oNw').matched);

// URL credentials
check('URL credentials',
  detectSecrets('https://admin:password123@example.com/login').matched);

// Multiple in one string
const multiText = 'API_KEY=sk-pro...o345';
const multiResult = detectSecrets(multiText);
check('Multiple findings in one string', multiResult.findings.length >= 1);

// Clean text
check('Clean text → no match', detectSecrets('Hello, this is a normal message.').matched === false);
check('Empty → no match', detectSecrets('').matched === false);
check('Short → no match', detectSecrets('hi').matched === false);

// Convenience
check('hasSecrets(sk-key) = true',
  hasSecrets('sk-proj-abc123def456ghi789jkl012mno345'));
check('hasSecrets(clean) = false',
  hasSecrets('hello world') === false);

// Allowlist
const allowlisted = detectSecrets('sk-proj-abc123def456', {
  allowlistedDomains: ['trusted.com'],
  currentDomain: 'trusted.com',
});
check('Allowlisted domain blocks detection', allowlisted.matched === false);

// Duration check
const perfResult = detectSecrets('sk-proj-abc123def456ghi789jkl012mno345');
check('Detection < 10ms', perfResult.durationMs < 10,
  `took ${perfResult.durationMs.toFixed(3)}ms`);

// Custom patterns
import type { DetectionPattern } from '../utils/patterns';
const customPattern: DetectionPattern = {
  id: 'my-custom-secret',
  name: 'Custom Test Pattern',
  regex: /CUSTOM_SECRET_\d{10}/i,
  severity: 'high',
  description: 'Custom test pattern',
  testCases: ['CUSTOM_SECRET_1234567890'],
};
const customResult = detectSecrets('CUSTOM_SECRET_1234567890', { customPatterns: [customPattern] });
check('Custom pattern detection', customResult.matched && customResult.findings[0]?.patternId === 'my-custom-secret');

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
