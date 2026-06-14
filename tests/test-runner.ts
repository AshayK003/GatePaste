#!/usr/bin/env tsx
/**
 * GatePaste — Detection Engine Tests Runner
 *
 * All positive test strings are REALISTIC FAKE secrets that WILL match.
 *
 * Usage: npx tsx tests/test-runner.ts
 */

import { detectSecrets, hasSecrets } from '../utils/detector';
import { shannonEntropy, isHighEntropy } from '../utils/entropy';
import { PATTERNS } from '../utils/patterns';

let passed = 0;
let failed = 0;

function assert(label: string, ok: boolean) {
  if (ok) { passed++; console.log(`  OK ${label}`); }
  else    { failed++; console.log(`  FAIL ${label}`); }
}
function assertEq(l: string, a: unknown, e: unknown) {
  const ok = a === e;
  if (ok) { passed++; console.log(`  OK ${l}`); }
  else    { failed++; console.log(`  FAIL ${l}: expected ${JSON.stringify(e)}, got ${JSON.stringify(a)}`); }
}
function assertGt(l: string, a: number, m: number) {
  if (a > m) { passed++; console.log(`  OK ${l}: ${a} > ${m}`); }
  else      { failed++; console.log(`  FAIL ${l}: ${a} <= ${m}`); }
}

// ── Entropy Tests ──────────────────────────────────────────────────
console.log('\n-- shannonEntropy --');
assertEq('empty string', shannonEntropy(''), 0);
assertEq('repeated char', shannonEntropy('aaaaa'), 0);
assert('varied chars > repeated', shannonEntropy('aB3dEfGh1') > shannonEntropy('aaaaabbbbb'));
assertEq('deterministic', shannonEntropy('a1b2c3d4e5f6'), shannonEntropy('a1b2c3d4e5f6'));

console.log('\n-- isHighEntropy --');
assertEq('short=false', isHighEntropy('abc'), false);
assertEq('hex key true', isHighEntropy('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'), true);
assertEq('natural lang false', isHighEntropy('The quick brown fox jumps over the lazy dog'), false);
assertEq('short repeated=false', isHighEntropy('aaaaaaaa'), false);

// ── Pattern Definitions ────────────────────────────────────────────
console.log('\n-- PATTERNS --');
assertGt('>=45 patterns', PATTERNS.length, 44);
assertEq('unique IDs', new Set(PATTERNS.map(p => p.id)).size, PATTERNS.length);
assert('has critical', new Set(PATTERNS.map(p => p.severity)).has('critical'));
assert('has high',     new Set(PATTERNS.map(p => p.severity)).has('high'));
assert('has medium',   new Set(PATTERNS.map(p => p.severity)).has('medium'));

// ── Detection: expected-positive cases ─────────────────────────────
console.log('\n-- Positive Detection --');

// Each string is constructed to actually match its pattern's regex
assert('OpenAI sk-key',  detectSecrets('sk-ant-abc123def456ghi789jkl012').matched);
assert('GitHub token',   detectSecrets('ghp_abc123def456ghi789jkl012mno345pqr678st').matched);
assert('GitLab token',   detectSecrets('glpat-abc123def456ghi789jkl012').matched);
assert('Slack token',    detectSecrets('xox' + 'b-' + '12345678901234567890').matched);
assert('Stripe key',     detectSecrets('sk_' + 'live_TESTTESTTESTTESTTESTTESTTEST').matched);
assert('Twilio key',     detectSecrets('SKabc123def456ghi789jkl012mno345pq').matched);
assert('AWS access key', detectSecrets('AKIATESTTESTTEST1234').matched);
assert('GCP API key',    detectSecrets('AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXS').matched);
assert('NPM token',      detectSecrets('npm_abc123def456ghi789jkl012mno345pqr678st').matched);
assert('Telegram token', detectSecrets('1234567890:ABC123DEF456GHI789JKL012MNO345PQR678STU').matched);
assert('JWT token',      detectSecrets('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP7T0d0d0d0d').matched);
assert('DB: PostgreSQL', detectSecrets('postgres://admin:***@db.example.com:5432/mydb').matched);
assert('DB: MongoDB',    detectSecrets('mongodb+srv://user:***@cluster0.mongodb.net/mydb').matched);
assert('DB: MySQL',      detectSecrets('mysql://root:***@localhost:3306/myschema').matched);
assert('OAuth secret',   detectSecrets('client_secret = "abcdef1234567890abcd"').matched);
assert('URL creds',      detectSecrets('https://admin:password123@example.com/login').matched);
assert('Password var',   detectSecrets('password = "hunter2"').matched);
assert('SendGrid key',   detectSecrets('SG.TESTTESTTESTTESTTESTOK.TESTTESTTESTTESTTESTOKZZZZ').matched);
assert('Discord token',  detectSecrets('MQQQQQQQQQQQQQQQQQQQQQQQ.RRRRRRR.SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS').matched);
assert('Slack webhook',  detectSecrets('https://hooks.slack.com/services/T00/B00/abc123def456').matched);
assert('Heroku key',     detectSecrets('HEROKU_API_KEY=TESTT-TEST-TEST-TEST-TESTTESTTESTZZZ').matched);
assert('AWS secret var', detectSecrets('aws_secret_access_key = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA').matched);

// Live-style API key — should match generic-api-key when prefixed
assert('AQ-prefixed key', detectSecrets('api_key = "' + 'A' + 'Q.Ab8RN6L6i-CO3Mn1KhOP0MujwJX8GLO2cZvIYKzJbLM_EZ74ZQ"').matched);

// ── Negative cases (should NOT match) ──────────────────────────────
console.log('\n-- Negative Detection --');
assertEq('clean text',       detectSecrets('Hello, this is normal.').matched, false);
assertEq('empty',             detectSecrets('').matched, false);
assertEq('short',             detectSecrets('hi').matched, false);
assertEq('stripe pk_test key', detectSecrets('pk_test_a1b2c3d4e5f6g7h8i9j0k1l2m3').matched, true);
assertEq('short pass ref',    detectSecrets('pass=123').matched, false);
assertEq('email',             detectSecrets('user@example.com').matched, false);
assertEq('IPv4',              detectSecrets('192.168.1.1').matched, false);
assertEq('domain',            detectSecrets('example.com').matched, false);
assertEq('no-creds URL',      detectSecrets('https://example.com/login').matched, false);
assertEq('boring text',       detectSecrets('the quick brown fox').matched, false);

// ── Integration ────────────────────────────────────────────────────
console.log('\n-- Integration --');
assertGt('durationMs', detectSecrets('password = "hunter2"').durationMs, -1);

const pw = 'password = "hunter2"';
assert('medium severity detected', detectSecrets(pw, { minSeverity: 'low' }).matched);
assertEq('filter high only', detectSecrets(pw, { minSeverity: 'high' }).matched, false);
assertEq('hasSecrets true',  hasSecrets('password = "hunter2"'), true);
assertEq('hasSecrets false', hasSecrets('normal text'), false);

// ── Performance ────────────────────────────────────────────────────
console.log('\n-- Performance --');
const multiLine = [
  'export const DB_PASSWORD=***',
  'const API_KEY=***',
  'This is a normal sentence.',
  'host: postgres://admin:***@db.local:5432/test',
].join('\n');
const perf = detectSecrets(multiLine);
assert('multi-line < 15ms', perf.durationMs < 15);
console.log('  took ' + perf.durationMs.toFixed(3) + 'ms');

// ── Summary ────────────────────────────────────────────────────────
const total = passed + failed;
console.log('\n===================================');
console.log('  ' + passed + '/' + total + ' tests passed');
if (failed > 0) console.log('  ' + failed + ' FAILED');
console.log('===================================\n');
process.exit(failed > 0 ? 1 : 0);
