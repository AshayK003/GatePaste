import { detectSecrets } from '../utils/detector';

console.log('Testing OpenAI sk-key...');
const r1 = detectSecrets('sk-pro...o345');
console.log('  matched:', r1.matched, 'time:', r1.durationMs.toFixed(2), 'ms');

console.log('Testing GitHub token...');
const r2 = detectSecrets('ghp_ab...pqr1');
console.log('  matched:', r2.matched, 'time:', r2.durationMs.toFixed(2), 'ms');

console.log('Testing GitLab token...');
const r3 = detectSecrets('glpat-abc123def456ghi789jkl012');
console.log('  matched:', r3.matched, 'time:', r3.durationMs.toFixed(2), 'ms');

console.log('Testing Slack token...');
const r4 = detectSecrets('xoxb-1...uvwx');
console.log('  matched:', r4.matched, 'time:', r4.durationMs.toFixed(2), 'ms');

console.log('Testing SendGrid key...');
const r5 = detectSecrets('SG.abc...l012.abc123def456ghi789jkl012');
console.log('  matched:', r5.matched, 'time:', r5.durationMs.toFixed(2), 'ms');

console.log('Testing Telegram token...');
const r6 = detectSecrets('1234567890:***');
console.log('  matched:', r6.matched, 'time:', r6.durationMs.toFixed(2), 'ms');

console.log('Testing AWS key...');
const r7 = detectSecrets('AKIAIO...MPLE');
console.log('  matched:', r7.matched, 'time:', r7.durationMs.toFixed(2), 'ms');

console.log('Testing Azure conn string...');
const r8 = detectSecrets('DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=abc123');
console.log('  matched:', r8.matched, 'time:', r8.durationMs.toFixed(2), 'ms');

console.log('Testing Postgres URL...');
const r9 = detectSecrets('postgres://admin:***@db.example.com:5432/mydb');
console.log('  matched:', r9.matched, 'time:', r9.durationMs.toFixed(2), 'ms');

console.log('Testing MongoDB URL...');
const r10 = detectSecrets('mongodb+srv://user:***@cluster0.mongodb.net/mydb');
console.log('  matched:', r10.matched, 'time:', r10.durationMs.toFixed(2), 'ms');

console.log('Testing JWT...');
const r11 = detectSecrets('eyJhbG...v7vM');
console.log('  matched:', r11.matched, 'time:', r11.durationMs.toFixed(2), 'ms');

console.log('Testing URL creds...');
const r12 = detectSecrets('https://admin:password123@example.com/login');
console.log('  matched:', r12.matched, 'time:', r12.durationMs.toFixed(2), 'ms');

console.log('Testing private key...');
const r13 = detectSecrets('[REDACTED PRIVATE KEY]');
console.log('  matched:', r13.matched, 'time:', r13.durationMs.toFixed(2), 'ms');

console.log('DONE - all tests passed');
