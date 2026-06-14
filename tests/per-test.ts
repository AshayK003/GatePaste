import { detectSecrets } from '../utils/detector';

const tests = [
  'glpat-abc123def456ghi789jkl012',
  'sk-pro...i789',
  'ghp_ab...78st',
  'xoxb-1...7890',
  'AKIAIO...MPLE',
  'AIzaSyABC123DEF456GHI789JKL',
  'npm_ab...qr67',
  'sk_liv...mno3',
  'SKabc123def456ghi789jkl012mno345pq',
  '1234567890:***',
  'postgres://admin:***@db.example.com:5432/mydb',
  'mongodb+srv://user:***@cluster0.mongodb.net/mydb',
  'mysql://root:***@localhost:3306/myschema',
  'eyJhbG...d0d0',
  'client_secret = "abc123def456ghi789"',
  'https://admin:password123@example.com/login',
  'password = "hunter2"',
  '[REDACTED PRIVATE KEY]',
];

for (const t of tests) {
  const start = performance.now();
  const result = detectSecrets(t);
  const elapsed = performance.now() - start;
  const status = result.matched ? '✓ MATCH' : '✗ no match';
  const details = result.findings.map(f => f.patternId).join(', ');
  console.log(`${status} | ${elapsed.toFixed(2)}ms | ${t.slice(0, 50).padEnd(50)} | ${details}`);
}
console.log('DONE');
