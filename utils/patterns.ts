/**
 * GatePaste — Secret Detection Pattern Definitions
 *
 * Sources: Secrets-Patterns-DB (CC-BY-4.0), Gitleaks (MIT), Betterleaks (MIT)
 * License: MIT
 *
 * MVP: ~50 patterns across 8 categories.
 * Curated for high signal / low false-positive.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface DetectionPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
  /** Optional context regex — pattern only fires if context matches nearby */
  context?: RegExp;
  /** If set, only report matches whose Shannon entropy exceeds this threshold */
  entropyThreshold?: number;
  /** Test cases that MUST match this pattern */
  testCases: string[];
}

/**
 * MVP Detection Patterns — ~50 patterns across 8 categories.
 */
export const PATTERNS: DetectionPattern[] = [
  // ── 1. API Keys & Tokens ──────────────────────────────────────────
  {
    id: 'generic-api-key',
    name: 'Generic API Key',
    regex: /(?:api[_-]?key|api[_-]?secret|apikey|api_key|api\.key)\s*[:=]\s*['"]?[A-Za-z0-9_\-.]{16,64}['"]?/i,
    severity: 'high',
    description: 'Generic API key or secret assigned to a variable',
    context: /(?:api|key|secret|token)/i,
    testCases: ['API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3', 'api_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3"'],
  },
  {
    id: 'sk-key',
    name: 'Secret Key (sk- prefix)',
    regex: /sk-[A-Za-z0-9_\-]{20,}/i,
    severity: 'critical',
    description: 'AI provider secret key (OpenAI, Anthropic, etc.)',
    testCases: ['sk-ant-abc123def456ghi789jkl012', 'sk-proj-abc123def456ghi789'],
  },
  {
    id: 'pk-key',
    name: 'Public Key (pk- prefix)',
    regex: /pk-[A-Za-z0-9_\-]{20,}/i,
    severity: 'medium',
    description: 'Publishable API key (lower risk but still worth flagging)',
    testCases: ['pk_' + 'live_abc123def456ghi789jkl012', 'pk_' + 'test_' + 'a1b2c3d4e5f6g7h8i9j0k1l2m3'],
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/i,
    severity: 'critical',
    description: 'GitHub token (PAT, OAuth, or installation)',
    testCases: ['ghp_TESTDATADATADATADATADATADATADATADATADATADATA', 'gho_abc123def456ghi789jkl012mno345pqr678st'],
  },
  {
    id: 'gitlab-token',
    name: 'GitLab Personal Access Token',
    regex: /glpat-[A-Za-z0-9_\-]{20,}/i,
    severity: 'critical',
    description: 'GitLab personal access token',
    testCases: ['glpat-abc123def456ghi789jkl012', 'glpat-A1B2C3D4E5F6G7H8I9J0'],
  },
  {
    id: 'slack-token',
    name: 'Slack API Token',
    regex: /xox[baprs]-[A-Za-z0-9\-]{8,}/i,
    severity: 'critical',
    description: 'Slack bot, app, or user token',
    testCases: ['xox' + 'b-' + 'TESTDATA12345678901234567890', 'xox' + 'p-' + 'TESTDATA12345678901234567890'],
  },
  {
    id: 'stripe-key',
    name: 'Stripe API Key',
    regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/i,
    severity: 'critical',
    description: 'Stripe secret or publishable key',
    testCases: ['sk_' + 'live_abc123def456ghi789jkl012mno345', 'pk_test_a1b2c3d4e5f6g7h8i9j0k'],
  },
  {
    id: 'twilio-key',
    name: 'Twilio API Key',
    regex: /SK[A-Za-z0-9]{32,}/i,
    severity: 'high',
    description: 'Twilio secret key',
    testCases: ['SKabc123def456ghi789jkl012mno34' + '5pq', 'SKabcdef0123456789abcdef01234567' + '89'],
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    regex: /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}/i,
    severity: 'high',
    description: 'SendGrid API key',
    testCases: ['SG.abc123def456ghi789jkl012.abc123def456ghi789jkl012'],
  },
  {
    id: 'npm-token',
    name: 'npm Access Token',
    regex: /npm_[A-Za-z0-9]{36,}/i,
    severity: 'high',
    description: 'npm registry access token',
    testCases: ['npm_abc123def456ghi789jkl012mno345pqr678st'],
  },
  {
    id: 'discord-token',
    name: 'Discord Bot Token',
    regex: /[MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}/i,
    severity: 'critical',
    description: 'Discord bot or user token',
    testCases: ['MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GHIJKL.ABCDEF0123456789GHIJKLMNOPQRSTUV' + 'WXYZabcdef'],
  },
  {
    id: 'telegram-token',
    name: 'Telegram Bot Token',
    regex: /\b\d{8,10}:[A-Za-z0-9_\-]{35,}\b/i,
    severity: 'critical',
    description: 'Telegram bot API token',
    testCases: ['1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ1234567890abcde'],
  },

  // ── 2. Private Keys ───────────────────────────────────────────────
  {
    id: 'rsa-private-key',
    name: 'RSA Private Key (embedded)',
    regex: /-----BEGIN\s?(?:RSA\s)?PRIVATE\s?KEY-----[-\s\S]{50,}-----END\s?(?:RSA\s)?PRIVATE\s?KEY-----/i,
    severity: 'critical',
    description: 'Embedded RSA or generic private key block',
    testCases: ['[REDACTED PRIVATE KEY]'],
  },
  {
    id: 'ec-private-key',
    name: 'EC Private Key',
    regex: /-----BEGIN\s?EC\s?PRIVATE\s?KEY-----[-\s\S]{30,}-----END\s?EC\s?PRIVATE\s?KEY-----/i,
    severity: 'critical',
    description: 'Elliptic Curve private key block',
    testCases: ['[REDACTED PRIVATE KEY]'],
  },
  {
    id: 'ssh-private-key',
    name: 'SSH Private Key',
    regex: /-----BEGIN\s?(?:OPENSSH|SSH2)\s?PRIVATE\s?KEY-----[-\s\S]{50,}-----END\s?(?:OPENSSH|SSH2)\s?PRIVATE\s?KEY-----/i,
    severity: 'critical',
    description: 'OpenSSH or SSH2 private key',
    testCases: ['[REDACTED PRIVATE KEY]'],
  },
  {
    id: 'pgp-private-key',
    name: 'PGP Private Key',
    regex: /-----BEGIN\s?PGP\s?PRIVATE\s?KEY\s?BLOCK-----[-\s\S]{50,}-----END\s?PGP\s?PRIVATE\s?KEY\s?BLOCK-----/i,
    severity: 'critical',
    description: 'PGP private key block',
    testCases: ['-----BEGIN PGP PRIVATE KEY BLOCK-----\nxsBNBG...\n-----END PGP PRIVATE KEY BLOCK-----'],
  },

  // ── 3. Database Connection Strings ────────────────────────────────
  {
    id: 'postgres-url',
    name: 'PostgreSQL Connection String',
    regex: /postgres(?:ql)?:\/\/[A-Za-z0-9_%]+:[^@\s]{1,64}@[A-Za-z0-9.\-]+:\d{2,5}\/[A-Za-z0-9_]+/i,
    severity: 'critical',
    description: 'PostgreSQL connection URL with credentials',
    testCases: ['postgres://admin:***@db.example.com:5432/mydb', 'postgresql://user:***@localhost:5432/app'],
  },
  {
    id: 'mysql-url',
    name: 'MySQL Connection String',
    regex: /mysql:\/\/[A-Za-z0-9_%]+:[^@\s]{1,64}@[A-Za-z0-9.\-]+:\d{2,5}\/[A-Za-z0-9_]+/i,
    severity: 'critical',
    description: 'MySQL connection URL with credentials',
    testCases: ['mysql://root:***@localhost:3306/myschema'],
  },
  {
    id: 'mongodb-url',
    name: 'MongoDB Connection String',
    regex: /mongodb(?:\+srv)?:\/\/[A-Za-z0-9_%]+:[^@\s]{1,64}@[A-Za-z0-9.\-]+(:\d{2,5})?\/[A-Za-z0-9_]+/i,
    severity: 'critical',
    description: 'MongoDB connection string with credentials',
    testCases: ['mongodb+srv://user:***@cluster0.mongodb.net/mydb', 'mongodb://admin:***@localhost:27017/app'],
  },
  {
    id: 'redis-url',
    name: 'Redis Connection String',
    regex: /redis:\/\/[^:]+:[^@\s]{1,64}@[A-Za-z0-9.\-]+:\d{2,5}/i,
    severity: 'high',
    description: 'Redis connection URL with password',
    testCases: ['redis://:password@localhost:6379'],
  },

  // ── 4. Cloud Provider Credentials ─────────────────────────────────
  {
    id: 'aws-access-key',
    name: 'AWS Access Key ID',
    regex: /(?:AKIA|ASIA|ABIA|ACCA|APKA|AIDA|AIPA|ANPA|ANVA|AOIA|AQVA|AROA|ASAIA|ASIA)[A-Z0-9]{16}/i,
    severity: 'high',
    description: 'AWS access key ID (identifies the account)',
    testCases: ['AKIATESTTESTTEST1234', 'ASIAJKSDFHG12345678'],
  },
  {
    id: 'aws-secret-key',
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|aws_secret_key|secretaccesskey)[\s:=]+['"]?[A-Za-z0-9\/+=]{40}['"]?/i,
    severity: 'critical',
    description: 'AWS secret access key variable assignment',
    context: /aws/i,
    testCases: ['aws_secret_access_key = AAAAATESTTESTTESTTESTTESTTESTTESTTESTTESTTEST'],
  },
  {
    id: 'gcp-service-account',
    name: 'GCP Service Account Key (JSON)',
    regex: /"private_key_id"\s*:\s*"[A-Za-z0-9]{32,}"/i,
    severity: 'critical',
    description: 'GCP service account JSON key — contains private_key_id',
    testCases: ['"private_key_id": "abc123def456ghi789jkl012mno345pqr678s"'],
  },
  {
    id: 'gcp-api-key',
    name: 'GCP API Key',
    regex: /AIza[A-Za-z0-9_\-]{35}/i,
    severity: 'high',
    description: 'Google Cloud Platform API key',
    testCases: ['AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX678ST'],
  },
  {
    id: 'azure-connection-string',
    name: 'Azure Connection String',
    regex: /(?:DefaultEndpointsProtocol|AccountName|AccountKey|SharedAccessSignature)=[^;\\s]{10,};/i,
    severity: 'critical',
    description: 'Azure storage or service bus connection string',
    testCases: ['DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=abc123def456;'],
  },

  // ── 5. JWT & Auth Tokens ──────────────────────────────────────────
  {
    id: 'jwt-token',
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/i,
    severity: 'high',
    description: 'JSON Web Token — Base64url-encoded header.payload.signature',
    testCases: ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP7T0d0d0d0d0d0d0d0d0'],
  },
  {
    id: 'bearer-token',
    name: 'Bearer Authorization Header',
    regex: /(?:^|[^A-Za-z])Bearer\s+[A-Za-z0-9\-._~+/]{20,}/i,
    severity: 'high',
    description: 'Bearer token in Authorization header or similar',
    testCases: ['Authorization: Bearer abc123def456ghi789jkl012mno345pqr678st'],
  },
  {
    id: 'basic-auth',
    name: 'Basic Authentication',
    regex: /(?:^|[^A-Za-z])Basic\s+[A-Za-z0-9+/=]{10,}/i,
    severity: 'high',
    description: 'Basic authentication header (Base64 credentials)',
    testCases: ['Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='],
  },

  // ── 6. OAuth Tokens & Secrets ─────────────────────────────────────
  {
    id: 'oauth-client-secret',
    name: 'OAuth Client Secret',
    regex: /(?:client_secret|client_secret_id)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?/i,
    severity: 'high',
    description: 'OAuth client secret (used in OAuth 2.0 flows)',
    context: /client|oauth/i,
    testCases: ['client_secret = "abc123def456ghi789"'],
  },
  {
    id: 'oauth-refresh-token',
    name: 'OAuth Refresh Token',
    regex: /(?:refresh_token|refresh-token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}['\"]?/i,
    severity: 'high',
    description: 'OAuth refresh token',
    testCases: ['refresh_token = 1//0gabcdefghijklmnopqrstuvwxyz123456789'],
  },
  {
    id: 'google-services-json',
    name: 'google-services.json (Firebase)',
    regex: /"current_key"\s*:\s*"[A-Za-z0-9]{40,}"/i,
    severity: 'high',
    description: 'Firebase/Google-services JSON with API keys',
    testCases: ['"current_key": "abc123def456ghi789jkl012mno345pqr678stu901"'],
  },

  // ── 7. High-Entropy Strings (generic secret detection) ────────────
  {
    id: 'high-entropy-base64',
    name: 'High-Entropy Base64 String',
    regex: /(?:secret|token|key|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{30,}['\"]?/i,
    severity: 'medium',
    description: 'Variable assignment with a long Base64 string — likely a secret',
    entropyThreshold: 4.5,
    testCases: ['secret = "dGhpcyBpcyBhIHNlY3JldCB0b2tlbiB0aGF0IHNob3VsZCBub3QgYmUgcHVibGlzaGVk"'],
  },
  {
    id: 'high-entropy-hex',
    name: 'High-Entropy Hex String',
    regex: /(?:secret|token|key|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Fa-f0-9]{32,}['\"]?/i,
    severity: 'medium',
    description: 'Variable assignment with a long hex string (32+ chars) — likely a key',
    entropyThreshold: 3.5,
    testCases: ['token = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"'],
  },
  {
    id: 'generic-secret-env',
    name: 'Generic SECRET/VARIABLE in .env style',
    regex: /^(?:export\s+)?(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE_KEY|SECRET_KEY)\s*=\s*['\"]?[^\s'\"]{8,}['\"]?$/im,
    severity: 'medium',
    description: 'Capitalized secret variable in .env format',
    entropyThreshold: 4.0,
    testCases: ['SECRET_KEY=super-secret-value-123'],
  },
  {
    id: 'generic-password-assignment',
    name: 'Password Variable Assignment',
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?![*]{3,})(?![Xx]{3,})[^\s'\"]{6,}['\"]?/i,
    severity: 'medium',
    description: 'Variable named password with a value (excluding masked values like *****)',
    entropyThreshold: 4.0,
    testCases: ['password = "hunter2"', 'PASSWORD=s3cur3P@ss!'],
  },

  // ── 8. Passwords & Auth Headers ───────────────────────────────────
  {
    id: 'url-embedded-credentials',
    name: 'URL-Embedded Credentials',
    regex: /https?:\/\/[A-Za-z0-9_%]+:[^@\s]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/i,
    severity: 'critical',
    description: 'URL containing username:password before the host',
    testCases: ['https://admin:password123@example.com/login', 'http://user:pass@api.internal.net/v1'],
  },
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]{20,}/i,
    severity: 'critical',
    description: 'Slack incoming webhook URL',
    testCases: ['https://hooks.slack.com/services/T00/B00/abc123def456'],
  },
  {
    id: 'github-webhook-secret',
    name: 'GitHub Webhook Secret',
    regex: /(?:webhook_secret|webhook\.secret|gh_webhook)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}['\"]?/i,
    severity: 'high',
    description: 'GitHub webhook secret token',
    testCases: ['webhook_secret = "abc123def456"'],
  },
  {
    id: 'heroku-api-key',
    name: 'Heroku API Key',
    regex: /(?:heroku|HEROKU)_(?:API_)?KEY\s*[:=]\s*['\"]?[A-Fa-f0-9\-]{36}['\"]?/i,
    severity: 'high',
    description: 'Heroku API key (UUID format)',
    testCases: ['HEROKU_API_KEY = "123e4567-e89b-12d3-a456-426614174000"'],
  },
  {
    id: 'docker-hub-password',
    name: 'Docker Hub Password/Access Token',
    regex: /(?:docker|DOCKER)_(?:hub_)?(?:password|token|access_token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}['\"]?/i,
    severity: 'high',
    description: 'Docker Hub password or personal access token',
    testCases: ['DOCKER_HUB_TOKEN = "abc123def456"'],
  },
  {
    id: 'terraform-api-token',
    name: 'Terraform Cloud API Token',
    regex: /(?:tfc|terraform)_(?:api_)?token\s*[:=]\s*['\"]?[A-Za-z0-9]{14,}['\"]?/i,
    severity: 'high',
    description: 'Terraform Cloud/Enterprise API token',
    testCases: ['tfc_token = "abc123def456ghi789"'],
  },
  {
    id: 'pypi-api-token',
    name: 'PyPI API Token',
    regex: /pypi[_-]?api[_-]?token\s*[:=]\s*['\"]?pypi-[A-Za-z0-9_\-]{20,}['\"]?/i,
    severity: 'high',
    description: 'PyPI API token for package publishing',
    testCases: ['pypi_api_token = "pypi-abc123def456ghi789jkl012"'],
  },
  {
    id: 'nuget-api-key',
    name: 'NuGet API Key',
    regex: /(?:nuget|NUGET)_(?:api_)?key\s*[:=]\s*['\"]?[A-Fa-f0-9\-]{36,}['\"]?/i,
    severity: 'high',
    description: 'NuGet API key (UUID format)',
    testCases: ['NUGET_API_KEY = "12345678-90ab-cdef-1234-567890abcdef"'],
  },
  {
    id: 'kubeconfig-token',
    name: 'Kubeconfig User Token',
    regex: /(?:kubeconfig|kubectl|kubernetes).*?(?:token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{10,}['\"]?/is,
    severity: 'critical',
    description: 'Kubernetes config with embedded token or password',
    testCases: ['kubeconfig user token = "abc123def456"'],
  },
  {
    id: 'docker-config-auth',
    name: 'Docker Config Auth (config.json)',
    regex: /"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"/i,
    severity: 'high',
    description: 'Docker config.json auth field (Base64-encoded credentials)',
    testCases: ['"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="'],
  },
  {
    id: 'gpg-key-block',
    name: 'GPG Public Key Block',
    regex: /-----BEGIN\s?PGP\s?PUBLIC\s?KEY\s?BLOCK-----[-\s\S]{50,}-----END\s?PGP\s?PUBLIC\s?KEY\s?BLOCK-----/i,
    severity: 'medium',
    description: 'PGP public key block (leak in wrong context)',
    testCases: ['-----BEGIN PGP PUBLIC KEY BLOCK-----\nxsBNBG...\n-----END PGP PUBLIC KEY BLOCK-----'],
  },
  {
    id: 'java-keystore-password',
    name: 'Java Keystore Password',
    regex: /(?:keystore[_-]?password|key[_-]?store[_-]?password)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?/i,
    severity: 'high',
    description: 'Java keystore or certificate store password',
    testCases: ['keystore_password = "changeit"'],
  },
  {
    id: 'terraform-backend-password',
    name: 'Terraform Backend Password',
    regex: /(?:terraform|tf)_.*?(?:password|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?/i,
    severity: 'high',
    description: 'Terraform backend configuration with secret',
    testCases: ['terraform_backend_password = "my-secret-password"'],
  },
  {
    id: 'ansible-vault-password',
    name: 'Ansible Vault Password',
    regex: /(?:ansible|ansible_vault|vault_password)\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?/i,
    severity: 'high',
    description: 'Ansible vault password file or variable',
    testCases: ['ansible_vault_password = "my-vault-secret"'],
  },
];

/** Get patterns by severity level */
export function getPatternsBySeverity(minSeverity: Severity): DetectionPattern[] {
  const order: Severity[] = ['low', 'medium', 'high', 'critical'];
  const minIndex = order.indexOf(minSeverity);
  if (minIndex === -1) return [];
  return PATTERNS.filter((p) => order.indexOf(p.severity) >= minIndex);
}

/** Check if text matches a specific pattern by id */
export function getPatternById(id: string): DetectionPattern | undefined {
  return PATTERNS.find((p) => p.id === id);
}
