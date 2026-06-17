# GatePaste 🔒

**Detect secrets in your clipboard before you paste into web forms.**

GatePaste is a browser extension that runs a 50+ pattern detection engine on every paste event, with Shannon entropy verification to reduce false positives. If it finds an API key, private key, database connection string, or other credential, it warns you with a clean overlay before the data reaches the form field.

## Why GatePaste?

- 🛡️ **Prevent accidental exposure** — don't paste `AWS_SECRET_ACCESS_KEY` into a GitHub issue or `sk-proj-*` into a ChatGPT prompt
- ⚡ **~1ms detection** — 50+ regex patterns run in under 2ms, with entropy verification on generic patterns. Config cached in-memory after first paste
- 🔒 **Privacy-first** — clipboard content never leaves your device. All detection is local
- 🎨 **Sleek overlay** — Shadow DOM isolated warning card with mask / raw / cancel options, Escape key support, "Don't ask again" per-domain opt-out
- ⚙️ **Configurable** — per-domain rules (exact + subdomain matching, no substring false positives), sensitivity levels, audit log
- ♿ **Accessible** — keyboard focus indicators, WCAG AA contrast, screen reader compatible

## Quick Start

```bash
# Install dependencies
npm install

# Build the extension
npm run build

# Output is in dist/ — load as unpacked extension in Chrome
```

**Load in Chrome:**
1. Go to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" → select `dist/`

## Project Structure

```
GatePaste/
├── entrypoints/
│   ├── background.ts        # Service worker — message routing, lifecycle
│   ├── content.ts           # Paste interception + overlay trigger
│   ├── popup/               # Browser action popup UI
│   └── options/             # Settings page
├── utils/
│   ├── detector.ts          # Detection engine — regex patterns + entropy verification
│   ├── entropy.ts           # Shannon entropy calculator
│   ├── patterns.ts          # 50+ secret patterns (8 categories)
│   ├── overlay.ts           # Shadow DOM warning overlay (Escape to close, domain opt-out)
│   └── storage.ts           # chrome.storage wrapper (config → sync, audit log → local)
├── public/icons/            # Extension icons (SVG)
├── tests/                   # Unit tests (Vitest)
├── scripts/                 # Build helpers
└── .github/workflows/       # CI pipeline
```

## Architecture

**Storage:** Config and domain rules sync across devices via `chrome.storage.sync`. Audit log uses `chrome.storage.local` to avoid the 102KB sync quota limit.

**Config cache:** Content script caches config in memory after first fetch. Cache is invalidated on storage changes — subsequent pastes skip the service worker message round-trip.

**Domain matching:** Rules use exact match or subdomain suffix (`.endsWith('.' + domain)`) — never substring `includes()`, which could match unintended domains like `evil-example.com` for a rule targeting `example.com`.

## Detection Engine

**50+ patterns across 8 categories:**

| Category | Examples | Count |
|---|---|---|
| API Keys & Tokens | OpenAI `sk-*`, GitHub `ghp_*`, Stripe, Slack, Discord, Telegram | ~15 |
| Private Keys | RSA, EC, SSH, PGP | ~5 |
| Database URLs | PostgreSQL, MySQL, MongoDB, Redis | ~4 |
| Cloud Provider | AWS keys, GCP keys/service accounts, Azure | ~5 |
| JWT & Auth Tokens | JWT, Bearer, Basic Auth | ~3 |
| OAuth Secrets | Client secrets, refresh tokens, Firebase | ~3 |
| High-Entropy Strings | Base64, hex, .env style | ~5 |
| Passwords & Headers | URL credentials, webhooks, Docker, Terraform, kubeconfig | ~10 |

Built with regex patterns sourced from [Secrets-Patterns-DB](https://github.com/mazen160/secrets-patterns-db) (CC-BY-4.0) and [Gitleaks](https://github.com/gitleaks/gitleaks) (MIT).

## Development

```bash
# Watch mode (auto-rebuilds on changes)
npm run dev

# Type check
npm run compile

# Lint & format
npm run lint
npm run format

# Run tests
npm test             # single run
npm run test:watch   # watch mode
```

### Adding patterns

Edit `utils/patterns.ts` — add a new entry to the `PATTERNS` array with:
- `id` — unique kebab-case identifier
- `name` — human-readable name
- `regex` — detection regex (must include `i` flag)
- `severity` — one of `low`, `medium`, `high`, `critical`
- `entropyThreshold` — optional; if set, only reports matches whose Shannon entropy exceeds this value (reduces false positives on generic patterns)
- `testCases` — array of strings that should match (used in tests)

Then add corresponding tests in `tests/detector.test.ts`.

## Tech Stack

- **[WXT](https://wxt.dev)** — Next-gen web extension framework (Vite + Manifest V3)
- **TypeScript** — Full type safety
- **Vitest** — Unit tests
- **Biome** — Linting & formatting
- **[ReCheck](https://recheck.dev)** — Regex security audit (CI)

## License

MIT — see [LICENSE](LICENSE).

---

*GatePaste — Because you only leak production keys once.*
