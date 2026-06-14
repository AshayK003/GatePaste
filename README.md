# GatePaste 🔒

**Detect secrets in your clipboard before you paste into web forms.**

GatePaste is a browser extension that runs a 50+ pattern detection engine on every paste event. If it finds an API key, private key, database connection string, or other credential, it warns you with a clean overlay before the data reaches the form field.

## Why GatePaste?

- 🛡️ **Prevent accidental exposure** — don't paste `AWS_SECRET_ACCESS_KEY` into a GitHub issue or `sk-proj-*` into a ChatGPT prompt
- ⚡ **~1ms detection** — 50+ regex patterns run in under 2ms, no perceptible lag
- 🔒 **Privacy-first** — clipboard content never leaves your device. All detection is local
- 🎨 **Sleek overlay** — Shadow DOM isolated warning card with mask / raw / cancel options
- ⚙️ **Configurable** — per-domain rules, sensitivity levels, audit log

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
│   ├── detector.ts          # Detection engine — runs 50+ regex patterns
│   ├── entropy.ts           # Shannon entropy calculator
│   ├── patterns.ts          # 50+ secret patterns (8 categories)
│   ├── overlay.ts           # Shadow DOM warning overlay
│   └── storage.ts           # chrome.storage wrapper
├── public/icons/            # Extension icons (SVG)
├── tests/                   # Unit tests (Vitest)
├── scripts/                 # Build helpers
└── .github/workflows/       # CI pipeline
```

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
