# Claude API Inspector

A terminal-noir dashboard to test your Anthropic API key, fire prompts, and track live usage stats.

## Setup

### Prerequisites
- Node.js v18+ (check: `node -v`)
- npm (comes with Node)

### Install & Run

```bash
# 1. Install dependencies
npm install

# 2. Start dev server (opens at http://localhost:3000)
npm run dev
```

### Build for production
```bash
npm run build
npm run preview
```

## Features
- **API Key Validation** — tests your key with a minimal request
- **Test Request** — send prompts to Opus 4.6, Sonnet 4.6, or Haiku 4.5
- **Usage Stats** — live session token counts and USD cost breakdown per model
- **Event Log** — timestamped stream of all requests, responses, and errors

## Security
Your API key is stored only in React component state (in-memory).  
It is never saved to disk, localStorage, or sent anywhere except `api.anthropic.com`.

## Notes
- The app uses `anthropic-dangerous-direct-browser-access: true` header which is required for direct browser → Anthropic API calls
- For production use, route requests through your own backend to keep the key server-side
