# 🧅 MiseOS — Pantry → Recipes

Type what's in your kitchen, get three real recipes. The Gemini API key lives
**only** in the backend; the browser talks to your Express proxy and never
sees a secret.

```
miseos/
├── index.html            # Frontend (plain HTML/JS — no build step)
└── backend/
    ├── server.js         # Express + Gemini proxy (rate-limited, demo fallback)
    ├── package.json
    └── env.example.txt   # copy to backend/.env and add your key
```

## Run it

```bash
cd miseos/backend
npm install
cp env.example.txt .env        # then paste your real GEMINI_API_KEY into .env
npm start                      # proxy on http://localhost:3000
```

Open `http://localhost:3000` (the backend serves `index.html`). You can also
open `index.html` directly from disk — it calls the same local proxy.

## Modes

- **Live mode** — `GEMINI_API_KEY` set in `backend/.env`: real recipes from
  Gemini (`gemini-2.5-flash` by default), structured with a JSON schema.
- **Demo mode** — no key: clearly-labeled placeholder recipes so the UI works
  end to end. The status pill in the header tells you which mode you're in.

## Notes

- Rate limit: 10 synthesis requests / minute / IP (HTTP 429 after that).
- Get a key at [Google AI Studio](https://aistudio.google.com/). Keep it in
  `backend/.env` — that file is gitignored and never committed.
