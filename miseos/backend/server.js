/**
 * MiseOS backend — Express + Google Gemini recipe synthesis proxy.
 *
 * The browser never sees the API key: it POSTs a pantry list here, this
 * server calls Gemini with the key from .env, and returns structured
 * recipes. Without a key configured the server degrades to a clearly
 * labeled local "demo mode" so the UI still works end to end.
 */
"use strict";

const path = require("path");
const express = require("express");
const { GoogleGenAI } = require("@google/genai");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "32kb" }));

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0"; // 0.0.0.0 so managed previews can reach it
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
const GEMINI_TIMEOUT_MS = Number(process.env.GEMINI_TIMEOUT_MS) || 45000;

const ai = GEMINI_API_KEY ? new GoogleGenAI({ apiKey: GEMINI_API_KEY }) : null;

// ---------------------------------------------------------------------------
// Tiny middleware
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
  next();
});

// Minimal per-IP rate limit (10 requests / minute / IP on synthesis).
const hits = new Map();
function rateLimit(req, res, next) {
  const key = req.ip || "unknown";
  const now = Date.now();
  const window = (hits.get(key) || []).filter((t) => now - t < 60_000);
  if (window.length >= 10) {
    return res.status(429).json({ error: "Slow down — try again in a minute." });
  }
  window.push(now);
  hits.set(key, window);
  if (hits.size > 5000) hits.clear(); // keep the map bounded
  next();
}

// ---------------------------------------------------------------------------
// Recipe synthesis
// ---------------------------------------------------------------------------
const RECIPE_SCHEMA = {
  type: "object",
  properties: {
    recipes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          description: { type: "string" },
          cuisine: { type: "string" },
          difficulty: { type: "string" },
          prepMinutes: { type: "integer" },
          cookMinutes: { type: "integer" },
          servings: { type: "integer" },
          ingredients: {
            type: "array",
            items: {
              type: "object",
              properties: { item: { type: "string" }, amount: { type: "string" } },
              required: ["item", "amount"],
            },
          },
          steps: { type: "array", items: { type: "string" } },
          tips: { type: "array", items: { type: "string" } },
        },
        required: ["name", "description", "ingredients", "steps"],
      },
    },
  },
  required: ["recipes"],
};

function buildPrompt(ingredients, opts) {
  return [
    "You are MiseOS, a resourceful line cook. Create exactly 3 distinct recipes",
    "that a home cook can make primarily from this pantry:",
    ingredients.map((i) => `- ${i}`).join("\n"),
    opts.cuisine && opts.cuisine !== "any" ? `Cuisine direction: ${opts.cuisine}.` : "",
    opts.diet && opts.diet !== "none" ? `Dietary constraint: ${opts.diet}.` : "",
    `Servings: ${opts.servings}.`,
    "",
    "Rules: assume basic staples exist (salt, pepper, cooking oil, water).",
    "If a recipe needs 1-2 extra store items, that is fine — list them.",
    "Keep steps numbered, concrete, and safe (cook temps, doneness cues).",
    "Vary the cooking methods across the three recipes (e.g. skillet, oven, simmer).",
  ]
    .filter(Boolean)
    .join("\n");
}

async function synthesizeWithGemini(ingredients, opts) {
  const withTimeout = Promise.race([
    ai.models.generateContent({
      model: GEMINI_MODEL,
      contents: buildPrompt(ingredients, opts),
      config: {
        temperature: 0.9,
        responseMimeType: "application/json",
        responseSchema: RECIPE_SCHEMA,
      },
    }),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Gemini timed out")), GEMINI_TIMEOUT_MS)
    ),
  ]);

  const result = await withTimeout;
  const parsed = JSON.parse(result.text);
  const recipes = Array.isArray(parsed.recipes) ? parsed.recipes : null;
  if (!recipes || recipes.length === 0) throw new Error("Model returned no recipes");
  return recipes.slice(0, 3);
}

// ---------------------------------------------------------------------------
// Demo fallback (no API key configured) — deterministic, clearly labeled
// ---------------------------------------------------------------------------
function hash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function demoRecipes(ingredients, opts) {
  const list = ingredients.join(", ");
  const h = hash(ingredients.join("|").toLowerCase());
  const styles = [
    {
      name: "One-Pan Mise Skillet",
      method: "skillet",
      cuisine: "rustic fusion",
      desc: `A golden-edged skillet hash that lets ${list} caramelize together.`,
      verbs: ["Sear", "Toss", "Fold in", "Finish with"],
    },
    {
      name: "Sheet-Pan Supper",
      method: "oven",
      cuisine: "weeknight classic",
      desc: `Everything roasts on one tray while the edges crisp: ${list}.`,
      verbs: ["Preheat", "Spread", "Roast", "Rest"],
    },
    {
      name: "Big-Bowl Simmer",
      method: "pot",
      cuisine: "brothy comfort",
      desc: `A brothy, ladle-worthy bowl built around ${list}.`,
      verbs: ["Sweat", "Pour over", "Simmer", "Ladle"],
    },
  ];
  return styles.map((s, idx) => ({
    name: s.name,
    description: s.desc,
    cuisine: opts.cuisine && opts.cuisine !== "any" ? opts.cuisine : s.cuisine,
    difficulty: ["easy", "easy", "medium"][idx],
    prepMinutes: 10 + idx * 5,
    cookMinutes: 15 + idx * 10,
    servings: opts.servings,
    ingredients: ingredients.map((item, i) => ({
      item,
      amount: i === 0 ? "as the star — plenty" : "a good handful",
    })),
    steps: [
      `${s.verbs[0]} your pan/pot over medium-high heat with a spoonful of oil.`,
      `Add the heartiest ingredients first (${ingredients.slice(0, 3).join(", ")}); cook until they take on color.`,
      `${s.verbs[2]} the remaining ingredients (${ingredients.slice(3).join(", ") || "staples"}) and season well.`,
      `Cook by the ${s.method} method until everything is tender and glossy, 10-20 minutes.`,
      `${s.verbs[3]} a squeeze of acid (lemon or vinegar) and taste before serving.`,
    ],
    tips: [
      "Demo mode: shapes are placeholders — add GEMINI_API_KEY to backend/.env for real recipes.",
      "Salt in layers, not all at once.",
    ],
  }));
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "MiseOS backend",
    model: GEMINI_MODEL,
    geminiConnected: Boolean(ai),
  });
});

app.post("/api/synthesize", rateLimit, async (req, res) => {
  const body = req.body || {};
  let ingredients = Array.isArray(body.ingredients) ? body.ingredients : [];
  ingredients = [
    ...new Set(
      ingredients
        .filter((i) => typeof i === "string")
        .map((i) => i.trim().slice(0, 64))
        .filter(Boolean)
    ),
  ].slice(0, 40);

  if (ingredients.length === 0) {
    return res.status(400).json({ error: "Add at least one ingredient first." });
  }

  const opts = {
    cuisine: typeof body.cuisine === "string" ? body.cuisine.slice(0, 40) : "any",
    diet: typeof body.diet === "string" ? body.diet.slice(0, 40) : "none",
    servings: Math.min(Math.max(Number(body.servings) || 2, 1), 12),
  };

  if (!ai) {
    return res.json({ demo: true, recipes: demoRecipes(ingredients, opts) });
  }

  try {
    const recipes = await synthesizeWithGemini(ingredients, opts);
    res.json({ demo: false, recipes });
  } catch (err) {
    console.error("Gemini synthesis failed:", err.message);
    res.status(502).json({
      error: "The chef is unreachable right now (Gemini call failed). Try again shortly.",
    });
  }
});

// Serve the frontend — index.html only, so backend secrets can never be listed.
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "index.html"));
});

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.listen(PORT, HOST, () => {
  console.log(`MiseOS proxy running on http://${HOST}:${PORT}`);
  console.log(
    ai
      ? `Gemini connected (model: ${GEMINI_MODEL})`
      : "No GEMINI_API_KEY set — running in DEMO mode"
  );
});
