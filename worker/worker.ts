// =============================================================================
// Multi-role LLM router for the cybersecurity RAG pipeline (Cloudflare Worker)
// -----------------------------------------------------------------------------
// Replaces a single hardcoded model with per-role model selection, matching
// the design doc's tiered-model rationale (Section 3.2 / Section 7):
//   - router_pass1  : coarse scope triage (answerable / ambiguous / out_of_scope)
//                     -> cheapest usable model, called on every query
//   - router_pass2  : "unsafe" classification, theoretical/illustrative only
//                     -> a more capable model than pass1, still far cheaper
//                        than the generator; called less often (only on
//                        queries that passed pass 1 as non-out-of-scope)
//   - generator     : drafts the final cited answer
//                     -> the one role worth spending the bigger model on
//   - ingestion     : one-time-per-chunk context blurb generation
//                     (Anthropic's Contextual Retrieval, design doc Section 2.4)
//                     -> called many times at index-build time; must be cheap
//
// Why this file exists: Workers AI's free tier is a SHARED 10,000-neuron/day
// pool across every model call from your account. Larger models (e.g. Llama
// 4 Scout) cost roughly 24.5k neurons per million input tokens and 77k
// neurons per million output tokens - a single generator-quality call can
// already run ~30-40 neurons, and this pipeline makes 3-5 LLM calls per
// query (router pass 1, router pass 2, generator, possible regenerate) plus
// one call per chunk at ingestion time. Routing cheap roles to small models
// and reserving the expensive model for the one role where quality actually
// matters (the Generator) is what keeps a full day of testing inside the
// free allocation. Model IDs and free-tier neuron costs are checked against
// Cloudflare's public pricing page as of writing; if you change models,
// re-check https://developers.cloudflare.com/workers-ai/platform/pricing/
// since per-model cost varies by an order of magnitude across the catalog.
//
// Docs referenced:
//   https://developers.cloudflare.com/workers-ai/get-started/workers-wrangler/
//   https://developers.cloudflare.com/workers-ai/platform/bindings/
//   https://developers.cloudflare.com/workers/configuration/secrets/
//   https://developers.cloudflare.com/workers-ai/platform/pricing/
// =============================================================================

export interface Env {
  AI: Ai;
  // Set via `wrangler secret put WORKER_AUTH_KEY` before deploying - never
  // hardcode this in source, and never commit a filled-in .dev.vars file.
  // See "Setup" at the bottom of this file for the exact commands.
  WORKER_AUTH_KEY: string;
}

// -----------------------------------------------------------------------------
// Per-role model selection
// -----------------------------------------------------------------------------
// Update these constants after checking current availability/pricing:
// https://developers.cloudflare.com/workers-ai/models/
// Every model below is confirmed present in Cloudflare's free-tier catalog
// as of writing. Cloudflare periodically deprecates and adds models, so this
// is the single place to update if a model name changes.
const MODELS_BY_ROLE = {
  // Cheapest usable instruct model. This is the highest-call-volume role
  // (runs on every single query), so cost per call matters most here.
  router_pass1: "@cf/meta/llama-3.2-3b-instruct",

  // Meaningfully more capable than pass1, but still far cheaper than the
  // generator-tier model. Runs less often than pass1 (only on queries that
  // were not already classified out_of_scope), and per the design doc this
  // classification is treated as a theoretical/illustrative design
  // consideration, not a production safety system - so a mid-tier model is
  // an appropriate, proportionate choice rather than the largest available.
  router_pass2_unsafe_check: "@cf/meta/llama-3.1-8b-instruct-fast",

  // The one role where output quality most directly affects what the user
  // reads. Worth the higher per-call neuron cost.
  generator: "@cf/meta/llama-4-scout-17b-16e-instruct",

  // Called once per chunk at ingestion time (Contextual Retrieval blurb
  // generation, design doc Section 2.4/3.3). This can be hundreds of calls
  // for a modest KB, so it must stay on the cheapest tier regardless of how
  // large the KB grows.
  ingestion_blurb: "@cf/meta/llama-3.2-3b-instruct",
} as const;

type Role = keyof typeof MODELS_BY_ROLE;

function isValidRole(value: unknown): value is Role {
  return typeof value === "string" && value in MODELS_BY_ROLE;
}

// -----------------------------------------------------------------------------
// Request/response shapes
// -----------------------------------------------------------------------------
interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface WorkerRequestBody {
  role: string;
  // Either provide `prompt` (simple single-turn) or `messages` (multi-turn /
  // custom system prompt). If both are given, `messages` takes precedence.
  prompt?: string;
  messages?: ChatMessage[];
  // Optional per-request override, e.g. for the Verifier's regeneration
  // retry (design doc Section 3.5) where a lower temperature may be wanted.
  temperature?: number;
  max_tokens?: number;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "POST") {
      return Response.json(
        { error: "Only POST requests are allowed." },
        { status: 405 },
      );
    }

    // --- Auth check -----------------------------------------------------
    // WORKER_AUTH_KEY is a secret (wrangler secret put), never a literal in
    // this file. See "Setup" below for how to configure it.
    const authHeader = request.headers.get("Authorization");
    const expected = `Bearer ${env.WORKER_AUTH_KEY}`;
    if (!env.WORKER_AUTH_KEY || authHeader !== expected) {
      return Response.json({ error: "Unauthorized." }, { status: 401 });
    }

    // --- Parse and validate body -----------------------------------------
    let body: WorkerRequestBody;
    try {
      body = await request.json();
    } catch {
      return Response.json(
        { error: "Request body must be valid JSON." },
        { status: 400 },
      );
    }

    const { role, prompt, messages, temperature, max_tokens } = body;

    if (!isValidRole(role)) {
      return Response.json(
        {
          error: `Invalid or missing 'role'. Expected one of: ${Object.keys(MODELS_BY_ROLE).join(", ")}`,
        },
        { status: 400 },
      );
    }

    if (!prompt && (!messages || messages.length === 0)) {
      return Response.json(
        { error: "Provide either 'prompt' (string) or 'messages' (array)." },
        { status: 400 },
      );
    }

    const model = MODELS_BY_ROLE[role];

    const chatMessages: ChatMessage[] =
      messages ??
      [
        { role: "system", content: systemPromptFor(role) },
        { role: "user", content: prompt as string },
      ];

    // --- Call Workers AI ---------------------------------------------------
    try {
      const aiResponse = await env.AI.run(model, {
        messages: chatMessages,
        ...(temperature !== undefined ? { temperature } : {}),
        ...(max_tokens !== undefined ? { max_tokens } : {}),
      });

      // Workers AI's response shape is generally { response: string, ... }
      // for chat-style calls, but this is not guaranteed identical across
      // every model in the catalog - return the raw shape alongside the
      // common `reply` field so the caller can fall back if needed.
      const reply =
        typeof aiResponse === "object" &&
        aiResponse !== null &&
        "response" in aiResponse
          ? (aiResponse as { response: string }).response
          : null;

      return Response.json({
        role,
        model,
        reply,
        raw: aiResponse,
      });
    } catch (error) {
      // Workers AI throws (or the binding surfaces an error) when the
      // account's daily neuron allocation is exhausted, among other
      // failure modes. Surface this distinctly so the LangGraph pipeline
      // can distinguish "model said no" from "budget exhausted, back off /
      // abstain" rather than treating every failure identically.
      const message = error instanceof Error ? error.message : String(error);
      const likelyQuotaExceeded = /neuron|quota|rate.?limit/i.test(message);

      return Response.json(
        {
          error: message,
          likely_quota_exceeded: likelyQuotaExceeded,
          role,
          model,
        },
        { status: likelyQuotaExceeded ? 429 : 500 },
      );
    }
  },
} satisfies ExportedHandler<Env>;

// -----------------------------------------------------------------------------
// Default system prompts per role (used only when the caller sends `prompt`
// rather than a full `messages` array - the LangGraph agents will generally
// want to send their own carefully constructed messages, per the design
// doc's Sections 3.2-3.5, but these defaults make the Worker usable
// standalone for quick testing).
// -----------------------------------------------------------------------------
function systemPromptFor(role: Role): string {
  switch (role) {
    case "router_pass1":
      return (
        "You are a triage classifier for a cybersecurity question-answering " +
        "system. Classify the user's query as exactly one of: answerable, " +
        "ambiguous, out_of_scope. Respond with only the label."
      );
    case "router_pass2_unsafe_check":
      return (
        "You are a safety classifier for a cybersecurity question-answering " +
        "system. Determine whether the user's query is a genuine request to " +
        "understand or defend against a threat (safe) or a request for " +
        "active assistance conducting an attack (unsafe). Respond with only " +
        "'safe' or 'unsafe'."
      );
    case "generator":
      return (
        "You are a cybersecurity assistant. Answer only using the provided " +
        "retrieved context. Never use outside knowledge. Cite the specific " +
        "chunk ID(s) that support each claim. If the context does not " +
        "support an answer, say so explicitly."
      );
    case "ingestion_blurb":
      return (
        "Given a document and one chunk of text from it, write a short " +
        "(1-2 sentence) note identifying what document this chunk is from " +
        "and what specific subject (e.g. CVE ID, ATT&CK technique) it " +
        "discusses. Do not summarize the chunk's content, only identify it."
      );
  }
}

// =============================================================================
// Setup
// =============================================================================
//
// 1. Bind Workers AI in wrangler.jsonc (or wrangler.toml):
//
//    { "ai": { "binding": "AI" } }
//
// 2. Set the auth secret (do NOT put this in wrangler.jsonc or source):
//
//    npx wrangler secret put WORKER_AUTH_KEY
//    (you'll be prompted to paste a value - generate a long random string,
//     e.g. `openssl rand -hex 32`)
//
// 3. For local dev, create a .dev.vars file (add it to .gitignore):
//
//    WORKER_AUTH_KEY=your-local-dev-key-here
//
// 4. Deploy:
//
//    npx wrangler deploy
//
// 5. Call from your LangGraph pipeline, one call per role, e.g.:
//
//    const res = await fetch("https://your-worker.workers.dev", {
//      method: "POST",
//      headers: {
//        "Content-Type": "application/json",
//        "Authorization": `Bearer ${process.env.WORKER_AUTH_KEY}`,
//      },
//      body: JSON.stringify({
//        role: "generator",
//        messages: [
//          { role: "system", content: "..." },
//          { role: "user", content: "..." },
//        ],
//      }),
//    });
//    const { reply } = await res.json();
//
// 6. Monitor free-tier usage: Cloudflare dashboard -> Workers & Pages ->
//    Workers AI -> Analytics. The 10,000-neuron/day pool is shared across
//    ALL models and resets at 00:00 UTC - if you see 429s with
//    likely_quota_exceeded: true, that's the daily pool, not a bug.
// =============================================================================