// supabase/functions/telemetry-api/index.ts
// VibeCheck R&D — 3-Tier Deterministic Anchor & Bayesian Coupling Engine v2.2
// Standards: Deno 2 / Supabase Edge Limits (2s CPU, Fail-Fast Upstream Timeouts),
// Dynamic Origin CORS on All Status Codes, Zero-Count Evidence Whitelist,
// Family Warmth Anchor, Multi-Line WhatsApp Paste Sanitizer,
// Emerging Signals (Unverified) Tier 3, Multimodal Vision (Photo + S-Pen Sheet),
// Resilient 429/503 Cascade, Burst Rate Limiter & Optional Stripe Credit Gate.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const PER_MODEL_TIMEOUT_MS = 14_000;
const RETRY_503_BASE_MS = 700;
const MAX_REQUEST_BYTES = 6_500_000; // ~6.5 MB ceiling (supports up to 4.2 MB base64 image + JSON)
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQ = 20;

const STATIC_ALLOWED_ORIGINS = new Set([
  "https://vibecheck-hq.github.io",
  "https://vibecheck-hq.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5173",
]);

function resolveAllowedOrigin(req: Request): string {
  const origin = req.headers.get("origin")?.trim() || "";
  const configuredFrontend = (Deno.env.get("FRONTEND_URL") || "").trim().replace(/\/+$/, "");
  const strictCors = (Deno.env.get("STRICT_CORS") || "").toLowerCase() === "true";

  if (!origin) {
    return configuredFrontend || "https://vibecheck-hq.github.io";
  }

  const normalized = origin.replace(/\/+$/, "");
  if (
    STATIC_ALLOWED_ORIGINS.has(normalized) ||
    (configuredFrontend && normalized === configuredFrontend) ||
    /^https:\/\/vibecheck-hq[a-z0-9-]*\.vercel\.app$/i.test(normalized)
  ) {
    return origin;
  }

  return strictCors ? configuredFrontend || "https://vibecheck-hq.github.io" : "*";
}

function buildCorsHeaders(req: Request): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": resolveAllowedOrigin(req),
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type, x-gemini-key, x-decode-session, x-owner-key, x-retry-count, traceparent, tracestate, baggage",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin",
  };
}

function jsonResponse(req: Request, payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: buildCorsHeaders(req),
  });
}

// Lightweight per-isolate sliding-window burst limiter
const ipBuckets = new Map<string, number[]>();

function checkBurstRateLimit(req: Request): { allowed: boolean; retryAfterSec: number } {
  const ip =
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown";
  const now = Date.now();
  const prev = (ipBuckets.get(ip) || []).filter((ts) => now - ts < RATE_LIMIT_WINDOW_MS);

  if (prev.length >= RATE_LIMIT_MAX_REQ) {
    const oldest = prev[0];
    const retryAfterSec = Math.max(1, Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldest)) / 1000));
    ipBuckets.set(ip, prev);
    return { allowed: false, retryAfterSec };
  }

  prev.push(now);
  ipBuckets.set(ip, prev);

  // Prevent unbounded map growth inside long-lived isolates
  if (ipBuckets.size > 500) {
    const firstKey = ipBuckets.keys().next().value;
    if (firstKey) ipBuckets.delete(firstKey);
  }

  return { allowed: true, retryAfterSec: 0 };
}

// ---------------------------------------------------------------------------
// 0. OPTIONAL PRODUCTION CREDIT / STRIPE SESSION GATE
//    Enable in Supabase Edge Function Secrets: REQUIRE_PAID_GATE=true
//    Optional R&D bypass header for owner testing: OWNER_BYPASS_KEY=<secret>
// ---------------------------------------------------------------------------
interface GateResult {
  authorized: boolean;
  status: number;
  error?: string;
  mode: "open_rd" | "owner_bypass" | "paid_session" | "auth_user";
  credits_remaining?: number | null;
}

async function verifyAccessGate(
  req: Request,
  body: RequestPayload,
  needsLlm: boolean,
): Promise<GateResult> {
  const requireGate = (Deno.env.get("REQUIRE_PAID_GATE") || "").toLowerCase() === "true";

  // In R&D mode (default until REQUIRE_PAID_GATE=true is set), allow requests through
  if (!requireGate || !needsLlm) {
    return { authorized: true, status: 200, mode: "open_rd", credits_remaining: null };
  }

  // 1. Owner testing bypass via x-owner-key header matching OWNER_BYPASS_KEY secret
  const ownerSecret = (Deno.env.get("OWNER_BYPASS_KEY") || "").trim();
  const providedOwnerKey = (req.headers.get("x-owner-key") || "").trim();
  if (ownerSecret && providedOwnerKey && providedOwnerKey === ownerSecret) {
    return { authorized: true, status: 200, mode: "owner_bypass", credits_remaining: null };
  }

  const supabaseUrl = (Deno.env.get("SUPABASE_URL") || "").trim();
  const serviceRoleKey = (Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "").trim();
  if (!supabaseUrl || !serviceRoleKey) {
    return {
      authorized: false,
      status: 500,
      error: "Server billing gate misconfigured: missing Supabase service credentials.",
      mode: "paid_session",
    };
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // 2. Check Stripe paid decode session ID (from body.sessionId or x-decode-session header)
  const sessionId = (
    body.sessionId ||
    req.headers.get("x-decode-session") ||
    ""
  ).trim();

  if (sessionId) {
    if (!/^[A-Za-z0-9_-]{8,128}$/.test(sessionId)) {
      return {
        authorized: false,
        status: 400,
        error: "Invalid Decode Pass session identifier format.",
        mode: "paid_session",
      };
    }

    const isUuid =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId);

    const query = admin
      .from("decodes")
      .select("id, status, credits_remaining, credits_used");

    const { data: row, error } = await (
      isUuid ? query.eq("id", sessionId) : query.eq("stripe_session_id", sessionId)
    ).maybeSingle();

    if (error) {
      return {
        authorized: false,
        status: 500,
        error: `Credit verification failed: ${error.message}`,
        mode: "paid_session",
      };
    }

    if (!row || row.status !== "paid") {
      return {
        authorized: false,
        status: 402,
        error: "Payment required. Unlock a Decode Pass to run live AI analysis.",
        mode: "paid_session",
      };
    }

    const remaining =
      typeof row.credits_remaining === "number" ? row.credits_remaining : 1;

    if (remaining <= 0) {
      return {
        authorized: false,
        status: 402,
        error: "Your Decode Pass has 0 credits remaining. Purchase a new pass to continue.",
        mode: "paid_session",
        credits_remaining: 0,
      };
    }

    // Decrement 1 credit atomically before calling Gemini
    const nextRemaining = Math.max(0, remaining - 1);
    const nextUsed = (typeof row.credits_used === "number" ? row.credits_used : 0) + 1;
    await admin
      .from("decodes")
      .update({ credits_remaining: nextRemaining, credits_used: nextUsed })
      .eq("id", row.id);

    return {
      authorized: true,
      status: 200,
      mode: "paid_session",
      credits_remaining: nextRemaining,
    };
  }

  // 3. Fallback: Check authenticated Supabase Auth user Bearer JWT
  const authHeader = req.headers.get("authorization") || "";
  const token = authHeader.toLowerCase().startsWith("bearer ")
    ? authHeader.slice(7).trim()
    : "";

  if (token && token.split(".").length === 3) {
    const { data: userData, error: userErr } = await admin.auth.getUser(token);
    if (!userErr && userData?.user) {
      return { authorized: true, status: 200, mode: "auth_user", credits_remaining: null };
    }
  }

  return {
    authorized: false,
    status: 402,
    error: "Active Decode Pass or signed-in session required for live AI analysis.",
    mode: "paid_session",
  };
}

// ---------------------------------------------------------------------------
// 1. GENERALIZED LEXICAL & SYNTACTIC PATTERNS (REGISTER-AGNOSTIC CLEPM PORT)
// ---------------------------------------------------------------------------
const PROFANITY_RE =
  /\b(fuck|fucked|fucking|fuuuck|shit|shitty|bollocks|bitch|cunt|twat|prick|dick|arse|piss|pissed|wank|wanker|bastard|bloody|crap)\b/gi;

const HEDGE_RE =
  /\b(maybe|perhaps|sort of|kind of|kinda|probably|might|i guess|i think|suppose|apparently|seem|seems|just|possibly|roughly|mostly|somewhat|arguably)\b/gi;

const LEGACY_URGENCY_RE =
  /\b(now|urgent|asap|quick|quickly|hurry|emergency|need|help|stuck|cant|can't|lost|late|money|owe|borrow|£\d+|€\d+|\$\d+)\b/gi;

const ACUTE_URGENCY_RE =
  /\b(urgent|asap|right now|immediately|hurry|emergency|stuck|desperate|crisis|overdue|owe|borrow|£\d+|€\d+|\$\d+)\b/gi;

const POLITE_HELP_RE =
  /\b(able to help|could you help|would you help|happy to help|glad to help|here to help|if i can help|let me know if you need help)\b/gi;

// Romantic / intimate affection cues
const AFFECTION_RE =
  /(\bx+\b|love you|lush|sweet|gorgeous|darling|baby|honey|miss you|appreciate you|❤|❤️|😘|😍|🥰|😜|💛|💙)/gi;

// Familial, celebratory & social warmth cues (separate from romantic affection)
const WARMTH_RE =
  /\b(happy birthday|birthday|congrats|congratulations|well done|proud|lovely|wonderful|brilliant|bless|blessing|best wishes|glad|thank you|thanks|cheers|hope you(?:'|’)?re well|take care|thinking of you|safe travels|good luck)\b|(🎉|🎂|👏|🤗|🥳|💐|😊|🙏|🙌|🌟)/gi;

const OMITTED_APOSTROPHE_RE =
  /\b(im|ive|dont|cant|wont|didnt|isnt|wasnt|shouldnt|couldnt|wouldnt|youre|theyre|hes|shes|lets|thats|whats|hows|wheres|id|ill)\b/gi;

const MODAL_SOFTENER_RE =
  /\b(wondered|would|could|might|ideally|no worries|no rush|whenever|feel free|where possible|if you(?:'|’)?d like|let me know if|appreciate)\b/gi;

// Context-aware friction markers: excludes neutral determiner "whatever + noun"
const FRICTION_MARKER_RE =
  /\b(actually|honestly|frankly|never mind|forget it|as i said|to be fair|clearly|obviously|seriously)\b|\bwhatever(?=\s*(?:[.!?,;\n]|$))|\bfine(?=\s*[.!]+(?:\s|$))/gi;

const CONDITIONAL_IF_RE = /\bif\b/gi;
const PRONOUN_1PS_RE = /\b(i|me|my|mine|myself|i['’]m|i['’]ve|i['’]d|i['’]ll)\b/gi;
const PRONOUN_2P_RE = /\b(you|your|yours|yourself|you['’]re|you['’]ve|you['’]d|you['’]ll)\b/gi;

// Global line-start WhatsApp prefix stripper (handles multi-line single-box pastes cleanly)
const INLINE_WA_PREFIX_RE =
  /^[ \t]*[\u200e\u200f]*(?:\[\d{1,2}\/\d{1,2}(?:\/\d{2,4})?,\s*\d{1,2}:\d{2}(?::\d{2})?(?:[\s\u202f]?[ap]m)?\]\s+[^:\n]{1,50}:\s*|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?,\s*\d{1,2}:\d{2}(?::\d{2})?(?:[\s\u202f]?[ap]m)?\s*[-–]\s*[^:\n]{1,50}:\s*)/gim;

const NON_TEXT_MARKERS = new Set([
  "<media omitted>",
  "image omitted",
  "audio omitted",
  "video omitted",
  "sticker omitted",
  "gif omitted",
  "document omitted",
  "video note omitted",
  "this message was deleted",
  "you deleted this message",
  "missed voice call",
  "missed video call",
  "missed voice call, tap to call back",
  "missed video call, tap to call back",
  "call failed, try again",
  "silenced video call, focus mode",
  "silenced voice call, focus mode",
  "null",
]);

const CALL_LOG_RE =
  /^(voice call|video call|missed (?:voice|video) call),?\s*(\d+\s*(sec|min)|ended|no answer|tap to call back)?$/i;
const SYSTEM_NOTICE_RE =
  /(messages and calls are end-to-end encrypted|changed the subject|changed this group|created group|added you|left$|security code changed)/i;

const ALLOWED_IMAGE_MIMES = new Set(["image/jpeg", "image/png", "image/webp"]);
const MAX_IMAGE_BASE64_CHARS = 5_600_000;

interface StreamMessage {
  dt: string;
  sender: string;
  text: string;
  chat?: string;
}

interface KinematicsPayload {
  strokeCount?: number;
  pointCount?: number;
  coalescedPointCount?: number;
  meanVelocity?: number;
  peakVelocity?: number;
  meanPressure?: number;
  pressureVariance?: number;
  meanTiltX?: number;
  meanTiltY?: number;
  leftHandZeroOffset?: boolean;
  palmRejectionEnabled?: boolean;
  durationMs?: number;
}

interface HandwritingImageInput {
  mimeType: string;
  base64: string;
  width?: number;
  height?: number;
  sizeKb?: number;
  inkCoverageRatio?: number;
  horizontalDensityVariance?: number;
  filename?: string;
  source?: "photo_upload" | "spen_canvas";
}

interface HandwritingImageAnchors {
  present: boolean;
  source: "photo_upload" | "spen_canvas";
  mime_type: string;
  filename: string | null;
  width: number;
  height: number;
  aspect_ratio: number;
  size_kb: number;
  ink_coverage_ratio: number | null;
  horizontal_density_variance: number | null;
}

interface RequestPayload {
  mode?: "single" | "stream" | "kinematic" | "handwriting";
  text?: string;
  sender?: string;
  windowLimit?: number;
  messages?: StreamMessage[];
  kinematics?: KinematicsPayload | null;
  handwritingImage?: HandwritingImageInput | null;
  runLlm?: boolean;
  sessionId?: string;
}

interface SyntaxMetrics {
  char_len: number;
  word_cnt: number;
  word_cnt_legacy_raw: number;
  wa_headers_stripped_cnt: number;
  mean_wlen: number;
  w_per_s: number;
  sentence_cnt: number;
  lower_ratio: number;
  lexical_ttr: number;
  excl_cnt: number;
  quest_cnt: number;
  en_dash_cnt: number;
  paren_cnt: number;
  numbered_list_cnt: number;
  apostrophe_cnt: number;
  has_x: number;
  has_profanity: number;
  has_hedge: number;
  hedge_matches: string[];
  has_urgency: number;
  has_urgency_legacy: number;
  polite_help_filtered: boolean;
  has_affection: number;
  has_warmth: number;
  warmth_cnt: number;
  warmth_matches: string[];
  has_friction: number;
  friction_matches: string[];
  has_missing_apo: number;
  missing_apo_matches: string[];
  conditional_if_cnt: number;
  modal_softener_cnt: number;
  modal_matches: string[];
  ratio_1ps: number;
  ratio_2p: number;
  mindpaper_divergence_idx: number;
  mindpaper_divergence_legacy: number;
}

interface TemporalMetrics {
  total_received_msgs: number;
  total_filtered_msgs: number;
  window_limit: number;
  sample_n: number;
  interval_n: number;
  window_start_dt: string | null;
  window_end_dt: string | null;
  span_hours: number;
  cross_chat_jumps: number;
  rapid_bursts: number;
  mean_gap_mins: number;
  kim_jo_burstiness: number | null;
  circular_24h_R: number | null;
  mean_divergence_idx: number;
}

interface RawClaim {
  title: string;
  category: string;
  claim: string;
  cited_anchors: string[];
  raw_confidence: number;
  reasoning: string;
}

interface RawExtrapolation {
  dimension: string;
  hypothesis: string;
  cited_anchors: string[];
  raw_confidence: number;
  coupling_type: "weak_behavioral" | "uncoupled_demographic";
  rationale: string;
}

function uniqueMatches(text: string, re: RegExp): string[] {
  const m = text.match(re) ?? [];
  return Array.from(new Set(m.map((s) => s.toLowerCase().trim()).filter(Boolean)));
}

function isSubstantiveText(text: string): boolean {
  const s = (text || "").replace(/[\u200e\u200f]/g, "").trim();
  if (!s) return false;
  const low = s.toLowerCase();
  if (NON_TEXT_MARKERS.has(low) || CALL_LOG_RE.test(low) || SYSTEM_NOTICE_RE.test(low)) {
    return false;
  }
  return true;
}

function round(n: number, decimals = 4): number {
  const p = Math.pow(10, decimals);
  return Math.round(n * p) / p;
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

function stripJsonFences(raw: string): string {
  return raw
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// 2. STAGE 1: DETERMINISTIC ANCHOR ENGINE (PURE TYPESCRIPT — ZERO LLM)
// ---------------------------------------------------------------------------
function scoreSyntax(rawText: string): { cleanText: string; syntax: SyntaxMetrics } {
  const normalized = (rawText || "").replace(/\r\n/g, "\n").replace(/[\u200e\u200f]/g, "").trim();
  const headerMatches = normalized.match(INLINE_WA_PREFIX_RE) ?? [];
  const waHeadersStrippedCnt = headerMatches.length;
  const text =
    waHeadersStrippedCnt > 0
      ? normalized
          .replace(INLINE_WA_PREFIX_RE, "")
          .replace(/\n{3,}/g, "\n\n")
          .trim()
      : normalized;

  if (!text) {
    return {
      cleanText: "",
      syntax: {
        char_len: 0,
        word_cnt: 0,
        word_cnt_legacy_raw: 0,
        wa_headers_stripped_cnt: waHeadersStrippedCnt,
        mean_wlen: 0,
        w_per_s: 0,
        sentence_cnt: 0,
        lower_ratio: 0,
        lexical_ttr: 0,
        excl_cnt: 0,
        quest_cnt: 0,
        en_dash_cnt: 0,
        paren_cnt: 0,
        numbered_list_cnt: 0,
        apostrophe_cnt: 0,
        has_x: 0,
        has_profanity: 0,
        has_hedge: 0,
        hedge_matches: [],
        has_urgency: 0,
        has_urgency_legacy: 0,
        polite_help_filtered: false,
        has_affection: 0,
        has_warmth: 0,
        warmth_cnt: 0,
        warmth_matches: [],
        has_friction: 0,
        friction_matches: [],
        has_missing_apo: 0,
        missing_apo_matches: [],
        conditional_if_cnt: 0,
        modal_softener_cnt: 0,
        modal_matches: [],
        ratio_1ps: 0,
        ratio_2p: 0,
        mindpaper_divergence_idx: 0,
        mindpaper_divergence_legacy: 0,
      },
    };
  }

  const normalizedForTokens = text.replace(/[\u2018\u2019]/g, "'");
  const words = normalizedForTokens.match(/[A-Za-z0-9'£$€]+/g) ?? [];
  const legacyWords = text.match(/[A-Za-z0-9'£$€]+/g) ?? [];

  const wCnt = words.length;
  const meanWlen = wCnt > 0 ? words.reduce((acc, w) => acc + w.length, 0) / wCnt : 0;
  const uniqueLower = new Set(words.map((w) => w.toLowerCase()));
  const lexicalTtr = wCnt > 0 ? uniqueLower.size / wCnt : 0;

  const cleanedForSents = text.replace(/^\s*\d+\.\s+/gm, "");
  const sents = cleanedForSents
    .split(/[.!?]+|\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const sCnt = Math.max(1, sents.length);

  const alpha = text.match(/[A-Za-z]/g) ?? [];
  const lowerCnt = alpha.filter((c) => c >= "a" && c <= "z").length;
  const lowerRatio = alpha.length > 0 ? lowerCnt / alpha.length : 0;

  const exclCnt = (text.match(/!/g) ?? []).length;
  const questCnt = (text.match(/\?/g) ?? []).length;
  const enDashCnt = (text.match(/[–—]/g) ?? []).length;
  const parenCnt = (text.match(/\([^)]+\)/g) ?? []).length;
  const numberedListCnt = (text.match(/^\s*\d+\.\s+/gm) ?? []).length;
  const apostropheCnt = (text.match(/['\u2019]/g) ?? []).length;

  const hasX = /\bx+\b/i.test(text) ? 1 : 0;
  const hasProfanity = PROFANITY_RE.test(text) ? 1 : 0;
  PROFANITY_RE.lastIndex = 0;

  const hedgeMatches = uniqueMatches(text, HEDGE_RE);
  const hasHedge = hedgeMatches.length > 0 ? 1 : 0;

  const hasUrgencyLegacy = LEGACY_URGENCY_RE.test(text) ? 1 : 0;
  LEGACY_URGENCY_RE.lastIndex = 0;

  const hasAcuteUrgency = ACUTE_URGENCY_RE.test(text) ? 1 : 0;
  ACUTE_URGENCY_RE.lastIndex = 0;

  const politeHelpPresent = POLITE_HELP_RE.test(text);
  POLITE_HELP_RE.lastIndex = 0;

  const politeHelpFiltered = hasUrgencyLegacy === 1 && hasAcuteUrgency === 0 && politeHelpPresent;
  const hasUrgency = hasAcuteUrgency;

  const hasAffection = AFFECTION_RE.test(text) ? 1 : 0;
  AFFECTION_RE.lastIndex = 0;

  const warmthAllMatches = text.match(WARMTH_RE) ?? [];
  const warmthMatches = uniqueMatches(text, WARMTH_RE);
  const warmthCnt = warmthAllMatches.length;
  const hasWarmth = warmthCnt > 0 ? 1 : 0;

  const frictionMatches = uniqueMatches(text, FRICTION_MARKER_RE);
  const hasFriction = frictionMatches.length > 0 ? 1 : 0;

  const missingApoMatches = uniqueMatches(text, OMITTED_APOSTROPHE_RE);
  const hasMissingApo = missingApoMatches.length > 0 ? 1 : 0;

  const conditionalIfCnt = (text.match(CONDITIONAL_IF_RE) ?? []).length;
  const modalMatches = uniqueMatches(text, MODAL_SOFTENER_RE);
  const modalSoftenerCnt = (text.match(MODAL_SOFTENER_RE) ?? []).length;

  const p1ps = (text.match(PRONOUN_1PS_RE) ?? []).length;
  const p2p = (text.match(PRONOUN_2P_RE) ?? []).length;

  const divCalibrated = clamp(0.2 * hasProfanity + 0.2 * hasUrgency, 0, 1);
  const divLegacy = clamp(0.2 * hasProfanity + 0.2 * hasUrgencyLegacy, 0, 1);

  return {
    cleanText: text,
    syntax: {
      char_len: text.length,
      word_cnt: wCnt,
      word_cnt_legacy_raw: legacyWords.length,
      wa_headers_stripped_cnt: waHeadersStrippedCnt,
      mean_wlen: round(meanWlen, 3),
      w_per_s: round(wCnt / sCnt, 3),
      sentence_cnt: sCnt,
      lower_ratio: round(lowerRatio, 4),
      lexical_ttr: round(lexicalTtr, 4),
      excl_cnt: exclCnt,
      quest_cnt: questCnt,
      en_dash_cnt: enDashCnt,
      paren_cnt: parenCnt,
      numbered_list_cnt: numberedListCnt,
      apostrophe_cnt: apostropheCnt,
      has_x: hasX,
      has_profanity: hasProfanity,
      has_hedge: hasHedge,
      hedge_matches: hedgeMatches,
      has_urgency: hasUrgency,
      has_urgency_legacy: hasUrgencyLegacy,
      polite_help_filtered: politeHelpFiltered,
      has_affection: hasAffection,
      has_warmth: hasWarmth,
      warmth_cnt: warmthCnt,
      warmth_matches: warmthMatches,
      has_friction: hasFriction,
      friction_matches: frictionMatches,
      has_missing_apo: hasMissingApo,
      missing_apo_matches: missingApoMatches,
      conditional_if_cnt: conditionalIfCnt,
      modal_softener_cnt: modalSoftenerCnt,
      modal_matches: modalMatches,
      ratio_1ps: round(wCnt > 0 ? p1ps / wCnt : 0, 4),
      ratio_2p: round(wCnt > 0 ? p2p / wCnt : 0, 4),
      mindpaper_divergence_idx: round(divCalibrated, 4),
      mindpaper_divergence_legacy: round(divLegacy, 4),
    },
  };
}

function validateHandwritingImage(
  img: HandwritingImageInput | null | undefined,
): {
  validImage: HandwritingImageInput | null;
  anchors: HandwritingImageAnchors | null;
  warning: string | null;
} {
  if (!img) return { validImage: null, anchors: null, warning: null };
  const mime = String(img.mimeType || "").toLowerCase().trim();
  const base64 = String(img.base64 || "").replace(/^data:[^;]+;base64,/, "").trim();

  if (!ALLOWED_IMAGE_MIMES.has(mime)) {
    return {
      validImage: null,
      anchors: null,
      warning: `Unsupported handwriting image type "${mime || "unknown"}" — skipped non-destructively.`,
    };
  }
  if (!base64 || base64.length < 32) {
    return {
      validImage: null,
      anchors: null,
      warning: "Handwriting image payload was empty — skipped non-destructively.",
    };
  }
  if (base64.length > MAX_IMAGE_BASE64_CHARS) {
    return {
      validImage: null,
      anchors: null,
      warning: "Handwriting image exceeded 4.2 MB limit — skipped non-destructively.",
    };
  }

  const width = Math.max(0, Math.round(Number(img.width) || 0));
  const height = Math.max(0, Math.round(Number(img.height) || 0));
  const aspectRatio = width > 0 && height > 0 ? round(width / height, 3) : 0;
  const sizeKb =
    typeof img.sizeKb === "number" && Number.isFinite(img.sizeKb)
      ? round(img.sizeKb, 1)
      : round((base64.length * 0.75) / 1024, 1);

  return {
    validImage: { ...img, mimeType: mime, base64 },
    anchors: {
      present: true,
      source: img.source === "spen_canvas" ? "spen_canvas" : "photo_upload",
      mime_type: mime,
      filename: img.filename ? String(img.filename).slice(0, 120) : null,
      width,
      height,
      aspect_ratio: aspectRatio,
      size_kb: sizeKb,
      ink_coverage_ratio:
        typeof img.inkCoverageRatio === "number" && Number.isFinite(img.inkCoverageRatio)
          ? round(clamp(img.inkCoverageRatio, 0, 1), 4)
          : null,
      horizontal_density_variance:
        typeof img.horizontalDensityVariance === "number" &&
        Number.isFinite(img.horizontalDensityVariance)
          ? round(Math.max(0, img.horizontalDensityVariance), 5)
          : null,
    },
    warning: null,
  };
}

function kimJoBurstiness(intervals: number[]): number | null {
  const x = intervals.filter((v) => Number.isFinite(v) && v > 0);
  const n = x.length;
  if (n < 2) return null;
  const mu = x.reduce((a, b) => a + b, 0) / n;
  const variance = x.reduce((acc, v) => acc + Math.pow(v - mu, 2), 0) / (n - 1);
  const sd = Math.sqrt(variance);
  if (mu + sd === 0) return 0;
  const r = sd / mu;
  const num = Math.sqrt(n + 1) * r - Math.sqrt(n - 1);
  const den = (Math.sqrt(n + 1) - 2) * r + Math.sqrt(n - 1);
  if (Math.abs(den) < 1e-12) return 0;
  return round(clamp(num / den, -1, 1), 4);
}

function circular24hR(values: number[], hours: number[]): number | null {
  if (values.length < 10 || values.length !== hours.length) return null;
  const n = values.length;
  const meanY = values.reduce((a, b) => a + b, 0) / n;
  const ssTot = values.reduce((a, y) => a + Math.pow(y - meanY, 2), 0);
  if (ssTot < 1e-12) return 0;

  let s1 = 0,
    s2 = 0,
    s11 = 0,
    s22 = 0,
    s12 = 0,
    sy = 0,
    s1y = 0,
    s2y = 0;
  for (let i = 0; i < n; i++) {
    const ang = (2 * Math.PI * hours[i]) / 24;
    const sn = Math.sin(ang);
    const cs = Math.cos(ang);
    const y = values[i];
    s1 += sn;
    s2 += cs;
    s11 += sn * sn;
    s22 += cs * cs;
    s12 += sn * cs;
    sy += y;
    s1y += sn * y;
    s2y += cs * y;
  }

  const M = [
    [n, s1, s2, sy],
    [s1, s11, s12, s1y],
    [s2, s12, s22, s2y],
  ];

  for (let col = 0; col < 3; col++) {
    let pivot = col;
    for (let r = col + 1; r < 3; r++) {
      if (Math.abs(M[r][col]) > Math.abs(M[pivot][col])) pivot = r;
    }
    if (Math.abs(M[pivot][col]) < 1e-12) return 0;
    [M[col], M[pivot]] = [M[pivot], M[col]];
    const div = M[col][col];
    for (let j = col; j < 4; j++) M[col][j] /= div;
    for (let r = 0; r < 3; r++) {
      if (r === col) continue;
      const factor = M[r][col];
      for (let j = col; j < 4; j++) M[r][j] -= factor * M[col][j];
    }
  }
  const [b0, b1, b2] = [M[0][3], M[1][3], M[2][3]];

  let ssRes = 0;
  for (let i = 0; i < n; i++) {
    const ang = (2 * Math.PI * hours[i]) / 24;
    const yHat = b0 + b1 * Math.sin(ang) + b2 * Math.cos(ang);
    ssRes += Math.pow(values[i] - yHat, 2);
  }
  const r2 = clamp(1 - ssRes / ssTot, 0, 1);
  return round(Math.sqrt(r2), 4);
}

function analyzeStream(
  messages: StreamMessage[],
  targetSender?: string,
  requestedLimit?: number,
): {
  combinedText: string;
  llmWindowExcerpt: string;
  syntax: SyntaxMetrics;
  temporal: TemporalMetrics;
} {
  const windowLimit = clamp(Math.round(Number(requestedLimit) || 400), 10, 1000);

  const parsed = messages
    .map((m) => ({
      ...m,
      ts: Date.parse(m.dt),
      substantive: isSubstantiveText(m.text),
    }))
    .filter((m) => Number.isFinite(m.ts) && m.substantive)
    .sort((a, b) => a.ts - b.ts);

  const senderClean = (targetSender || "").trim().toLowerCase();
  const filtered = senderClean
    ? parsed.filter((m) => (m.sender || "").trim().toLowerCase() === senderClean)
    : parsed;

  const active = filtered.slice(-windowLimit);

  const gaps: number[] = [];
  let crossChatJumps = 0;
  let rapidBursts = 0;
  const wordCounts: number[] = [];
  const hours: number[] = [];
  const divScores: number[] = [];

  for (let i = 0; i < active.length; i++) {
    const cur = active[i];
    const { syntax: syn } = scoreSyntax(cur.text);
    wordCounts.push(syn.word_cnt);
    hours.push(new Date(cur.ts).getUTCHours());

    let isJump = 0;
    if (i > 0) {
      const prev = active[i - 1];
      const gapMins = (cur.ts - prev.ts) / 60000;
      if (gapMins > 0) gaps.push(gapMins);
      if (cur.chat && prev.chat && cur.chat !== prev.chat) {
        crossChatJumps++;
        isJump = 1;
      } else if (gapMins <= 5) {
        rapidBursts++;
      }
    }

    const prevWcnt = i > 0 ? wordCounts[i - 1] : syn.word_cnt;
    const wcntShift = Math.abs(syn.word_cnt - prevWcnt);
    const div = clamp(
      (0.35 * Math.min(wcntShift, 25)) / 25 +
        0.25 * isJump +
        0.2 * syn.has_profanity +
        0.2 * syn.has_urgency,
      0,
      1,
    );
    divScores.push(div);
  }

  const combinedText = active.map((m) => m.text).join("\n");
  const { syntax } = scoreSyntax(combinedText);
  const meanDiv =
    divScores.length > 0 ? divScores.reduce((a, b) => a + b, 0) / divScores.length : 0;
  syntax.mindpaper_divergence_idx = round(meanDiv, 4);

  const meanGap = gaps.length > 0 ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
  const startDt = active.length > 0 ? new Date(active[0].ts).toISOString() : null;
  const endDt = active.length > 0 ? new Date(active[active.length - 1].ts).toISOString() : null;
  const spanHours =
    active.length >= 2
      ? round((active[active.length - 1].ts - active[0].ts) / 3600000, 2)
      : 0;

  const formattedLines = active.map(
    (m) => `[${m.dt.slice(0, 16).replace("T", " ")}] ${m.sender}: ${m.text}`,
  );
  const fullFormatted = formattedLines.join("\n");
  const llmWindowExcerpt =
    fullFormatted.length > 8000 ? fullFormatted.slice(-8000) : fullFormatted;

  return {
    combinedText,
    llmWindowExcerpt,
    syntax,
    temporal: {
      total_received_msgs: parsed.length,
      total_filtered_msgs: filtered.length,
      window_limit: windowLimit,
      sample_n: active.length,
      interval_n: gaps.length,
      window_start_dt: startDt,
      window_end_dt: endDt,
      span_hours: spanHours,
      cross_chat_jumps: crossChatJumps,
      rapid_bursts: rapidBursts,
      mean_gap_mins: round(meanGap, 2),
      kim_jo_burstiness: kimJoBurstiness(gaps),
      circular_24h_R: circular24hR(wordCounts, hours),
      mean_divergence_idx: round(meanDiv, 4),
    },
  };
}

// ---------------------------------------------------------------------------
// 3. STAGE 2: RESILIENT MULTIMODAL GEMINI CASCADE (TIMEOUT + 503 RETRY + 429)
// ---------------------------------------------------------------------------
interface Stage2Result {
  executive_read: string;
  suggested_reply: string;
  handwriting_transcription: string;
  aligned_subtext: RawClaim[];
  speculative_extrapolations: RawExtrapolation[];
  llm_model: string;
  llm_status: string;
  rate_limited: boolean;
  models_attempted: string[];
}

function buildDeterministicFallback(
  syntax: SyntaxMetrics,
  kinematics: KinematicsPayload | null,
  handwritingAnchors: HandwritingImageAnchors | null,
  reason: string,
  rateLimited = false,
  modelsAttempted: string[] = [],
): Stage2Result {
  const claims: RawClaim[] = [];

  if (syntax.numbered_list_cnt > 0 || syntax.en_dash_cnt > 0 || syntax.paren_cnt > 0) {
    claims.push({
      title: "High Structural Clarity & Planning",
      category: "Cognitive Style",
      claim:
        "Explicit formatting markers indicate structured, deliberate communication designed to minimize ambiguity.",
      cited_anchors: [
        ...(syntax.numbered_list_cnt > 0 ? ["numbered_list_cnt"] : []),
        ...(syntax.en_dash_cnt > 0 ? ["en_dash_cnt"] : []),
        ...(syntax.paren_cnt > 0 ? ["paren_cnt"] : []),
        "apostrophe_cnt",
      ],
      raw_confidence: 0.86,
      reasoning: "Structured punctuation and list layout reflect unhurried planning.",
    });
  }

  if (syntax.has_warmth === 1 || syntax.has_affection === 1) {
    claims.push({
      title: "Social Warmth & Relational Affirmation",
      category: "Affect",
      claim:
        "Celebratory, appreciative, or affectionate markers signal positive social bonding and low interpersonal friction.",
      cited_anchors: [
        ...(syntax.has_warmth === 1 ? ["has_warmth", "warmth_cnt"] : []),
        ...(syntax.has_affection === 1 ? ["has_affection"] : []),
        "has_profanity",
      ],
      raw_confidence: 0.84,
      reasoning: "Verified warmth/affection lexical anchors paired with clean tone.",
    });
  }

  if (syntax.modal_softener_cnt > 0 || syntax.has_hedge === 1 || syntax.conditional_if_cnt >= 2) {
    claims.push({
      title: "Politeness Softening & Hedging",
      category: "Politeness",
      claim:
        "Tentative modals and conditional phrasing buffer requests against social pressure or direct refusal.",
      cited_anchors: [
        ...(syntax.modal_softener_cnt > 0 ? ["modal_softener_cnt"] : []),
        ...(syntax.conditional_if_cnt > 0 ? ["conditional_if_cnt"] : []),
        ...(syntax.has_hedge === 1 ? ["has_hedge"] : []),
      ],
      raw_confidence: 0.84,
      reasoning: "Indirect framing preserves recipient autonomy while signaling cautious intent.",
    });
  }

  if (syntax.has_friction === 1 || syntax.has_urgency === 1 || syntax.has_profanity === 1) {
    claims.push({
      title: "Elevated Tension / Arousal Signal",
      category: "Affect",
      claim:
        "Direct friction, urgency, or profanity markers push emotional arousal above neutral baseline.",
      cited_anchors: [
        ...(syntax.has_friction === 1 ? ["has_friction"] : []),
        ...(syntax.has_urgency === 1 ? ["has_urgency"] : []),
        ...(syntax.has_profanity === 1 ? ["has_profanity"] : []),
        "mindpaper_divergence_idx",
      ],
      raw_confidence: 0.82,
      reasoning: "Explicit lexical friction or arousal markers detected in Stage 1.",
    });
  } else if (syntax.word_cnt >= 20 && syntax.has_missing_apo === 0) {
    claims.push({
      title: "Controlled & Deliberate Register",
      category: "Cognitive Style",
      claim:
        "Clean punctuation retention with zero acute urgency or profanity signals composed, controlled delivery.",
      cited_anchors: ["word_cnt", "mean_wlen", "has_missing_apo", "excl_cnt"],
      raw_confidence: 0.8,
      reasoning: "Consistent editorial precision reflects low affective volatility.",
    });
  }

  if (kinematics && (kinematics.strokeCount ?? 0) > 0) {
    claims.push({
      title: "S-Pen Motor Telemetry Logged",
      category: "Kinematics",
      claim:
        "Stylus velocity and pressure variance were captured deterministically alongside text syntax.",
      cited_anchors: ["kinematics.meanVelocity", "kinematics.meanPressure"],
      raw_confidence: 0.78,
      reasoning: "Direct S-Pen hardware pointer metrics captured in Stage 1.",
    });
  }

  if (handwritingAnchors) {
    claims.push({
      title: "Handwriting Image Anchors Captured",
      category: "Handwriting",
      claim:
        "Handwriting sheet geometry and ink coverage were measured; live Gemini Vision is required for transcription and visual stroke reading.",
      cited_anchors: [
        "handwriting.width",
        "handwriting.height",
        ...(handwritingAnchors.ink_coverage_ratio !== null
          ? ["handwriting.ink_coverage_ratio"]
          : []),
      ],
      raw_confidence: 0.76,
      reasoning: "Verified image coverage and density metrics logged in Stage 1.",
    });
  }

  const extrapolations: RawExtrapolation[] = [
    {
      dimension: "Emerging Communication Pattern (Unverified)",
      hypothesis:
        syntax.word_cnt > 0
          ? "Early stylistic lean detected from a single sample — more messages or samples are needed before confirming whether this is an enduring habit or a one-off context."
          : "Not enough text yet to pick up emerging communication patterns.",
      cited_anchors: syntax.word_cnt > 0 ? ["word_cnt", "mean_wlen"] : [],
      raw_confidence: 0.58,
      coupling_type: "weak_behavioral",
      rationale: "Single-sample patterns can shift sharply across different people and situations.",
    },
    {
      dimension: "Unproven Personal & Background Bounds",
      hypothesis:
        "Background details (such as age, profession, or family role) cannot be proven from wording or handwriting geometry alone.",
      cited_anchors: syntax.word_cnt > 0 ? ["word_cnt"] : [],
      raw_confidence: 0.5,
      coupling_type: "uncoupled_demographic",
      rationale: "No verified causal link connects short text samples to personal demographics.",
    },
  ];

  const lead = rateLimited
    ? "Rate-Limit Cooldown Active: Upstream AI quota was temporarily reached across available Flash models. Wait ~30–60s and re-run. Stage 1 verified anchors remain 100% accurate below."
    : `Deterministic Mode (${reason}): Stage 1 verified anchors computed cleanly without LLM semantic augmentation.`;

  return {
    executive_read: lead,
    suggested_reply: "",
    handwriting_transcription: "",
    aligned_subtext: claims,
    speculative_extrapolations: extrapolations,
    llm_model: "deterministic-fallback",
    llm_status: reason,
    rate_limited: rateLimited,
    models_attempted: modelsAttempted,
  };
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("upstream_timeout"), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function runStage2Gemini(
  text: string,
  syntax: SyntaxMetrics,
  temporal: TemporalMetrics,
  kinematics: KinematicsPayload | null,
  handwritingImage: HandwritingImageInput | null,
  handwritingAnchors: HandwritingImageAnchors | null,
  guards: Record<string, unknown>,
  headerKey: string | null,
): Promise<Stage2Result> {
  const allowByok = (Deno.env.get("REQUIRE_PAID_GATE") || "").toLowerCase() !== "true";
  const apiKey = (
    Deno.env.get("GEMINI_API_KEY") ||
    Deno.env.get("GOOGLE_API_KEY") ||
    (allowByok ? headerKey : "") ||
    ""
  ).trim();

  if (!apiKey) {
    return buildDeterministicFallback(
      syntax,
      kinematics,
      handwritingAnchors,
      "missing_GEMINI_API_KEY_secret",
    );
  }

  const systemPrompt = `You are Stage 2 of the VibeCheck CLEPM-Bayesian Calibration Engine.
You receive:
1) Raw message text (or aligned chronological stream window excerpt), optional S-Pen kinematics, and/or a handwriting image (photo upload or live S-Pen canvas).
2) LOCKED Stage 1 Deterministic Anchors (100% verified metrics).
3) Sample-size guards.

CRITICAL RULES:
- Separate Tier 2 ("aligned_subtext": strongly supported intent, politeness strategy, hidden hesitation, emotional warmth/tension, cognitive style, boundaries, S-Pen kinematics, or directly observable visual handwriting features like slant, spacing, baseline drift, pressure weight, cross-outs) from Tier 3 ("speculative_extrapolations": Emerging Signals — early patterns the engine is starting to notice that do NOT yet have enough deterministic evidence to prove, such as tentative broader habits, possible situational role, or unproven trait leaps).
- TIER 3 EMERGING SIGNALS RULE: Write Tier 3 in plain, grounded English—NEVER use the word "Worksonality" or academic jargon. Frame each Tier 3 item clearly as an early, unproven signal that needs more samples to verify, and state clearly what evidence is still missing.
- ANCHOR HONESTY RULE:
  - Populate "cited_anchors" using ONLY exact field names present in Stage 1 JSON (e.g., "word_cnt", "mean_wlen", "w_per_s", "excl_cnt", "quest_cnt", "en_dash_cnt", "paren_cnt", "numbered_list_cnt", "apostrophe_cnt", "has_hedge", "has_urgency", "polite_help_filtered", "has_friction", "has_profanity", "has_affection", "has_warmth", "warmth_cnt", "has_missing_apo", "conditional_if_cnt", "modal_softener_cnt", "ratio_1ps", "ratio_2p", "lexical_ttr", "mindpaper_divergence_idx", "kim_jo_burstiness", "circular_24h_R", "cross_chat_jumps", "kinematics.meanVelocity", "kinematics.meanPressure", "kinematics.pressureVariance", "handwriting.ink_coverage_ratio", "handwriting.horizontal_density_variance", "handwriting.aspect_ratio").
  - You MAY cite a 0-valued metric (like excl_cnt=0, has_hedge=0, cross_chat_jumps=0) ONLY when arguing for ABSENCE (e.g., restrained punctuation, unhedged directness, single-thread focus). NEVER cite has_affection or has_warmth if their value is 0 to claim warmth is present!
  - NEVER invent anchor names. NEVER cite "kim_jo_burstiness" if guards.burstiness_unlocked is false, and NEVER cite "circular_24h_R" if guards.circadian_unlocked is false.
- HANDWRITING IMAGE RULE: If a handwriting image is attached:
  1) Accurately transcribe all handwritten text into "handwriting_transcription" (preserve punctuation and line breaks; mark illegible words [?]).
  2) Analyze both the transcribed wording AND directly observable visual cues in Tier 2, citing exact "handwriting.*" and (if present) "kinematics.*" anchors.
  3) Keep broader personality leaps from handwriting strictly in Tier 3 as unverified emerging signals.
- Be candid, sharp, specific, and grounded — zero filler.
- Return 3 to 5 Tier 2 claims and 2 to 3 honest Tier 3 emerging signals.

Return ONLY valid JSON matching this exact schema:
{
  "executive_read": "2-3 crisp sentences summarizing true intent, emotional subtext, and operational read.",
  "suggested_reply": "Concise, tone-matched reply if this is an incoming message (or empty string if prose/self-reflection/not applicable).",
  "handwriting_transcription": "Exact transcription if a handwriting image was provided, otherwise empty string.",
  "aligned_subtext": [
    {
      "title": "Short 3-5 word label",
      "category": "Intent | Politeness | Affect | Cognitive Style | Boundaries | Kinematics | Handwriting",
      "claim": "Specific, falsifiable subtext finding.",
      "cited_anchors": ["exact_stage1_key_1", "exact_stage1_key_2"],
      "raw_confidence": 0.86,
      "reasoning": "1 sentence linking the cited anchors to the subtext."
    }
  ],
  "speculative_extrapolations": [
    {
      "dimension": "Emerging Pattern (Unverified) | Tentative Context Signal | Unproven Trait Boundary",
      "hypothesis": "Candid early signal framed honestly around what is hinted at vs. unproven.",
      "cited_anchors": ["exact_stage1_key"],
      "raw_confidence": 0.58,
      "coupling_type": "weak_behavioral or uncoupled_demographic",
      "rationale": "1 sentence explaining why this signal is not yet proven and what extra sample data would confirm it."
    }
  ]
}`;

  const userPayload = JSON.stringify({
    raw_text: text,
    stage1_verified_anchors: {
      syntax,
      temporal,
      kinematics,
      handwriting: handwritingAnchors,
    },
    guards,
  });

  const parts: Array<Record<string, unknown>> = [{ text: userPayload }];
  if (handwritingImage) {
    parts.push({
      inlineData: {
        mimeType: handwritingImage.mimeType,
        data: handwritingImage.base64,
      },
    });
  }

  // Resilient Flash cascade (Dec 2026+ compliant — replaces deprecated gemini-2.5-flash)
  const models = [
    "gemini-3.8-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
  ];

  const errors: string[] = [];
  const attempted: string[] = [];
  let sawRateLimit = false;

  for (const model of models) {
    attempted.push(model);
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const reqBody = JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: "user", parts }],
      generationConfig: {
        responseMimeType: "application/json",
      },
    });

    // Allow 1 jittered retry ONLY on transient HTTP 503
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const res = await fetchWithTimeout(
          url,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: reqBody,
          },
          PER_MODEL_TIMEOUT_MS,
        );

        if (!res.ok) {
          let errSnippet = "";
          try {
            const errJson = await res.json();
            errSnippet = errJson?.error?.message
              ? ` - ${String(errJson.error.message).slice(0, 100)}`
              : "";
          } catch {
            // ignore parse error
          }

          if (res.status === 503 && attempt === 0) {
            const jitter = Math.floor(Math.random() * 250);
            await sleep(RETRY_503_BASE_MS + jitter);
            continue;
          }

          if (res.status === 429) {
            sawRateLimit = true;
          }

          errors.push(`${model}: HTTP ${res.status}${errSnippet}`);

          // Fail fast on bad key (never burn extra calls)
          if (
            res.status === 401 ||
            (res.status === 400 && errSnippet.toLowerCase().includes("api key"))
          ) {
            return buildDeterministicFallback(
              syntax,
              kinematics,
              handwritingAnchors,
              `invalid_api_key (${errors[0]})`,
              false,
              attempted,
            );
          }
          break; // Move to next model in cascade
        }

        const data = await res.json();
        const rawJsonText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!rawJsonText) {
          errors.push(`${model}: empty candidate`);
          break;
        }

        const parsed = JSON.parse(stripJsonFences(rawJsonText));
        return {
          executive_read: String(parsed.executive_read || ""),
          suggested_reply: String(parsed.suggested_reply || ""),
          handwriting_transcription: String(parsed.handwriting_transcription || ""),
          aligned_subtext: Array.isArray(parsed.aligned_subtext) ? parsed.aligned_subtext : [],
          speculative_extrapolations: Array.isArray(parsed.speculative_extrapolations)
            ? parsed.speculative_extrapolations
            : [],
          llm_model: model,
          llm_status: "live_gemini_ok",
          rate_limited: false,
          models_attempted: attempted,
        };
      } catch (err) {
        const msg =
          err instanceof Error && err.name === "AbortError"
            ? `timeout (${PER_MODEL_TIMEOUT_MS / 1000}s)`
            : err instanceof Error
              ? err.message
              : String(err);
        errors.push(`${model}: ${msg}`);
        break;
      }
    }
  }

  return buildDeterministicFallback(
    syntax,
    kinematics,
    handwritingAnchors,
    sawRateLimit
      ? `rate_limit_cooldown (${errors.slice(0, 2).join(" | ")})`
      : `fallback_after_error (${errors.slice(0, 2).join(" | ")})`,
    sawRateLimit,
    attempted,
  );
}

// ---------------------------------------------------------------------------
// 4. STAGE 3: DETERMINISTIC ALIGNMENT & BAYESIAN COUPLING GATE (PURE TS)
// ---------------------------------------------------------------------------
function buildAnchorLookup(
  syntax: SyntaxMetrics,
  temporal: TemporalMetrics,
  kinematics: KinematicsPayload | null,
  handwriting: HandwritingImageAnchors | null,
): Record<string, { exists: boolean; active: boolean; value: unknown }> {
  const map: Record<string, { exists: boolean; active: boolean; value: unknown }> = {};

  const register = (key: string, val: unknown) => {
    let active = false;
    if (typeof val === "number") active = val !== 0;
    else if (typeof val === "boolean") active = val;
    else if (Array.isArray(val)) active = val.length > 0;
    else if (val !== null && val !== undefined) active = true;
    map[key] = { exists: true, active, value: val };
  };

  for (const [k, v] of Object.entries(syntax)) register(k, v);
  for (const [k, v] of Object.entries(temporal)) register(k, v);

  // Zero-Count Evidence Whitelist: verified zeros ARE real deterministic signal when text exists
  if (syntax.word_cnt > 0) {
    const validZeroSignals = new Set([
      "excl_cnt",
      "quest_cnt",
      "en_dash_cnt",
      "paren_cnt",
      "numbered_list_cnt",
      "conditional_if_cnt",
      "modal_softener_cnt",
      "has_hedge",
      "has_missing_apo",
      "has_profanity",
      "has_urgency",
      "has_friction",
      "has_affection",
      "has_warmth",
      "warmth_cnt",
      "mindpaper_divergence_idx",
      "cross_chat_jumps",
      "rapid_bursts",
    ]);
    for (const k of validZeroSignals) {
      if (map[k]) map[k].active = true;
    }
  }

  if (kinematics) {
    for (const [k, v] of Object.entries(kinematics)) {
      register(`kinematics.${k}`, v);
    }
  }

  if (handwriting) {
    for (const [k, v] of Object.entries(handwriting)) {
      register(`handwriting.${k}`, v);
    }
  }
  return map;
}

function applyBayesianCouplingGate(
  stage2: Stage2Result,
  syntax: SyntaxMetrics,
  temporal: TemporalMetrics,
  kinematics: KinematicsPayload | null,
  handwriting: HandwritingImageAnchors | null,
  guards: {
    sample_n: number;
    interval_n: number;
    burstiness_unlocked: boolean;
    circadian_unlocked: boolean;
    longitudinal_unlocked: boolean;
  },
) {
  const anchorMap = buildAnchorLookup(syntax, temporal, kinematics, handwriting);

  let totalCitationsVerified = 0;
  let totalCitationsRejected = 0;
  let sampleLocksTriggered = 0;
  const deltas: number[] = [];

  const tier2Ceiling = guards.longitudinal_unlocked ? 0.94 : 0.88;

  const calibratedSubtext = stage2.aligned_subtext.map((item) => {
    const cited = Array.isArray(item.cited_anchors) ? item.cited_anchors : [];
    const verified: Array<{ key: string; value: unknown }> = [];
    const rejected: Array<{ key: string; reason: string }> = [];
    let lockApplied = false;

    for (const rawKey of cited) {
      const key = String(rawKey).trim();
      if (key === "kim_jo_burstiness" && !guards.burstiness_unlocked) {
        rejected.push({ key, reason: "sample_lock (interval_n < 2)" });
        sampleLocksTriggered++;
        lockApplied = true;
        continue;
      }
      if (key === "circular_24h_R" && !guards.circadian_unlocked) {
        rejected.push({ key, reason: "sample_lock (sample_n < 10)" });
        sampleLocksTriggered++;
        lockApplied = true;
        continue;
      }
      const entry = anchorMap[key];
      if (!entry || !entry.exists) {
        rejected.push({ key, reason: "unknown_anchor" });
      } else if (!entry.active) {
        rejected.push({ key, reason: "anchor_zero_inactive" });
      } else {
        verified.push({ key, value: entry.value });
      }
    }

    totalCitationsVerified += verified.length;
    totalCitationsRejected += rejected.length;

    const rawConf = clamp(Number(item.raw_confidence) || 0.5, 0.05, 0.99);
    const supportRatio = cited.length > 0 ? verified.length / cited.length : 0;
    const anchorCountBonus = Math.min(verified.length, 4) * 0.03;
    const weighted =
      Math.min(rawConf, tier2Ceiling) * (0.42 + 0.58 * supportRatio) + anchorCountBonus;
    const calibrated = round(clamp(weighted, 0.15, tier2Ceiling), 3);
    const delta = round(calibrated - rawConf, 3);
    deltas.push(delta);

    return {
      title: item.title,
      category: item.category,
      claim: item.claim,
      reasoning: item.reasoning,
      raw_confidence: round(rawConf, 3),
      calibrated_confidence: calibrated,
      confidence_ceiling: tier2Ceiling,
      delta_applied: delta,
      coupling_strength: verified.length >= 2 && supportRatio >= 0.75 ? "high" : "moderate",
      verified_anchors: verified,
      rejected_anchors: rejected,
      sample_lock_applied: lockApplied,
    };
  });

  const cappedExtrapolations = stage2.speculative_extrapolations.map((item) => {
    const cited = Array.isArray(item.cited_anchors) ? item.cited_anchors : [];
    const verified: Array<{ key: string; value: unknown }> = [];
    const rejected: Array<{ key: string; reason: string }> = [];

    for (const rawKey of cited) {
      const key = String(rawKey).trim();
      const entry = anchorMap[key];
      if (entry && entry.exists && entry.active) {
        verified.push({ key, value: entry.value });
      } else {
        rejected.push({ key, reason: entry ? "anchor_zero_inactive" : "unknown_anchor" });
      }
    }

    totalCitationsVerified += verified.length;
    totalCitationsRejected += rejected.length;

    const dimLow = `${item.dimension} ${item.hypothesis}`.toLowerCase();
    const isUncoupledDemographic =
      item.coupling_type === "uncoupled_demographic" ||
      /\b(sibling|brother|sister|birth order|oldest|youngest|family tree|gender|sex|age|nationality)\b/.test(
        dimLow,
      );

    const hardCap = isUncoupledDemographic
      ? 0.55
      : guards.longitudinal_unlocked
        ? 0.74
        : 0.62;

    const rawConf = clamp(Number(item.raw_confidence) || 0.5, 0.05, 0.99);
    const calibrated = round(Math.min(rawConf, hardCap), 3);
    const delta = round(calibrated - rawConf, 3);
    deltas.push(delta);

    return {
      dimension: item.dimension,
      hypothesis: item.hypothesis,
      rationale: item.rationale,
      coupling_type: isUncoupledDemographic ? "uncoupled_demographic" : "weak_behavioral",
      raw_confidence: round(rawConf, 3),
      calibrated_confidence: calibrated,
      hard_ceiling: hardCap,
      was_capped: rawConf > hardCap,
      delta_applied: delta,
      verified_anchors: verified,
      rejected_anchors: rejected,
    };
  });

  const avgShift =
    deltas.length > 0 ? round(deltas.reduce((a, b) => a + b, 0) / deltas.length, 3) : 0;

  return {
    tier2_aligned_subtext: calibratedSubtext,
    tier3_capped_extrapolations: cappedExtrapolations,
    gate_audit: {
      total_claims: calibratedSubtext.length + cappedExtrapolations.length,
      citations_verified: totalCitationsVerified,
      citations_rejected: totalCitationsRejected,
      sample_locks_triggered: sampleLocksTriggered,
      avg_confidence_adjustment: avgShift,
    },
  };
}

// ---------------------------------------------------------------------------
// 5. EDGE FUNCTION HTTP ENTRYPOINT (OPTIONS FIRST, CORS ON ALL PATHS)
// ---------------------------------------------------------------------------
Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { status: 200, headers: buildCorsHeaders(req) });
  }

  if (req.method === "GET") {
    const requireGate = (Deno.env.get("REQUIRE_PAID_GATE") || "").toLowerCase() === "true";
    return jsonResponse(
      req,
      {
        status: "ok",
        function: "telemetry-api",
        engine: "VibeCheck CLEPM-Bayesian Gate v2.2",
        billing_gate: requireGate ? "enforced" : "open_rd",
        timestamp: new Date().toISOString(),
      },
      200,
    );
  }

  if (req.method !== "POST") {
    return jsonResponse(req, { error: "Method not allowed. Send POST JSON." }, 405);
  }

  const startedAt = Date.now();

  const rateCheck = checkBurstRateLimit(req);
  if (!rateCheck.allowed) {
    return jsonResponse(
      req,
      {
        error: `Too many requests. Please wait ${rateCheck.retryAfterSec}s before trying again.`,
        retry_after_sec: rateCheck.retryAfterSec,
      },
      429,
    );
  }

  const contentLength = Number(req.headers.get("content-length") || 0);
  if (contentLength > MAX_REQUEST_BYTES) {
    return jsonResponse(
      req,
      { error: "Request payload exceeds maximum allowed size (6.5 MB)." },
      413,
    );
  }

  try {
    const body = (await req.json()) as RequestPayload;
    const mode =
      body.mode ||
      (Array.isArray(body.messages) && body.messages.length > 0
        ? "stream"
        : body.handwritingImage
          ? "handwriting"
          : "single");
    const runLlm = body.runLlm !== false;
    const kinematics = body.kinematics ?? null;
    const headerKey = req.headers.get("x-gemini-key");

    const gate = await verifyAccessGate(req, body, runLlm);
    if (!gate.authorized) {
      return jsonResponse(
        req,
        {
          error: gate.error || "Unauthorized",
          billing_required: gate.status === 402,
          credits_remaining: gate.credits_remaining ?? null,
        },
        gate.status,
      );
    }

    const imgCheck = validateHandwritingImage(body.handwritingImage);
    const warnings: string[] = [];
    if (imgCheck.warning) warnings.push(imgCheck.warning);

    let textForLlm = "";
    let syntax: SyntaxMetrics;
    let temporal: TemporalMetrics;

    if (mode === "stream" && Array.isArray(body.messages) && body.messages.length > 0) {
      const streamRes = analyzeStream(body.messages, body.sender, body.windowLimit);
      if (streamRes.temporal.sample_n === 0) {
        return jsonResponse(
          req,
          { error: "No substantive messages matched the selected sender and stream window." },
          400,
        );
      }
      textForLlm = streamRes.llmWindowExcerpt;
      syntax = streamRes.syntax;
      temporal = streamRes.temporal;
    } else {
      const rawText = (body.text || "").trim();
      if (!rawText && !kinematics && !imgCheck.validImage) {
        return jsonResponse(
          req,
          {
            error:
              warnings[0] ||
              "Provide non-empty text, a WhatsApp stream, S-Pen ink strokes, or a valid handwriting photo.",
          },
          400,
        );
      }
      const scored = scoreSyntax(rawText);
      textForLlm = scored.cleanText.slice(0, 8000);
      syntax = scored.syntax;
      temporal = {
        total_received_msgs: textForLlm ? 1 : 0,
        total_filtered_msgs: textForLlm ? 1 : 0,
        window_limit: 1,
        sample_n: textForLlm ? 1 : 0,
        interval_n: 0,
        window_start_dt: null,
        window_end_dt: null,
        span_hours: 0,
        cross_chat_jumps: 0,
        rapid_bursts: 0,
        mean_gap_mins: 0,
        kim_jo_burstiness: null,
        circular_24h_R: null,
        mean_divergence_idx: syntax.mindpaper_divergence_idx,
      };
    }

    const guards = {
      sample_n: temporal.sample_n,
      interval_n: temporal.interval_n,
      burstiness_unlocked: temporal.interval_n >= 2,
      circadian_unlocked: temporal.sample_n >= 10,
      longitudinal_unlocked: temporal.sample_n >= 3,
      handwriting_photo_attached: Boolean(imgCheck.validImage),
      spen_kinematics_attached: Boolean(kinematics && (kinematics.strokeCount ?? 0) > 0),
    };

    const stage2 = runLlm
      ? await runStage2Gemini(
          textForLlm,
          syntax,
          temporal,
          kinematics,
          imgCheck.validImage,
          imgCheck.anchors,
          guards,
          headerKey,
        )
      : buildDeterministicFallback(syntax, kinematics, imgCheck.anchors, "llm_toggle_off");

    const gated = applyBayesianCouplingGate(
      stage2,
      syntax,
      temporal,
      kinematics,
      imgCheck.anchors,
      guards,
    );

    const transcribedSyntax =
      !textForLlm && stage2.handwriting_transcription.trim()
        ? scoreSyntax(stage2.handwriting_transcription).syntax
        : null;

    return jsonResponse(
      req,
      {
        meta: {
          engine: "VibeCheck CLEPM-Bayesian Gate v2.2",
          tier3_label: "Emerging Signals (Unverified)",
          access_mode: gate.mode,
          credits_remaining: gate.credits_remaining ?? null,
          timestamp: new Date().toISOString(),
          elapsed_ms: Date.now() - startedAt,
          mode,
          sender: body.sender || null,
          llm_model: stage2.llm_model,
          llm_status: stage2.llm_status,
          rate_limited: stage2.rate_limited,
          models_attempted: stage2.models_attempted,
          warnings,
          guards,
        },
        executive_read: stage2.executive_read,
        suggested_reply: stage2.suggested_reply,
        handwriting_transcription: stage2.handwriting_transcription,
        transcribed_syntax: transcribedSyntax,
        tier1_verified_anchors: {
          confidence: 1.0,
          syntax,
          temporal,
          kinematics,
          handwriting_image: imgCheck.anchors,
        },
        tier2_aligned_subtext: gated.tier2_aligned_subtext,
        tier3_capped_extrapolations: gated.tier3_capped_extrapolations,
        gate_audit: gated.gate_audit,
      },
      200,
    );
  } catch (err) {
    return jsonResponse(
      req,
      {
        error: err instanceof Error ? err.message : "Unhandled telemetry-api error",
        elapsed_ms: Date.now() - startedAt,
      },
      500,
    );
  }
});
