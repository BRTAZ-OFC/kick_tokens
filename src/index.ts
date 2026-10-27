/** Kick OAuth Worker for LiveNexus. Backend-only private API. */
interface Env {
  KICK_STORE: KVNamespace;
  KICK_CLIENT_ID: string;
  KICK_CLIENT_SECRET: string;
  LIVENEXUS_API_KEY: string;
  WORKER_URL: string;
  LIVENEXUS_ORIGIN: string;
}
type JsonData = Record<string, unknown>;
interface OAuthTransaction { userId: string; verifier: string; redirectUri: string }
interface KickTokens { accessToken: string; refreshToken: string | null; expiresAt: number }
interface KickResponse { access_token?: string; refresh_token?: string; expires_in?: number }
interface KickChannel {
  slug?: string;
  stream_title?: string;
  category?: { id?: number; name?: string } | null;
  stream?: { is_live?: boolean } | null;
}
class HttpError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}
const KICK_AUTH = "https://id.kick.com/oauth/authorize";
const KICK_TOKEN = "https://id.kick.com/oauth/token";
const KICK_CHANNEL = "https://api.kick.com/public/v1/channels";
const SCOPE = "user:read channel:read channel:write";
const SAFE_HEADERS = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};
const responseJson = (value: JsonData, status = 200): Response =>
  new Response(JSON.stringify(value), {
    status, headers: { ...SAFE_HEADERS, "Content-Type": "application/json; charset=utf-8" },
  });
const kvToken = (id: string): string => "kick:tokens:" + id;
const kvState = (state: string): string => "kick:oauth:" + state;

function requireUserId(value: unknown): string {
  if (typeof value !== "string" || !/^[\w.:\-@]{1,128}$/.test(value))
    throw new HttpError(400, "user_id invalido.");
  return value;
}
async function readBody(request: Request): Promise<JsonData> {
  let value: unknown;
  try { value = await request.json(); } catch { throw new HttpError(400, "JSON invalido."); }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new HttpError(400, "JSON invalido.");
  return value as JsonData;
}
function configured(env: Env): boolean {
  return Boolean(env.KICK_STORE && env.KICK_CLIENT_ID?.trim()
    && env.KICK_CLIENT_SECRET?.trim() && env.LIVENEXUS_API_KEY?.length >= 32
    && env.WORKER_URL?.trim() && env.LIVENEXUS_ORIGIN?.trim());
}
function ensureConfigured(env: Env): void {
  if (!configured(env)) throw new HttpError(503, "Secrets, URLs ou KV ainda nao configurados.");
}
function expectedCallback(env: Env): string {
  try {
    const url = new URL(env.WORKER_URL);
    if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash)
      throw new Error("URL");
    return url.origin + "/auth/kick/callback";
  } catch { throw new HttpError(503, "WORKER_URL invalida: informe somente a origem HTTPS."); }
}
function expectedOrigin(env: Env): string {
  try {
    const url = new URL(env.LIVENEXUS_ORIGIN);
    if (url.origin !== env.LIVENEXUS_ORIGIN || url.protocol !== "https:")
      throw new Error("Origem");
    return url.origin;
  } catch { throw new HttpError(503, "LIVENEXUS_ORIGIN invalida: informe somente a origem HTTPS."); }
}
function adminAuthorized(request: Request, env: Env): boolean {
  const supplied = (request.headers.get("Authorization") || "").replace(/^Bearer /, "");
  const expected = env.LIVENEXUS_API_KEY || "";
  if (!supplied || supplied.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++)
    diff |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}
function randomToken(bytes = 32): string {
  let text = "";
  for (const byte of crypto.getRandomValues(new Uint8Array(bytes)))
    text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function sha256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let text = "";
  for (const byte of new Uint8Array(digest)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function requestTokens(env: Env, params: Record<string, string>): Promise<KickResponse> {
  const body = new URLSearchParams({
    ...params, client_id: env.KICK_CLIENT_ID, client_secret: env.KICK_CLIENT_SECRET,
  });
  const response = await fetch(KICK_TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
  });
  if (!response.ok)
    throw new HttpError(401, "Kick recusou a troca/renovacao do token (HTTP " + response.status + ").");
  let tokens: KickResponse;
  try { tokens = await response.json() as KickResponse; }
  catch { throw new HttpError(502, "Resposta de token invalida da Kick."); }
  if (!tokens.access_token || typeof tokens.access_token !== "string")
    throw new HttpError(502, "Kick nao forneceu access_token.");
  return tokens;
}
function normalizedTokens(raw: KickResponse, fallbackRefresh: string | null = null): KickTokens {
  return {
    accessToken: raw.access_token as string,
    refreshToken: raw.refresh_token || fallbackRefresh,
    expiresAt: Date.now() + Math.max(60, Number(raw.expires_in) || 3600) * 1000,
  };
}
async function activeTokens(env: Env, userId: string): Promise<KickTokens> {
  const saved = await env.KICK_STORE.get<KickTokens>(kvToken(userId), "json");
  if (!saved?.accessToken) throw new HttpError(401, "Kick nao conectada. Autorize sua conta.");
  if (saved.expiresAt > Date.now() + 60_000) return saved;
  if (!saved.refreshToken) throw new HttpError(401, "Token Kick expirou. Autorize novamente.");
  const renewed = normalizedTokens(await requestTokens(env, {
    grant_type: "refresh_token", refresh_token: saved.refreshToken,
  }), saved.refreshToken);
  await env.KICK_STORE.put(kvToken(userId), JSON.stringify(renewed));
  return renewed;
}
async function authorize(request: Request, env: Env): Promise<Response> {
  const userId = requireUserId((await readBody(request)).user_id);
  const redirectUri = expectedCallback(env);
  expectedOrigin(env);
  const state = randomToken();
  const verifier = randomToken();
  const transaction: OAuthTransaction = { userId, verifier, redirectUri };
  await env.KICK_STORE.put(kvState(state), JSON.stringify(transaction), { expirationTtl: 600 });

  const url = new URL(KICK_AUTH);
  url.searchParams.set("client_id", env.KICK_CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("scope", SCOPE);
  url.searchParams.set("code_challenge", await sha256Challenge(verifier));
  url.searchParams.set("code_challenge_method", "S256");
  return responseJson({ ok: true, authorization_url: url.toString(), callback_url: redirectUri });
}
function oauthPage(env: Env, success: boolean): Response {
  const nonce = randomToken(16);
  const payload = JSON.stringify({
    type: success ? "KICK_AUTH_SUCCESS" : "KICK_AUTH_ERROR",
    platform: "kick",
  });
  const origin = JSON.stringify(expectedOrigin(env));
  const html = [
    '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">',
    '<title>Kick - LiveNexus</title></head><body><h2>',
    success ? "Kick conectada." : "Autorizacao Kick falhou.",
    '</h2><p>Voce pode fechar esta janela.</p>',
    '<script nonce="' + nonce + '">',
    'if(window.opener){window.opener.postMessage(' + payload + ',' + origin + ');window.close();}',
    '</script></body></html>',
  ].join("");
  return new Response(html, {
    status: success ? 200 : 400,
    headers: {
      ...SAFE_HEADERS, "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; script-src 'nonce-" + nonce + "'; frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    },
  });
}
async function callback(request: Request, env: Env): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const state = params.get("state") || "";
  if (!/^[A-Za-z0-9_-]{43}$/.test(state)) return oauthPage(env, false);
  const record = await env.KICK_STORE.get<OAuthTransaction>(kvState(state), "json");
  if (!record?.userId || !record.verifier || !record.redirectUri) return oauthPage(env, false);
  // Remove o state antes de trocar o codigo; codigo OAuth da Kick tambem e de uso unico.
  await env.KICK_STORE.delete(kvState(state));
  const code = params.get("code");
  if (!code || params.has("error")) return oauthPage(env, false);
  try {
    const raw = await requestTokens(env, {
      grant_type: "authorization_code", code, code_verifier: record.verifier,
      redirect_uri: record.redirectUri,
    });
    await env.KICK_STORE.put(kvToken(record.userId), JSON.stringify(normalizedTokens(raw)));
    return oauthPage(env, true);
  } catch { return oauthPage(env, false); }
}
async function kickChannel(env: Env, userId: string, patch?: JsonData): Promise<JsonData> {
  const tokens = await activeTokens(env, userId);
  const update = patch !== undefined;
  const response = await fetch(KICK_CHANNEL, {
    method: update ? "PATCH" : "GET",
    headers: {
      Authorization: "Bearer " + tokens.accessToken,
      Accept: "application/json",
      ...(update ? { "Content-Type": "application/json" } : {}),
    },
    ...(update ? { body: JSON.stringify(patch) } : {}),
  });
  if (response.status === 401 || response.status === 403)
    throw new HttpError(response.status, "Kick nao autorizou a operacao. Reconecte a conta.");
  if (!response.ok)
    throw new HttpError(502, "Kick retornou erro HTTP " + response.status + ".");
  if (update) return { ok: true, message: "Titulo/categoria atualizados na Kick." };
  let data: { data?: KickChannel[] };
  try { data = await response.json() as { data?: KickChannel[] }; }
  catch { throw new HttpError(502, "Resposta do canal Kick invalida."); }
  const channel = Array.isArray(data.data) ? data.data[0] : undefined;
  return {
    ok: true, connected: true,
    slug: channel?.slug || null,
    title: channel?.stream_title || null,
    category: channel?.category || null,
    is_live: channel?.stream?.is_live ?? false,
  };
}
async function updateChannel(request: Request, env: Env): Promise<Response> {
  const body = await readBody(request);
  const userId = requireUserId(body.user_id);
  const patch: JsonData = {};
  if (body.title !== undefined) {
    if (typeof body.title !== "string" || !body.title.trim() || body.title.trim().length > 100)
      throw new HttpError(400, "Titulo invalido (1 a 100 caracteres).");
    patch.stream_title = body.title.trim();
  }
  if (body.category_id !== undefined) {
    const id = Number(body.category_id);
    if (!Number.isSafeInteger(id) || id <= 0)
      throw new HttpError(400, "category_id invalido.");
    patch.category_id = id;
  }
  if (!Object.keys(patch).length) throw new HttpError(400, "Informe title e/ou category_id.");
  return responseJson(await kickChannel(env, userId, patch));
}
async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/" || url.pathname === "/health")
    return responseJson({ ok: true, service: "kick_tokens", configured: configured(env) });

  if (url.pathname === "/auth/kick/callback" && request.method === "GET") {
    ensureConfigured(env);
    return callback(request, env);
  }
  if (!url.pathname.startsWith("/api/kick/"))
    return responseJson({ ok: false, message: "Rota inexistente." }, 404);
  if (!adminAuthorized(request, env))
    return responseJson({ ok: false, message: "Nao autorizado." }, 401);
  ensureConfigured(env);

  if (url.pathname === "/api/kick/authorize" && request.method === "POST")
    return authorize(request, env);
  if (url.pathname === "/api/kick/status" && request.method === "GET")
    return responseJson(await kickChannel(env, requireUserId(url.searchParams.get("user_id"))));
  if (url.pathname === "/api/kick/channel" && request.method === "PATCH")
    return updateChannel(request, env);
  if (url.pathname === "/api/kick/disconnect" && request.method === "POST") {
    const body = await readBody(request);
    await env.KICK_STORE.delete(kvToken(requireUserId(body.user_id)));
    return responseJson({ ok: true, message: "Kick desconectada." });
  }
  return responseJson({ ok: false, message: "Rota inexistente." }, 404);
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try { return await handle(request, env); }
    catch (err) {
      if (err instanceof HttpError)
        return responseJson({ ok: false, message: err.message }, err.status);
      // Nao imprimir tokens, state, Client Secret ou respostas OAuth.
      console.error("[Kick Worker] Falha interna:", err instanceof Error ? err.name : "Error");
      return responseJson({ ok: false, message: "Falha interna no Worker Kick." }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
