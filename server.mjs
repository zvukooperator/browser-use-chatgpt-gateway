import http from "node:http";
import crypto from "node:crypto";

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const UPSTREAM_MCP_URL = "https://api.browser-use.com/v3/mcp";
const REQUIRED_SCOPE = "browser:use";
const CODE_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_SECONDS = 8 * 60 * 60;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const authorizationCodes = new Map();
const failedLogins = new Map();

function publicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/$/, "");
  if (process.env.RENDER_EXTERNAL_HOSTNAME) return `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;
  const forwardedProto = req.headers["x-forwarded-proto"]?.split(",")[0]?.trim();
  const protocol = forwardedProto || (req.socket.encrypted ? "https" : "http");
  return `${protocol}://${req.headers.host}`;
}

function resourceUrl(req) {
  return `${publicBaseUrl(req)}/mcp`;
}

function json(res, status, value, extraHeaders = {}) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function text(res, status, body, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "content-type": contentType,
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  res.end(body);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("request_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function safeEqual(left, right) {
  const a = Buffer.from(left || "");
  const b = Buffer.from(right || "");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function signingKey() {
  const password = process.env.GATEWAY_PASSWORD || "";
  const apiKey = process.env.BROWSER_USE_API_KEY || "";
  return crypto.createHash("sha256").update(`browser-use-gateway\0${password}\0${apiKey}`).digest();
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function signAccessToken(claims) {
  const payload = b64url(JSON.stringify(claims));
  const signature = crypto.createHmac("sha256", signingKey()).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verifyAccessToken(token, expectedAudience) {
  if (!token || !token.includes(".")) return false;
  const [payload, signature] = token.split(".");
  const expected = crypto.createHmac("sha256", signingKey()).update(payload).digest("base64url");
  if (!safeEqual(signature, expected)) return false;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return (
      claims.exp > Math.floor(Date.now() / 1000) &&
      claims.aud === expectedAudience &&
      claims.scope?.split(" ").includes(REQUIRED_SCOPE)
    );
  } catch {
    return false;
  }
}

function isAllowedRedirect(uri) {
  try {
    const url = new URL(uri);
    return url.protocol === "https:" && url.hostname === "chatgpt.com" && (
      url.pathname.startsWith("/connector/oauth/") ||
      url.pathname === "/connector_platform_oauth_redirect"
    );
  } catch {
    return false;
  }
}

function isAllowedClientId(clientId) {
  try {
    const url = new URL(clientId);
    return url.protocol === "https:" && url.hostname === "chatgpt.com" &&
      url.pathname.startsWith("/oauth/") && url.pathname.endsWith("/client.json");
  } catch {
    return false;
  }
}

function cleanExpiredState() {
  const now = Date.now();
  for (const [code, record] of authorizationCodes) {
    if (record.expiresAt <= now) authorizationCodes.delete(code);
  }
  for (const [ip, record] of failedLogins) {
    if (record.resetAt <= now) failedLogins.delete(ip);
  }
}

function clientIp(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
}

function loginBlocked(req) {
  cleanExpiredState();
  const record = failedLogins.get(clientIp(req));
  return Boolean(record && record.count >= 8 && record.resetAt > Date.now());
}

function recordFailedLogin(req) {
  const ip = clientIp(req);
  const current = failedLogins.get(ip);
  if (!current || current.resetAt <= Date.now()) {
    failedLogins.set(ip, { count: 1, resetAt: Date.now() + 15 * 60 * 1000 });
  } else {
    current.count += 1;
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function authorizePage(params, error = "") {
  const hidden = [...params.entries()]
    .filter(([key]) => key !== "password")
    .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
    .join("\n");
  const errorHtml = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Browser Use — подключение</title>
<style>body{font:16px system-ui;background:#101014;color:#f5f5f5;display:grid;place-items:center;min-height:100vh;margin:0}.box{width:min(420px,calc(100% - 40px));background:#19191f;padding:28px;border-radius:16px}label,input,button{display:block;width:100%;box-sizing:border-box}input{margin:8px 0 18px;padding:12px;border-radius:9px;border:1px solid #555;background:#0f0f13;color:#fff}button{padding:12px;border:0;border-radius:9px;background:#7c5cff;color:#fff;font-weight:700;cursor:pointer}.error{color:#ff8e8e}.muted{color:#aaa;font-size:14px}</style>
</head><body><main class="box"><h1>Browser Use Cloud</h1><p>Разрешить этому ChatGPT запускать задачи Browser Use через ваш приватный шлюз.</p>${errorHtml}
<form method="post" action="/authorize">${hidden}<label>Пароль шлюза<input type="password" name="password" autocomplete="current-password" required autofocus></label><button type="submit">Подключить</button></form>
<p class="muted">API‑ключ Browser Use не передаётся в ChatGPT и хранится только в Render.</p></main></body></html>`;
}

function validateAuthorizeParams(params, req) {
  if (params.get("response_type") !== "code") return "Неподдерживаемый response_type";
  if (!params.get("state")) return "Отсутствует state";
  if (!params.get("code_challenge") || params.get("code_challenge_method") !== "S256") return "Требуется PKCE S256";
  if (!isAllowedRedirect(params.get("redirect_uri"))) return "Недопустимый redirect_uri";
  if (!isAllowedClientId(params.get("client_id"))) return "Недопустимый client_id";
  if (params.get("resource") !== resourceUrl(req)) return "Недопустимый resource";
  const scopes = (params.get("scope") || "").split(/\s+/);
  if (!scopes.includes(REQUIRED_SCOPE)) return "Недопустимый scope";
  return "";
}

async function handleAuthorize(req, res, url) {
  let params;
  if (req.method === "GET") {
    params = url.searchParams;
  } else {
    const body = await readBody(req);
    params = new URLSearchParams(body.toString("utf8"));
  }

  const validationError = validateAuthorizeParams(params, req);
  if (validationError) return text(res, 400, validationError);
  if (!process.env.GATEWAY_PASSWORD || process.env.GATEWAY_PASSWORD.length < 16) {
    return text(res, 503, "GATEWAY_PASSWORD must be configured with at least 16 characters.");
  }

  if (req.method === "GET") {
    return text(res, 200, authorizePage(params), "text/html; charset=utf-8");
  }

  if (loginBlocked(req)) return text(res, 429, authorizePage(params, "Слишком много попыток. Повторите позднее."), "text/html; charset=utf-8");
  if (!safeEqual(params.get("password"), process.env.GATEWAY_PASSWORD)) {
    recordFailedLogin(req);
    return text(res, 401, authorizePage(params, "Неверный пароль."), "text/html; charset=utf-8");
  }

  const code = crypto.randomBytes(32).toString("base64url");
  authorizationCodes.set(code, {
    clientId: params.get("client_id"),
    redirectUri: params.get("redirect_uri"),
    codeChallenge: params.get("code_challenge"),
    resource: params.get("resource"),
    scope: REQUIRED_SCOPE,
    expiresAt: Date.now() + CODE_TTL_MS,
  });

  const redirect = new URL(params.get("redirect_uri"));
  redirect.searchParams.set("code", code);
  redirect.searchParams.set("state", params.get("state"));
  redirect.searchParams.set("iss", publicBaseUrl(req));
  res.writeHead(302, { location: redirect.toString(), "cache-control": "no-store" });
  res.end();
}

async function handleToken(req, res) {
  const params = new URLSearchParams((await readBody(req)).toString("utf8"));
  if (params.get("grant_type") !== "authorization_code") return json(res, 400, { error: "unsupported_grant_type" });
  const code = params.get("code");
  const record = authorizationCodes.get(code);
  authorizationCodes.delete(code);
  if (!record || record.expiresAt <= Date.now()) return json(res, 400, { error: "invalid_grant" });
  if (params.get("client_id") !== record.clientId || params.get("redirect_uri") !== record.redirectUri) {
    return json(res, 400, { error: "invalid_grant" });
  }
  const verifier = params.get("code_verifier") || "";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  if (!safeEqual(challenge, record.codeChallenge)) return json(res, 400, { error: "invalid_grant" });

  const now = Math.floor(Date.now() / 1000);
  const accessToken = signAccessToken({
    iss: publicBaseUrl(req),
    aud: record.resource,
    sub: "gateway-owner",
    scope: record.scope,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS,
    jti: crypto.randomUUID(),
  });
  return json(res, 200, {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: TOKEN_TTL_SECONDS,
    scope: record.scope,
  });
}

function unauthorized(req, res) {
  const metadata = `${publicBaseUrl(req)}/.well-known/oauth-protected-resource`;
  json(res, 401, { error: "unauthorized" }, {
    "www-authenticate": `Bearer resource_metadata="${metadata}", scope="${REQUIRED_SCOPE}"`,
  });
}

async function proxyMcp(req, res, url) {
  if (!process.env.BROWSER_USE_API_KEY?.startsWith("bu_")) return text(res, 503, "BROWSER_USE_API_KEY is not configured.");
  const bearer = req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!verifyAccessToken(bearer, resourceUrl(req))) return unauthorized(req, res);

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (!value || ["host", "authorization", "content-length", "connection"].includes(key)) continue;
    headers.set(key, Array.isArray(value) ? value.join(", ") : value);
  }
  headers.set("x-browser-use-api-key", process.env.BROWSER_USE_API_KEY);
  headers.set("accept-encoding", "identity");

  const body = ["GET", "HEAD"].includes(req.method) ? undefined : await readBody(req);
  const upstreamUrl = new URL(UPSTREAM_MCP_URL);
  upstreamUrl.search = url.search;
  const upstream = await fetch(upstreamUrl, { method: req.method, headers, body, redirect: "manual" });
  const responseHeaders = {};
  for (const [key, value] of upstream.headers) {
    if (["content-encoding", "content-length", "transfer-encoding", "connection"].includes(key)) continue;
    responseHeaders[key] = value;
  }
  res.writeHead(upstream.status, responseHeaders);
  if (!upstream.body) return res.end();
  for await (const chunk of upstream.body) res.write(chunk);
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, publicBaseUrl(req));
    const base = publicBaseUrl(req);
    const resource = resourceUrl(req);

    if (req.method === "GET" && url.pathname === "/health") {
      return json(res, 200, {
        ok: true,
        browserUseConfigured: Boolean(process.env.BROWSER_USE_API_KEY?.startsWith("bu_")),
        gatewayPasswordConfigured: Boolean(process.env.GATEWAY_PASSWORD?.length >= 16),
      });
    }
    if (req.method === "GET" && ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"].includes(url.pathname)) {
      return json(res, 200, {
        resource,
        authorization_servers: [base],
        scopes_supported: [REQUIRED_SCOPE],
        resource_documentation: "https://docs.browser-use.com/cloud/guides/mcp-server",
      });
    }
    if (req.method === "GET" && ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"].includes(url.pathname)) {
      return json(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        token_endpoint_auth_methods_supported: ["none"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: [REQUIRED_SCOPE],
      });
    }
    if (["GET", "POST"].includes(req.method) && url.pathname === "/authorize") return await handleAuthorize(req, res, url);
    if (req.method === "POST" && url.pathname === "/token") return await handleToken(req, res);
    if (["GET", "POST", "DELETE"].includes(req.method) && url.pathname === "/mcp") return await proxyMcp(req, res, url);
    return text(res, 404, "Not found");
  } catch (error) {
    console.error(error);
    if (!res.headersSent) {
      const status = error?.message === "request_too_large" ? 413 : 500;
      return json(res, status, { error: status === 413 ? "request_too_large" : "internal_error" });
    }
    res.destroy(error);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Browser Use ChatGPT gateway listening on port ${PORT}`);
});

export { server, signAccessToken, verifyAccessToken, isAllowedClientId, isAllowedRedirect };
