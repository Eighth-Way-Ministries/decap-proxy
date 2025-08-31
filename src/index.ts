/**
 * Cloudflare Worker – Decap OAuth proxy (GitHub)
 * - /auth: generate state, set cookie, 302 to GitHub authorize
 * - /callback: verify state, exchange code->token, postMessage back, clear cookie
 */

interface Env {
  GITHUB_OAUTH_ID: string;
  GITHUB_OAUTH_SECRET: string;
}

/* ---------- Utils ---------- */

// Web Crypto (no node:crypto)
const makeState = (): string => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
};

const getCookie = (cookieHeader: string | null, name: string): string | null => {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(/; */);
  for (const c of cookies) {
    const [k, ...v] = c.split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
};

const htmlCloseWith = (msg: string, extraHeaders: Record<string, string> = {}): Response =>
  new Response(
    "<!doctype html><meta charset=\"utf-8\">" +
      `<script>(function(){
        try {
          var m='${msg}';
          if (window.opener) {
            // Always send the original string message (new + failure cases)
            window.opener.postMessage(m,'*');

            // If success with JSON payload, also send legacy and object forms
            if (m.indexOf('authorization:github:success:') === 0) {
              try {
                // Legacy colon form (kept from previous behavior)
                if (m.indexOf('authorization:github:success:{\"token\":')===0) {
                  var legacy=m.replace(/:\{"token":"([^"]+)"\}$/, ':$1');
                  window.opener.postMessage(legacy,'*');
                }
                // Object form for newer Decap CMS
                var jsonPart = m.slice('authorization:github:success:'.length);
                var parsed = JSON.parse(jsonPart || 'null');
                if (parsed && parsed.token) {
                  var token = parsed.token;
                  var state = parsed.state || '';
                  // Also send the space-delimited legacy JSON form
                  try { window.opener.postMessage('authorization:github ' + JSON.stringify({ token: token, state: state }), '*'); } catch(_){ }
                  // Also send the space-delimited plain token form
                  try { window.opener.postMessage('authorization:github ' + token, '*'); } catch(_){ }
                  // Object form for newer Decap CMS
                  window.opener.postMessage({ type: 'authorization', provider: 'github', token: token, state: state }, '*');
                }
              } catch (_) { /* swallow */ }
            }
          }
        } catch (e) { /* swallow */ }
        setTimeout(function(){ try{ window.close(); }catch(_){} },150);
      }())</script>`,
    { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders } }
  );

const buildAuthorizeURL = (clientId: string, redirectUri: string, state: string): string => {
  const u = new URL("https://github.com/login/oauth/authorize");
  u.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,          // keep EXACTLY in sync with OAuth App setting
    scope: "repo user",                 // space-separated per GitHub canonical format
    state,
  }).toString();
  return u.toString();
};

const exchangeCodeForToken = async (
  env: Env,
  code: string,
  redirectUri: string
): Promise<{ access_token?: string; error?: string }> => {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Accept": "application/json", // critical: ensures JSON response on both success & error
    },
    body: new URLSearchParams({
      client_id: env.GITHUB_OAUTH_ID,
      client_secret: env.GITHUB_OAUTH_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });
  // On any HTTP status, GitHub returns JSON when Accept: application/json is set
  return res.json();
};

/* ---------- Handlers ---------- */

const handleAuth = async (request: Request, env: Env): Promise<Response> => {
  const url = new URL(request.url);
  const provider = url.searchParams.get("provider");
  if (provider !== "github") {
    return new Response("Invalid provider", { status: 400, headers: { "Cache-Control": "no-store" } });
  }

  // Sanity: ensure env vars exist
  if (!env.GITHUB_OAUTH_ID || !env.GITHUB_OAUTH_SECRET) {
    return new Response("Server not configured", { status: 500, headers: { "Cache-Control": "no-store" } });
  }

  const redirectUri = `${url.origin}/callback?provider=github`;
  const state = makeState();

  const location = buildAuthorizeURL(env.GITHUB_OAUTH_ID, redirectUri, state);

  return new Response(null, {
    status: 302, // do NOT use 301; avoid caching
    headers: {
      "Location": location,
      "Cache-Control": "no-store",
      // Cross-site popup flow requires SameSite=None; Secure; HttpOnly
      "Set-Cookie": `decap_oauth_state=${encodeURIComponent(state)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600`,
    },
  });
};

const handleCallback = async (request: Request, env: Env): Promise<Response> => {
  const url = new URL(request.url);
  const provider = url.searchParams.get("provider");
  if (provider !== "github") {
    // Clear cookie on any bad path
    return htmlCloseWith("authorization:github:failure:invalid_provider", {
      "Set-Cookie": "decap_oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None",
    });
  }

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state") || "";

  const cookieHeader = request.headers.get("Cookie");
  const cookieState = getCookie(cookieHeader, "decap_oauth_state") || "";

  if (!code || !returnedState || !cookieState || returnedState !== cookieState) {
    // MUST clear the state cookie on invalid_state (must-fix #4)
    return htmlCloseWith("authorization:github:failure:invalid_state", {
      "Set-Cookie": "decap_oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None",
    });
  }

  // State matches: clear cookie now (one-time)
  const clearStateCookie = "decap_oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None";
  const redirectUri = `${url.origin}/callback?provider=github`;

  // Exchange code -> token (must-fix #2)
  try {
    const data = await exchangeCodeForToken(env, code, redirectUri);

    if (data.access_token) {
      // Include state so Decap can correlate pending auth request
      return htmlCloseWith(`authorization:github:success:${JSON.stringify({ token: data.access_token, state: returnedState })}` , {
        "Set-Cookie": clearStateCookie,
      });
    }

    // Error from GitHub (e.g., bad_verification_code, incorrect_client_credentials, etc.)
    const errMsg = (data.error || "exchange_failed").replace(/'/g, "\\'");
    return htmlCloseWith(`authorization:github:failure:${errMsg}`, { "Set-Cookie": clearStateCookie });
  } catch (e: any) {
    const errMsg = String(e?.message || e || "exchange_failed").replace(/'/g, "\\'");
    return htmlCloseWith(`authorization:github:failure:${errMsg}`, { "Set-Cookie": clearStateCookie });
  }
};

/* ---------- Router (supports with/without trailing slash) ---------- */

const handleRequest = async (request: Request, env: Env): Promise<Response> => {
  const { pathname } = new URL(request.url);

  if (pathname === "/auth" || pathname === "/auth/") {
    return handleAuth(request, env);
  }
  if (pathname === "/callback" || pathname === "/callback/") {
    return handleCallback(request, env);
  }
  return new Response("Not found", { status: 404, headers: { "Cache-Control": "no-store" } });
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};
