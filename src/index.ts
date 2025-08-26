import { randomBytes } from 'node:crypto';
import type { PagesFunction } from '@cloudflare/workers-types';
import { OAuthClient } from './oauth';

interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
}

/** Utils */
const makeState = () => randomBytes(16).toString('hex');

const getCookie = (cookieHeader: string | null, name: string): string | null => {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(/; */);
  for (const c of cookies) {
    const [k, ...v] = c.split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
};

const createOAuth = (env: Env) => {
  return new OAuthClient({
    id: env.GITHUB_CLIENT_ID,
    secret: env.GITHUB_CLIENT_SECRET,
    target: {
      tokenHost: 'https://github.com',
      tokenPath: '/login/oauth/access_token',
      authorizePath: '/login/oauth/authorize',
    },
  });
};

/** Builds a tiny HTML page that posts a message back to the opener and closes. */
const callbackScriptResponse = (
  status: 'success' | 'error',
  payload: Record<string, string>
) => {
  const json = JSON.stringify(payload);
  return new Response(
    `<!doctype html>
<html>
<head><meta charset="utf-8"></head>
<body>
<script>
  const receiveMessage = () => {
    window.opener.postMessage('authorization:github:${status}:${json}', '*');
    window.removeEventListener('message', receiveMessage, false);
    window.close();
  };
  window.addEventListener('message', receiveMessage, false);
  window.opener?.postMessage('authorizing:github', '*');
</script>
<p>Authorizing Decap...</p>
</body>
</html>`,
    {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    }
  );
};

/** /auth handler: sets state cookie and 302s to GitHub authorize */
const handleAuth = async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const provider = url.searchParams.get('provider');
  if (provider !== 'github') {
    return new Response('Invalid provider', { status: 400 });
  }

  const redirectUri = `${url.origin}/callback?provider=github`;
  const state = makeState();

  const oauth2 = createOAuth(env);
  const authorizationUri = oauth2.authorizeURL({
    redirect_uri: redirectUri,
    scope: 'repo,user',
    state,
  });

  return new Response(null, {
    status: 302, // use 302, not 301 (avoid caching)
    headers: {
      Location: authorizationUri,
      'Cache-Control': 'no-store',
      // Cross-site popup requires SameSite=None; Secure
      'Set-Cookie': `decap_oauth_state=${encodeURIComponent(
        state
      )}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=300`,
    },
  });
};

/** /callback handler: verifies state and exchanges code -> token */
const handleCallback = async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const provider = url.searchParams.get('provider');
  if (provider !== 'github') {
    return new Response('Invalid provider', { status: 400 });
  }

  const code = url.searchParams.get('code');
  if (!code) {
    return new Response('Missing code', { status: 400 });
  }

  const returnedState = url.searchParams.get('state') || '';
  const cookieState = getCookie(request.headers.get('Cookie'), 'decap_oauth_state') || '';
  if (!returnedState || !cookieState || returnedState !== cookieState) {
    return callbackScriptResponse('error', { message: 'invalid_state' });
  }

  const redirectUri = `${url.origin}/callback?provider=github`;
  const oauth2 = createOAuth(env);

  try {
    // Ensure your OAuthClient uses Accept: application/json under the hood.
    // If not, update it to set that header when calling GitHub.
    const tokenRes: any = await oauth2.getToken({
      code,
      redirect_uri: redirectUri,
    });

    // Normalize possible shapes
    const accessToken =
      typeof tokenRes === 'string'
        ? tokenRes
        : tokenRes.access_token ??
          tokenRes.token?.access_token ??
          '';

    if (!accessToken) {
      return callbackScriptResponse('error', { message: 'no_access_token' });
    }

    // Success: post back to the opener
    return callbackScriptResponse('success', { token: accessToken });
  } catch (err: any) {
    const message = err instanceof Error ? err.message : String(err ?? 'unknown error');
    return callbackScriptResponse('error', { message });
  }
};

/** Router supporting both with/without trailing slashes */
const handleRequest = async (request: Request, env: Env): Promise<Response> => {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/auth' || path === '/auth/') {
    return handleAuth(request, env);
  }
  if (path === '/callback' || path === '/callback/') {
    return handleCallback(request, env);
  }
  return new Response('Hello 👋');
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  },
};

// Cloudflare Pages Functions entry (optional, keeps Workers + Pages parity)
export const onRequest: PagesFunction<Env> = async (context) => {
  return handleRequest(context.request, context.env);
};
