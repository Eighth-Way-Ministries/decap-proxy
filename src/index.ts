export default {
  async fetch(req: Request, env: any) {
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === "/auth" || p === "/auth/") {
      const state = crypto.getRandomValues(new Uint32Array(1))[0].toString(16);
      const u = new URL("https://github.com/login/oauth/authorize");
      u.search = new URLSearchParams({
        response_type: "code",
        client_id: env.GITHUB_CLIENT_ID,
        redirect_uri: "https://decap.eighthwayministries.org/callback?provider=github",
        scope: "repo user",
        state,
      }).toString();

      return new Response(null, {
        status: 302,
        headers: {
          Location: u.toString(),
          "Set-Cookie": `decap_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600`,
          "Cache-Control": "no-store",
        },
      });
    }

    if (p === "/callback" || p === "/callback/") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const cookie = req.headers.get("Cookie") || "";
      const m = /(?:^|;\s*)decap_oauth_state=([^;]+)/.exec(cookie);
      const saved = m ? decodeURIComponent(m[1]) : "";

      const html = (msg: string, extraHeaders: Record<string, string> = {}) =>
        new Response(`<!doctype html><meta charset="utf-8">
<script>window.opener&&window.opener.postMessage('${msg}','*');window.close();</script>`,
        { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders } });

      if (!code || !state || !saved || state !== saved)
        return html("authorization:github:error:invalid_state");

      const r = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "Accept": "application/json" },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: "https://decap.eighthwayministries.org/callback?provider=github",
        }),
      });
      const j = await r.json();

      const msg = j.access_token
        ? `authorization:github:success:${j.access_token}`
        : `authorization:github:error:${j.error || "exchange_failed"}`;

      return html(msg, { "Set-Cookie": "decap_oauth_state=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None" });
    }

    return new Response("Not found", { status: 404 });
  }
};
