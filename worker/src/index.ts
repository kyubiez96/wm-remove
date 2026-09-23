export interface Env {
  ASSETS: { fetch(request: Request): Promise<Response> };
  SITE_PASSWORD: string;
  COOKIE_SECRET: string;
  SPACE_URL: string;
  SPACE_KEY: string;
}

const M = "";
const COOKIE_NAME = "wm_session";
const TTL_MS = 30 * 24 * 60 * 60 * 1000;

async function hmacB64(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function constEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function b64u(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64u(s: string): string {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(p + "=".repeat((4 - (p.length % 4)) % 4));
}

function cookieValue(request: Request): string | null {
  const h = request.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === COOKIE_NAME) return rest.join("=");
  }
  return null;
}

async function sessionOk(request: Request, env: Env): Promise<boolean> {
  const raw = cookieValue(request);
  if (!raw) return false;
  const dot = raw.indexOf(".");
  if (dot <= 0) return false;
  const expB64 = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  let expStr: string;
  try {
    expStr = unb64u(expB64);
  } catch {
    return false;
  }
  if (!/^\d+$/.test(expStr)) return false;
  if (Number(expStr) < Date.now()) return false;
  const expected = await hmacB64(env.COOKIE_SECRET, "wm:" + expStr);
  return constEq(sig, expected);
}

const LOGIN_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>wm-remove</title>
<style>
  body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#0b1020;
       color:#e2e8f0;font-family:ui-sans-serif,system-ui,sans-serif}
  form{background:#141b33;border:1px solid #2b3a67;border-radius:12px;padding:28px;
       width:min(320px,86vw);display:grid;gap:12px}
  h1{margin:0;font-size:1.15rem;color:#a5b4fc}
  input{padding:10px 12px;border-radius:8px;border:1px solid #334;background:#0b1020;color:#e2e8f0}
  button{padding:10px;border:0;border-radius:8px;background:#6366f1;color:#fff;font-weight:600;cursor:pointer}
  p{font-size:.8rem;color:#94a3b8;margin:0}
</style></head>
<body>
  <form method="post" action="${M}/login">
    <h1>wm-remove · sign in</h1>
    <input type="password" name="password" placeholder="password" autofocus required/>
    <button type="submit">Enter</button>
  </form>
</body></html>`;

function htmlResponse(body: string, status = 200, headers: HeadersInit = {}): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

async function readFields(request: Request): Promise<Record<string, string>> {
  const ct = request.headers.get("content-type") || "";
  const text = await request.text();
  if (ct.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(text).entries());
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    let rel = url.pathname;
    if (rel === M || rel === "") rel = "/";
    else if (rel.startsWith(M + "/")) rel = rel.slice(M.length);
    else return new Response("Not found", { status: 404 });

    if (request.method === "POST" && rel === "/login") {
      const fields = await readFields(request);
      if (constEq(fields.password || "", env.SITE_PASSWORD)) {
        const exp = String(Date.now() + TTL_MS);
        const sig = await hmacB64(env.COOKIE_SECRET, "wm:" + exp);
        const res = new Response(null, {
          status: 302,
          headers: { Location: "/" },
        });
        res.headers.set(
          "Set-Cookie",
          `${COOKIE_NAME}=${b64u(exp)}.${sig}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${TTL_MS / 1000}`
        );
        return res;
      }
      return htmlResponse(LOGIN_HTML.replace("sign in", "wrong password · sign in"), 401);
    }

    if (request.method === "POST" && rel === "/logout") {
      const res = htmlResponse("<meta http-equiv=\"refresh\" content=\"0;url=" + M + "/login\"><p>Signed out.</p>");
      res.headers.set(
        "Set-Cookie",
        `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
      );
      return res;
    }

    if (rel.startsWith("/api/")) {
      const target = env.SPACE_URL.replace(/\/$/, "") + rel + url.search;
      const headers = new Headers(request.headers);
      headers.set("Authorization", "Bearer " + env.SPACE_KEY);
      headers.delete("cookie");
      headers.delete("origin");
      headers.delete("cf-connecting-ip");
      const init: RequestInit = { method: request.method, headers, redirect: "manual" };
      if (request.method === "POST" || request.method === "PUT") init.body = request.body;
      try {
        const resp = await fetch(target, init);
        const out = new Response(resp.body, resp);
        out.headers.delete("set-cookie");
        return out;
      } catch {
        return new Response(
          JSON.stringify({ ok: false, error: "backend unreachable (waking?) — retry in ~30s" }),
          { status: 502, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    if (!(await sessionOk(request, env))) {
      return htmlResponse(LOGIN_HTML);
    }

    return env.ASSETS.fetch(new Request(new URL(rel, request.url).toString(), request));
  },
};