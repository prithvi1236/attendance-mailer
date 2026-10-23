// Vercel Routing Middleware: password gate for the whole site.
// Env vars (Vercel → Settings → Environment Variables), never sent to the browser:
//   USERS          = [{"hash":"pbkdf2_sha256$…","email":"you@gmail.com","name":"Your Name"}, …]
//                    (make hashes with tools/hash-passwords.html — plain passwords are never stored)
//   SESSION_SECRET = 32+ random characters
//   SESSION_HOURS  = optional, default 12
//   MAIL_TO / MAIL_CC / MAIL_BCC = default recipients, comma separated, e.g. "Name <a@b.com>, c@d.com"
const enc = new TextEncoder();

const SECURITY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

function users() {
  try { return JSON.parse(process.env.USERS || "[]"); } catch { return []; }
}

const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = s => atob(s.replace(/-/g, "+").replace(/_/g, "/"));

async function hmac(data) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(process.env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data))));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// hash = "pbkdf2_sha256$<iterations>$<salt b64url>$<hash b64url>"
async function verifyHash(password, stored) {
  const [alg, iter, salt64, hash64] = String(stored || "").split("$");
  if (alg !== "pbkdf2_sha256" || !hash64) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = Uint8Array.from(fromB64url(salt64), c => c.charCodeAt(0));
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: Number(iter) }, key, 256);
  return safeEqual(b64url(new Uint8Array(bits)), hash64);
}

async function findByPassword(password) {
  let match = null;
  // Check every user so timing doesn't reveal how far down the list a match is.
  for (const u of users()) {
    if (await verifyHash(password, u.hash) && !match) match = u;
  }
  return match;
}

// Cookie = "<email b64>.<expiry>.<sig>". The signature covers the user's password hash,
// so changing or removing a password in USERS logs that person out.
async function makeSession(u) {
  const email = b64url(enc.encode(u.email));
  const exp = Date.now() + Number(process.env.SESSION_HOURS || 12) * 3600e3;
  return `${email}.${exp}.${await hmac(`s:${u.email}:${exp}:${u.hash}`)}`;
}

async function currentUser(request) {
  const m = (request.headers.get("cookie") || "").match(/(?:^|;\s*)am_session=([^;]+)/);
  if (!m) return null;
  const [email64, exp, sig] = m[1].split(".");
  if (!sig || Date.now() > Number(exp)) return null;
  let email;
  try { email = fromB64url(email64); } catch { return null; }
  const u = users().find(x => x.email === email);
  if (!u) return null;
  return safeEqual(await hmac(`s:${u.email}:${exp}:${u.hash}`), sig) ? u : null;
}

const cookie = (value, maxAge) => `am_session=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function redirect(request, to, setCookie) {
  const headers = new Headers({ ...SECURITY_HEADERS, Location: new URL(to, request.url).toString() });
  if (setCookie) headers.set("Set-Cookie", setCookie);
  return new Response(null, { status: 303, headers });
}

export default async function middleware(request) {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    return new Response("Server not configured: set SESSION_SECRET (32+ chars) and USERS.", { status: 500 });
  }
  const { pathname } = new URL(request.url);
  const user = await currentUser(request);

  if (pathname === "/login" && request.method === "POST") {
    const form = await request.formData().catch(() => null);
    const u = await findByPassword(String(form?.get("password") || ""));
    if (!u) return redirect(request, "/login?e=bad");
    return redirect(request, "/", cookie(await makeSession(u), Number(process.env.SESSION_HOURS || 12) * 3600));
  }

  if (pathname === "/logout" && request.method === "POST") {
    return redirect(request, "/login", cookie("", 0));
  }

  if (pathname === "/api/me") {
    if (!user) return Response.json({ error: "unauthorized" }, { status: 401, headers: SECURITY_HEADERS });
    // The people list is everyone in USERS (names + emails only), unless marked "listed": false.
    const people = users().filter(u => u.listed !== false).map(u => ({ name: u.name, email: u.email }));
    return Response.json({
      email: user.email, name: user.name, people,
      to: process.env.MAIL_TO || "", cc: process.env.MAIL_CC || "", bcc: process.env.MAIL_BCC || "",
    }, { headers: SECURITY_HEADERS });
  }

  if (pathname === "/login" || pathname === "/login.html") {
    return user ? redirect(request, "/") : undefined; // serve the login page
  }

  if (!user) return redirect(request, "/login");
  // Signed in: fall through to the static app page.
}
