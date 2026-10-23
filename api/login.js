// POST /api/login — check the password against USERS and set the session cookie.
import { configured, notConfigured, findByPassword, makeSession, cookie, redirect, sessionSeconds } from "./_auth.js";

export async function POST(request) {
  if (!configured()) return notConfigured();
  const form = await request.formData().catch(() => null);
  const u = await findByPassword(String(form?.get("password") || ""));
  if (!u) return redirect(request, "/login?e=bad");
  return redirect(request, "/", cookie(await makeSession(u), sessionSeconds()));
}
