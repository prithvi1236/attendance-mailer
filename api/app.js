// GET / (rewritten here by vercel.json) — serve the app page only to signed-in users.
// The page lives in app/, outside the public folder, so it can't be fetched directly.
import fs from "node:fs";
import path from "node:path";
import { configured, notConfigured, currentUser, redirect, SECURITY_HEADERS } from "./_auth.js";

const page = fs.readFileSync(path.join(process.cwd(), "app", "index.html"));

export async function GET(request) {
  if (!configured()) return notConfigured();
  if (!(await currentUser(request))) return redirect(request, "/login");
  return new Response(page, { headers: { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" } });
}
