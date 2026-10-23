// POST /api/logout — clear the session cookie.
import { cookie, redirect } from "./_auth.js";

export function POST(request) {
  return redirect(request, "/login", cookie("", 0));
}
