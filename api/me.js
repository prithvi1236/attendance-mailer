// GET /api/me — the signed-in sender, the people list and default recipients (no hashes).
import { configured, notConfigured, currentUser, users, SECURITY_HEADERS } from "./_auth.js";

export async function GET(request) {
  if (!configured()) return notConfigured();
  const user = await currentUser(request);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401, headers: SECURITY_HEADERS });
  // The people list is everyone in USERS (names + emails only), unless marked "listed": false.
  const people = users().filter(u => u.listed !== false).map(u => ({ name: u.name, email: u.email }));
  return Response.json({
    email: user.email, name: user.name, people,
    to: process.env.MAIL_TO || "", cc: process.env.MAIL_CC || "", bcc: process.env.MAIL_BCC || "",
  }, { headers: SECURITY_HEADERS });
}
