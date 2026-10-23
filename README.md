# Attendance Mailer

Drafts attendance emails in Gmail. Login is checked by Vercel Functions in [api/](api); each password maps to
a sender (Gmail + name) kept in Vercel environment variables, which are never sent to the browser.

- `public/login.html` — the only public page
- `app/index.html` — the app, served only by `api/app.js` to signed-in users (`/` is rewritten there)
- `api/login.js`, `api/logout.js`, `api/me.js` — sign in, sign out, and the signed-in user's data
- `/demo` — guest mode: the same app with made-up people and addresses; no login, no real data, Gmail never opens

## Deploy on Vercel

1. Push this folder to a GitHub repo and import it in Vercel (Framework preset: **Other**, no build command).
2. In **Settings → Environment Variables** add:
   - `SESSION_SECRET` — 32+ random characters (e.g. from `openssl rand -hex 32` or a password generator)
   - `USERS` — JSON list of **hashed** passwords. Make it with [tools/hash-passwords.html](tools/hash-passwords.html):
     open that file in your browser, type each person's password (12+ chars, all different), click
     **Generate USERS value** and paste the result. Hashing happens in your browser; the tool is not deployed.
     ```json
     [{"hash":"pbkdf2_sha256$100000$<salt>$<hash>","email":"person1@gmail.com","name":"Person One"}]
     ```
   - `MAIL_TO` — e.g. `Manager Name <manager@company.com>`
   - `MAIL_CC` — always-Cc'd addresses, comma separated, e.g. `Team Lead <lead@company.com>`
   - `MAIL_BCC` — optional, always-Bcc'd addresses
   - `SESSION_HOURS` — optional, default 12
3. Redeploy after any change to the variables.

Changing or removing someone's hash in `USERS` (and redeploying) logs them out.
Changing `SESSION_SECRET` logs everyone out.

## Notes

- Passwords are stored only as PBKDF2-SHA256 hashes (100,000 rounds, random salt per user).
- There is no attempt counter (the functions keep no state), so use long random passwords.
  For extra protection add a rate-limit rule on `/login` in Vercel → Firewall.
- The people list on the page is built from `USERS` (names and emails only — hashes never leave the server).
  To give someone a login without listing them on the page, add `"listed": false` to their entry.
  Every signed-in user sees the full list.
