# Engagement Desk: CBO Partner Assistant

A scope-locked AI assistant for CBO (community-based organisation) partners. It does exactly three things, all grounded in your engagement register:

1. Answers questions about engagements, reporting, funding and policies.
2. Helps plan community engagement meetings (agendas, logistics, prep timelines).
3. Breaks down budgets and estimates spend using your standard rates, rendered as a ledger table with totals recalculated in the browser.

Anything outside that scope is politely declined. The AI is Claude, called through the Anthropic API from the server, never from the partner's browser.

Access is gated: partners register, and **only the admin can approve registration requests**. Nobody can chat until they're approved.

## Requirements

- Node.js 20.6 or newer (`node --version` to check)
- An Anthropic API key from https://console.anthropic.com

## Setup

1. Install dependencies:

   ```
   npm install
   ```

2. Create your environment file:

   ```
   cp .env.example .env
   ```

   Edit `.env` and set three values: `ANTHROPIC_API_KEY`, plus `ADMIN_EMAIL` and `ADMIN_PASSWORD` for the admin account.

3. Start the server:

   ```
   npm start
   ```

4. Open http://localhost:3000 and sign in with your admin email and password.

## How access control works

- **Partners request access** on the registration page (name, organisation, email, password). Their account is created with status `pending`; they cannot sign in yet.
- **The admin signs in** and sees an extra **Approvals** tab listing every pending request. Approve or reject each one; the routes behind this are admin-only, enforced on the server.
- **Approved partners sign in** and get the chat. Pending partners who try to sign in are told their request is still under review; rejected partners are told to contact the engagement office.
- **Sessions** last 7 days, stored server-side and referenced by an httpOnly cookie. The chat endpoint (`/api/chat`) requires a signed-in, approved user. A logged-out visitor gets nothing, and your API credits are protected.
- **Passwords** are never stored in plain text (scrypt-hashed with per-user salts, using Node's built-in crypto, no extra dependencies).

The admin account is seeded from `.env` on first start, and its password is refreshed from `.env` on every start, so to change the admin password, edit `.env` and restart.

## Where things live

- `server.js`: the AI and all auth logic. The only thing that talks to the Claude API.
- `knowledge-base.txt`: the assistant's entire world: engagement records, policies, and the standard rates used for budgeting. Server-side, so partners can never edit it. Re-read on every request; edit the file and the next answer uses the new content.
- `public/index.html`: the partner-facing app: sign-in, registration, chat, and (for the admin) the Approvals panel.
- `data/users.json`: accounts and sessions. Created automatically. Back it up, never commit it (`.gitignore` already excludes it). To revoke a partner later, change their `status` in this file; it takes effect on their very next request.

## Configuration

- `CLAUDE_MODEL` (optional): defaults to `claude-haiku-4-5-20251001`, which is fast and low cost per message. Set it to `claude-sonnet-4-6` if you want more capable answers for complex planning questions.
- `PORT` (optional): defaults to 3000.

## Branding

The interface uses the Wits RHI colour palette (HEX values from the brand toolkit, as specified for digital applications): dark teal header, mid teal actions, light teal accents, mid blue links, light blue focus states, grey hairlines, gold budget highlights, on a white backdrop. All colours are defined once as CSS variables at the top of `public/index.html`, so adjusting the palette later is a one-place change.

## Before going live

- Serve over HTTPS (behind a reverse proxy or a platform like Render, Railway or Fly.io) and set `NODE_ENV=production` so the session cookie is marked `Secure`.
- Add rate limiting on `/api/login` and `/api/chat` to slow password guessing and control spend.
- Add request logging so you can review conversations.
- Consider email notifications when a registration arrives, so approvals don't wait.
- When the partner base grows, move `data/users.json` into a real database.

## When your data outgrows one file

This version injects the whole register into every request, which works well up to roughly a few hundred records. When your mix of documents, spreadsheets and CRM data grows beyond that, switch to retrieval: break the material into records, search for the pieces relevant to each question, and pass only those to the model. The API docs at https://docs.claude.com/en/api/overview cover the tools you'll need for that stage.
