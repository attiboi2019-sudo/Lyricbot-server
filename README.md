# Lyrical Bot server

Accounts for Lyrical Bot: sign up with an emailed 6-digit code, choose a username and password, and your uploaded songs and characters follow you to every device.

One small Node server. It also serves the Lyrical Bot web page at `/`, so people can use it in a browser as well as in the desktop app.

## 1. Try it on your own computer (free, 2 minutes)

Install Node.js 20 or newer, then in this folder:

    npm install
    npm start

Open http://localhost:3000. In this dev mode **no email is sent**: the 6-digit code is printed in the terminal window.

## 2. Email (required for real use)

The codes have to be emailed. Set these environment variables (see `.env.example`):

- **Brevo** (free plan: 300 emails a day, so at most about 300 sign-ups, resets and resends per day): `BREVO_API_KEY` and `MAIL_FROM`.
- **Resend**: `RESEND_API_KEY` and `MAIL_FROM="Lyrical Bot <login@yourdomain.com>"`. Needs a domain you own.

For emails to reliably reach inboxes instead of spam, **use an address on a domain you own and authenticate that domain with your provider** (they give you DNS records to add). Mail from unauthenticated senders gets rewritten or filtered by Gmail and Yahoo, and a gmail.com address as the sender is not a good idea.

Brevo gotcha: Brevo can block API calls from IP addresses it hasn't seen. If codes stop arriving and the server log says `email failed: brevo 401`, go to Brevo, Security, Authorised IPs, and deactivate blocking for API keys (your key lives only in the server's settings).

## 3. Put it online

You need a host that runs Docker or Node, gives you HTTPS, and keeps a **persistent disk**. Accounts live in one SQLite file in `DATA_DIR` (`/data` in the Docker image). A host whose disk is wiped on restart will delete every account.

**Railway:**
1. Put these files in a GitHub repository (not `.env`, not `node_modules`).
2. New Project, Deploy from GitHub repo. Railway builds the Dockerfile.
3. Add a Volume to the service with mount path `/data`.
4. Add variables `BREVO_API_KEY` and `MAIL_FROM`.
5. In the service's networking settings, generate a public domain. That `https://...up.railway.app` address is your server.

Other hosts work too: Render needs a paid instance to attach a disk, and any small VPS works with Docker:

    docker build -t lyricbot .
    docker run -p 3000:3000 -v lyricbot-data:/data -e BREVO_API_KEY=xxxx -e MAIL_FROM=login@yourdomain.com lyricbot

Note: do not add a `VOLUME` line to the Dockerfile for Railway, its builder rejects it.

## 4. Connect the apps

- **Web:** open your server's address. Accounts just work.
- **Desktop app (LyricBot.exe):** Account card, type your server address, press Connect. It remembers it.

## What it stores, and the rules

- Email (to sign in and send codes), username, a salted scrypt hash of the password, songs, characters.
- Codes: 6 digits, expire in 10 minutes, die after 5 wrong tries, stored hashed.
- 8 wrong passwords lock that account for 15 minutes. Requests are rate-limited per IP and per email.
- Sessions last 30 days and are stored hashed. Resetting a password signs out every other device.
- Limits per account: 100 songs (300 lines each), 20 characters (about 300 KB each).
- **Delete account** in the app removes the user and all their songs and characters.
- Back up by copying `lyricbot.db` (for example with `sqlite3 lyricbot.db ".backup copy.db"`).

## Good to know

- Rate limits are kept in memory and reset on restart, so run a single instance.
- Not included: CAPTCHA, two-factor login, changing email address, a privacy policy page. If strangers will sign up, add a short privacy note and check the rules where you and your users live.
- Always use HTTPS in production, since passwords travel to the server.
