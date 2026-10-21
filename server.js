"use strict";
const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const scrypt = require("util").promisify(crypto.scrypt);

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const MULT = Number(process.env.RATE_MULT) || 1;                       // multiplies rate limits (tests only)
const CODE_GAP = process.env.CODE_GAP_MS ? Number(process.env.CODE_GAP_MS) : 45e3;
const MIN = 60e3, DAY = 864e5;

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "lyricbot.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL COLLATE NOCASE, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS codes(email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tickets(hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS songs(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, lines TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS characters(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, data TEXT NOT NULL, created INTEGER NOT NULL);
`);

// ---------- helpers ----------
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const rnd = () => crypto.randomBytes(32).toString("base64url");
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const normEmail = e => String(e || "").trim().toLowerCase();
const validEmail = e => e.length <= 254 && /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(e);
const validUser = u => /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPw = p => typeof p === "string" && p.length >= 8 && p.length <= 200;
const fail = (res, code, msg) => res.status(code).json({ error: msg });
async function hashPw(pw, salt = crypto.randomBytes(16).toString("hex")) { return { salt, hash: (await scrypt(pw, salt, 64)).toString("hex") }; }
const DUMMY_SALT = "00".repeat(16);

// in-memory sliding-window rate limiter (resets on restart; fine for a single instance)
const hits = new Map();
const recent = (k, w) => { const n = Date.now(), a = (hits.get(k) || []).filter(t => n - t < w); hits.set(k, a); return a.length; };
const hit = k => { const a = hits.get(k) || []; a.push(Date.now()); hits.set(k, a); };
const allow = (k, max, w) => { if (recent(k, w) >= max * MULT) return false; hit(k); return true; };
setInterval(() => {
  const n = Date.now();
  for (const [k, a] of hits) if (!a.length || n - a[a.length - 1] > 60 * MIN) hits.delete(k);
  db.prepare("DELETE FROM codes WHERE expires<?").run(n);
  db.prepare("DELETE FROM tickets WHERE expires<?").run(n);
  db.prepare("DELETE FROM sessions WHERE expires<?").run(n);
}, 30 * MIN).unref();

// ---------- email ----------
const PROVIDER = process.env.RESEND_API_KEY ? "resend" : process.env.BREVO_API_KEY ? "brevo" : "dev";
async function sendCode(to, code) {
  const subject = "Your Lyrical Bot code", from = process.env.MAIL_FROM || "";
  const text = `Your Lyrical Bot code is ${code}. It expires in 10 minutes. If you didn’t ask for it, you can ignore this email.`;
  if (PROVIDER === "resend") {
    const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + process.env.RESEND_API_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ from, to: [to], subject, text }) });
    if (!r.ok) throw new Error("resend " + r.status + " " + (await r.text()));
  } else if (PROVIDER === "brevo") {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", { method: "POST", headers: { "api-key": process.env.BREVO_API_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ sender: { email: from, name: "Lyrical Bot" }, to: [{ email: to }], subject, textContent: text }) });
    if (!r.ok) throw new Error("brevo " + r.status + " " + (await r.text()));
  } else {
    console.log(`[DEV EMAIL] to=${to} code=${code}`);
  }
}

// ---------- app ----------
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Authorization, Content-Type", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" });
  if (req.path.startsWith("/api/")) res.set("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: "600kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.get("/api/health", (req, res) => res.json({ ok: true }));

function newSession(userId) {
  const token = rnd();
  db.prepare("INSERT INTO sessions(hash,user_id,expires) VALUES(?,?,?)").run(sha(token), userId, Date.now() + 30 * DAY);
  return token;
}
function auth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get("Authorization") || "");
  const row = m && db.prepare("SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires>?").get(sha(m[1]), Date.now());
  if (!row) return fail(res, 401, "Please log in again.");
  req.user = row; req.tokenHash = sha(m[1]); next();
}

// 1) ask for a code
app.post("/api/auth/request-code", async (req, res) => {
  const email = normEmail(req.body.email);
  if (!validEmail(email)) return fail(res, 400, "Enter a valid email address.");
  if (!allow("ipc:" + req.ip, 10, 60 * MIN) || !allow("emc:" + email, 5, 60 * MIN)) return fail(res, 429, "Too many codes requested. Try again later.");
  const prev = db.prepare("SELECT sent FROM codes WHERE email=?").get(email);
  if (prev && Date.now() - prev.sent < CODE_GAP) return fail(res, 429, "Please wait a moment before asking for another code.");
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, "0");
  db.prepare("INSERT OR REPLACE INTO codes(email,code_hash,expires,tries,sent) VALUES(?,?,?,0,?)").run(email, sha(email + ":" + code), Date.now() + 10 * MIN, Date.now());
  try { await sendCode(email, code); }
  catch (e) { console.error("email failed:", e.message); db.prepare("DELETE FROM codes WHERE email=?").run(email); return fail(res, 502, "Couldn’t send the email. Try again later."); }
  res.json({ ok: true });   // same answer whether or not the email already has an account
});

// 2) check the code -> short-lived ticket
app.post("/api/auth/verify-code", (req, res) => {
  if (!allow("ipv:" + req.ip, 30, 10 * MIN)) return fail(res, 429, "Too many attempts. Try again later.");
  const email = normEmail(req.body.email), code = String(req.body.code || "").replace(/\s/g, "");
  const row = db.prepare("SELECT * FROM codes WHERE email=?").get(email);
  if (!row || row.expires < Date.now() || row.tries >= 5) return fail(res, 400, "That code isn’t valid any more. Ask for a new one.");
  db.prepare("UPDATE codes SET tries=tries+1 WHERE email=?").run(email);
  if (!/^\d{6}$/.test(code) || !safeEq(row.code_hash, sha(email + ":" + code))) return fail(res, 400, "Wrong code.");
  db.prepare("DELETE FROM codes WHERE email=?").run(email);
  const ticket = rnd();
  db.prepare("INSERT INTO tickets(hash,email,expires) VALUES(?,?,?)").run(sha(ticket), email, Date.now() + 15 * MIN);
  res.json({ ticket, existing: !!db.prepare("SELECT 1 FROM users WHERE email=?").get(email) });
});

// 3) choose username + password (new account) or a new password (existing account)
app.post("/api/auth/complete", async (req, res) => {
  if (!allow("ipx:" + req.ip, 20, 60 * MIN)) return fail(res, 429, "Too many attempts. Try again later.");
  const { ticket, username, password } = req.body;
  const t = typeof ticket === "string" && db.prepare("SELECT * FROM tickets WHERE hash=? AND expires>?").get(sha(ticket), Date.now());
  if (!t) return fail(res, 400, "Your sign-up expired. Start again.");
  if (!validPw(password)) return fail(res, 400, "Password must be 8 to 200 characters.");
  const existing = db.prepare("SELECT id,username FROM users WHERE email=?").get(t.email);
  const { salt, hash } = await hashPw(password);
  let user;
  if (existing) {
    db.prepare("UPDATE users SET salt=?,hash=? WHERE id=?").run(salt, hash, existing.id);
    db.prepare("DELETE FROM sessions WHERE user_id=?").run(existing.id);   // reset signs out every other device
    user = existing;
  } else {
    if (!validUser(username)) return fail(res, 400, "Username must be 3 to 20 letters, numbers or underscores.");
    try { const r = db.prepare("INSERT INTO users(email,username,salt,hash,created) VALUES(?,?,?,?,?)").run(t.email, username, salt, hash, Date.now()); user = { id: r.lastInsertRowid, username }; }
    catch (e) { if (String(e.code).startsWith("SQLITE_CONSTRAINT")) return fail(res, 409, "That username is taken."); throw e; }
  }
  db.prepare("DELETE FROM tickets WHERE hash=?").run(t.hash);
  res.json({ token: newSession(user.id), user: { username: user.username } });
});

app.post("/api/auth/login", async (req, res) => {
  const login = String(req.body.login || "").trim().toLowerCase(), password = String(req.body.password || "");
  if (!login || !password || login.length > 254 || password.length > 200) return fail(res, 400, "Enter your username and password.");
  if (!allow("ipl:" + req.ip, 40, 10 * MIN)) return fail(res, 429, "Too many attempts. Try again in a few minutes.");
  if (recent("lf:" + login, 15 * MIN) >= 8 * MULT) return fail(res, 429, "Too many wrong passwords. Try again in 15 minutes.");
  const user = db.prepare(`SELECT * FROM users WHERE ${login.includes("@") ? "email" : "username"}=?`).get(login);
  const { hash } = await hashPw(password, user ? user.salt : DUMMY_SALT);   // always do the work so timing doesn't reveal accounts
  if (!user || !safeEq(user.hash, hash)) { hit("lf:" + login); return fail(res, 401, "Wrong username or password."); }
  res.json({ token: newSession(user.id), user: { username: user.username } });
});
app.post("/api/auth/logout", auth, (req, res) => { db.prepare("DELETE FROM sessions WHERE hash=?").run(req.tokenHash); res.json({ ok: true }); });
app.get("/api/me", auth, (req, res) => res.json({ username: req.user.username }));
app.delete("/api/me", auth, async (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id), pw = String(req.body.password || "");
  if (!allow("del:" + req.user.id, 5, 15 * MIN)) return fail(res, 429, "Too many attempts. Try again later.");
  if (!safeEq(u.hash, (await hashPw(pw, u.salt)).hash)) return fail(res, 401, "Wrong password.");
  db.prepare("DELETE FROM users WHERE id=?").run(u.id);   // sessions, songs and characters go with it
  res.json({ ok: true });
});

// ---------- library ----------
const count = (t, id) => db.prepare(`SELECT COUNT(*) n FROM ${t} WHERE user_id=?`).get(id).n;
app.get("/api/library", auth, (req, res) => res.json({
  songs: db.prepare("SELECT id,title,lines FROM songs WHERE user_id=? ORDER BY id").all(req.user.id).map(s => ({ id: s.id, title: s.title, lines: JSON.parse(s.lines) })),
  characters: db.prepare("SELECT id,name,data FROM characters WHERE user_id=? ORDER BY id").all(req.user.id)
}));
app.post("/api/songs", auth, (req, res) => {
  const title = String(req.body.title || "").trim().slice(0, 80);
  const lines = Array.isArray(req.body.lines) ? req.body.lines.map(l => typeof l === "string" ? l.trim().slice(0, 200) : "").filter(Boolean) : [];
  if (!title || !lines.length || lines.length > 300) return fail(res, 400, "A song needs a title and 1 to 300 lines.");
  if (count("songs", req.user.id) >= 100) return fail(res, 400, "You’ve reached the limit of 100 songs.");
  const r = db.prepare("INSERT INTO songs(user_id,title,lines,created) VALUES(?,?,?,?)").run(req.user.id, title, JSON.stringify(lines), Date.now());
  res.json({ id: Number(r.lastInsertRowid) });
});
app.delete("/api/songs/:id", auth, (req, res) => {
  const r = db.prepare("DELETE FROM songs WHERE id=? AND user_id=?").run(Number(req.params.id), req.user.id);
  r.changes ? res.json({ ok: true }) : fail(res, 404, "Not found.");
});
app.post("/api/characters", auth, (req, res) => {
  const name = String(req.body.name || "My character").trim().slice(0, 40) || "My character", data = req.body.data;
  if (typeof data !== "string" || data.length > 450000 || !/^data:image\/(webp|png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(data)) return fail(res, 400, "That image can’t be saved.");
  if (count("characters", req.user.id) >= 20) return fail(res, 400, "You’ve reached the limit of 20 characters.");
  const r = db.prepare("INSERT INTO characters(user_id,name,data,created) VALUES(?,?,?,?)").run(req.user.id, name, data, Date.now());
  res.json({ id: Number(r.lastInsertRowid) });
});
app.delete("/api/characters/:id", auth, (req, res) => {
  const r = db.prepare("DELETE FROM characters WHERE id=? AND user_id=?").run(Number(req.params.id), req.user.id);
  r.changes ? res.json({ ok: true }) : fail(res, 404, "Not found.");
});

app.use("/api", (req, res) => fail(res, 404, "Not found."));
app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") return fail(res, 413, "That file is too big.");
  if (err instanceof SyntaxError) return fail(res, 400, "Bad request.");
  console.error(err); fail(res, 500, "Server error.");
});

app.listen(PORT, () => {
  console.log(`Lyrical Bot server on :${PORT}  (email: ${PROVIDER === "dev" ? "DEV MODE, codes are printed here, nothing is emailed" : PROVIDER})`);
  if (PROVIDER === "dev" && process.env.NODE_ENV === "production") console.warn("WARNING: no email provider configured, so nobody can receive codes. Set BREVO_API_KEY or RESEND_API_KEY.");
});
