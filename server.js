// Nomber OTP backend: Express + SQLite. Manual UPI QR + UTR top-ups, admin panel, NumberOTP supplier.
// Env: JWT_SECRET, ADMIN_EMAIL, NUMBEROTP_API_KEY, NUMBEROTP_COUNTRY (India's id from NumberOTP), UPI_ID
//      optional: NUMBEROTP_MAX_PRICE, PORT
const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
if (!JWT_SECRET) throw new Error("Set JWT_SECRET");
const WAIT_MS = 5 * 60 * 1000;

const dbPath = process.env.DB_PATH || "nomber.db";
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pass TEXT, balance INTEGER DEFAULT 0, is_admin INT DEFAULT 0, banned INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INT, service TEXT, number TEXT, supplier TEXT, supplier_ref TEXT, otp TEXT, status TEXT, price INT, created INT, expires INT);
CREATE TABLE IF NOT EXISTS topups(id INTEGER PRIMARY KEY, user_id INT, amount INT, utr TEXT UNIQUE, status TEXT DEFAULT 'pending', created INT, decided INT);
CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, user_id INT, delta INT, reason TEXT, ref TEXT, created INT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
`);
const DEFAULTS = { price: 10, min_topup: 50 };
const setting = k => Number(db.prepare("SELECT v FROM settings WHERE k=?").get(k)?.v ?? DEFAULTS[k]);
const price = () => setting("price"), minTopup = () => setting("min_topup");

// Every balance change goes through here so the ledger always matches balances. Call inside a transaction.
function credit(uid, delta, reason, ref) {
  db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(delta, uid);
  db.prepare("INSERT INTO ledger(user_id,delta,reason,ref,created) VALUES(?,?,?,?,?)").run(uid, delta, reason, String(ref || ""), Date.now());
}

// ---------- Supplier: NumberOTP (docs: https://www.numberotp.com/docs/api) ----------
const NB = "https://api.numberotp.com/v1";
async function nreq(path, opt = {}) {
  try {
    const r = await fetch(NB + path, { ...opt, headers: { "Content-Type": "application/json", Authorization: "Bearer " + process.env.NUMBEROTP_API_KEY }, timeout: 10000 });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || "supplier " + r.status); e.code = j.code; throw e; }
    return j;
  } catch (e) {
    console.error("NumberOTP API error:", e.message);
    throw e;
  }
}
let svcCache = { at: 0, map: {} };
async function serviceCode(name) {
  if (Date.now() - svcCache.at > 3600e3) {
    try {
      const j = await (await fetch(NB + "/public/services", { timeout: 10000 })).json();
      const arr = Array.isArray(j) ? j : j.services || j.data || [];
      svcCache = { at: Date.now(), map: Object.fromEntries(arr.map(s => [String(s.name || s.title || "").toLowerCase(), s.code || s.id || s.slug])) };
    } catch (e) {
      console.error("Failed to cache services:", e.message);
    }
  }
  const code = svcCache.map[name.toLowerCase()];
  if (!code) throw new Error("service not supported by supplier");
  return code;
}
const Suppliers = [{
  name: "NumberOTP",
  async getNumber(service) {
    const body = { service: await serviceCode(service), country: process.env.NUMBEROTP_COUNTRY, pool: "auto" };
    if (process.env.NUMBEROTP_MAX_PRICE) body.max_price = Number(process.env.NUMBEROTP_MAX_PRICE);
    const j = await nreq("/activations", { method: "POST", body: JSON.stringify(body) });
    const a = j.activation || j;
    const num = String(a.phone_number || a.number || "");
    if (!num || !(a.id || a.activation_id)) throw new Error("bad supplier response");
    return { number: "+" + num.replace(/^\+/, ""), ref: String(a.id || a.activation_id) };
  },
  async getOtp(ref) { const j = await nreq("/activations/" + encodeURIComponent(ref)); return (j.activation || j).otp || null; },
  async cancel() { /* NumberOTP documents no cancel endpoint; check their refund policy for unused numbers */ },
}];
const stats = {};
const rate = s => { const t = stats[s.name] || { ok: 1, fail: 1 }; return t.ok / (t.ok + t.fail); };
const mark = (n, ok) => { const t = (stats[n] ||= { ok: 1, fail: 1 }); ok ? t.ok++ : t.fail++; };

// ---------- App ----------
const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: false }));

// Ensure public dir exists
const publicDir = path.join(__dirname, "public");
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });

app.use(express.static(publicDir));

// Health check
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

function auth(req, res, next) {
  try {
    const { uid } = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), JWT_SECRET);
    const u = db.prepare("SELECT id,is_admin,banned FROM users WHERE id=?").get(uid);
    if (!u || u.banned) return res.status(401).json({ error: "login required" });
    req.uid = u.id; req.isAdmin = !!u.is_admin; next();
  } catch { res.status(401).json({ error: "login required" }); }
}
const admin = (req, res, next) => (req.isAdmin ? next() : res.status(403).json({ error: "admin only" }));
const token = id => jwt.sign({ uid: id }, JWT_SECRET, { expiresIn: "7d" });

app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email || "") || (password || "").length < 8) return res.status(400).json({ error: "valid email and 8+ char password required" });
  try {
    const e = email.toLowerCase();
    const r = db.prepare("INSERT INTO users(email,pass,is_admin) VALUES(?,?,?)").run(e, await bcrypt.hash(password, 10), e === ADMIN_EMAIL ? 1 : 0);
    res.json({ token: token(r.lastInsertRowid) });
  } catch (err) { res.status(409).json({ error: "email already used" }); }
});
app.post("/auth/login", async (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(String(req.body?.email || "").toLowerCase());
  if (!u || u.banned || !(await bcrypt.compare(req.body.password || "", u.pass))) return res.status(401).json({ error: "wrong credentials" });
  res.json({ token: token(u.id) });
});

app.get("/me", auth, (req, res) => res.json({
  balance: db.prepare("SELECT balance FROM users WHERE id=?").get(req.uid).balance,
  orders: db.prepare("SELECT id,service,number,otp,status,price,created,expires FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.uid),
  topups: db.prepare("SELECT amount,utr,status,created FROM topups WHERE user_id=? ORDER BY id DESC LIMIT 20").all(req.uid),
  config: { price: price(), minTopup: minTopup(), upiId: process.env.UPI_ID || "", hasQr: fs.existsSync(path.join(publicDir, "qr.png")) },
  isAdmin: req.isAdmin,
}));

// Manual top-up: user pays your QR, submits amount + UTR, admin verifies in the bank/merchant app and approves.
app.post("/topups", auth, (req, res) => {
  const amount = Math.floor(Number(req.body?.amount)), utr = String(req.body?.utr || "").trim();
  if (!(amount >= minTopup())) return res.status(400).json({ error: "minimum top-up is Rs " + minTopup() });
  if (!/^\d{12}$/.test(utr)) return res.status(400).json({ error: "UTR must be 12 digits" });
  if (db.prepare("SELECT COUNT(*) c FROM topups WHERE user_id=? AND status='pending'").get(req.uid).c >= 5) return res.status(429).json({ error: "too many pending requests, wait for approval" });
  try { db.prepare("INSERT INTO topups(user_id,amount,utr,created) VALUES(?,?,?,?)").run(req.uid, amount, utr, Date.now()); res.json({ ok: true }); }
  catch { res.status(409).json({ error: "this UTR was already submitted" }); }
});

// QR upload endpoint (admin only)
app.post("/admin/qr/upload", auth, admin, express.raw({ type: "image/*", limit: "5mb" }), (req, res) => {
  try {
    const qrPath = path.join(publicDir, "qr.png");
    fs.writeFileSync(qrPath, req.body);
    res.json({ ok: true, size: req.body.length });
  } catch (e) {
    res.status(500).json({ error: "Failed to save QR: " + e.message });
  }
});

app.post("/orders", auth, async (req, res) => {
  const service = String(req.body?.service || "").trim().slice(0, 40), P = price();
  if (!service) return res.status(400).json({ error: "service required" });
  const paid = db.transaction(() => {
    if (!db.prepare("SELECT 1 FROM users WHERE id=? AND balance>=?").get(req.uid, P)) return false;
    credit(req.uid, -P, "order-hold", service); return true;
  })();
  if (!paid) return res.status(402).json({ error: "insufficient balance" });
  for (const s of [...Suppliers].sort((a, b) => rate(b) - rate(a))) {
    try {
      const n = await s.getNumber(service), now = Date.now();
      const r = db.prepare("INSERT INTO orders(user_id,service,number,supplier,supplier_ref,status,price,created,expires) VALUES(?,?,?,?,?,'waiting',?,?,?)").run(req.uid, service, n.number, s.name, n.ref, P, now, now + WAIT_MS);
      return res.json({ id: r.lastInsertRowid });
    } catch (e) {
      console.error(`Supplier ${s.name} failed:`, e.message);
      mark(s.name, false);
    }
  }
  db.transaction(() => credit(req.uid, P, "order-no-stock", service))();
  res.status(503).json({ error: "no numbers available for this app right now, try again later" });
});

// Idempotent refund: only one caller can move an order out of an allowed state.
async function refund(o, status, from = ["waiting"]) {
  const ok = db.transaction(() => {
    const r = db.prepare(`UPDATE orders SET status=? WHERE id=? AND status IN (${from.map(() => "?").join(",")})`).run(status, o.id, ...from);
    if (r.changes) credit(o.user_id, o.price, "refund-" + status, o.id);
    return r.changes > 0;
  })();
  if (ok) { try { await Suppliers.find(x => x.name === o.supplier)?.cancel(o.supplier_ref); } catch {} }
  return ok;
}
app.post("/orders/:id/cancel", auth, async (req, res) => {
  const o = db.prepare("SELECT * FROM orders WHERE id=? AND user_id=?").get(req.params.id, req.uid);
  if (!o) return res.sendStatus(404);
  (await refund(o, "cancelled")) ? res.json({ ok: true }) : res.status(409).json({ error: "order already finished" });
});

// ---------- Admin ----------
const A = [auth, admin];
app.get("/admin/summary", ...A, (req, res) => {
  const day = Date.now() - 864e5, c = (q, ...a) => db.prepare(q).get(...a);
  res.json({
    users: c("SELECT COUNT(*) n FROM users").n,
    walletTotal: c("SELECT COALESCE(SUM(balance),0) n FROM users").n,
    pendingTopups: c("SELECT COUNT(*) n FROM topups WHERE status='pending'").n,
    orders24h: c("SELECT COUNT(*) n FROM orders WHERE created>?", day).n,
    revenue24h: c("SELECT COALESCE(SUM(price),0) n FROM orders WHERE status='done' AND created>?", day).n,
    suppliers: Suppliers.map(s => ({ name: s.name, successRate: Math.round(rate(s) * 100) })),
  });
});
app.get("/admin/topups", ...A, (req, res) => res.json(db.prepare("SELECT t.*,u.email FROM topups t JOIN users u ON u.id=t.user_id WHERE (?='all' OR t.status=?) ORDER BY t.id DESC LIMIT 200").all(req.query.status || "pending", req.query.status || "pending")));
app.post("/admin/topups/:id/:act", ...A, (req, res) => {
  const act = req.params.act;
  if (!["approve", "reject"].includes(act)) return res.sendStatus(404);
  const ok = db.transaction(() => {
    const t = db.prepare("SELECT * FROM topups WHERE id=?").get(req.params.id);
    if (!t || db.prepare("UPDATE topups SET status=?,decided=? WHERE id=? AND status='pending'").run(act === "approve" ? "approved" : "rejected", Date.now(), t.id).changes === 0) return false;
    if (act === "approve") credit(t.user_id, t.amount, "topup-utr", t.utr);
    return true;
  })();
  ok ? res.json({ ok: true }) : res.status(409).json({ error: "already decided or not found" });
});
app.get("/admin/users", ...A, (req, res) => res.json(db.prepare("SELECT id,email,balance,is_admin,banned FROM users WHERE email LIKE ? ORDER BY id DESC LIMIT 100").all("%" + (req.query.q || "") + "%")));
app.post("/admin/users/:id/adjust", ...A, (req, res) => {
  const d = Math.trunc(Number(req.body?.delta));
  if (!d) return res.status(400).json({ error: "enter a non-zero amount" });
  const ok = db.transaction(() => {
    if (d < 0 && !db.prepare("SELECT 1 FROM users WHERE id=? AND balance>=?").get(req.params.id, -d)) return false;
    credit(req.params.id, d, "admin-adjust", String(req.body?.note || "").slice(0, 100)); return true;
  })();
  ok ? res.json({ ok: true }) : res.status(400).json({ error: "balance cannot go below zero" });
});
app.post("/admin/users/:id/ban", ...A, (req, res) => {
  if (Number(req.params.id) === req.uid) return res.status(400).json({ error: "cannot ban yourself" });
  db.prepare("UPDATE users SET banned=? WHERE id=?").run(req.body?.banned ? 1 : 0, req.params.id); res.json({ ok: true });
});
app.get("/admin/orders", ...A, (req, res) => res.json(db.prepare("SELECT o.*,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200").all()));
app.post("/admin/orders/:id/refund", ...A, async (req, res) => {
  const o = db.prepare("SELECT * FROM orders WHERE id=?").get(req.params.id);
  if (o && (await refund(o, "refunded", ["waiting", "done"]))) return res.json({ ok: true });
  res.status(409).json({ error: "order not found or already refunded" });
});
app.get("/admin/settings", ...A, (req, res) => res.json({ price: price(), min_topup: minTopup() }));
app.post("/admin/settings", ...A, (req, res) => {
  for (const k of ["price", "min_topup"]) {
    const v = Math.floor(Number(req.body?.[k]));
    if (!(v >= 1 && v <= 10000)) return res.status(400).json({ error: k + " must be 1-10000" });
    db.prepare("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").run(k, String(v));
  }
  res.json({ ok: true });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Error:", err.message, err.stack);
  res.status(500).json({ error: "Server error: " + (err.message || "unknown") });
});

// 404 handler
app.use((req, res) => res.status(404).json({ error: "not found" }));

// ---------- Worker: poll for OTPs, auto-refund on timeout ----------
setInterval(async () => {
  try {
    for (const o of db.prepare("SELECT * FROM orders WHERE status='waiting'").all()) {
      const s = Suppliers.find(x => x.name === o.supplier);
      try {
        const otp = await s.getOtp(o.supplier_ref);
        if (otp) { db.prepare("UPDATE orders SET otp=?,status='done' WHERE id=? AND status='waiting'").run(otp, o.id); mark(s.name, true); continue; }
      } catch (e) {
        console.error(`Failed to get OTP for order ${o.id}:`, e.message);
      }
      if (Date.now() > o.expires && (await refund(o, "refunded"))) mark(o.supplier, false);
    }
  } catch (e) {
    console.error("Worker error:", e.message);
  }
}, 4000);

if (ADMIN_EMAIL) db.prepare("UPDATE users SET is_admin=1 WHERE email=?").run(ADMIN_EMAIL);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Nomber OTP running on port ${PORT}`);
  console.log(`Database: ${dbPath}`);
  console.log(`Admin email: ${ADMIN_EMAIL}`);
  console.log(`NumberOTP country: ${process.env.NUMBEROTP_COUNTRY}`);
});
