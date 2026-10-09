require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { createClient } = require("redis");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.warn("WARNING: Set a strong JWT_SECRET (at least 32 characters) for production.");
}

app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json({ limit: "20kb" }));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100 }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const redis = createClient({ url: process.env.REDIS_URL });
redis.on("error", (err) => console.error("Redis error:", err.message));

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "mailpit",
  port: Number(process.env.SMTP_PORT || 1025),
  secure: false
});

const PENDING_TTL_SECONDS = 15 * 60;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
function tokenDigest(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, emailVerified: row.email_verified };
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    await redis.ping();
    res.json({ status: "ok", database: "connected", redis: "connected" });
  } catch (err) {
    res.status(503).json({ status: "unavailable", message: err.message });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 120) {
      return res.status(400).json({ message: "Name must be between 2 and 120 characters." });
    }
    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({ message: "Enter a valid email address." });
    }
    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ message: "Password must be 8–72 characters long." });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rowCount) {
      return res.status(409).json({ message: "An account with this email already exists. Please log in." });
    }

    const pendingKey = `pending-user:${email}`;
    if (await redis.exists(pendingKey)) {
      return res.status(409).json({ message: "A verification email was already sent. Check your inbox or wait 15 minutes before registering again." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const token = crypto.randomBytes(32).toString("hex");
    const verifyKey = `verify:${tokenDigest(token)}`;
    const pending = { name, email, passwordHash, verifyKey };

    // Pending registration is stored only in Redis until verification.
    await redis.set(pendingKey, JSON.stringify(pending), { EX: PENDING_TTL_SECONDS });
    await redis.set(verifyKey, JSON.stringify(pending), { EX: PENDING_TTL_SECONDS });

    const verificationUrl = `${FRONTEND_URL}/verify?token=${encodeURIComponent(token)}`;
    try {
      await mailer.sendMail({
        from: process.env.SMTP_FROM || "Demo App <no-reply@example.test>",
        to: email,
        subject: "Verify your email address",
        text: `Hello ${name},\n\nVerify your email using this link (expires in 15 minutes):\n${verificationUrl}\n\nIf you did not request this, you can ignore this email.`,
        html: `<p>Hello ${escapeHtml(name)},</p><p>Click below to verify your email. This link expires in 15 minutes.</p><p><a href="${verificationUrl}">Verify email</a></p><p>If you did not request this, ignore this email.</p>`
      });
    } catch (mailErr) {
      await redis.del(pendingKey, verifyKey);
      console.error("Email delivery failed:", mailErr.message);
      return res.status(502).json({ message: "Could not send verification email. Please try again." });
    }

    return res.status(201).json({
      message: "Registration started. Check your email for the verification link.",
      expiresInMinutes: 15
    });
  } catch (err) {
    console.error("Registration error:", err);
    return res.status(500).json({ message: "Unexpected server error." });
  }
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}

app.get("/api/auth/verify", async (req, res) => {
  const token = String(req.query.token || "");
  if (!/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).json({ message: "Verification link is invalid or expired." });
  }

  const verifyKey = `verify:${tokenDigest(token)}`;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Redis token has a TTL and is removed after successful verification.
    const pendingJson = await redis.get(verifyKey);
    if (!pendingJson) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "Verification link is invalid, expired, or already used." });
    }
    const pending = JSON.parse(pendingJson);

    await client.query(
      `INSERT INTO users (name, email, password_hash, email_verified)
       VALUES ($1, $2, $3, TRUE)
       ON CONFLICT (email) DO NOTHING`,
      [pending.name, pending.email, pending.passwordHash]
    );
    await client.query("COMMIT");

    await redis.del(verifyKey, `pending-user:${pending.email}`);
    return res.json({ message: "Email verified successfully. You can now log in." });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Verification error:", err);
    return res.status(500).json({ message: "Could not verify email. Please try again." });
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    if (!validEmail(email) || !password) {
      return res.status(400).json({ message: "Enter your email and password." });
    }

    const result = await pool.query(
      "SELECT id, name, email, password_hash, email_verified FROM users WHERE email = $1",
      [email]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ message: "Invalid email or password." });
    }
    if (!user.email_verified) {
      return res.status(403).json({ message: "Please verify your email before logging in." });
    }

    const authToken = jwt.sign(
      { sub: String(user.id), email: user.email },
      JWT_SECRET || "development-only-change-this-secret-32chars",
      { expiresIn: "1h", issuer: "email-verification-app" }
    );
    return res.json({ message: "Login successful.", token: authToken, user: publicUser(user) });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Unexpected server error." });
  }
});

app.get("/api/auth/me", async (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Authentication required." });

  try {
    const payload = jwt.verify(token, JWT_SECRET || "development-only-change-this-secret-32chars", {
      issuer: "email-verification-app"
    });
    const result = await pool.query(
      "SELECT id, name, email, email_verified FROM users WHERE id = $1",
      [payload.sub]
    );
    if (!result.rowCount || !result.rows[0].email_verified) {
      return res.status(401).json({ message: "User not found or not verified." });
    }
    res.json({ user: publicUser(result.rows[0]) });
  } catch (_err) {
    res.status(401).json({ message: "Authentication token is invalid or expired." });
  }
});

async function start() {
  await redis.connect();
  await pool.query("SELECT 1");
  app.listen(PORT, "0.0.0.0", () => console.log(`Backend listening on port ${PORT}`));
}
start().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
