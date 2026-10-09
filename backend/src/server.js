const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

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
const PENDING_TTL_SECONDS = 15 * 60;

// Validate configuration before starting.
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set and at least 32 characters long.");
}

app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json({ limit: "20kb" }));

app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
  }),
);

// PostgreSQL connection.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Redis connection.
const redis = createClient({
  url: process.env.REDIS_URL,
});

redis.on("error", (err) => {
  console.error("Redis error:", err.message);
});

// Email configuration (Mailpit works for local testing).
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "mailpit",
  port: Number(process.env.SMTP_PORT || 1025),
  secure: false,
});

// Helper functions.
function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

function tokenDigest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function escapeHtml(value) {
  return String(value).replace(
    /[&<>"']/g,
    (ch) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[ch],
  );
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    emailVerified: row.email_verified,
  };
}

// Health check.
app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    await redis.ping();

    res.json({
      status: "ok",
      database: "connected",
      redis: "connected",
    });
  } catch (err) {
    res.status(503).json({
      status: "unavailable",
      message: err.message,
    });
  }
});

// REGISTER: Generate and email a 6-digit OTP.
app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 120) {
      return res.status(400).json({
        message: "Name must be between 2 and 120 characters.",
      });
    }

    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({
        message: "Enter a valid email address.",
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        message: "Password must be 8–72 characters long.",
      });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [
      email,
    ]);

    if (existing.rowCount > 0) {
      return res.status(409).json({
        message: "Account already exists. Please log in.",
      });
    }

    const pendingKey = `pending-user:${email}`;
    const otpKey = `email-otp:${email}`;
    const attemptsKey = `otp-attempts:${email}`;

    if (await redis.exists(pendingKey)) {
      return res.status(409).json({
        message: "An OTP was already sent. Check your email.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const otp = generateOTP();

    const pending = {
      name,
      email,
      passwordHash,
    };

    // Store the OTP hash, not the original OTP.
    const otpHash = tokenDigest(otp);

    // Save pending user and OTP in Redis for 15 minutes.
    await redis.set(pendingKey, JSON.stringify(pending), {
      EX: PENDING_TTL_SECONDS,
    });

    await redis.set(otpKey, otpHash, { EX: PENDING_TTL_SECONDS });

    // Send OTP email.
    try {
      await mailer.sendMail({
        from: process.env.SMTP_FROM || "Demo App <no-reply@example.test>",
        to: email,
        subject: "Your email verification OTP",
        text:
          `Hello ${name},\n\n` +
          `Your email verification OTP is: ${otp}\n\n` +
          "This OTP expires in 15 minutes.\n\n" +
          "If you did not request this, ignore this email.",
        html:
          `<p>Hello ${escapeHtml(name)},</p>` +
          "<p>Your email verification OTP is:</p>" +
          `<h2>${otp}</h2>` +
          "<p>This OTP expires in 15 minutes.</p>" +
          "<p>If you did not request this, ignore this email.</p>",
      });
    } catch (mailErr) {
      await redis.del(pendingKey, otpKey);

      console.error("Email delivery failed:", mailErr.message);

      return res.status(502).json({
        message: "Could not send OTP email. Please try again.",
      });
    }

    return res.status(201).json({
      message: "OTP sent successfully. Check your email.",
      expiresInMinutes: 15,
    });
  } catch (err) {
    console.error("Registration error:", err);

    return res.status(500).json({
      message: "Unexpected server error.",
    });
  }
});

// VERIFY OTP: Validate the OTP and create a verified user.
app.post("/api/auth/verify", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const otp = String(req.body.otp || "");

  if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({
      message: "Enter a valid email and 6-digit OTP.",
    });
  }

  const pendingKey = `pending-user:${email}`;
  const otpKey = `email-otp:${email}`;
  const attemptsKey = `otp-attempts:${email}`;

  try {
    const pendingJson = await redis.get(pendingKey);
    const storedHash = await redis.get(otpKey);

    if (!pendingJson || !storedHash) {
      return res.status(400).json({
        message: "OTP expired or registration not found. Register again.",
      });
    }

    // Allow at most five attempts.
    const attempts = await redis.incr(attemptsKey);

    if (attempts === 1) {
      await redis.expire(attemptsKey, PENDING_TTL_SECONDS);
    }

    if (attempts > 5) {
      await redis.del(pendingKey, otpKey);

      return res.status(429).json({
        message: "Too many attempts. Please register again.",
      });
    }

    const submittedHash = tokenDigest(otp);

    if (submittedHash !== storedHash) {
      return res.status(400).json({
        message: "Incorrect OTP. Please try again.",
      });
    }

    const pending = JSON.parse(pendingJson);

    await pool.query(
      `INSERT INTO users
        (name, email, password_hash, email_verified)
       VALUES ($1, $2, $3, TRUE)
       ON CONFLICT (email) DO NOTHING`,
      [pending.name, pending.email, pending.passwordHash],
    );

    // Remove OTP and pending registration after success.
    await redis.del(pendingKey, otpKey, attemptsKey);

    return res.json({
      message: "Email verified successfully. You can now log in.",
    });
  } catch (err) {
    console.error("Verification error:", err);

    return res.status(500).json({
      message: "Could not verify email. Please try again.",
    });
  }
});

// LOGIN: Only verified users can log in.
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!validEmail(email) || !password) {
      return res.status(400).json({
        message: "Enter your email and password.",
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, email_verified
       FROM users
       WHERE email = $1`,
      [email],
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        message: "Invalid email or password.",
      });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        message: "Please verify your email before logging in.",
      });
    }

    const authToken = jwt.sign(
      {
        sub: String(user.id),
        email: user.email,
      },
      JWT_SECRET,
      {
        expiresIn: "1h",
        issuer: "email-verification-app",
      },
    );

    return res.json({
      message: "Login successful.",
      token: authToken,
      user: publicUser(user),
    });
  } catch (err) {
    console.error("Login error:", err);

    return res.status(500).json({
      message: "Unexpected server error.",
    });
  }
});

// GET CURRENT USER: Requires a valid JWT.
app.get("/api/auth/me", async (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) {
    return res.status(401).json({
      message: "Authentication required.",
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      issuer: "email-verification-app",
    });

    const result = await pool.query(
      `SELECT id, name, email, email_verified
       FROM users
       WHERE id = $1`,
      [payload.sub],
    );

    if (!result.rowCount || !result.rows[0].email_verified) {
      return res.status(401).json({
        message: "User not found or not verified.",
      });
    }

    return res.json({
      user: publicUser(result.rows[0]),
    });
  } catch (_err) {
    return res.status(401).json({
      message: "Authentication token is invalid or expired.",
    });
  }
});

// Start application.
async function start() {
  await redis.connect();
  await pool.query("SELECT 1");

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Backend listening on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Startup failed:", err);
  process.exit(1);
});
