require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const Stripe = require("stripe");
const { Resend } = require("resend");
const { Pool } = require("pg");
const multer = require("multer");
const { v2: cloudinary } = require("cloudinary");

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set and contain at least 32 characters");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set (your Neon/Postgres connection string)");
}

const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

const cloudinaryConfigured = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
if (cloudinaryConfigured) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  });
}
// Keep uploads in memory (not on disk) — Render's free tier disk isn't
// durable across deploys anyway, so we stream straight to Cloudinary.
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
// Resend's free tier requires this exact sender address until you verify
// your own domain with them — real "from your store" addresses come later.
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
// Where customers land after paying. This MUST be your frontend's URL (the
// React app), not the backend — otherwise Stripe redirects people to a
// bare backend response instead of your actual confirmation page.
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

if (!process.env.STRIPE_WEBHOOK_SECRET && stripe) {
  console.warn("STRIPE_WEBHOOK_SECRET is not set — the /api/webhook route will reject all events until it is.");
}

// Fire-and-forget email helper. Never throws — a broken email provider
// should never take down an order or a password reset; we just log it.
async function sendEmail({ to, subject, html }) {
  if (!resend) {
    console.log(`[email skipped — no RESEND_API_KEY] to=${to} subject="${subject}"`);
    return;
  }
  try {
    await resend.emails.send({ from: FROM_EMAIL, to, subject, html });
  } catch (error) {
    console.error("Failed to send email:", error.message || error);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000
});

// Idle clients in the pool can be dropped by the database side (common on
// free-tier serverless Postgres). Without this handler, that error is
// unhandled and crashes the whole Node process. With it, the pool just logs
// and moves on — the next query gets a fresh connection automatically.
pool.on("error", (error) => {
  console.error("Unexpected error on idle database client", error);
});

const app = express();
// Render sits in front of your app behind a proxy, so Express needs to be
// told to trust the X-Forwarded-For header it sets. Without this, the rate
// limiter below can't reliably tell users apart by IP.
app.set("trust proxy", 1);
const now = () => new Date().toISOString();

// --- Row -> API shape mappers (snake_case DB columns -> camelCase JSON) ------

function mapUser(row) {
  return {
    id: row.id, name: row.name, email: row.email, role: row.role,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

function mapCategory(row) {
  return {
    id: row.id, name: row.name, active: row.active,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

function mapProduct(row) {
  return {
    id: row.id, name: row.name, description: row.description,
    price: Number(row.price), category: row.category, stock: row.stock,
    images: row.images || [], active: row.active,
    inStock: row.stock > 0,
    averageRating: row.avg_rating !== undefined ? Math.round(Number(row.avg_rating) * 10) / 10 : 0,
    reviewCount: row.review_count !== undefined ? Number(row.review_count) : 0,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

function mapReview(row) {
  return {
    id: row.id, productId: row.product_id, userId: row.user_id, userName: row.user_name,
    rating: row.rating, comment: row.comment,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

function mapCoupon(row) {
  return {
    id: row.id, code: row.code, type: row.type, value: Number(row.value),
    expiresAt: row.expires_at ? row.expires_at.toISOString() : null, active: row.active,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

function mapOrder(row, items) {
  return {
    id: row.id, userId: row.user_id,
    items: items.map((item) => ({ productId: item.product_id, name: item.name, price: Number(item.price), quantity: item.quantity })),
    subtotal: Number(row.subtotal), couponCode: row.coupon_code, discount: Number(row.discount), total: Number(row.total),
    shippingAddress: row.shipping_address, status: row.status, paymentStatus: row.payment_status,
    stripeSessionId: row.stripe_session_id,
    createdAt: row.created_at.toISOString(), updatedAt: row.updated_at.toISOString()
  };
}

async function getOrderItems(orderId, client = pool) {
  const result = await client.query("SELECT product_id, name, price, quantity FROM order_items WHERE order_id = $1", [orderId]);
  return result.rows;
}

async function loadFullOrder(orderId, client = pool) {
  const orderResult = await client.query("SELECT * FROM orders WHERE id = $1", [orderId]);
  if (!orderResult.rows[0]) return null;
  const items = await getOrderItems(orderId, client);
  return mapOrder(orderResult.rows[0], items);
}

// --- Auth helpers -------------------------------------------------------------

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}

async function authenticate(req, res, next) {
  const header = req.get("authorization");
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [payload.sub]);
    if (!result.rows[0]) return res.status(401).json({ error: "User no longer exists" });
    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

function requireFields(body, fields) {
  const missing = fields.filter((field) =>
    body[field] === undefined || body[field] === null || body[field] === ""
  );
  return missing;
}

function paginate(items, query) {
  const pageNumber = Math.max(1, Number(query.page) || 1);
  const pageSize = Math.min(100, Math.max(1, Number(query.limit) || 20));
  const start = (pageNumber - 1) * pageSize;
  return {
    data: items.slice(start, start + pageSize),
    pagination: {
      page: pageNumber, limit: pageSize, total: items.length,
      pages: Math.ceil(items.length / pageSize)
    }
  };
}

function isValidShippingAddress(address) {
  if (!address || typeof address !== "object" || Array.isArray(address)) return false;
  const required = ["line1", "city", "postalCode", "country"];
  return required.every((field) => typeof address[field] === "string" && address[field].trim().length > 0);
}

async function findActiveCoupon(code) {
  if (!code) return null;
  const normalized = String(code).trim().toUpperCase();
  const result = await pool.query(
    "SELECT * FROM coupons WHERE code = $1 AND active = true AND (expires_at IS NULL OR expires_at > now())",
    [normalized]
  );
  return result.rows[0] || null;
}

function applyDiscount(total, coupon) {
  if (!coupon) return { discount: 0, finalTotal: total };
  const value = Number(coupon.value);
  const discount = coupon.type === "percent"
    ? Math.round(total * (value / 100) * 100) / 100
    : Math.min(value, total);
  return { discount, finalTotal: Math.round((total - discount) * 100) / 100 };
}

// Builds an order from the user's cart inside a DB transaction: locks the
// relevant product rows, validates stock, applies any coupon, decrements
// stock, inserts the order + order_items, and clears the cart. Either all of
// this happens or none of it does.
async function buildOrderFromCart(user, body, extraFields = {}) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const cartResult = await client.query(
      `SELECT ci.product_id, ci.quantity, p.name, p.price, p.stock
       FROM cart_items ci JOIN products p ON p.id = ci.product_id
       WHERE ci.user_id = $1
       FOR UPDATE OF p`,
      [user.id]
    );
    if (!cartResult.rows.length) {
      await client.query("ROLLBACK");
      return { error: "Your cart is empty", status: 400 };
    }
    const missingStock = cartResult.rows.find((item) => item.quantity > item.stock);
    if (missingStock) {
      await client.query("ROLLBACK");
      return { error: `${missingStock.name} no longer has enough stock`, status: 400 };
    }
    const required = requireFields(body, ["shippingAddress"]);
    if (required.length) {
      await client.query("ROLLBACK");
      return { error: `Missing fields: ${required.join(", ")}`, status: 400 };
    }
    if (!isValidShippingAddress(body.shippingAddress)) {
      await client.query("ROLLBACK");
      return { error: "shippingAddress must include line1, city, postalCode and country", status: 400 };
    }
    let coupon = null;
    if (body.couponCode) {
      const couponResult = await client.query(
        "SELECT * FROM coupons WHERE code = $1 AND active = true AND (expires_at IS NULL OR expires_at > now())",
        [String(body.couponCode).trim().toUpperCase()]
      );
      coupon = couponResult.rows[0] || null;
      if (!coupon) {
        await client.query("ROLLBACK");
        return { error: "Coupon is invalid or expired", status: 400 };
      }
    }
    const subtotal = Math.round(cartResult.rows.reduce((sum, item) => sum + Number(item.price) * item.quantity, 0) * 100) / 100;
    const { discount, finalTotal } = applyDiscount(subtotal, coupon);

    const status = extraFields.status || "pending";
    const orderInsert = await client.query(
      `INSERT INTO orders (user_id, subtotal, coupon_code, discount, total, shipping_address, status, payment_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [user.id, subtotal, coupon ? coupon.code : null, discount, finalTotal, body.shippingAddress, status, "unpaid"]
    );
    const order = orderInsert.rows[0];

    for (const item of cartResult.rows) {
      await client.query("UPDATE products SET stock = stock - $1, updated_at = now() WHERE id = $2", [item.quantity, item.product_id]);
      await client.query(
        "INSERT INTO order_items (order_id, product_id, name, price, quantity) VALUES ($1,$2,$3,$4,$5)",
        [order.id, item.product_id, item.name, item.price, item.quantity]
      );
    }
    await client.query("DELETE FROM cart_items WHERE user_id = $1", [user.id]);

    await client.query("COMMIT");
    const items = await getOrderItems(order.id);
    return { order: mapOrder(order, items) };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// Restores stock for every item in an order (used on cancellation or an
// abandoned Stripe checkout).
async function restockOrder(orderId, client = pool) {
  const items = await getOrderItems(orderId, client);
  for (const item of items) {
    await client.query("UPDATE products SET stock = stock + $1, updated_at = now() WHERE id = $2", [item.quantity, item.product_id]);
  }
}

async function sendOrderConfirmation(user, order) {
  const itemsHtml = order.items.map((item) =>
    `<li>${item.quantity} × ${item.name} — $${item.price.toFixed(2)} each</li>`
  ).join("");
  await sendEmail({
    to: user.email,
    subject: `Order confirmed — #${order.id.slice(0, 8)}`,
    html: `<p>Hi ${user.name},</p><p>Thanks for your order! Here's what you ordered:</p><ul>${itemsHtml}</ul>
      <p>Subtotal: $${order.subtotal.toFixed(2)}${order.discount ? `<br>Discount: -$${order.discount.toFixed(2)}` : ""}<br><strong>Total: $${order.total.toFixed(2)}</strong></p>
      <p>Shipping to: ${order.shippingAddress.line1}, ${order.shippingAddress.city}, ${order.shippingAddress.country}</p>
      <p>Order ID: ${order.id}</p>`
  });
}

// Marks an order as paid, idempotently (safe to call more than once for the
// same order — e.g. if both the webhook and a status-check endpoint fire).
// Used by the Stripe webhook below.
async function markOrderPaid(orderId) {
  const orderResult = await pool.query("SELECT * FROM orders WHERE id = $1", [orderId]);
  const order = orderResult.rows[0];
  if (!order) {
    console.error(`Webhook: no order found for id ${orderId}`);
    return;
  }
  if (order.payment_status === "paid") return; // already processed, nothing to do
  await pool.query(
    "UPDATE orders SET payment_status = 'paid', status = 'pending', updated_at = now() WHERE id = $1",
    [orderId]
  );
  const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [order.user_id]);
  if (userResult.rows[0]) {
    const items = await getOrderItems(orderId);
    await sendOrderConfirmation(userResult.rows[0], mapOrder({ ...order, payment_status: "paid", status: "pending" }, items));
  }
}

async function seedAdmin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return;
  const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
  const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
  if (existing.rows[0]) return;
  const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
  await pool.query(
    "INSERT INTO users (name, email, password_hash, role) VALUES ($1,$2,$3,'admin')",
    [process.env.ADMIN_NAME || "Administrator", email, passwordHash]
  );
}

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(",") : true }));

// --- Stripe webhook ------------------------------------------------------------
// IMPORTANT: this route is registered BEFORE express.json() below, and uses
// express.raw() instead, because Stripe's signature verification needs the
// exact raw request body bytes. If this route were registered after
// express.json() (or without express.raw()), the signature check would
// always fail with a 400, even with the correct secret.
app.post("/api/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe) return res.status(500).send("Stripe is not configured on this server");
  if (!process.env.STRIPE_WEBHOOK_SECRET) return res.status(500).send("STRIPE_WEBHOOK_SECRET is not configured");

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.get("stripe-signature"), process.env.STRIPE_WEBHOOK_SECRET);
  } catch (error) {
    console.error("Webhook signature verification failed:", error.message);
    return res.status(400).send(`Webhook Error: ${error.message}`);
  }

  try {
    if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
      const session = event.data.object;
      // We stash the order id as session metadata when creating the
      // Checkout Session (see /api/checkout below), so we can find it here
      // without trusting anything else in the payload.
      const orderId = session.metadata && session.metadata.orderId;
      if (orderId) {
        await markOrderPaid(orderId);
      } else {
        console.error("Webhook: checkout.session.completed with no orderId in metadata", session.id);
      }
    }
    // Acknowledge receipt so Stripe doesn't keep retrying. Any event type we
    // don't explicitly handle is still a 200 — we just ignore it.
    res.json({ received: true });
  } catch (error) {
    console.error("Error handling webhook event:", error);
    res.status(500).send("Webhook handler failed");
  }
});

app.use(express.json({ limit: "1mb" }));
app.use(morgan("combined"));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." }
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", time: now(), database: "connected" });
  } catch (error) {
    res.status(500).json({ status: "error", database: "unreachable" });
  }
});

// --- Auth ----------------------------------------------------------------------

app.post("/api/auth/register", authLimiter, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["name", "email", "password"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const { name, email, password } = req.body;
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "Password must contain at least 8 characters" });
    }
    const normalizedEmail = String(email).toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: "A valid email is required" });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    // The unique constraint on users.email is the real guard against the
    // race condition we hit with the JSON file — Postgres rejects the
    // second concurrent insert outright instead of us having to re-check.
    let result;
    try {
      result = await pool.query(
        "INSERT INTO users (name, email, password_hash, role) VALUES ($1,$2,$3,'customer') RETURNING *",
        [String(name).trim(), normalizedEmail, passwordHash]
      );
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Email is already registered" });
      throw error;
    }
    const user = result.rows[0];
    res.status(201).json({ user: mapUser(user), token: signToken(user) });
  } catch (error) { next(error); }
});

app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["email", "password"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [String(req.body.email).toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    res.json({ user: mapUser(user), token: signToken(user) });
  } catch (error) { next(error); }
});

app.get("/api/auth/me", authenticate, (req, res) => res.json({ user: mapUser(req.user) }));

app.patch("/api/auth/me", authenticate, async (req, res, next) => {
  try {
    const updates = [];
    const values = [];
    if (req.body.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name) return res.status(400).json({ error: "Name cannot be empty" });
      values.push(name);
      updates.push(`name = $${values.length}`);
    }
    if (req.body.password !== undefined) {
      if (typeof req.body.password !== "string" || req.body.password.length < 8) {
        return res.status(400).json({ error: "Password must contain at least 8 characters" });
      }
      values.push(await bcrypt.hash(req.body.password, 12));
      updates.push(`password_hash = $${values.length}`);
    }
    if (!updates.length) return res.json({ user: mapUser(req.user) });
    values.push(req.user.id);
    const result = await pool.query(
      `UPDATE users SET ${updates.join(", ")}, updated_at = now() WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json({ user: mapUser(result.rows[0]) });
  } catch (error) { next(error); }
});

// --- Password reset ---------------------------------------------------------

app.post("/api/auth/forgot-password", authLimiter, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["email"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const email = String(req.body.email).toLowerCase().trim();
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    // Always respond the same way whether or not the account exists —
    // otherwise this endpoint lets anyone discover which emails are registered.
    const genericResponse = { message: "If that email is registered, a reset link has been sent." };
    if (!user) return res.json(genericResponse);

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const expires = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    await pool.query(
      "UPDATE users SET reset_token_hash = $1, reset_token_expires = $2 WHERE id = $3",
      [tokenHash, expires, user.id]
    );

    const resetLink = `${FRONTEND_URL}/?reset=${rawToken}`;
    await sendEmail({
      to: user.email,
      subject: "Reset your password",
      html: `<p>Hi ${user.name},</p><p>Click below to reset your password (valid for 30 minutes):</p><p><a href="${resetLink}">${resetLink}</a></p>`
    });

    res.json(genericResponse);
  } catch (error) { next(error); }
});

app.post("/api/auth/reset-password", authLimiter, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["token", "password"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    if (typeof req.body.password !== "string" || req.body.password.length < 8) {
      return res.status(400).json({ error: "Password must contain at least 8 characters" });
    }
    const tokenHash = crypto.createHash("sha256").update(String(req.body.token)).digest("hex");
    const result = await pool.query(
      "SELECT * FROM users WHERE reset_token_hash = $1 AND reset_token_expires > now()",
      [tokenHash]
    );
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Reset token is invalid or has expired" });

    const passwordHash = await bcrypt.hash(req.body.password, 12);
    await pool.query(
      "UPDATE users SET password_hash = $1, reset_token_hash = NULL, reset_token_expires = NULL, updated_at = now() WHERE id = $2",
      [passwordHash, user.id]
    );
    res.json({ message: "Password has been reset successfully. You can now log in with your new password." });
  } catch (error) { next(error); }
});

app.post("/api/auth/change-password", authenticate, authLimiter, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["currentPassword", "newPassword"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    if (typeof req.body.newPassword !== "string" || req.body.newPassword.length < 8) {
      return res.status(400).json({ error: "New password must contain at least 8 characters" });
    }
    const ok = await bcrypt.compare(req.body.currentPassword, req.user.password_hash);
    if (!ok) return res.status(401).json({ error: "Current password is incorrect" });
    const passwordHash = await bcrypt.hash(req.body.newPassword, 12);
    await pool.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [passwordHash, req.user.id]);
    res.json({ message: "Password changed successfully." });
  } catch (error) { next(error); }
});

// --- Categories ---------------------------------------------------------

app.get("/api/categories", async (req, res, next) => {
  try {
    const result = await pool.query("SELECT * FROM categories WHERE active <> false ORDER BY name");
    res.json(result.rows.map(mapCategory));
  } catch (error) { next(error); }
});

app.post("/api/categories", authenticate, adminOnly, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["name"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const name = String(req.body.name).trim();
    try {
      const result = await pool.query("INSERT INTO categories (name) VALUES ($1) RETURNING *", [name]);
      res.status(201).json(mapCategory(result.rows[0]));
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Category already exists" });
      throw error;
    }
  } catch (error) { next(error); }
});

app.patch("/api/categories/:categoryId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const updates = [];
    const values = [];
    if (req.body.name !== undefined) { values.push(String(req.body.name).trim()); updates.push(`name = $${values.length}`); }
    if (req.body.active !== undefined) { values.push(Boolean(req.body.active)); updates.push(`active = $${values.length}`); }
    if (!updates.length) {
      const existing = await pool.query("SELECT * FROM categories WHERE id = $1", [req.params.categoryId]);
      if (!existing.rows[0]) return res.status(404).json({ error: "Category not found" });
      return res.json(mapCategory(existing.rows[0]));
    }
    values.push(req.params.categoryId);
    const result = await pool.query(
      `UPDATE categories SET ${updates.join(", ")}, updated_at = now() WHERE id = $${values.length} RETURNING *`,
      values
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Category not found" });
    res.json(mapCategory(result.rows[0]));
  } catch (error) { next(error); }
});

app.delete("/api/categories/:categoryId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query("UPDATE categories SET active = false, updated_at = now() WHERE id = $1 RETURNING id", [req.params.categoryId]);
    if (!result.rows[0]) return res.status(404).json({ error: "Category not found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Image upload (admin) ---------------------------------------------------

// Streams an in-memory file buffer to Cloudinary without ever writing it to
// disk — needed since Render's free tier disk doesn't persist across deploys.
function uploadBufferToCloudinary(buffer) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder: "shop-backend", resource_type: "image" },
      (error, result) => (error ? reject(error) : resolve(result))
    );
    stream.end(buffer);
  });
}

app.post("/api/admin/upload-image", authenticate, adminOnly, upload.single("image"), async (req, res, next) => {
  try {
    if (!cloudinaryConfigured) {
      return res.status(500).json({ error: "Image uploads are not configured on this server (missing Cloudinary credentials)" });
    }
    if (!req.file) return res.status(400).json({ error: "No image file was provided (use field name 'image')" });
    if (!req.file.mimetype.startsWith("image/")) {
      return res.status(400).json({ error: "Uploaded file must be an image" });
    }
    const result = await uploadBufferToCloudinary(req.file.buffer);
    res.status(201).json({ url: result.secure_url });
  } catch (error) { next(error); }
});

// --- Products ------------------------------------------------------------

app.get("/api/products", async (req, res, next) => {
  try {
    const { search, category, minPrice, maxPrice, page = 1, limit = 20 } = req.query;
    const conditions = ["p.active <> false"];
    const values = [];
    if (search) {
      values.push(`%${String(search).toLowerCase()}%`);
      conditions.push(`(LOWER(p.name) LIKE $${values.length} OR LOWER(p.description) LIKE $${values.length})`);
    }
    if (category) { values.push(category); conditions.push(`p.category = $${values.length}`); }
    if (minPrice !== undefined) { values.push(Number(minPrice)); conditions.push(`p.price >= $${values.length}`); }
    if (maxPrice !== undefined) { values.push(Number(maxPrice)); conditions.push(`p.price <= $${values.length}`); }

    const query = `
      SELECT p.*, COALESCE(AVG(r.rating), 0) AS avg_rating, COUNT(r.id) AS review_count
      FROM products p LEFT JOIN reviews r ON r.product_id = p.id
      WHERE ${conditions.join(" AND ")}
      GROUP BY p.id
      ORDER BY p.created_at DESC`;
    const result = await pool.query(query, values);
    const { data, pagination } = paginate(result.rows, { page, limit });
    res.json({ data: data.map(mapProduct), pagination });
  } catch (error) { next(error); }
});

app.get("/api/products/:productId", async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.*, COALESCE(AVG(r.rating), 0) AS avg_rating, COUNT(r.id) AS review_count
       FROM products p LEFT JOIN reviews r ON r.product_id = p.id
       WHERE p.id = $1 GROUP BY p.id`,
      [req.params.productId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Product not found" });
    res.json(mapProduct(result.rows[0]));
  } catch (error) { next(error); }
});

async function isKnownActiveCategory(name) {
  const result = await pool.query("SELECT 1 FROM categories WHERE name = $1 AND active <> false", [name]);
  return !!result.rows[0];
}

app.post("/api/products", authenticate, adminOnly, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["name", "description", "price", "category", "stock"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const price = Number(req.body.price);
    const stock = Number(req.body.stock);
    if (!Number.isFinite(price) || price < 0 || !Number.isInteger(stock) || stock < 0) {
      return res.status(400).json({ error: "Price must be non-negative and stock must be a non-negative integer" });
    }
    const category = String(req.body.category).trim();
    const categoryCountResult = await pool.query("SELECT COUNT(*) FROM categories");
    if (Number(categoryCountResult.rows[0].count) > 0 && !(await isKnownActiveCategory(category))) {
      return res.status(400).json({ error: "Category does not exist. Create it first via POST /api/categories" });
    }
    const images = Array.isArray(req.body.images) ? req.body.images : [];
    const result = await pool.query(
      `INSERT INTO products (name, description, price, category, stock, images, active)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [String(req.body.name).trim(), String(req.body.description), Math.round(price * 100) / 100, category, stock, JSON.stringify(images), req.body.active !== false]
    );
    res.status(201).json(mapProduct({ ...result.rows[0], avg_rating: 0, review_count: 0 }));
  } catch (error) { next(error); }
});

app.patch("/api/products/:productId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const updates = [];
    const values = [];
    if (req.body.category !== undefined) {
      const category = String(req.body.category).trim();
      const categoryCountResult = await pool.query("SELECT COUNT(*) FROM categories");
      if (Number(categoryCountResult.rows[0].count) > 0 && !(await isKnownActiveCategory(category))) {
        return res.status(400).json({ error: "Category does not exist. Create it first via POST /api/categories" });
      }
      values.push(category); updates.push(`category = $${values.length}`);
    }
    if (req.body.name !== undefined) { values.push(String(req.body.name).trim()); updates.push(`name = $${values.length}`); }
    if (req.body.description !== undefined) { values.push(String(req.body.description)); updates.push(`description = $${values.length}`); }
    if (req.body.images !== undefined) { values.push(JSON.stringify(req.body.images)); updates.push(`images = $${values.length}`); }
    if (req.body.active !== undefined) { values.push(Boolean(req.body.active)); updates.push(`active = $${values.length}`); }
    if (req.body.price !== undefined) {
      const price = Number(req.body.price);
      if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: "Invalid price" });
      values.push(Math.round(price * 100) / 100); updates.push(`price = $${values.length}`);
    }
    if (req.body.stock !== undefined) {
      if (!Number.isInteger(Number(req.body.stock)) || Number(req.body.stock) < 0) {
        return res.status(400).json({ error: "Invalid stock" });
      }
      values.push(Number(req.body.stock)); updates.push(`stock = $${values.length}`);
    }
    if (!updates.length) {
      const existing = await pool.query("SELECT * FROM products WHERE id = $1", [req.params.productId]);
      if (!existing.rows[0]) return res.status(404).json({ error: "Product not found" });
      return res.json(mapProduct({ ...existing.rows[0], avg_rating: 0, review_count: 0 }));
    }
    values.push(req.params.productId);
    const result = await pool.query(
      `UPDATE products SET ${updates.join(", ")}, updated_at = now() WHERE id = $${values.length} RETURNING *`,
      values
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Product not found" });
    res.json(mapProduct({ ...result.rows[0], avg_rating: 0, review_count: 0 }));
  } catch (error) { next(error); }
});

app.delete("/api/products/:productId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query("UPDATE products SET active = false, updated_at = now() WHERE id = $1 RETURNING id", [req.params.productId]);
    if (!result.rows[0]) return res.status(404).json({ error: "Product not found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Reviews ---------------------------------------------------------------

app.get("/api/products/:productId/reviews", async (req, res, next) => {
  try {
    const productResult = await pool.query("SELECT id FROM products WHERE id = $1", [req.params.productId]);
    if (!productResult.rows[0]) return res.status(404).json({ error: "Product not found" });
    const { page = 1, limit = 20 } = req.query;
    const result = await pool.query("SELECT * FROM reviews WHERE product_id = $1 ORDER BY created_at DESC", [req.params.productId]);
    const { data, pagination } = paginate(result.rows, { page, limit });
    res.json({ data: data.map(mapReview), pagination });
  } catch (error) { next(error); }
});

app.post("/api/products/:productId/reviews", authenticate, async (req, res, next) => {
  try {
    const productResult = await pool.query("SELECT id FROM products WHERE id = $1", [req.params.productId]);
    if (!productResult.rows[0]) return res.status(404).json({ error: "Product not found" });
    const missing = requireFields(req.body, ["rating"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const rating = Number(req.body.rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be an integer from 1 to 5" });
    }
    try {
      const result = await pool.query(
        `INSERT INTO reviews (product_id, user_id, user_name, rating, comment)
         VALUES ($1,$2,$3,$4,$5) RETURNING *`,
        [req.params.productId, req.user.id, req.user.name, rating, req.body.comment ? String(req.body.comment).trim() : ""]
      );
      res.status(201).json(mapReview(result.rows[0]));
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "You have already reviewed this product" });
      throw error;
    }
  } catch (error) { next(error); }
});

app.delete("/api/reviews/:reviewId", authenticate, async (req, res, next) => {
  try {
    const reviewResult = await pool.query("SELECT * FROM reviews WHERE id = $1", [req.params.reviewId]);
    const review = reviewResult.rows[0];
    if (!review) return res.status(404).json({ error: "Review not found" });
    if (review.user_id !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "You can only delete your own review" });
    }
    await pool.query("DELETE FROM reviews WHERE id = $1", [req.params.reviewId]);
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Wishlist ----------------------------------------------------------------

app.get("/api/wishlist", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.*, COALESCE(AVG(r.rating), 0) AS avg_rating, COUNT(r.id) AS review_count
       FROM wishlist_items w JOIN products p ON p.id = w.product_id
       LEFT JOIN reviews r ON r.product_id = p.id
       WHERE w.user_id = $1 GROUP BY p.id`,
      [req.user.id]
    );
    res.json({ items: result.rows.map(mapProduct) });
  } catch (error) { next(error); }
});

app.post("/api/wishlist/items", authenticate, async (req, res, next) => {
  try {
    const { productId } = req.body;
    const productResult = await pool.query("SELECT id FROM products WHERE id = $1", [productId]);
    if (!productResult.rows[0]) return res.status(404).json({ error: "Product not found" });
    await pool.query(
      "INSERT INTO wishlist_items (user_id, product_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [req.user.id, productId]
    );
    const listResult = await pool.query("SELECT product_id FROM wishlist_items WHERE user_id = $1", [req.user.id]);
    res.status(201).json({ items: listResult.rows.map((row) => row.product_id) });
  } catch (error) { next(error); }
});

app.delete("/api/wishlist/items/:productId", authenticate, async (req, res, next) => {
  try {
    await pool.query("DELETE FROM wishlist_items WHERE user_id = $1 AND product_id = $2", [req.user.id, req.params.productId]);
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Cart ------------------------------------------------------------------

async function cartSummary(userId) {
  const result = await pool.query(
    `SELECT ci.quantity, p.id, p.name, p.description, p.price, p.category, p.stock, p.images, p.active, p.created_at, p.updated_at
     FROM cart_items ci JOIN products p ON p.id = ci.product_id
     WHERE ci.user_id = $1`,
    [userId]
  );
  const items = result.rows.map((row) => {
    const product = mapProduct({ ...row, avg_rating: 0, review_count: 0 });
    return { productId: row.id, quantity: row.quantity, product, subtotal: Math.round(product.price * row.quantity * 100) / 100 };
  });
  return {
    items,
    totalItems: items.reduce((sum, item) => sum + item.quantity, 0),
    total: Math.round(items.reduce((sum, item) => sum + item.subtotal, 0) * 100) / 100
  };
}

app.get("/api/cart", authenticate, async (req, res, next) => {
  try { res.json(await cartSummary(req.user.id)); } catch (error) { next(error); }
});

app.post("/api/cart/items", authenticate, async (req, res, next) => {
  try {
    const { productId, quantity = 1 } = req.body;
    const amount = Number(quantity);
    if (!Number.isInteger(amount) || amount < 1) return res.status(400).json({ error: "Quantity must be a positive integer" });
    const productResult = await pool.query("SELECT * FROM products WHERE id = $1 AND active <> false", [productId]);
    const product = productResult.rows[0];
    if (!product) return res.status(404).json({ error: "Product not found" });
    const existingResult = await pool.query("SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2", [req.user.id, productId]);
    const nextQuantity = (existingResult.rows[0] ? existingResult.rows[0].quantity : 0) + amount;
    if (nextQuantity > product.stock) return res.status(400).json({ error: "Requested quantity exceeds stock" });
    await pool.query(
      `INSERT INTO cart_items (user_id, product_id, quantity) VALUES ($1,$2,$3)
       ON CONFLICT (user_id, product_id) DO UPDATE SET quantity = $3`,
      [req.user.id, productId, nextQuantity]
    );
    res.status(201).json(await cartSummary(req.user.id));
  } catch (error) { next(error); }
});

app.patch("/api/cart/items/:productId", authenticate, async (req, res, next) => {
  try {
    const quantity = Number(req.body.quantity);
    const productResult = await pool.query("SELECT * FROM products WHERE id = $1", [req.params.productId]);
    const itemResult = await pool.query("SELECT quantity FROM cart_items WHERE user_id = $1 AND product_id = $2", [req.user.id, req.params.productId]);
    if (!itemResult.rows[0] || !productResult.rows[0]) return res.status(404).json({ error: "Cart item not found" });
    const product = productResult.rows[0];
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > product.stock) {
      return res.status(400).json({ error: "Quantity must be a positive integer within available stock" });
    }
    await pool.query("UPDATE cart_items SET quantity = $1 WHERE user_id = $2 AND product_id = $3", [quantity, req.user.id, req.params.productId]);
    res.json(await cartSummary(req.user.id));
  } catch (error) { next(error); }
});

app.delete("/api/cart/items/:productId", authenticate, async (req, res, next) => {
  try {
    await pool.query("DELETE FROM cart_items WHERE user_id = $1 AND product_id = $2", [req.user.id, req.params.productId]);
    res.status(204).send();
  } catch (error) { next(error); }
});

app.delete("/api/cart", authenticate, async (req, res, next) => {
  try {
    await pool.query("DELETE FROM cart_items WHERE user_id = $1", [req.user.id]);
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Coupons (admin) ------------------------------------------------------

app.get("/api/coupons", authenticate, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT * FROM coupons ORDER BY created_at DESC");
    res.json(result.rows.map(mapCoupon));
  } catch (error) { next(error); }
});

app.post("/api/coupons", authenticate, adminOnly, async (req, res, next) => {
  try {
    const missing = requireFields(req.body, ["code", "type", "value"]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(", ")}` });
    const type = req.body.type;
    const value = Number(req.body.value);
    if (!["percent", "fixed"].includes(type)) return res.status(400).json({ error: "type must be 'percent' or 'fixed'" });
    if (!Number.isFinite(value) || value <= 0) return res.status(400).json({ error: "value must be a positive number" });
    if (type === "percent" && value > 100) return res.status(400).json({ error: "Percent value cannot exceed 100" });
    const code = String(req.body.code).trim().toUpperCase();
    try {
      const result = await pool.query(
        "INSERT INTO coupons (code, type, value, expires_at) VALUES ($1,$2,$3,$4) RETURNING *",
        [code, type, value, req.body.expiresAt || null]
      );
      res.status(201).json(mapCoupon(result.rows[0]));
    } catch (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Coupon code already exists" });
      throw error;
    }
  } catch (error) { next(error); }
});

app.patch("/api/coupons/:couponId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const updates = [];
    const values = [];
    if (req.body.active !== undefined) { values.push(Boolean(req.body.active)); updates.push(`active = $${values.length}`); }
    if (req.body.expiresAt !== undefined) { values.push(req.body.expiresAt); updates.push(`expires_at = $${values.length}`); }
    if (!updates.length) {
      const existing = await pool.query("SELECT * FROM coupons WHERE id = $1", [req.params.couponId]);
      if (!existing.rows[0]) return res.status(404).json({ error: "Coupon not found" });
      return res.json(mapCoupon(existing.rows[0]));
    }
    values.push(req.params.couponId);
    const result = await pool.query(
      `UPDATE coupons SET ${updates.join(", ")}, updated_at = now() WHERE id = $${values.length} RETURNING *`,
      values
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Coupon not found" });
    res.json(mapCoupon(result.rows[0]));
  } catch (error) { next(error); }
});

app.delete("/api/coupons/:couponId", authenticate, adminOnly, async (req, res, next) => {
  try {
    const result = await pool.query("DELETE FROM coupons WHERE id = $1 RETURNING id", [req.params.couponId]);
    if (!result.rows[0]) return res.status(404).json({ error: "Coupon not found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

// --- Orders ------------------------------------------------------------------

app.post("/api/orders", authenticate, async (req, res, next) => {
  try {
    const result = await buildOrderFromCart(req.user, req.body);
    if (result.error) return res.status(result.status).json({ error: result.error });
    sendOrderConfirmation(req.user, result.order);
    res.status(201).json(result.order);
  } catch (error) { next(error); }
});

// Always the logged-in user's OWN orders, regardless of role. Used by the
// plain customer-facing "Orders" screen — unlike GET /api/orders below,
// this never widens to "everyone's orders" just because the caller is an
// admin, so an admin account browsing their own purchase history doesn't
// accidentally see every customer's orders mixed in.
app.get("/api/orders/me", authenticate, async (req, res, next) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const result = await pool.query(
      "SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    const { data, pagination } = paginate(result.rows, { page, limit });
    const withItems = [];
    for (const row of data) withItems.push(mapOrder(row, await getOrderItems(row.id)));
    res.json({ data: withItems, pagination });
  } catch (error) { next(error); }
});

app.get("/api/orders", authenticate, async (req, res, next) => {
  try {
    const { page = 1, limit = 20, status, sortBy = "newest" } = req.query;
    const conditions = [];
    const values = [];
    if (req.user.role !== "admin") { values.push(req.user.id); conditions.push(`user_id = $${values.length}`); }
    if (status) { values.push(status); conditions.push(`status = $${values.length}`); }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const sortOptions = {
      newest: "created_at DESC",
      oldest: "created_at ASC",
      "total-desc": "total DESC",
      "total-asc": "total ASC"
    };
    const orderClause = sortOptions[sortBy] || sortOptions.newest;

    const result = await pool.query(`SELECT * FROM orders ${where} ORDER BY ${orderClause}`, values);
    const { data, pagination } = paginate(result.rows, { page, limit });
    const withItems = [];
    for (const row of data) withItems.push(mapOrder(row, await getOrderItems(row.id)));
    res.json({ data: withItems, pagination });
  } catch (error) { next(error); }
});

app.get("/api/orders/:orderId", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query("SELECT * FROM orders WHERE id = $1", [req.params.orderId]);
    const order = result.rows[0];
    if (!order || (req.user.role !== "admin" && order.user_id !== req.user.id)) {
      return res.status(404).json({ error: "Order not found" });
    }
    res.json(mapOrder(order, await getOrderItems(order.id)));
  } catch (error) { next(error); }
});

app.patch("/api/orders/:orderId/status", authenticate, adminOnly, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const allowed = ["pending", "processing", "shipped", "delivered", "cancelled"];
    if (!allowed.includes(req.body.status)) return res.status(400).json({ error: `Status must be one of: ${allowed.join(", ")}` });
    await client.query("BEGIN");
    const result = await client.query("SELECT * FROM orders WHERE id = $1 FOR UPDATE", [req.params.orderId]);
    const order = result.rows[0];
    if (!order) { await client.query("ROLLBACK"); return res.status(404).json({ error: "Order not found" }); }
    if (order.status === "cancelled" && req.body.status !== "cancelled") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Cancelled orders cannot be moved to another status" });
    }
    if (req.body.status === "cancelled" && order.status !== "cancelled") {
      await restockOrder(order.id, client);
    }
    const updateResult = await client.query(
      "UPDATE orders SET status = $1, updated_at = now() WHERE id = $2 RETURNING *",
      [req.body.status, req.params.orderId]
    );
    await client.query("COMMIT");
    res.json(mapOrder(updateResult.rows[0], await getOrderItems(req.params.orderId)));
  } catch (error) {
    await client.query("ROLLBACK");
    next(error);
  } finally {
    client.release();
  }
});

// --- Stripe checkout -----------------------------------------------------------

function requireStripe(req, res, next) {
  if (!stripe) return res.status(500).json({ error: "Stripe is not configured on this server (missing STRIPE_SECRET_KEY)" });
  next();
}

app.post("/api/checkout", authenticate, requireStripe, async (req, res, next) => {
  try {
    const result = await buildOrderFromCart(req.user, req.body, { status: "awaiting_payment" });
    if (result.error) return res.status(result.status).json({ error: result.error });
    const order = result.order;

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: req.user.email,
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: { name: `Order ${order.id}` },
          unit_amount: Math.round(order.total * 100)
        },
        quantity: 1
      }],
      // Stashing the orderId here lets the webhook below find and mark the
      // right order paid, without trusting anything from the client.
      metadata: { orderId: order.id },
      // These send the customer back to the FRONTEND (your React app), so
      // they see the actual confirmation/cancelled screens, not a bare
      // backend response. The frontend reads ?checkout=success|cancelled.
      success_url: `${FRONTEND_URL}/?checkout=success`,
      cancel_url: `${FRONTEND_URL}/?checkout=cancelled`
    });

    await pool.query("UPDATE orders SET stripe_session_id = $1, updated_at = now() WHERE id = $2", [session.id, order.id]);
    res.status(201).json({ order: { ...order, stripeSessionId: session.id }, checkoutUrl: session.url });
  } catch (error) { next(error); }
});

// Kept as a manual/fallback check — the webhook above is now the primary way
// orders get marked paid, so this being hit or not no longer matters for
// correctness. Still useful if you ever want to double check a specific
// order's payment status directly against Stripe.
app.get("/api/checkout/:orderId/status", authenticate, requireStripe, async (req, res, next) => {
  try {
    const orderResult = await pool.query("SELECT * FROM orders WHERE id = $1", [req.params.orderId]);
    const order = orderResult.rows[0];
    if (!order || (req.user.role !== "admin" && order.user_id !== req.user.id)) {
      return res.status(404).json({ error: "Order not found" });
    }
    if (!order.stripe_session_id) return res.status(400).json({ error: "This order has no associated payment session" });
    const session = await stripe.checkout.sessions.retrieve(order.stripe_session_id);
    if (session.payment_status === "paid" && order.payment_status !== "paid") {
      await markOrderPaid(order.id);
    }
    const finalResult = await pool.query("SELECT * FROM orders WHERE id = $1", [order.id]);
    res.json({ order: mapOrder(finalResult.rows[0], await getOrderItems(order.id)), stripePaymentStatus: session.payment_status });
  } catch (error) { next(error); }
});

// --- Users (admin) ------------------------------------------------------------

app.get("/api/users", authenticate, adminOnly, async (req, res, next) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const result = await pool.query("SELECT * FROM users ORDER BY created_at DESC");
    const { data, pagination } = paginate(result.rows, { page, limit });
    res.json({ data: data.map(mapUser), pagination });
  } catch (error) { next(error); }
});

// --- Admin stats ---------------------------------------------------------------

app.get("/api/admin/stats", authenticate, adminOnly, async (req, res, next) => {
  try {
    const usersCount = await pool.query("SELECT COUNT(*) FROM users");
    const productsCount = await pool.query("SELECT COUNT(*) FROM products WHERE active <> false");
    const ordersCount = await pool.query("SELECT COUNT(*) FROM orders");
    const revenueResult = await pool.query("SELECT COALESCE(SUM(total),0) AS revenue FROM orders WHERE status <> 'cancelled'");
    const statusResult = await pool.query("SELECT status, COUNT(*) FROM orders GROUP BY status");
    const ordersByStatus = {};
    statusResult.rows.forEach((row) => { ordersByStatus[row.status] = Number(row.count); });
    const topProductsResult = await pool.query(`
      SELECT oi.product_id, p.name, SUM(oi.quantity) AS units_sold
      FROM order_items oi
      JOIN orders o ON o.id = oi.order_id AND o.status <> 'cancelled'
      LEFT JOIN products p ON p.id = oi.product_id
      GROUP BY oi.product_id, p.name
      ORDER BY units_sold DESC
      LIMIT 5
    `);
    res.json({
      totalUsers: Number(usersCount.rows[0].count),
      totalProducts: Number(productsCount.rows[0].count),
      totalOrders: Number(ordersCount.rows[0].count),
      revenue: Math.round(Number(revenueResult.rows[0].revenue) * 100) / 100,
      ordersByStatus,
      topProducts: topProductsResult.rows.map((row) => ({
        productId: row.product_id, name: row.name || "Unknown product", unitsSold: Number(row.units_sold)
      }))
    });
  } catch (error) { next(error); }
});

app.use((req, res) => res.status(404).json({ error: "Route not found" }));
app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: "Internal server error" });
});

seedAdmin().then(() => {
  app.listen(PORT, () => console.log(`Shopping API listening on port ${PORT}`));
}).catch((error) => {
  console.error("Unable to initialize database", error);
  process.exit(1);
});