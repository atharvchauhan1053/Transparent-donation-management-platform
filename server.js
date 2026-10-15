/* =========================================================
   TRUSTDONATE BACKEND  (Node.js + Express + Razorpay)
   ========================================================= */
require("dotenv").config();

const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Razorpay = require("razorpay");
const { data, save } = require("./db");

const PORT = process.env.PORT || 3000;
const AUTO_APPROVE = String(process.env.AUTO_APPROVE_ACCOUNTS || "true") === "true";

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn("WARNING: JWT_SECRET missing in .env - using a temporary one (logins reset on restart).");
}

const KEY_ID = process.env.RAZORPAY_KEY_ID || "";
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || "";
const WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || "";

const razorpay =
  KEY_ID && KEY_SECRET && !KEY_ID.includes("xxxx")
    ? new Razorpay({ key_id: KEY_ID, key_secret: KEY_SECRET })
    : null;

if (!razorpay) {
  console.warn("WARNING: Razorpay keys are not set in .env - payments will not work until you add them.");
}

/* Organizations that exist as cards in the donate page of the HTML.
   Nobody may register an account using these names (prevents impersonation). */
const BUILT_IN_ORGS = [
  "Helping Hands Foundation",
  "Hope Education Trust",
  "Green Earth NGO",
  "Care & Smile Foundation"
];
const PURPOSES = ["Education", "Healthcare", "Food", "Environment", "General"];

/* ---------------- helpers ---------------- */

const clean = (v, max = 200) => String(v ?? "").trim().slice(0, max);
const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    phone: u.phone,
    role: u.role,
    organizationName: u.organizationName || ""
  };
}

function signToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}

function generateDonationId() {
  let id;
  do {
    id = "TD-" + new Date().getFullYear() + "-" + crypto.randomInt(100000, 1000000);
  } while (data.donations.some((d) => d.id === id));
  return id;
}

function maskName(name) {
  const parts = String(name || "").trim().split(/\s+/);
  if (parts.length < 2) return parts[0] || "Donor";
  return parts[0] + " " + parts[parts.length - 1][0] + ".";
}

const isPaid = (d) => d.paymentStatus === "paid";

/* Donation shape sent to dashboards (no emails / order ids leak to others) */
function donationView(d, includePayment = false) {
  const v = {
    id: d.id,
    donorName: d.donorName,
    organization: d.organization,
    amount: d.amount,
    purpose: d.purpose,
    status: d.status,
    bankStatus: d.bankStatus,
    date: d.date,
    blockchainHash: d.blockchainHash || ""
  };
  if (includePayment) v.paymentId = d.razorpayPaymentId || "";
  return v;
}

function knownOrganizations() {
  const registered = data.users
    .filter((u) => u.role === "organization" && u.approved)
    .map((u) => u.organizationName);
  return [...new Set([...BUILT_IN_ORGS, ...registered])];
}

function markPaid(donation, paymentId) {
  if (isPaid(donation)) return donation; // idempotent
  donation.paymentStatus = "paid";
  donation.razorpayPaymentId = paymentId || donation.razorpayPaymentId || "";
  donation.status = "Pending";               // waiting for CA verification
  donation.bankStatus = "Payment Received";  // CA marks it "Deposited"
  donation.paidAt = new Date().toISOString();
  save();
  return donation;
}

/* very small in-memory rate limiter for login/register */
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const key = req.ip + req.path;
    const now = Date.now();
    const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
    if (list.length >= max) {
      return res.status(429).json({ error: "Too many attempts. Please try again in a few minutes." });
    }
    list.push(now);
    hits.set(key, list);
    next();
  };
}

/* ---------------- auth middleware ---------------- */

function readUser(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    const user = data.users.find((u) => u.id === payload.id);
    return user && user.approved ? user : null;
  } catch {
    return null;
  }
}

function optionalAuth(req, res, next) {
  req.user = readUser(req);
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    const user = readUser(req);
    if (!user) return res.status(401).json({ error: "Please login again." });
    if (user.role !== role) return res.status(403).json({ error: "You do not have access to this." });
    req.user = user;
    next();
  };
}

const app = express();
app.set("trust proxy", 1);

/* ---------------- Razorpay webhook (needs the RAW body, so before express.json) ---------------- */
app.post("/api/razorpay/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!WEBHOOK_SECRET) return res.status(503).send("Webhook secret not configured");

  const signature = req.headers["x-razorpay-signature"] || "";
  const expected = crypto.createHmac("sha256", WEBHOOK_SECRET).update(req.body).digest("hex");
  const a = Buffer.from(String(signature));
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(400).send("Invalid signature");
  }

  try {
    const event = JSON.parse(req.body.toString("utf8"));
    if (event.event === "payment.captured" || event.event === "order.paid") {
      const payment = event.payload?.payment?.entity;
      if (payment?.order_id) {
        const donation = data.donations.find((d) => d.razorpayOrderId === payment.order_id);
        if (donation) markPaid(donation, payment.id);
      }
    }
  } catch (e) {
    console.error("Webhook error:", e.message);
  }
  res.json({ ok: true });
});

app.use(express.json({ limit: "100kb" }));

/* =========================================================
   AUTH
   ========================================================= */

app.post("/api/auth/register", rateLimit(20, 15 * 60 * 1000), async (req, res) => {
  try {
    const b = req.body || {};
    const name = clean(b.name, 80);
    const phone = clean(b.phone, 20);
    const email = clean(b.email, 120).toLowerCase();
    const password = String(b.password || "");
    const role = clean(b.role, 20);

    if (!name) return res.status(400).json({ error: "Please enter your name." });
    if (!isEmail(email)) return res.status(400).json({ error: "Please enter a valid email address." });
    if (!/^[0-9+\-\s]{7,15}$/.test(phone)) return res.status(400).json({ error: "Please enter a valid phone number." });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters." });
    if (!["donor", "organization", "ca"].includes(role)) return res.status(400).json({ error: "Invalid account type." });
    if (data.users.some((u) => u.email === email)) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const user = {
      id: "U" + Date.now() + crypto.randomInt(100, 999),
      name,
      phone,
      email,
      passwordHash: await bcrypt.hash(password, 10),
      role,
      approved: role === "donor" ? true : AUTO_APPROVE,
      createdAt: new Date().toISOString()
    };

    if (role === "organization") {
      const organizationName = clean(b.organizationName, 120);
      const registrationNumber = clean(b.registrationNumber, 60);
      if (!organizationName) return res.status(400).json({ error: "Please enter organization name." });
      if (!registrationNumber) return res.status(400).json({ error: "Please enter the organization registration number." });

      const taken = knownOrganizations().concat(BUILT_IN_ORGS)
        .some((n) => n.toLowerCase() === organizationName.toLowerCase());
      const pendingTaken = data.users.some(
        (u) => u.role === "organization" && (u.organizationName || "").toLowerCase() === organizationName.toLowerCase()
      );
      if (taken || pendingTaken) {
        return res.status(409).json({ error: "An organization with this name is already registered." });
      }
      user.organizationName = organizationName;
      user.registrationNumber = registrationNumber;
    }

    if (role === "ca") {
      const membership = clean(b.caMembership, 60);
      if (!membership) return res.status(400).json({ error: "Please enter your CA membership number." });
      user.caMembership = membership;
    }

    data.users.push(user);
    save();

    res.status(201).json({
      message: user.approved
        ? "Account created successfully."
        : "Account created. It will be activated after verification by the TrustDonate team.",
      approved: user.approved
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not create account." });
  }
});

app.post("/api/auth/login", rateLimit(30, 15 * 60 * 1000), async (req, res) => {
  try {
    const email = clean(req.body?.email, 120).toLowerCase();
    const password = String(req.body?.password || "");
    const role = clean(req.body?.role, 20);

    const user = data.users.find((u) => u.email === email && u.role === role);
    const ok = user && (await bcrypt.compare(password, user.passwordHash));
    if (!ok) return res.status(401).json({ error: "Invalid email, password or account type." });
    if (!user.approved) {
      return res.status(403).json({ error: "Your account is awaiting verification. Please try again later." });
    }
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed." });
  }
});

app.get("/api/auth/me", (req, res) => {
  const user = readUser(req);
  if (!user) return res.status(401).json({ error: "Not logged in." });
  res.json({ user: publicUser(user) });
});

/* =========================================================
   ORGANIZATIONS
   ========================================================= */

app.get("/api/organizations", (req, res) => {
  const list = data.users
    .filter((u) => u.role === "organization" && u.approved)
    .map((u) => ({ name: u.organizationName, registrationNumber: u.registrationNumber || "" }));
  res.json({ organizations: list });
});

/* =========================================================
   DONATIONS + RAZORPAY
   ========================================================= */

/* Step 1: create donation + Razorpay order */
app.post("/api/donations/create-order", optionalAuth, async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Payment gateway is not configured. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to the .env file and restart the server."
      });
    }

    const b = req.body || {};
    const donorName = clean(b.donorName, 80);
    let donorEmail = clean(b.donorEmail, 120).toLowerCase();
    const organization = clean(b.organization, 120);
    const purpose = clean(b.purpose, 40) || "General";
    const amount = Math.round(Number(b.amount) * 100) / 100;

    let userId = null;
    if (req.user && req.user.role === "donor") {
      userId = req.user.id;
      donorEmail = req.user.email; // always tie to the logged-in account
    }

    if (!donorName) return res.status(400).json({ error: "Please enter your name." });
    if (!isEmail(donorEmail)) return res.status(400).json({ error: "Please enter a valid email address." });
    if (!knownOrganizations().includes(organization)) return res.status(400).json({ error: "Please select a valid organization." });
    if (!PURPOSES.includes(purpose)) return res.status(400).json({ error: "Invalid donation purpose." });
    if (!Number.isFinite(amount) || amount < 1 || amount > 500000) {
      return res.status(400).json({ error: "Amount must be between ₹1 and ₹5,00,000." });
    }

    const id = generateDonationId();
    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // paise
      currency: "INR",
      receipt: id,
      notes: { donationId: id, organization }
    });

    data.donations.unshift({
      id,
      userId,
      donorName,
      donorEmail,
      organization,
      amount,
      purpose,
      status: "Awaiting Payment",
      paymentStatus: "created",
      bankStatus: "Not Received",
      razorpayOrderId: order.id,
      razorpayPaymentId: "",
      blockchainHash: "",
      recordHash: "",
      date: new Date().toISOString()
    });
    save();

    res.json({
      donationId: id,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: KEY_ID
    });
  } catch (e) {
    console.error("create-order error:", e?.error || e);
    const msg = e?.error?.description || "Could not start the payment. Please check your Razorpay keys.";
    res.status(502).json({ error: msg });
  }
});

/* Step 2: verify the payment signature sent by Razorpay Checkout */
app.post("/api/donations/verify", (req, res) => {
  try {
    if (!KEY_SECRET) return res.status(503).json({ error: "Payment gateway is not configured." });

    const orderId = clean(req.body?.razorpay_order_id, 100);
    const paymentId = clean(req.body?.razorpay_payment_id, 100);
    const signature = clean(req.body?.razorpay_signature, 200);

    const donation = data.donations.find((d) => d.razorpayOrderId === orderId);
    if (!donation) return res.status(404).json({ error: "Donation not found." });

    const expected = crypto.createHmac("sha256", KEY_SECRET).update(orderId + "|" + paymentId).digest("hex");
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(400).json({ error: "Payment verification failed. If money was deducted it will be refunded by your bank." });
    }

    markPaid(donation, paymentId);
    res.json({ donation: donationView(donation, true) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not verify payment." });
  }
});

/* Donor dashboard */
app.get("/api/donations/mine", requireRole("donor"), (req, res) => {
  const list = data.donations
    .filter((d) => d.userId === req.user.id && isPaid(d))
    .map((d) => donationView(d, true));
  res.json({ donations: list });
});

/* Organization dashboard */
app.get("/api/donations/organization", requireRole("organization"), (req, res) => {
  const name = req.user.organizationName;
  const list = data.donations
    .filter((d) => d.organization === name && isPaid(d))
    .map((d) => donationView(d));
  res.json({ organization: name, donations: list });
});

/* CA dashboard */
app.get("/api/donations/all", requireRole("ca"), (req, res) => {
  res.json({ donations: data.donations.filter(isPaid).map((d) => donationView(d)) });
});

/* CA verifies a donation + confirms bank deposit */
app.post("/api/donations/:id/verify", requireRole("ca"), (req, res) => {
  const donation = data.donations.find((d) => d.id === req.params.id);
  if (!donation || !isPaid(donation)) return res.status(404).json({ error: "Donation record not found." });
  if (donation.status === "Verified") return res.json({ donation: donationView(donation) });

  const verifiedAt = new Date().toISOString();
  // chain each record to the previously verified one (tamper-evident)
  const prevHash =
    data.donations
      .filter((d) => d.recordHash && d.verifiedAt)
      .sort((x, y) => y.verifiedAt.localeCompare(x.verifiedAt))[0]?.recordHash || "GENESIS";

  const full = crypto
    .createHash("sha256")
    .update([donation.id, donation.organization, donation.amount, donation.razorpayPaymentId, verifiedAt, prevHash].join("|"))
    .digest("hex");

  donation.status = "Verified";
  donation.bankStatus = "Deposited";
  donation.verifiedAt = verifiedAt;
  donation.verifiedBy = req.user.name;
  donation.recordHash = full;
  donation.blockchainHash = "0x" + full.slice(0, 12);
  save();

  res.json({ donation: donationView(donation) });
});

/* Public tracking */
app.get("/api/track/:id", (req, res) => {
  const id = clean(req.params.id, 40).toUpperCase();
  const d = data.donations.find((x) => x.id.toUpperCase() === id && isPaid(x));
  if (!d) return res.status(404).json({ error: "No donation found with ID " + id + "." });

  res.json({
    donation: {
      id: d.id,
      donorName: maskName(d.donorName),
      organization: d.organization,
      amount: d.amount,
      purpose: d.purpose,
      status: d.status,
      bankStatus: d.bankStatus,
      date: d.date,
      paidAt: d.paidAt || d.date,
      verifiedAt: d.verifiedAt || "",
      blockchainHash: d.blockchainHash || ""
    }
  });
});

app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));

/* =========================================================
   STATIC FRONTEND
   ========================================================= */
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

/* =========================================================
   SEED DEMO DATA (first run only)
   ========================================================= */
async function seed() {
  if (data.users.length > 0) return;
  const mk = async (id, name, email, pw, phone, role, extra = {}) => ({
    id, name, email, phone, role,
    passwordHash: await bcrypt.hash(pw, 10),
    approved: true,
    createdAt: new Date().toISOString(),
    ...extra
  });

  data.users.push(
    await mk("U001", "Demo Donor", "donor@example.com", "donor123", "9876543210", "donor"),
    await mk("U002", "Helping Hands Foundation", "ngo@example.com", "ngo123", "9876543211", "organization", {
      organizationName: "Helping Hands Foundation",
      registrationNumber: "NGO-2026-001"
    }),
    await mk("U003", "Verified Accountant", "ca@example.com", "ca123", "9876543212", "ca", { caMembership: "ICAI-000001" })
  );

  const demo = (id, org, amount, date, hash) => ({
    id, userId: "U001", donorName: "Demo Donor", donorEmail: "donor@example.com",
    organization: org, amount, purpose: "Education",
    status: "Verified", paymentStatus: "paid", bankStatus: "Deposited",
    razorpayOrderId: "demo_order_" + id, razorpayPaymentId: "demo_payment_" + id,
    blockchainHash: hash, recordHash: hash.replace("0x", "").padEnd(64, "0"),
    date, paidAt: date, verifiedAt: date, verifiedBy: "Verified Accountant"
  });

  data.donations.push(
    demo("TD-2026-100001", "Helping Hands Foundation", 5000, "2026-08-10T10:30:00.000Z", "0x7f91a82c4d00"),
    demo("TD-2026-100002", "Hope Education Trust", 2500, "2026-08-14T13:00:00.000Z", "0x8a21b72e5f00")
  );
  save();
  console.log("Demo accounts created (donor@example.com / donor123, ngo@example.com / ngo123, ca@example.com / ca123)");
}

seed().then(() => {
  app.listen(PORT, () => {
    console.log("\nTrustDonate is running  ->  http://localhost:" + PORT + "\n");
  });
});