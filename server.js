
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const DATA_FILE = path.join(DATA_DIR, "registrations.json");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const WALLET_FILE = path.join(DATA_DIR, "wallets.json");
const REQUESTS_FILE = path.join(DATA_DIR, "wallet-requests.json");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"]
    }
  }
}));

app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/", rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
}));

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

for (const file of [DATA_FILE, USERS_FILE, WALLET_FILE, REQUESTS_FILE]) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "[]", "utf8");
  }
}

function readJSON(file) {
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function writeJSON(file, value) {
  const temp = file + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(value, null, 2), "utf8");
  fs.renameSync(temp, file);
}

function readUsers() { return readJSON(USERS_FILE); }
function writeUsers(rows) { writeJSON(USERS_FILE, rows); }
function readRegistrations() { return readJSON(DATA_FILE); }
function writeRegistrations(rows) { writeJSON(DATA_FILE, rows); }
function readWallets() { return readJSON(WALLET_FILE); }
function writeWallets(rows) { writeJSON(WALLET_FILE, rows); }
function readRequests() { return readJSON(REQUESTS_FILE); }
function writeRequests(rows) { writeJSON(REQUESTS_FILE, rows); }

function safeText(value, max = 100) {
  return String(value || "").trim().replace(/[<>]/g, "").slice(0, max);
}

function validPhone(phone) {
  return /^[6-9]\d{9}$/.test(phone);
}

function validMode(mode) {
  return ["Solo", "Duo", "Squad", "Lone Wolf"].includes(mode);
}

function playerCount(mode) {
  if (mode === "Solo") return 1;
  if (mode === "Duo" || mode === "Lone Wolf") return 2;
  if (mode === "Squad") return 4;
  return 0;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function passwordMatches(password, user) {
  const attempted = Buffer.from(hashPassword(password, user.salt), "hex");
  const saved = Buffer.from(user.passwordHash, "hex");

  return attempted.length === saved.length &&
    crypto.timingSafeEqual(attempted, saved);
}

function signToken(payloadObject, secret) {
  const payload = Buffer.from(JSON.stringify(payloadObject)).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(token, secret) {
  if (!token || !secret) return null;

  const parts = String(token).split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest();

  let supplied;

  try {
    supplied = Buffer.from(signature, "base64url");
  } catch {
    return null;
  }

  if (
    expected.length !== supplied.length ||
    !crypto.timingSafeEqual(expected, supplied)
  ) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!data.exp || Date.now() > data.exp) return null;

    return data;
  } catch {
    return null;
  }
}

function getTokenUser(req) {
  const header = String(req.headers.authorization || "");

  if (!header.startsWith("Bearer ")) return null;

  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) return null;

  const data = verifyToken(header.slice(7), secret);

  if (!data || !data.phone) return null;

  return readUsers().find(user => user.phone === data.phone) || null;
}

function requireLogin(req, res, next) {
  const user = getTokenUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please login again."
    });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const header = String(req.headers.authorization || "");

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Admin login required."
    });
  }

  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "SESSION_SECRET is not configured."
    });
  }

  const data = verifyToken(header.slice(7), secret);

  if (!data || data.role !== "admin") {
    return res.status(403).json({
      error: "Admin access only."
    });
  }

  req.admin = true;
  next();
}

function getWallet(phone) {
  const wallets = readWallets();

  let wallet = wallets.find(item => item.phone === phone);

  if (!wallet) {
    wallet = {
      phone,
      balance: 0,
      updatedAt: new Date().toISOString()
    };

    wallets.push(wallet);
    writeWallets(wallets);
  }

  return wallet;
}

function updateWallet(phone, amount) {
  const wallets = readWallets();

  let wallet = wallets.find(item => item.phone === phone);

  if (!wallet) {
    wallet = {
      phone,
      balance: 0,
      updatedAt: new Date().toISOString()
    };

    wallets.push(wallet);
  }

  wallet.balance += amount;
  wallet.updatedAt = new Date().toISOString();

  writeWallets(wallets);

  return wallet;
}

// Live-money payment gateway remains disabled.
app.use(
  ["/api/create-order", "/api/verify-payment"],
  (req, res) => {
    return res.status(403).json({
      error: "Live-money tournament payments are disabled. Demo wallet only."
    });
  }
);

// Website configuration
app.get("/api/config", (req, res) => {
  res.json({
    feePaise: Math.max(
      100,
      Number.parseInt(process.env.ENTRY_FEE_PAISE || "2000", 10)
    ),
    demo: true,
    livePayments: false
  });
});

// ACCOUNT REGISTER
app.post("/api/auth/register", (req, res) => {
  const phone = safeText(req.body.phone, 10);
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");
  const uid = safeText(req.body.uid, 30);

  if (!validPhone(phone)) {
    return res.status(400).json({
      error: "Enter a valid 10-digit Indian mobile number."
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: "Password must be at least 8 characters."
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: "Passwords do not match."
    });
  }

  if (!/^\d{5,20}$/.test(uid)) {
    return res.status(400).json({
      error: "Enter a valid Free Fire Game UID."
    });
  }

  const users = readUsers();

  if (users.some(user => user.phone === phone)) {
    return res.status(409).json({
      error: "This mobile number is already registered. Please login."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");

  const user = {
    id: crypto.randomUUID(),
    phone,
    uid,
    salt,
    passwordHash: hashPassword(password, salt),
    createdAt: new Date().toISOString()
  };

  users.push(user);
  writeUsers(users);

  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "Server setup incomplete. Check SESSION_SECRET in .env."
    });
  }

  const token = signToken({
    phone,
    exp: Date.now() + 24 * 60 * 60 * 1000
  }, secret);

  res.status(201).json({
    ok: true,
    message: "Account created successfully.",
    token,
    user: {
      phone,
      uid
    }
  });
});

// ACCOUNT LOGIN
app.post("/api/auth/login", (req, res) => {
  const phone = safeText(req.body.phone, 10);
  const password = String(req.body.password || "");

  if (!validPhone(phone) || !password) {
    return res.status(400).json({
      error: "Enter your mobile number and password."
    });
  }

  const user = readUsers().find(item => item.phone === phone);

  if (!user || !passwordMatches(password, user)) {
    return res.status(401).json({
      error: "Incorrect mobile number or password."
    });
  }

  const secret = process.env.SESSION_SECRET;

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "Server setup incomplete. Check SESSION_SECRET in .env."
    });
  }

  const token = signToken({
    phone,
    exp: Date.now() + 24 * 60 * 60 * 1000
  }, secret);

  res.json({
    ok: true,
    message: "Login successful.",
    token,
    user: {
      phone: user.phone,
      uid: user.uid
    }
  });
});

// Current logged-in account
app.get("/api/auth/me", requireLogin, (req, res) => {
  res.json({
    user: {
      phone: req.user.phone,
      uid: req.user.uid
    }
  });
});

// FORGOT PASSWORD — DEMO OTP
const passwordResetOtps = new Map();

app.post("/api/auth/forgot-password", (req, res) => {
  const phone = safeText(req.body.phone, 10);

  if (!validPhone(phone)) {
    return res.status(400).json({
      error: "Enter a valid 10-digit mobile number."
    });
  }

  if (!readUsers().some(user => user.phone === phone)) {
    return res.status(404).json({
      error: "No account found with this mobile number."
    });
  }

  const otp = String(crypto.randomInt(100000, 1000000));

  passwordResetOtps.set(phone, {
    otp,
    expires: Date.now() + 5 * 60 * 1000
  });

  console.log(`Password reset OTP for ${phone}: ${otp}`);

  res.json({
    ok: true,
    message: "Demo OTP generated. Check the server terminal."
  });
});

app.post("/api/auth/reset-password", (req, res) => {
  const phone = safeText(req.body.phone, 10);
  const otp = safeText(req.body.otp, 6);
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");

  const saved = passwordResetOtps.get(phone);

  if (!saved || saved.expires < Date.now()) {
    passwordResetOtps.delete(phone);

    return res.status(400).json({
      error: "OTP expired. Please request a new OTP."
    });
  }

  if (saved.otp !== otp) {
    return res.status(400).json({
      error: "Incorrect OTP."
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: "Password must be at least 8 characters."
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: "Passwords do not match."
    });
  }

  const users = readUsers();
  const user = users.find(item => item.phone === phone);

  if (!user) {
    return res.status(404).json({
      error: "Account not found."
    });
  }

  const salt = crypto.randomBytes(16).toString("hex");

  user.salt = salt;
  user.passwordHash = hashPassword(password, salt);

  writeUsers(users);
  passwordResetOtps.delete(phone);

  res.json({
    ok: true,
    message: "Password changed successfully. Please login."
  });
});

// OLD OTP ROUTES — DEMO ONLY
const loginOtps = new Map();

app.post("/api/send-otp", (req, res) => {
  const phone = safeText(req.body.phone, 10);

  if (!validPhone(phone)) {
    return res.status(400).json({
      error: "Enter a valid 10-digit mobile number."
    });
  }

  const otp = String(crypto.randomInt(100000, 1000000));

  loginOtps.set(phone, {
    otp,
    expires: Date.now() + 5 * 60 * 1000
  });

  console.log(`Demo OTP for ${phone}: ${otp}`);

  res.json({
    ok: true,
    message: "Demo OTP generated. Check the server terminal."
  });
});

app.post("/api/verify-otp", (req, res) => {
  const phone = safeText(req.body.phone, 10);
  const otp = safeText(req.body.otp, 6);

  const saved = loginOtps.get(phone);

  if (!saved || saved.expires < Date.now()) {
    loginOtps.delete(phone);

    return res.status(400).json({
      error: "OTP expired. Please request a new OTP."
    });
  }

  if (saved.otp !== otp) {
    return res.status(400).json({
      error: "Incorrect OTP."
    });
  }

  loginOtps.delete(phone);

  res.json({
    ok: true,
    message: "OTP verified successfully."
  });
});

// TOURNAMENT REGISTRATION — DEMO
app.post("/api/register", requireLogin, (req, res) => {
  const mode = safeText(req.body.mode, 30);
  const gameUid = safeText(req.body.gameUid || req.body.uid, 30);

  const playerNames = Array.isArray(req.body.playerNames)
    ? req.body.playerNames.map(name => safeText(name, 40))
    : [];

  if (!validMode(mode)) {
    return res.status(400).json({
      error: "Please select Solo, Duo, Squad, or Lone Wolf."
    });
  }

  if (!/^\d{5,20}$/.test(gameUid)) {
    return res.status(400).json({
      error: "Enter a valid Free Fire Game UID."
    });
  }

  const needed = playerCount(mode);

  if (playerNames.length !== needed) {
    return res.status(400).json({
      error: `Please enter ${needed} player name(s) for ${mode}.`
    });
  }

  if (playerNames.some(name => !name)) {
    return res.status(400).json({
      error: "Please enter all player names."
    });
  }

  const registrations = readRegistrations();

  const registration = {
    id: crypto.randomUUID(),
    phone: req.user.phone,
    gameUid,
    mode,
    playerNames,
    status: "DEMO",
    createdAt: new Date().toISOString()
  };

  registrations.push(registration);
  writeRegistrations(registrations);

  res.status(201).json({
    ok: true,
    message: "Demo tournament registration saved.",
    registration
  });
});

// DEMO WALLET BALANCE
app.get("/api/wallet", requireLogin, (req, res) => {
  const wallet = getWallet(req.user.phone);

  const requests = readRequests()
    .filter(item => item.phone === req.user.phone)
    .map(({ id, type, amount, status, createdAt, adminNote }) => ({
      id,
      type,
      amount,
      status,
      createdAt,
      adminNote
    }));

  res.json({
    demo: true,
    balance: wallet.balance,
    requests
  });
});

// DEMO DEPOSIT REQUEST
app.post("/api/wallet/deposit", requireLogin, (req, res) => {
  const amount = Number(req.body.amount);
  const utr = safeText(req.body.utr, 80);
  const screenshotName = safeText(req.body.screenshotName, 150);

  if (!Number.isSafeInteger(amount) || amount < 50 || amount > 100000) {
    return res.status(400).json({
      error: "Demo deposit amount must be between ₹50 and ₹100000."
    });
  }

  if (!utr) {
    return res.status(400).json({
      error: "Enter the UTR / transaction reference."
    });
  }

  const requests = readRequests();

  const request = {
    id: crypto.randomUUID(),
    phone: req.user.phone,
    type: "deposit",
    amount,
    utr,
    screenshotName,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  requests.unshift(request);
  writeRequests(requests);

  res.status(201).json({
    ok: true,
    demo: true,
    message: "Demo deposit request submitted for admin review.",
    request: {
      id: request.id,
      status: request.status
    }
  });
});

// DEMO WITHDRAWAL REQUEST
app.post("/api/wallet/withdraw", requireLogin, (req, res) => {
  const amount = Number(req.body.amount);
  const accountName = safeText(req.body.accountName, 100);
  const accountNumber = safeText(req.body.accountNumber, 34);
  const ifsc = safeText(req.body.ifsc, 11).toUpperCase();
  const upiId = safeText(req.body.upiId, 100);

  if (!Number.isSafeInteger(amount) || amount < 100) {
    return res.status(400).json({
      error: "Minimum demo withdrawal is 100 points."
    });
  }

  if (
    !accountName ||
    !accountNumber ||
    !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)
  ) {
    return res.status(400).json({
      error: "Enter valid account holder name, account number and IFSC."
    });
  }

  if (amount > getWallet(req.user.phone).balance) {
    return res.status(400).json({
      error: "Insufficient demo points balance."
    });
  }

  const requests = readRequests();

  const request = {
    id: crypto.randomUUID(),
    phone: req.user.phone,
    type: "withdrawal",
    amount,
    accountName,
    accountNumber,
    ifsc,
    upiId,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  requests.unshift(request);
  writeRequests(requests);

  res.status(201).json({
    ok: true,
    demo: true,
    message: "Demo withdrawal request submitted for admin review.",
    request: {
      id: request.id,
      status: request.status
    }
  });
});

// ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
  const password = String(req.body.password || "");
  const adminPassword = process.env.ADMIN_PASSWORD;
  const secret = process.env.SESSION_SECRET;

  if (!adminPassword || adminPassword.length < 12) {
    return res.status(503).json({
      error: "Set ADMIN_PASSWORD (at least 12 characters) in .env first."
    });
  }

  if (!secret || secret.length < 32) {
    return res.status(500).json({
      error: "SESSION_SECRET must be at least 32 characters."
    });
  }

  const a = Buffer.from(password);
  const b = Buffer.from(adminPassword);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({
      error: "Incorrect admin password."
    });
  }

  const token = signToken({
    role: "admin",
    exp: Date.now() + 8 * 60 * 60 * 1000
  }, secret);

  res.json({
    ok: true,
    token
  });
});

// ADMIN: VIEW WALLET REQUESTS
app.get("/api/admin/wallet-requests", requireAdmin, (req, res) => {
  res.json({
    requests: readRequests()
  });
});

// ADMIN: APPROVE OR REJECT
app.post("/api/admin/wallet-requests/:id/review", requireAdmin, (req, res) => {
  const action = safeText(req.body.action, 20).toLowerCase();
  const note = safeText(req.body.note, 200);

  if (!["approve", "reject"].includes(action)) {
    return res.status(400).json({
      error: "Action must be approve or reject."
    });
  }

  const requests = readRequests();
  const request = requests.find(item => item.id === req.params.id);

  if (!request) {
    return res.status(404).json({
      error: "Request not found."
    });
  }

  if (request.status !== "pending") {
    return res.status(409).json({
      error: "This request has already been reviewed."
    });
  }

  if (action === "approve" && request.type === "withdrawal") {
    const wallet = getWallet(request.phone);

    if (wallet.balance < request.amount) {
      return res.status(409).json({
        error: "User no longer has enough demo points."
      });
    }

    updateWallet(request.phone, -request.amount);
  }

  if (action === "approve" && request.type === "deposit") {
    updateWallet(request.phone, request.amount);
  }

  request.status = action === "approve" ? "approved" : "rejected";
  request.adminNote = note;
  request.reviewedAt = new Date().toISOString();

  writeRequests(requests);

  res.json({
    ok: true,
    demo: true,
    message: `Request ${request.status}. No real money was transferred.`,
    request
  });
});

// ADMIN: VIEW TOURNAMENT REGISTRATIONS
app.get("/api/admin/registrations", requireAdmin, (req, res) => {
  res.json({
    registrations: readRegistrations()
  });
});
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    demo: true
  });
});

app.use((req, res) => {
  res.status(404).json({
    error: "Not found."
  });
});

app.listen(PORT, () => {
  console.log(`FREE FIRE GAMER server running on port ${PORT}`);
});