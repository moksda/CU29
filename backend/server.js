'use strict';
require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt     = require('bcrypt');
const speakeasy  = require('speakeasy');
const QRCode     = require('qrcode');
const { doubleCsrf } = require('csrf-csrf');
const cookieParser = require('cookie-parser');

const app  = express();
const PORT = process.env.PORT || 3001;
const PROD = process.env.NODE_ENV === 'production';

// ── HTTPS redirect — production only ─────────────────────────────
if (PROD) {
  app.set('trust proxy', 1);
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, 'https://' + req.headers.host + req.url);
    }
    next();
  });
}

// ── Security headers (helmet) ─────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'script.google.com'],
      scriptSrcElem: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'script.google.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'fonts.gstatic.com'],
      fontSrc:       ["'self'", 'fonts.gstatic.com'],
      connectSrc:    ["'self'"],
      imgSrc:        ["'self'", 'data:']
    }
  }
}));

// ── CORS — same origin only ───────────────────────────────────────
const ALLOWED_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:8099';
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-CSRF-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Parsers ───────────────────────────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// ── Session ───────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'cu29.sid',
  cookie: {
    httpOnly: true,
    secure: PROD,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000  // 30 minutes — financial platform best practice
  }
}));

// ── CSRF ──────────────────────────────────────────────────────────
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  getSessionIdentifier: (req) => req.session?.id || '',
  cookieName: PROD ? '__Host-psifi.x-csrf-token' : 'psifi.x-csrf-token',
  cookieOptions: { secure: PROD, sameSite: 'strict', httpOnly: true },
  size: 64,
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'] || req.body?._csrf
});
const csrfProtection = doubleCsrfProtection;

// ── Rate limiters ─────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15-minute window
  max: 5,                       // 5 attempts max
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { success: false, error: 'Too many login attempts. Try again in 15 minutes.' }
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { success: false, error: 'Too many requests.' }
});

const applyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 5,
  message: { success: false, error: 'Too many registration attempts. Try again in 1 hour.' }
});

const twoFALimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many 2FA attempts. Try again in 15 minutes.' }
});

app.use('/api/', globalLimiter);

// ── Input sanitisation helpers ────────────────────────────────────
function failValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ success: false, errors: errors.array().map(e => e.msg) });
    return true;
  }
  return false;
}

// ── Apps Script proxy ─────────────────────────────────────────────
// All user-supplied data is validated/sanitised before it gets here,
// so Apps Script only ever receives clean values.
async function callAppsScript(params, method = 'POST') {
  const base = process.env.APPS_SCRIPT_URL;
  console.log('[appsScript] →', method, base.slice(-30), '| action:', params.action);
  let res, text;
  try {
    if (method === 'GET') {
      const qs = new URLSearchParams(params).toString();
      res = await fetch(`${base}?${qs}`, { redirect: 'follow' });
      text = await res.text();
      return JSON.parse(text);
    }
    res = await fetch(base, {
      redirect: 'follow',
      method: 'POST',
      body: new URLSearchParams(params),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    text = await res.text();
    console.log('[appsScript] ←', res.status, text.slice(0, 120));
    return JSON.parse(text);
  } catch (err) {
    console.error('[appsScript] ERROR', res && res.status, text && text.slice(0, 120), err.message);
    throw err;
  }
}

// ════════════════════════════════════════════════════════════════
// Routes
// ════════════════════════════════════════════════════════════════

// CSRF token — fetch this before submitting any form
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// ── Login ─────────────────────────────────────────────────────────
app.post('/api/login',
  loginLimiter,
  csrfProtection,
  [
    body('email')
      .isEmail().withMessage('Valid email required')
      .normalizeEmail(),
    body('password')
      .isLength({ min: 6, max: 128 }).withMessage('Password must be 6–128 characters')
  ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const { email, password } = req.body;

      // Admin — compared against bcrypt hash in .env, never hits the sheet
      if (email === process.env.ADMIN_EMAIL.toLowerCase()) {
        const ok = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
        if (!ok) return res.status(401).json({ success: false, error: 'Invalid credentials' });
        const adminUser = { name: 'Admin', role: 'admin', email };
        if (process.env.ADMIN_2FA_SECRET) {
          req.session.pending2FA = { secret: process.env.ADMIN_2FA_SECRET, user: adminUser };
          return res.json({ success: true, requires2FA: true });
        }
        req.session.user = adminUser;
        return res.json({ success: true, name: 'Admin', role: 'admin' });
      }

      // Regular investors — Apps Script returns the stored bcrypt hash + 2FA secret
      const data = await callAppsScript({ action: 'login', email, password }, 'POST');
      if (!data.success) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      // Verify password against bcrypt hash server-side
      const passwordMatch = await bcrypt.compare(password, data.hash);
      if (!passwordMatch) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      const investorUser = { name: data.name, role: data.role || 'investor', email: data.email, twoFASecret: data.twoFASecret || null };

      // If investor has 2FA enabled, require TOTP before granting session
      if (data.twoFASecret) {
        req.session.pending2FA = { secret: data.twoFASecret, user: investorUser };
        return res.json({ success: true, requires2FA: true });
      }

      req.session.user = investorUser;
      res.json({ success: true, name: data.name, role: data.role || 'investor' });
    } catch (err) {
      console.error('[login]', err.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ── Logout ────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ── 2FA: Complete login after TOTP check ──────────────────────────
app.post('/api/2fa/complete',
  twoFALimiter,
  csrfProtection,
  [ body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Invalid code') ],
  (req, res) => {
    if (failValidation(req, res)) return;
    if (!req.session.pending2FA) {
      return res.status(400).json({ success: false, error: 'No pending 2FA session' });
    }
    const { secret, user } = req.session.pending2FA;
    const valid = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: req.body.token,
      window: 1  // allow 30s clock skew
    });
    if (!valid) {
      return res.status(401).json({ success: false, error: 'Invalid code. Try again.' });
    }
    req.session.user = user;
    delete req.session.pending2FA;
    res.json({ success: true, name: user.name, role: user.role });
  }
);

// ── 2FA: Generate setup QR code (must be logged in) ───────────────
app.get('/api/2fa/setup', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  const secret = speakeasy.generateSecret({
    name: `InvestCu29 (${req.session.user.email})`,
    length: 32
  });
  QRCode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
    if (err) return res.status(500).json({ error: 'QR generation failed' });
    req.session.pending2FASecret = secret.base32;
    res.json({ qr: dataUrl, secret: secret.base32 });
  });
});

// ── 2FA: Enable — verify first code then save secret ─────────────
app.post('/api/2fa/enable',
  twoFALimiter,
  csrfProtection,
  [ body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Invalid code') ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    if (!req.session.user || !req.session.pending2FASecret) {
      return res.status(400).json({ success: false, error: 'No setup in progress' });
    }
    const valid = speakeasy.totp.verify({
      secret: req.session.pending2FASecret,
      encoding: 'base32',
      token: req.body.token,
      window: 1
    });
    if (!valid) {
      return res.status(401).json({ success: false, error: 'Invalid code — make sure your app is synced and try again.' });
    }
    try {
      // Save secret to Apps Script sheet for investors; admin stores in session (update .env manually)
      if (req.session.user.role === 'admin') {
        // Admin: log the secret — must be saved to ADMIN_2FA_SECRET in .env manually
        console.log('[2FA] Admin 2FA secret (save to .env as ADMIN_2FA_SECRET):', req.session.pending2FASecret);
      } else {
        await callAppsScript({ action: 'save_2fa_secret', email: req.session.user.email, secret: req.session.pending2FASecret });
      }
      req.session.user.has2FA = true;
      delete req.session.pending2FASecret;
      res.json({ success: true });
    } catch (err) {
      console.error('[2fa/enable]', err.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ── 2FA: Disable ──────────────────────────────────────────────────
app.post('/api/2fa/disable',
  twoFALimiter,
  csrfProtection,
  [ body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Invalid code') ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    // Verify current TOTP before disabling
    const secret = req.session.user.role === 'admin'
      ? process.env.ADMIN_2FA_SECRET
      : req.session.user.twoFASecret;
    if (!secret) return res.status(400).json({ success: false, error: '2FA is not enabled' });
    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token: req.body.token, window: 1 });
    if (!valid) return res.status(401).json({ success: false, error: 'Invalid code' });
    try {
      if (req.session.user.role !== 'admin') {
        await callAppsScript({ action: 'save_2fa_secret', email: req.session.user.email, secret: '' });
      }
      req.session.user.has2FA = false;
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ── Investor application ──────────────────────────────────────────
app.post('/api/apply',
  applyLimiter,
  csrfProtection,
  [
    body('first_name').trim().isLength({ min: 1, max: 80 }).escape().withMessage('First name required'),
    body('last_name').trim().isLength({ min: 1, max: 80 }).escape().withMessage('Last name required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('phone').optional({ checkFalsy: true }).trim().isLength({ max: 30 }).escape(),
    body('dob').optional({ checkFalsy: true }).isISO8601().withMessage('Valid date of birth format required'),
    body('nationality').optional({ checkFalsy: true }).trim().isLength({ max: 80 }).escape(),
    body('country').optional({ checkFalsy: true }).trim().isLength({ max: 80 }).escape(),
    body('password')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/).withMessage('Password must include an uppercase letter')
      .matches(/[0-9]/).withMessage('Password must include a number'),
    body('capital').optional().trim().isLength({ max: 50 }).escape(),
    body('source_of_funds').optional().trim().isLength({ max: 200 }).escape(),
    body('pep').optional({ checkFalsy: true }).isIn(['yes', 'no']).default('no')
  ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const p = { ...req.body };
      p.password = await bcrypt.hash(p.password, 12);  // hash before storage
      const data = await callAppsScript({ ...p, action: 'apply_investor' });
      res.json(data);
    } catch (err) {
      console.error('[apply]', err.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ── Contact form ──────────────────────────────────────────────────
app.post('/api/contact',
  csrfProtection,
  [
    body('name').trim().isLength({ min: 1, max: 120 }).escape().withMessage('Name required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('phone').optional({ checkFalsy: true }).trim().isLength({ max: 30 }).escape(),
    body('subject').trim().isLength({ min: 1, max: 200 }).escape().withMessage('Subject required'),
    body('message').trim().isLength({ min: 1, max: 5000 }).escape().withMessage('Message required'),
    body('department')
      .isIn(['General Inquiries', 'Compliance & Verification', 'Charity & Impact'])
      .withMessage('Invalid department')
  ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const data = await callAppsScript({ ...req.body, action: 'contact' });
      res.json(data);
    } catch (err) {
      console.error('[contact]', err.message);
      res.status(500).json({ success: false, error: 'Server error' });
    }
  }
);

// ── Market data — Finnhub key stays server-side ───────────────────
app.get('/api/market', async (req, res) => {
  const syms = ['SPY', 'VNQ', 'GLD', 'USO', 'SCCO', 'QQQ', 'TLT'];
  try {
    const results = await Promise.all(
      syms.map(sym =>
        fetch(`https://finnhub.io/api/v1/quote?symbol=${sym}&token=${process.env.FINNHUB_TOKEN}`)
          .then(r => r.json())
          .then(d => [sym, { price: d.c || null, pct: d.dp != null ? Math.round(d.dp * 100) / 100 : null }])
          .catch(() => [sym, { price: null, pct: null }])
      )
    );
    res.json({ ok: true, quotes: Object.fromEntries(results) });
  } catch {
    res.status(500).json({ ok: false });
  }
});

// ── Serve static HTML files ───────────────────────────────────────
const path = require('path');

// Block sensitive files from being served publicly
app.use((req, res, next) => {
  const blocked = ['/users.js', '/.env', '/backend/server.js', '/backend/.env'];
  if (blocked.includes(req.path.toLowerCase())) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

app.use(express.static(path.join(__dirname, '..')));

// ── 404 ───────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Error handler (catches CSRF token errors too) ──────────────────
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN' || err.message === 'invalid csrf token') {
    return res.status(403).json({ success: false, error: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(500).json({ success: false, error: 'Server error' });
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`CU29 backend → http://localhost:${PORT} [${process.env.NODE_ENV || 'development'}]`);
});
