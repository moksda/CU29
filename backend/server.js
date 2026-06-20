'use strict';
require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt     = require('bcrypt');
const csrf       = require('csurf');
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
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
      styleSrc:   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'fonts.gstatic.com'],
      fontSrc:    ["'self'", 'fonts.gstatic.com'],
      connectSrc: ["'self'"],
      imgSrc:     ["'self'", 'data:']
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
    maxAge: 24 * 60 * 60 * 1000  // 24 hours
  }
}));

// ── CSRF ──────────────────────────────────────────────────────────
const csrfProtection = csrf({ cookie: false });  // session-based, not cookie

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
    return JSON.parse(text);
  } catch (err) {
    console.error('[appsScript] status:', res && res.status, 'body:', text, 'err:', err.message);
    throw err;
  }
}

// ════════════════════════════════════════════════════════════════
// Routes
// ════════════════════════════════════════════════════════════════

// CSRF token — fetch this before submitting any form
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
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
        req.session.user = { name: 'Admin', role: 'admin', email };
        return res.json({ success: true, name: 'Admin', role: 'admin' });
      }

      // Regular investors — Apps Script returns success/name/role on match
      const data = await callAppsScript({ action: 'login', email, password }, 'GET');
      if (!data.success) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      req.session.user = { name: data.name, role: data.role || 'investor', email: data.email };
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

// ── Investor application ──────────────────────────────────────────
app.post('/api/apply',
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
app.use(express.static(path.join(__dirname, '..')));

// ── 404 ───────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Error handler (catches CSRF token errors too) ──────────────────
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ success: false, error: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(500).json({ success: false, error: 'Server error' });
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`CU29 backend → http://localhost:${PORT} [${process.env.NODE_ENV || 'development'}]`);
});
