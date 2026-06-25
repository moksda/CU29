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
const crypto       = require('crypto');

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
      scriptSrc:     ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'script.google.com', 'script.googleusercontent.com'],
      scriptSrcElem: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'script.google.com', 'script.googleusercontent.com'],
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

// ── Admin guard ───────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

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
    } else {
      res = await fetch(base, {
        redirect: 'follow',
        method: 'POST',
        body: new URLSearchParams(params),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      text = await res.text();
    }
    console.log('[appsScript] ←', res.status, text.slice(0, 120));
    if (res.status === 401 || res.status === 403) {
      throw new Error('Google Apps Script access denied. Please re-deploy the script with "Anyone" access in the Google Apps Script editor.');
    }
    if (!res.ok) {
      throw new Error(`Apps Script returned HTTP ${res.status}`);
    }
    return JSON.parse(text);
  } catch (err) {
    if (err instanceof SyntaxError) {
      console.error('[appsScript] Non-JSON response', res && res.status, text && text.slice(0, 200));
      throw new Error('Apps Script returned an unexpected response. Check the deployment URL and access settings.');
    }
    console.error('[appsScript] ERROR', res && res.status, err.message);
    throw err;
  }
}

// ════════════════════════════════════════════════════════════════
// Routes
// ════════════════════════════════════════════════════════════════

// CSRF token — fetch this before submitting any form.
// Writing to req.session forces express-session (saveUninitialized:false)
// to persist the session and set cu29.sid so the session ID is stable
// across the follow-up POST that validates the CSRF HMAC.
app.get('/api/csrf-token', (req, res) => {
  req.session.csrf_init = true;
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// ── Login ─────────────────────────────────────────────────────────
app.post('/api/login',
  loginLimiter,
  csrfProtection,
  [
    body('email')
      .isEmail().withMessage('Valid email required')
      .normalizeEmail({ gmail_remove_dots: false, gmail_remove_subaddress: false }),
    body('password')
      .isLength({ min: 6, max: 128 }).withMessage('Password must be 6–128 characters')
  ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const { email, password } = req.body;

      // Build admin list from env — supports up to 5 admins via ADMIN_EMAIL_N / ADMIN_PASSWORD_N
      const adminAccounts = [];
      for (let n = 0; n <= 5; n++) {
        const suffix = n === 0 ? '' : `_${n}`;
        const e = (process.env[`ADMIN_EMAIL${suffix}`] || '').toLowerCase().trim();
        const p = (process.env[`ADMIN_PASSWORD${suffix}`] || '').trim();
        const ph = (process.env[`ADMIN_PASSWORD_HASH${suffix}`] || '').trim();
        const name = (process.env[`ADMIN_NAME${suffix}`] || 'Admin').trim();
        if (e) adminAccounts.push({ email: e, password: p, hash: ph, name });
      }

      const adminMatch = adminAccounts.find(a => a.email === email);
      if (adminMatch) {
        let ok = false;
        if (adminMatch.password) {
          ok = adminMatch.password === password.trim();
        } else if (adminMatch.hash) {
          ok = await bcrypt.compare(password, adminMatch.hash);
        }
        if (!ok) return res.status(401).json({ success: false, error: 'Invalid credentials' });
        const adminUser = { name: adminMatch.name, role: 'admin', email };
        if (process.env.ADMIN_2FA_SECRET) {
          req.session.pending2FA = { secret: process.env.ADMIN_2FA_SECRET, user: adminUser };
          return res.json({ success: true, requires2FA: true });
        }
        req.session.user = adminUser;
        return res.json({ success: true, name: adminMatch.name, role: 'admin' });
      }

      // Regular investors — Apps Script returns the stored bcrypt hash + 2FA secret
      const data = await callAppsScript({ action: 'login', email, password }, 'GET');
      if (!data.success) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      // Verify password against bcrypt hash server-side
      const passwordMatch = await bcrypt.compare(password, data.hash);
      if (!passwordMatch) return res.status(401).json({ success: false, error: 'Invalid credentials' });

      // Blank approved = legacy account created before approval gate → allow in
      const approved = data.approved || 'approved';
      if (approved === 'rejected') {
        return res.status(403).json({ success: false, error: 'Your application has been rejected. Contact us for more information.' });
      }
      if (approved === 'pending') {
        return res.status(403).json({ success: false, error: 'Your account is pending admin approval. You will be notified once reviewed.' });
      }

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

// ── Current session info ──────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ authenticated: false });
  res.json({ authenticated: true, name: req.session.user.name, role: req.session.user.role });
});

// ── CMS content (public read, admin write) ────────────────────────
let _contentCache = null;
let _contentCacheAt = 0;
app.get('/api/content', async (req, res) => {
  try {
    if (_contentCache && Date.now() - _contentCacheAt < 60000) return res.json(_contentCache);
    const data = await callAppsScript({ action: 'content' }, 'GET');
    _contentCache = data;
    _contentCacheAt = Date.now();
    res.json(data);
  } catch (e) {
    res.json({ success: true, content: {} });
  }
});

app.post('/api/admin/content', requireAdmin, csrfProtection,
  [body('key').trim().notEmpty(), body('value').trim()],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const data = await callAppsScript({ action: 'set_content', key: req.body.key, value: req.body.value });
      _contentCache = null; // bust cache
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// ── Admin: list applications ──────────────────────────────────────
app.get('/api/admin/applications', requireAdmin, async (req, res) => {
  try {
    const data = await callAppsScript({ action: 'admin_applications' }, 'GET');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Admin: list investors ─────────────────────────────────────────
app.get('/api/admin/investors', requireAdmin, async (req, res) => {
  try {
    const data = await callAppsScript({ action: 'admin_investors' }, 'GET');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Admin: list contact submissions ──────────────────────────────
app.get('/api/admin/contacts', requireAdmin, async (req, res) => {
  try {
    const data = await callAppsScript({ action: 'admin_contacts' }, 'GET');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Admin: delete application + account ──────────────────────────
app.post('/api/admin/delete-application',
  requireAdmin,
  csrfProtection,
  [body('email').isEmail().normalizeEmail({ gmail_remove_dots: false, gmail_remove_subaddress: false })],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const data = await callAppsScript({ action: 'delete_application', email: req.body.email });
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// ── Admin: set investor approved status ───────────────────────────
app.post('/api/admin/approve',
  requireAdmin,
  csrfProtection,
  [
    body('email').isEmail().normalizeEmail({ gmail_remove_dots: false, gmail_remove_subaddress: false }),
    body('status').isIn(['approved', 'rejected', 'pending'])
  ],
  async (req, res) => {
    if (failValidation(req, res)) return;
    try {
      const data = await callAppsScript({ action: 'set_approved', email: req.body.email, status: req.body.status });
      res.json(data);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

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

// ── Claude AI proxy (for test-auth loop) ─────────────────────────
app.post('/api/claude-proxy', async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'ANTHROPIC_API_KEY not configured' });
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Transfer notification ─────────────────────────────────────────
// Investor submits details of a bank transfer they have sent.
// Routed through Apps Script to notify the admin — no third-party fees.
const transferLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many submissions. Try again later.' }
});

app.post('/api/payment/notify',
  transferLimiter,
  csrfProtection,
  [
    body('amount')
      .isFloat({ min: 1 })
      .withMessage('Valid amount required'),
    body('currency')
      .isIn(['USD', 'EUR', 'GBP'])
      .withMessage('Select a currency'),
    body('method')
      .isIn(['bank_wire', 'bank_transfer', 'sepa', 'ach', 'crypto'])
      .withMessage('Select a payment method'),
    body('reference')
      .trim()
      .isLength({ min: 1, max: 120 })
      .escape()
      .withMessage('Transfer reference is required'),
    body('notes')
      .optional({ checkFalsy: true })
      .trim()
      .isLength({ max: 500 })
      .escape()
  ],
  async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
    if (failValidation(req, res)) return;
    try {
      const { amount, currency, method, reference, notes } = req.body;
      await callAppsScript({
        action:    'contact',
        name:      req.session.user.name,
        email:     req.session.user.email,
        phone:     '',
        subject:   `Transfer Notification — ${currency} ${parseFloat(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
        message:   `Investor: ${req.session.user.name} (${req.session.user.email})\nAmount: ${currency} ${amount}\nMethod: ${method}\nReference: ${reference}\nNotes: ${notes || 'N/A'}`,
        department:'General Inquiries'
      });
      res.json({ success: true });
    } catch (err) {
      console.error('[payment/notify]', err.message);
      res.status(500).json({ success: false, error: 'Could not submit notification' });
    }
  }
);

// ── Serve static HTML files ───────────────────────────────────────
const path = require('path');

// Test-auth page gets its own CSP that allows CDN scripts + Babel eval
app.get('/test-auth', (req, res) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
  );
  res.sendFile(path.join(__dirname, '..', 'test-auth.html'));
});

// Block sensitive files from being served publicly
app.use((req, res, next) => {
  const blocked = ['/users.js', '/.env', '/backend/server.js', '/backend/.env'];
  if (blocked.includes(req.path.toLowerCase())) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

app.use(express.static(path.join(__dirname, '..'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

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
