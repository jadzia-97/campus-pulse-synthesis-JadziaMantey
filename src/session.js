'use strict';
const crypto = require('crypto');
const { query } = require('./db');
const { sha256, randomHex, parseCookies } = require('./security');
const { HttpError } = require('./validate');

const SESSION_DAYS = 7;

// Cookie holds a random token; the DB stores only its SHA-256 hash.
async function createSession(res, userId) {
  const token = randomHex(32);
  const csrf = randomHex(16);
  await query(
    `INSERT INTO sessions (id,user_id,csrf,expires_at)
     VALUES (?,?,?,DATE_ADD(UTC_TIMESTAMP(), INTERVAL ${SESSION_DAYS} DAY))`,
    [sha256(token), userId, csrf]);
  res.cookie('sid', token, {
    httpOnly: true, sameSite: 'lax', path: '/',
    secure: process.env.COOKIE_SECURE === '1',
    maxAge: SESSION_DAYS * 24 * 3600 * 1000,
  });
  return { csrf };
}

async function destroySession(req, res) {
  if (req.sessionId) await query('DELETE FROM sessions WHERE id=?', [req.sessionId]);
  res.clearCookie('sid', { path: '/' });
}

async function loadSession(req, res, next) {
  try {
    req.user = null;
    const token = parseCookies(req.headers.cookie).sid;
    if (token) {
      const rows = await query(
        `SELECT s.id AS sid, s.csrf, u.id, u.name, u.email, u.role
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id = ? AND s.expires_at > UTC_TIMESTAMP()`, [sha256(token)]);
      if (rows[0]) {
        const r = rows[0];
        req.user = { id: r.id, name: r.name, email: r.email, role: r.role };
        req.csrf = r.csrf;
        req.sessionId = r.sid;
      }
    }
    next();
  } catch (e) { next(e); }
}

const requireAuth = (req, res, next) =>
  req.user ? next() : next(new HttpError(401, 'Please log in.'));

const requireAdmin = (req, res, next) => {
  if (!req.user) return next(new HttpError(401, 'Please log in.'));
  if (req.user.role !== 'admin') return next(new HttpError(403, 'Admins only.'));
  next();
};

// Logged-in users must echo their CSRF token in the X-CSRF-Token header on every change.
function csrfGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || !req.user) return next();
  const sent = Buffer.from(String(req.get('x-csrf-token') || ''));
  const want = Buffer.from(req.csrf);
  if (sent.length !== want.length || !crypto.timingSafeEqual(sent, want)) {
    return next(new HttpError(403, 'Bad or missing CSRF token.'));
  }
  next();
}

module.exports = { createSession, destroySession, loadSession, requireAuth, requireAdmin, csrfGuard };
