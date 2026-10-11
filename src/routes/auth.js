'use strict';
const express = require('express');
const { query } = require('../db');
const { hashPassword, verifyPassword } = require('../security');
const { createSession, destroySession, csrfGuard } = require('../session');
const { HttpError, str, wrap } = require('../validate');

const router = express.Router();

// Tiny in-memory login throttle: 10 failures per IP+email per 15 minutes.
const attempts = new Map();
const blocked = (k) => { const a = attempts.get(k); return !!a && a.resetAt > Date.now() && a.count >= 10; };
function recordFailure(k) {
  if (attempts.size > 5000) attempts.clear();
  const now = Date.now(); const a = attempts.get(k);
  if (!a || a.resetAt <= now) attempts.set(k, { count: 1, resetAt: now + 15 * 60000 });
  else a.count += 1;
}

router.post('/register', wrap(async (req, res) => {
  const name = str(req.body.name, 60);
  const email = (str(req.body.email, 120) || '').toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!name) throw new HttpError(400, 'Name is required (max 60 characters).');
  if (!email.includes('@')) throw new HttpError(400, 'Enter a valid email.');
  if (password.length < 8 || password.length > 200) throw new HttpError(400, 'Password must be 8-200 characters.');
  let result;
  try {
    // role is ALWAYS 'student' here; whatever the client sends is ignored
    result = await query(
      "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,'student',UTC_TIMESTAMP())",
      [name, email, await hashPassword(password)]);
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') throw new HttpError(409, 'That email is already registered.');
    throw e;
  }
  const user = { id: result.insertId, name, email, role: 'student' };
  const { csrf } = await createSession(res, user.id);
  res.status(201).json({ user, csrf });
}));

router.post('/login', wrap(async (req, res) => {
  const email = (str(req.body.email, 120) || '').toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const key = `${req.ip}|${email}`;
  if (blocked(key)) throw new HttpError(429, 'Too many attempts. Try again in 15 minutes.');
  const rows = await query('SELECT id,name,email,role,password_hash FROM users WHERE email=?', [email]);
  const u = rows[0];
  if (!u || !(await verifyPassword(password, u.password_hash))) {
    recordFailure(key);
    throw new HttpError(401, 'Wrong email or password.');
  }
  attempts.delete(key);
  const { csrf } = await createSession(res, u.id);
  res.json({ user: { id: u.id, name: u.name, email: u.email, role: u.role }, csrf });
}));

router.get('/me', (req, res, next) => {
  if (!req.user) return next(new HttpError(401, 'Not logged in.'));
  res.json({ user: req.user, csrf: req.csrf });
});

router.post('/logout', csrfGuard, wrap(async (req, res) => {
  await destroySession(req, res);
  res.json({ ok: true });
}));

module.exports = router;
