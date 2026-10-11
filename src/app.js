'use strict';
const path = require('path');
const express = require('express');
const { query } = require('./db');
const { loadSession, csrfGuard } = require('./session');
const { HttpError } = require('./validate');

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',
      // only our own scripts/styles may run: blocks injected inline <script>
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    });
    next();
  });

  app.use(express.json({ limit: '20kb' }));
  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.get('/api/health', async (req, res, next) => {
    try { await query('SELECT 1'); res.json({ status: 'ok' }); } catch (e) { next(e); }
  });

  app.use('/api', loadSession);
  app.use('/api/auth', require('./routes/auth'));   // login/register are exempt from CSRF
  app.use('/api', csrfGuard);
  app.use('/api', require('./routes/board'), require('./routes/borrow'),
    require('./routes/fix'), require('./routes/admin'));
  app.use('/api', (req, res, next) => next(new HttpError(404, 'Not found')));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  });
  return app;
}
module.exports = { createApp };
