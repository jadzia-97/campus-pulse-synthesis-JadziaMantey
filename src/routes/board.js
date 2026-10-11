'use strict';
const express = require('express');
const { query } = require('../db');
const { requireAuth, requireAdmin } = require('../session');
const { HttpError, str, optStr, parseId, wrap } = require('../validate');
const { freshness } = require('../freshness');

const STATUSES = ['open', 'busy', 'closed', 'issue'];
const router = express.Router();

router.get('/places', requireAuth, wrap(async (req, res) => {
  const rows = await query(
    `SELECT p.id, p.name, p.category, u.status, u.note, u.is_official AS isOfficial,
            u.created_at AS updatedAt, usr.name AS author
     FROM places p
     LEFT JOIN status_updates u ON u.id = (
       SELECT id FROM status_updates WHERE place_id = p.id
       ORDER BY created_at DESC, id DESC LIMIT 1)
     LEFT JOIN users usr ON usr.id = u.user_id
     ORDER BY p.name`);
  res.json(rows.map((r) => ({ ...r, isOfficial: !!r.isOfficial, fresh: freshness(r.updatedAt) })));
}));

router.post('/places/:id/updates', requireAuth, wrap(async (req, res) => {
  const id = parseId(req.params.id);
  const status = req.body.status;
  if (!STATUSES.includes(status)) throw new HttpError(400, 'Invalid status.');
  const note = optStr(req.body.note, 140);
  const place = await query('SELECT id FROM places WHERE id=?', [id]);
  if (!place[0]) throw new HttpError(404, 'Place not found.');
  await query(
    `INSERT INTO status_updates (place_id,user_id,status,note,is_official,created_at)
     VALUES (?,?,?,?,?,UTC_TIMESTAMP())`,
    [id, req.user.id, status, note, req.user.role === 'admin' ? 1 : 0]);
  res.status(201).json({ ok: true });
}));

router.post('/places', requireAdmin, wrap(async (req, res) => {
  const name = str(req.body.name, 60);
  if (!name) throw new HttpError(400, 'Place name is required (max 60 characters).');
  const category = optStr(req.body.category, 30) || 'General';
  try {
    const r = await query('INSERT INTO places (name,category) VALUES (?,?)', [name, category]);
    res.status(201).json({ id: r.insertId, name, category });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') throw new HttpError(409, 'That place already exists.');
    throw e;
  }
}));

router.delete('/places/:id', requireAdmin, wrap(async (req, res) => {
  await query('DELETE FROM places WHERE id=?', [parseId(req.params.id)]);
  res.json({ ok: true });
}));

module.exports = router;
