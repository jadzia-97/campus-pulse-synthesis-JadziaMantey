'use strict';
const express = require('express');
const { query } = require('../db');
const { requireAuth, requireAdmin } = require('../session');
const { HttpError, str, optStr, parseId, wrap } = require('../validate');

const FIX_STATUSES = ['open', 'in_progress', 'resolved'];
const router = express.Router();

router.get('/reports', requireAuth, wrap(async (req, res) => {
  const base = `SELECT r.id, r.title, r.location, r.description, r.status,
                       r.admin_note AS adminNote, r.created_at AS createdAt, u.name AS reporterName
                FROM reports r JOIN users u ON u.id = r.reporter_id`;
  const rows = req.user.role === 'admin'
    ? await query(`${base} ORDER BY r.id DESC`)
    // students only ever receive their own reports
    : await query(`${base} WHERE r.reporter_id = ? ORDER BY r.id DESC`, [req.user.id]);
  res.json(rows);
}));

router.post('/reports', requireAuth, wrap(async (req, res) => {
  const title = str(req.body.title, 100);
  const location = str(req.body.location, 100);
  if (!title || !location) throw new HttpError(400, 'Title and location are required (max 100 characters each).');
  const r = await query(
    `INSERT INTO reports (reporter_id,title,location,description,created_at,updated_at)
     VALUES (?,?,?,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())`,
    [req.user.id, title, location, optStr(req.body.description, 500)]);
  res.status(201).json({ id: r.insertId });
}));

router.patch('/reports/:id', requireAdmin, wrap(async (req, res) => {
  const id = parseId(req.params.id);
  if (!FIX_STATUSES.includes(req.body.status)) throw new HttpError(400, 'Invalid status.');
  const exists = await query('SELECT id FROM reports WHERE id=?', [id]);
  if (!exists[0]) throw new HttpError(404, 'Report not found.');
  await query('UPDATE reports SET status=?, admin_note=?, updated_at=UTC_TIMESTAMP() WHERE id=?',
    [req.body.status, optStr(req.body.adminNote, 300), id]);
  res.json({ ok: true });
}));

module.exports = router;
