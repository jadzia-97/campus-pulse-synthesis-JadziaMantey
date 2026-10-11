'use strict';
const express = require('express');
const { query, tx } = require('../db');
const { requireAuth } = require('../session');
const { HttpError, str, optStr, parseId, wrap } = require('../validate');

const router = express.Router();

// loan state machine: requested -> approved -> returned   (or requested -> declined)
const TRANSITIONS = {
  approve: { from: 'requested', to: 'approved', item: 'lent' },
  decline: { from: 'requested', to: 'declined', item: 'available' },
  return: { from: 'approved', to: 'returned', item: 'available' },
};

router.get('/items', requireAuth, wrap(async (req, res) => {
  const rows = await query(
    `SELECT i.id, i.name, i.description, i.status, i.owner_id AS ownerId, u.name AS ownerName
     FROM items i JOIN users u ON u.id = i.owner_id ORDER BY i.id DESC`);
  res.json(rows.map((r) => ({ ...r, mine: r.ownerId === req.user.id })));
}));

router.post('/items', requireAuth, wrap(async (req, res) => {
  const name = str(req.body.name, 80);
  if (!name) throw new HttpError(400, 'Item name is required (max 80 characters).');
  const r = await query(
    'INSERT INTO items (owner_id,name,description,created_at) VALUES (?,?,?,UTC_TIMESTAMP())',
    [req.user.id, name, optStr(req.body.description, 300)]);
  res.status(201).json({ id: r.insertId });
}));

router.post('/items/:id/request', requireAuth, wrap(async (req, res) => {
  const id = parseId(req.params.id);
  await tx(async (conn) => {
    const rows = await query('SELECT id, owner_id FROM items WHERE id=? FOR UPDATE', [id], conn);
    if (!rows[0]) throw new HttpError(404, 'Item not found.');
    if (rows[0].owner_id === req.user.id) throw new HttpError(400, "You can't borrow your own item.");
    // atomic: only succeeds if the item is still available
    const upd = await query("UPDATE items SET status='requested' WHERE id=? AND status='available'", [id], conn);
    if (upd.affectedRows === 0) throw new HttpError(409, 'Item is not available right now.');
    await query(
      `INSERT INTO loans (item_id,borrower_id,status,created_at,updated_at)
       VALUES (?,?,'requested',UTC_TIMESTAMP(),UTC_TIMESTAMP())`, [id, req.user.id], conn);
  });
  res.status(201).json({ ok: true });
}));

router.delete('/items/:id', requireAuth, wrap(async (req, res) => {
  const id = parseId(req.params.id);
  const rows = await query('SELECT owner_id FROM items WHERE id=?', [id]);
  if (!rows[0]) throw new HttpError(404, 'Item not found.');
  if (rows[0].owner_id !== req.user.id && req.user.role !== 'admin') {
    throw new HttpError(403, 'Only the owner or an admin can remove this item.');
  }
  await query('DELETE FROM items WHERE id=?', [id]);
  res.json({ ok: true });
}));

router.get('/loans', requireAuth, wrap(async (req, res) => {
  const incoming = await query(
    `SELECT l.id, l.status, i.name AS itemName, b.name AS borrowerName
     FROM loans l JOIN items i ON i.id = l.item_id JOIN users b ON b.id = l.borrower_id
     WHERE i.owner_id = ? AND l.status IN ('requested','approved') ORDER BY l.id DESC`, [req.user.id]);
  const mine = await query(
    `SELECT l.id, l.status, i.name AS itemName
     FROM loans l JOIN items i ON i.id = l.item_id
     WHERE l.borrower_id = ? ORDER BY l.id DESC LIMIT 20`, [req.user.id]);
  res.json({ incoming, mine });
}));

router.post('/loans/:id/:action', requireAuth, wrap(async (req, res) => {
  if (!Object.hasOwn(TRANSITIONS, req.params.action)) throw new HttpError(404, 'Not found');
  const t = TRANSITIONS[req.params.action];
  const id = parseId(req.params.id);
  await tx(async (conn) => {
    const rows = await query(
      `SELECT l.id, l.item_id, i.owner_id FROM loans l
       JOIN items i ON i.id = l.item_id WHERE l.id=? FOR UPDATE`, [id], conn);
    if (!rows[0]) throw new HttpError(404, 'Loan not found.');
    if (rows[0].owner_id !== req.user.id) throw new HttpError(403, 'Only the item owner can do that.');
    const upd = await query(
      'UPDATE loans SET status=?, updated_at=UTC_TIMESTAMP() WHERE id=? AND status=?',
      [t.to, id, t.from], conn);
    if (upd.affectedRows === 0) throw new HttpError(409, "That action isn't possible right now.");
    await query('UPDATE items SET status=? WHERE id=?', [t.item, rows[0].item_id], conn);
  });
  res.json({ ok: true });
}));

module.exports = router;
