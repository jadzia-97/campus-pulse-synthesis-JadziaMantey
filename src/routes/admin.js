'use strict';
const express = require('express');
const { query } = require('../db');
const { requireAdmin } = require('../session');
const { wrap } = require('../validate');

const router = express.Router();

router.get('/admin/stats', requireAdmin, wrap(async (req, res) => {
  const [u] = await query('SELECT COUNT(*) AS n FROM users');
  const [r] = await query("SELECT COUNT(*) AS n FROM reports WHERE status <> 'resolved'");
  const [l] = await query("SELECT COUNT(*) AS n FROM loans WHERE status IN ('requested','approved')");
  res.json({ users: Number(u.n), unresolvedReports: Number(r.n), activeLoans: Number(l.n) });
}));

module.exports = router;
