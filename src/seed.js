'use strict';
const fs = require('fs');
const path = require('path');
const { pool, query } = require('./db');
const { hashPassword } = require('./security');

const DEFAULT_PLACES = [['Library', 'Study'], ['Cafeteria', 'Food'], ['Gym', 'Sports'],
  ['Computer Lab', 'Study'], ['Campus Wi-Fi', 'Services']];

async function createTables() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  for (const stmt of sql.split(';').map((s) => s.trim()).filter(Boolean)) {
    await pool.query(stmt);
  }
}

// Creates the first admin (from env vars) and default places if missing.
async function seed() {
  const [{ n }] = await query("SELECT COUNT(*) AS n FROM users WHERE role='admin'");
  if (Number(n) === 0) {
    const email = (process.env.ADMIN_EMAIL || 'admin@campus.test').toLowerCase();
    const password = process.env.ADMIN_PASSWORD || (process.env.NODE_ENV === 'production' ? '' : 'admin12345');
    if (!password) throw new Error('Set ADMIN_PASSWORD before starting in production.');
    await query(
      "INSERT INTO users (name,email,password_hash,role,created_at) VALUES ('Admin',?,?,'admin',UTC_TIMESTAMP())",
      [email, await hashPassword(password)]);
  }
  const [{ p }] = await query('SELECT COUNT(*) AS p FROM places');
  if (Number(p) === 0) {
    for (const [name, category] of DEFAULT_PLACES) {
      await query('INSERT INTO places (name,category) VALUES (?,?)', [name, category]);
    }
  }
}

async function initDb() { await createTables(); await seed(); }
module.exports = { initDb, seed };
