'use strict';
const mysql = require('mysql2/promise');

function config() {
  const common = {
    waitForConnections: true,
    connectionLimit: 10,
    timezone: 'Z',          // read/write DATETIME as UTC
    charset: 'utf8mb4',
  };
  if (process.env.DB_SSL === '1') common.ssl = { rejectUnauthorized: true };
  if (process.env.DATABASE_URL) {
    const u = new URL(process.env.DATABASE_URL);
    return { ...common, host: u.hostname, port: Number(u.port) || 3306,
      user: decodeURIComponent(u.username), password: decodeURIComponent(u.password),
      database: u.pathname.slice(1) };
  }
  return { ...common,
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'campus',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'campus_pulse' };
}

const pool = mysql.createPool(config());

// Prepared statement: values travel separately from the SQL text (no SQL injection).
// SELECT -> array of rows.  INSERT/UPDATE/DELETE -> {affectedRows, insertId}.
async function query(sql, params = [], conn = pool) {
  const [result] = await conn.execute(sql, params);
  return result;
}

// Run several statements as one all-or-nothing transaction.
async function tx(fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await fn(conn);
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { pool, query, tx };
