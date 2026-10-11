'use strict';
const { initDb } = require('../src/seed');
const { pool } = require('../src/db');
initDb()
  .then(() => console.log('Database ready (tables created, admin + default places seeded).'))
  .catch((e) => { console.error('init-db failed:', e.message); process.exitCode = 1; })
  .finally(() => pool.end());
