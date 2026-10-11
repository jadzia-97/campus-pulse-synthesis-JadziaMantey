'use strict';
// API tests against a REAL MariaDB test database (never your real one).
// Needs the DB settings from .env; uses TEST_DB_NAME (default campus_pulse_test).
// Run: npm test
process.env.DB_NAME = process.env.TEST_DB_NAME || 'campus_pulse_test';
delete process.env.DATABASE_URL;
process.env.ADMIN_EMAIL = 'admin@test.edu';
process.env.ADMIN_PASSWORD = 'adminpass123';

const { test, describe, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { pool, query } = require('../src/db');
const { initDb, seed } = require('../src/seed');
const { createApp } = require('../src/app');

let server;
let base;

class Client {
  constructor() { this.cookie = ''; this.csrf = ''; }
  async req(method, path, body, { csrf = true } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.cookie) headers.Cookie = this.cookie;
    if (this.csrf && csrf) headers['X-CSRF-Token'] = this.csrf;
    const res = await fetch(base + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const pair = c.split(';')[0];
      if (pair.startsWith('sid=')) this.cookie = pair === 'sid=' ? '' : pair;
    }
    let json = null;
    try { json = await res.json(); } catch (e) { /* no body */ }
    if (json && json.csrf) this.csrf = json.csrf;
    return { status: res.status, body: json };
  }
  get(p) { return this.req('GET', p); }
  post(p, b = {}) { return this.req('POST', p, b); }
  patch(p, b) { return this.req('PATCH', p, b); }
  del(p) { return this.req('DELETE', p); }
}

async function register(name, email, password = 'password123') {
  const c = new Client();
  const r = await c.post('/api/auth/register', { name, email, password });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return c;
}
async function adminClient() {
  const c = new Client();
  const r = await c.post('/api/auth/login', { email: 'admin@test.edu', password: 'adminpass123' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return c;
}
async function placeId(c, name) {
  return (await c.get('/api/places')).body.find((p) => p.name === name).id;
}

before(async () => {
  await initDb();
  server = createApp().listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { server.close(); await pool.end(); });
beforeEach(async () => {
  for (const t of ['sessions', 'loans', 'items', 'status_updates', 'reports', 'places', 'users']) {
    await query(`DELETE FROM ${t}`);
  }
  await seed();
});

describe('authentication', () => {
  test('register logs the student in', async () => {
    const c = await register('Ama', 'ama@test.edu');
    assert.equal((await c.get('/api/auth/me')).body.user.role, 'student');
  });
  test('password is stored hashed', async () => {
    await register('Ama', 'ama@test.edu', 'password123');
    const [row] = await query("SELECT password_hash FROM users WHERE email='ama@test.edu'");
    assert.ok(!row.password_hash.includes('password123'));
  });
  test('duplicate email rejected (case-insensitive)', async () => {
    await register('Ama', 'ama@test.edu');
    const r = await new Client().post('/api/auth/register', { name: 'X', email: 'AMA@test.edu', password: 'password123' });
    assert.equal(r.status, 409);
  });
  test('short password rejected', async () => {
    const r = await new Client().post('/api/auth/register', { name: 'A', email: 'a@test.edu', password: 'short' });
    assert.equal(r.status, 400);
  });
  test('cannot register as admin', async () => {
    await new Client().post('/api/auth/register',
      { name: 'Sly', email: 'sly@test.edu', password: 'password123', role: 'admin' });
    const [row] = await query("SELECT role FROM users WHERE email='sly@test.edu'");
    assert.equal(row.role, 'student');
  });
  test('wrong password and SQL injection both fail', async () => {
    await register('Ama', 'ama@test.edu');
    assert.equal((await new Client().post('/api/auth/login', { email: 'ama@test.edu', password: 'nope' })).status, 401);
    assert.equal((await new Client().post('/api/auth/login', { email: "' OR 1=1 --", password: 'x' })).status, 401);
    assert.equal((await new Client().post('/api/auth/login', { email: { $ne: 1 }, password: { $ne: 1 } })).status, 401);
  });
  test('protected endpoints need login', async () => {
    const c = new Client();
    for (const p of ['/api/places', '/api/items', '/api/loans', '/api/reports', '/api/admin/stats']) {
      assert.equal((await c.get(p)).status, 401, p);
    }
  });
  test('logout destroys the session', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const stolen = c.cookie;
    await c.post('/api/auth/logout');
    const thief = new Client(); thief.cookie = stolen;
    assert.equal((await thief.get('/api/places')).status, 401);
  });
  test('changes without the CSRF token are blocked', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const r = await c.req('POST', '/api/items', { name: 'Calc' }, { csrf: false });
    assert.equal(r.status, 403);
    assert.equal((await query('SELECT * FROM items')).length, 0);
  });
  test('health check and security headers', async () => {
    const res = await fetch(`${base}/api/health`);
    assert.equal((await res.json()).status, 'ok');
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });
});

describe('status board + freshness', () => {
  test('update appears and newest wins', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const id = await placeId(c, 'Library');
    await c.post(`/api/places/${id}/updates`, { status: 'busy', note: 'first' });
    await c.post(`/api/places/${id}/updates`, { status: 'open', note: 'second' });
    const lib = (await c.get('/api/places')).body.find((p) => p.id === id);
    assert.equal(lib.status, 'open');
    assert.equal(lib.note, 'second');
    assert.equal(lib.fresh.level, 'fresh');
  });
  test('old update becomes stale', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const id = await placeId(c, 'Gym');
    await c.post(`/api/places/${id}/updates`, { status: 'busy' });
    await query("UPDATE status_updates SET created_at='2020-01-01 00:00:00'");
    const gym = (await c.get('/api/places')).body.find((p) => p.id === id);
    assert.equal(gym.fresh.level, 'stale');
    assert.match(gym.fresh.label, /may be outdated/);
  });
  test('never-reported place shows none', async () => {
    const c = await register('Ama', 'ama@test.edu');
    assert.equal((await c.get('/api/places')).body[0].fresh.level, 'none');
  });
  test('invalid status and unknown place rejected', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const id = await placeId(c, 'Library');
    assert.equal((await c.post(`/api/places/${id}/updates`, { status: 'exploding' })).status, 400);
    assert.equal((await c.post('/api/places/99999/updates', { status: 'open' })).status, 404);
  });
  test('admin updates are official', async () => {
    const a = await adminClient();
    const id = await placeId(a, 'Library');
    await a.post(`/api/places/${id}/updates`, { status: 'closed', note: 'Maintenance' });
    assert.equal((await a.get('/api/places')).body.find((p) => p.id === id).isOfficial, true);
  });
});

describe('roles and permissions', () => {
  test('student cannot manage places or see admin stats', async () => {
    const c = await register('Ama', 'ama@test.edu');
    const id = await placeId(c, 'Library');
    assert.equal((await c.get('/api/admin/stats')).status, 403);
    assert.equal((await c.post('/api/places', { name: 'Hack Lab' })).status, 403);
    assert.equal((await c.del(`/api/places/${id}`)).status, 403);
    assert.equal((await query("SELECT * FROM places WHERE name='Hack Lab'")).length, 0);
  });
  test('admin manages places', async () => {
    const a = await adminClient();
    assert.equal((await a.get('/api/admin/stats')).status, 200);
    const r = await a.post('/api/places', { name: 'Chapel', category: 'Faith' });
    assert.equal(r.status, 201);
    assert.equal((await a.post('/api/places', { name: 'Chapel' })).status, 409);
    assert.equal((await a.del(`/api/places/${r.body.id}`)).status, 200);
  });
});

describe('BorrowLoop', () => {
  let alice; let bob; let cara; let itemId;
  beforeEach(async () => {
    alice = await register('Alice', 'alice@test.edu');
    bob = await register('Bob', 'bob@test.edu');
    cara = await register('Cara', 'cara@test.edu');
    itemId = (await alice.post('/api/items', { name: 'Calculator', description: 'Casio' })).body.id;
  });
  const itemStatus = async () => (await query('SELECT status FROM items WHERE id=?', [itemId]))[0].status;
  const lastLoan = async () => (await query('SELECT id FROM loans ORDER BY id DESC LIMIT 1'))[0].id;

  test('full lending flow', async () => {
    assert.equal((await bob.post(`/api/items/${itemId}/request`)).status, 201);
    assert.equal(await itemStatus(), 'requested');
    const loan = await lastLoan();
    assert.equal((await alice.post(`/api/loans/${loan}/approve`)).status, 200);
    assert.equal(await itemStatus(), 'lent');
    assert.equal((await alice.post(`/api/loans/${loan}/return`)).status, 200);
    assert.equal(await itemStatus(), 'available');
    assert.equal((await query('SELECT status FROM loans'))[0].status, 'returned');
  });
  test('cannot borrow own item', async () => {
    assert.equal((await alice.post(`/api/items/${itemId}/request`)).status, 400);
  });
  test('second request is refused', async () => {
    await bob.post(`/api/items/${itemId}/request`);
    assert.equal((await cara.post(`/api/items/${itemId}/request`)).status, 409);
    assert.equal((await query('SELECT * FROM loans')).length, 1);
  });
  test('two simultaneous requests: exactly one wins', async () => {
    const [r1, r2] = await Promise.all([
      bob.post(`/api/items/${itemId}/request`), cara.post(`/api/items/${itemId}/request`)]);
    assert.deepEqual([r1.status, r2.status].sort(), [201, 409]);
    assert.equal((await query('SELECT * FROM loans')).length, 1);
  });
  test('only the owner can approve', async () => {
    await bob.post(`/api/items/${itemId}/request`);
    const loan = await lastLoan();
    assert.equal((await bob.post(`/api/loans/${loan}/approve`)).status, 403);
    assert.equal((await cara.post(`/api/loans/${loan}/approve`)).status, 403);
    assert.equal(await itemStatus(), 'requested');
  });
  test('decline frees the item; cannot return before approval', async () => {
    await bob.post(`/api/items/${itemId}/request`);
    const loan = await lastLoan();
    assert.equal((await alice.post(`/api/loans/${loan}/return`)).status, 409);
    assert.equal((await alice.post(`/api/loans/${loan}/decline`)).status, 200);
    assert.equal(await itemStatus(), 'available');
  });
  test('unknown action is 404', async () => {
    await bob.post(`/api/items/${itemId}/request`);
    assert.equal((await alice.post(`/api/loans/${await lastLoan()}/constructor`)).status, 404);
  });
  test('delete permissions', async () => {
    assert.equal((await bob.del(`/api/items/${itemId}`)).status, 403);
    assert.equal((await query('SELECT * FROM items')).length, 1);
    assert.equal((await (await adminClient()).del(`/api/items/${itemId}`)).status, 200);
    assert.equal((await query('SELECT * FROM items')).length, 0);
  });
});

describe('FixTrack', () => {
  test('students only see their own reports', async () => {
    const a = await register('Ama', 'ama@test.edu');
    const b = await register('Ben', 'ben@test.edu');
    await a.post('/api/reports', { title: 'Broken projector', location: 'Room 4' });
    assert.equal((await a.get('/api/reports')).body.length, 1);
    assert.equal((await b.get('/api/reports')).body.length, 0);
  });
  test('admin sees all and updates status; student sees the result', async () => {
    const a = await register('Ama', 'ama@test.edu');
    const { body } = await a.post('/api/reports', { title: 'Leaking tap', location: 'Block B' });
    const adm = await adminClient();
    assert.equal((await adm.get('/api/reports')).body.length, 1);
    assert.equal((await adm.patch(`/api/reports/${body.id}`, { status: 'resolved', adminNote: 'Washer replaced' })).status, 200);
    const mine = (await a.get('/api/reports')).body[0];
    assert.equal(mine.status, 'resolved');
    assert.equal(mine.adminNote, 'Washer replaced');
  });
  test('student cannot change status', async () => {
    const a = await register('Ama', 'ama@test.edu');
    const { body } = await a.post('/api/reports', { title: 'Leaking tap', location: 'Block B' });
    assert.equal((await a.patch(`/api/reports/${body.id}`, { status: 'resolved' })).status, 403);
    assert.equal((await query('SELECT status FROM reports'))[0].status, 'open');
  });
  test('validation', async () => {
    const a = await register('Ama', 'ama@test.edu');
    assert.equal((await a.post('/api/reports', { title: '', location: 'x' })).status, 400);
    assert.equal((await a.post('/api/reports', { title: 'x', location: 'y'.repeat(101) })).status, 400);
  });
  test('script text is stored as plain data', async () => {
    const a = await register('Ama', 'ama@test.edu');
    await a.post('/api/reports', { title: '<script>alert(1)</script>', location: 'x' });
    const r = await a.get('/api/reports');
    assert.equal(r.body[0].title, '<script>alert(1)</script>'); // front end renders it via textContent
  });
});
