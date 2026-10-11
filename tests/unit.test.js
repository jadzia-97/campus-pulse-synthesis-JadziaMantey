'use strict';
// Pure-logic tests: no database needed.   Run: npm run test:unit
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { freshness } = require('../src/freshness');
const { hashPassword, verifyPassword, sha256, parseCookies } = require('../src/security');
const { str, optStr, parseId, HttpError } = require('../src/validate');

const MIN = 60000;

describe('freshness', () => {
  const now = Date.parse('2026-01-01T12:00:00Z');
  test('no report yet', () => {
    assert.equal(freshness(null, now).level, 'none');
  });
  test('fresh within 15 minutes', () => {
    assert.equal(freshness(new Date(now - 5 * MIN), now).level, 'fresh');
    assert.equal(freshness(new Date(now - 15 * MIN), now).level, 'fresh');
  });
  test('aging between 16 and 60 minutes', () => {
    assert.equal(freshness(new Date(now - 16 * MIN), now).level, 'aging');
    assert.equal(freshness(new Date(now - 60 * MIN), now).level, 'aging');
  });
  test('stale after 60 minutes and says so', () => {
    const f = freshness(new Date(now - 120 * MIN), now);
    assert.equal(f.level, 'stale');
    assert.match(f.label, /may be outdated/);
    assert.match(f.label, /2 h ago/);
  });
  test('just now, and clock skew never goes negative', () => {
    assert.equal(freshness(new Date(now), now).label, 'just now');
    assert.equal(freshness(new Date(now + 10 * MIN), now).minutes, 0);
  });
  test('accepts ISO strings and day-old reports', () => {
    assert.equal(freshness('2025-12-30T12:00:00Z', now).label, '2 d ago - may be outdated');
  });
});

describe('passwords', () => {
  test('hash is salted and never contains the password', async () => {
    const a = await hashPassword('correct horse');
    const b = await hashPassword('correct horse');
    assert.notEqual(a, b);
    assert.ok(!a.includes('correct horse'));
    assert.ok(a.startsWith('scrypt$'));
  });
  test('verify accepts the right password only', async () => {
    const h = await hashPassword('correct horse');
    assert.equal(await verifyPassword('correct horse', h), true);
    assert.equal(await verifyPassword('wrong horse', h), false);
  });
  test('verify rejects malformed hashes', async () => {
    assert.equal(await verifyPassword('x', 'plaintext'), false);
    assert.equal(await verifyPassword('x', ''), false);
  });
});

describe('helpers', () => {
  test('sha256 is stable', () => {
    assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  test('parseCookies', () => {
    assert.deepEqual(parseCookies('a=1; sid=abc%20d; empty'), { a: '1', sid: 'abc d' });
    assert.deepEqual(parseCookies(undefined), {});
  });
  test('str requires non-empty trimmed text within the limit', () => {
    assert.equal(str('  hi  ', 5), 'hi');
    assert.equal(str('', 5), null);
    assert.equal(str('   ', 5), null);
    assert.equal(str('toolong', 3), null);
    assert.equal(str(42, 5), null);
    assert.equal(str({ $ne: 1 }, 5), null);
  });
  test('optStr trims, truncates and defaults to empty', () => {
    assert.equal(optStr(undefined, 5), '');
    assert.equal(optStr('abcdefgh', 5), 'abcde');
  });
  test('parseId only accepts positive integers', () => {
    assert.equal(parseId('12'), 12);
    for (const bad of ['0', '-1', '1.5', 'abc', '1; DROP TABLE users', '99999999999']) {
      assert.throws(() => parseId(bad), (e) => e instanceof HttpError && e.status === 404);
    }
  });
});
