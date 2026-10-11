'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

// Passwords: salted scrypt (built into Node). Stored as scrypt$salt$hash.
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [alg, saltHex, hashHex] = String(stored).split('$');
  if (alg !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const key = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
module.exports = { hashPassword, verifyPassword, sha256, randomHex, parseCookies };
