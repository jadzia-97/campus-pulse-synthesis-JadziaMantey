'use strict';
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
// required string: trimmed, 1..max chars, else null
function str(v, max) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s.length > 0 && s.length <= max ? s : null;
}
// optional string: trimmed and cut to max chars ('' if missing)
function optStr(v, max) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}
function parseId(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 2147483647) throw new HttpError(404, 'Not found');
  return n;
}
// lets async route handlers send their errors to the error middleware
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
module.exports = { HttpError, str, optStr, parseId, wrap };
