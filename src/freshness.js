'use strict';
// Turns the age of the newest status update into a level + label.
// fresh <= 15 min, aging <= 60 min, stale > 60 min, none = never reported.
function freshness(ts, now = Date.now()) {
  if (!ts) return { level: 'none', label: 'No reports yet', minutes: null };
  const then = ts instanceof Date ? ts.getTime() : new Date(ts).getTime();
  const minutes = Math.max(Math.floor((now - then) / 60000), 0);
  const level = minutes <= 15 ? 'fresh' : minutes <= 60 ? 'aging' : 'stale';
  let ago;
  if (minutes < 1) ago = 'just now';
  else if (minutes < 60) ago = `${minutes} min ago`;
  else if (minutes < 1440) ago = `${Math.floor(minutes / 60)} h ago`;
  else ago = `${Math.floor(minutes / 1440)} d ago`;
  const label = level === 'stale' ? `${ago} - may be outdated` : ago;
  return { level, label, minutes };
}
module.exports = { freshness };
