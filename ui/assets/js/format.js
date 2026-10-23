// Formatting of dates for the web interface.

// The texts of the web interface are English, so relative times are too.
const relative = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });

const units = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

function isValid(date) {
  return date instanceof Date && !isNaN(date) && date.getFullYear() > 1970;
}

// relativeTime returns i.e. "2 weeks ago" or "yesterday".
export function relativeTime(date, now = Date.now()) {
  if (!isValid(date)) {
    return 'at an unknown time';
  }
  const seconds = (date.getTime() - now) / 1000;
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) {
      return relative.format(Math.round(seconds / size), unit);
    }
  }
  return 'just now';
}

// dateTime returns date and time in the format of the browser's locale.
export function dateTime(date) {
  if (!isValid(date)) {
    return 'unknown';
  }
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
