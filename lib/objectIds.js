'use strict';

const FORBIDDEN_CHARS = /[^.a-zA-Z0-9_-]+/g;
const TOKEN_KEYS = new Set([
  'access_token',
  'accessToken',
  'refresh_token',
  'refreshToken',
  'id_token',
  'sessionToken',
  'sessionSecret',
]);

function sanitizeObjectId(id) {
  return String(id).replace(FORBIDDEN_CHARS, '_');
}

function sanitizeJsonKeys(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeJsonKeys(entry));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const result = {};
  for (const [key, entry] of Object.entries(value)) {
    result[sanitizeObjectId(key).replace(/\./g, '_')] = sanitizeJsonKeys(entry);
  }
  return result;
}

function stringifyRedactedData(data) {
  return JSON.stringify(data, (key, value) => (TOKEN_KEYS.has(key) ? '<redacted>' : value));
}

module.exports = {
  FORBIDDEN_CHARS,
  sanitizeJsonKeys,
  sanitizeObjectId,
  stringifyRedactedData,
};
