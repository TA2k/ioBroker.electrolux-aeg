'use strict';

const FORBIDDEN_CHARS = /[^.a-zA-Z0-9_-]+/g;
// Everything that must not reach a log the user pastes into an issue: the tokens
// themselves, and the account data Gigya answers next to them. `UID` together with
// `UIDSignature` and `signatureTimestamp` is a valid identity proof, and `profile`
// carries the mail address and the name.
const SECRET_KEYS = new Set([
  'access_token',
  'accessToken',
  'refresh_token',
  'refreshToken',
  'id_token',
  'sessionToken',
  'sessionSecret',
  'UID',
  'UIDSignature',
  'signatureTimestamp',
  'profile',
  'loginID',
  'password',
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
  return JSON.stringify(data, (key, value) => (SECRET_KEYS.has(key) ? '<redacted>' : value));
}

module.exports = {
  FORBIDDEN_CHARS,
  sanitizeJsonKeys,
  sanitizeObjectId,
  stringifyRedactedData,
};
