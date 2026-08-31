'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SESSION_FILE = 'session.json';

/**
 * The refresh token is a full credential for the user's Electrolux account, so
 * it is kept in the instance data directory with owner only permissions and
 * never in a state: states are readable through the admin UI, scripts, the REST
 * adapter and every ioBroker backup.
 *
 * @param {string} dir - instance data directory
 * @returns {string}
 */
function sessionPath(dir) {
  return path.join(dir, SESSION_FILE);
}

/**
 * Read a stored session.
 *
 * A missing, unreadable or corrupt file is not an error - the adapter simply
 * logs in again.
 *
 * @param {string} dir - instance data directory
 * @returns {{refreshToken: string, accessToken: string|null, expiresAt: number, savedAt: number}|null}
 */
function loadSession(dir) {
  try {
    const raw = fs.readFileSync(sessionPath(dir), 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.refreshToken !== 'string' || !parsed.refreshToken) {
      return null;
    }
    return {
      refreshToken: parsed.refreshToken,
      accessToken: typeof parsed.accessToken === 'string' && parsed.accessToken ? parsed.accessToken : null,
      expiresAt: Number(parsed.expiresAt) || 0,
      savedAt: Number(parsed.savedAt) || 0,
    };
  } catch {
    return null;
  }
}

/**
 * Store a session.
 *
 * The access token is stored along with the refresh token, so a restart within
 * its lifetime needs no token request at all. The cloud answers a refresh that
 * follows too closely with `429 cas_3404`, which is exactly what a restart
 * produces. Both tokens are credentials of the same account, so storing the
 * short lived one next to the long lived one adds no exposure - the file holds
 * neither the user name nor the password.
 *
 * @param {string} dir - instance data directory
 * @param {any} session - current session
 * @returns {boolean} true when the session was written
 */
function saveSession(dir, session) {
  if (!session || typeof session.refreshToken !== 'string' || !session.refreshToken) {
    return false;
  }
  const file = sessionPath(dir);
  const expiresIn = Number(session.expiresIn);
  try {
    fs.mkdirSync(dir, { recursive: true });
    // Remove first, so the mode below also applies when the file already exists.
    try {
      fs.unlinkSync(file);
    } catch {
      // No previous session file.
    }
    fs.writeFileSync(
      file,
      JSON.stringify({
        refreshToken: session.refreshToken,
        accessToken: typeof session.accessToken === 'string' ? session.accessToken : null,
        expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : 0,
        savedAt: Date.now(),
      }),
      { encoding: 'utf8', mode: 0o600 },
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete a stored session, for example after the token was revoked.
 *
 * @param {string} dir - instance data directory
 */
function clearSession(dir) {
  try {
    fs.unlinkSync(sessionPath(dir));
  } catch {
    // Nothing stored.
  }
}

module.exports = {
  loadSession,
  saveSession,
  clearSession,
  sessionPath,
};
