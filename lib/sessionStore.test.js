'use strict';

const { expect } = require('chai');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadSession, saveSession, clearSession, sessionPath } = require('./sessionStore');

/**
 * Load a session and assert it exists, so the tests can use it without null checks.
 *
 * @param {string} directory
 * @returns {Exclude<ReturnType<typeof loadSession>, null>}
 */
function loadStored(directory) {
  const loaded = loadSession(directory);
  expect(loaded).to.not.equal(null);
  return /** @type {Exclude<ReturnType<typeof loadSession>, null>} */ (loaded);
}

describe('lib/sessionStore', () => {
  /** @type {string} */
  let dir;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'electrolux-session-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('returns null when nothing is stored', () => {
    expect(loadSession(dir)).to.equal(null);
    expect(loadSession(path.join(dir, 'does-not-exist'))).to.equal(null);
  });

  it('stores and reads back the refresh token', () => {
    expect(saveSession(dir, { refreshToken: 'token-1', accessToken: 'access' })).to.equal(true);
    const loaded = loadStored(dir);
    expect(loaded.refreshToken).to.equal('token-1');
    expect(loaded.savedAt).to.be.a('number').and.to.be.greaterThan(0);
  });

  it('stores the access token with its expiry, so a restart needs no token request', () => {
    saveSession(dir, { refreshToken: 'token-1', accessToken: 'access-1', expiresIn: 3600 });
    const loaded = loadStored(dir);
    expect(loaded.accessToken).to.equal('access-1');
    expect(loaded.expiresAt).to.be.greaterThan(Date.now() + 3500 * 1000);
  });

  it('has no expiry when the cloud did not advertise one', () => {
    saveSession(dir, { refreshToken: 'token-1', accessToken: 'access-1' });
    expect(loadStored(dir).expiresAt).to.equal(0);
  });

  it('never writes credentials to disk', () => {
    saveSession(dir, {
      refreshToken: 'token-1',
      accessToken: 'access-1',
      username: 'someone@example.com',
      password: 'super-secret-password',
    });
    const raw = fs.readFileSync(sessionPath(dir), 'utf8');
    expect(raw).to.not.contain('super-secret-password');
    expect(raw).to.not.contain('someone@example.com');
  });

  it('refuses to store a session without a refresh token', () => {
    expect(saveSession(dir, undefined)).to.equal(false);
    expect(saveSession(dir, {})).to.equal(false);
    expect(saveSession(dir, { refreshToken: '' })).to.equal(false);
    expect(fs.existsSync(sessionPath(dir))).to.equal(false);
  });

  it('creates the directory when it is missing', () => {
    const nested = path.join(dir, 'nested', 'instance');
    expect(saveSession(nested, { refreshToken: 'token-1' })).to.equal(true);
    expect(loadStored(nested).refreshToken).to.equal('token-1');
  });

  it('overwrites a previous session', () => {
    saveSession(dir, { refreshToken: 'token-1' });
    saveSession(dir, { refreshToken: 'token-2' });
    expect(loadStored(dir).refreshToken).to.equal('token-2');
  });

  it('treats a corrupt file as no session', () => {
    fs.writeFileSync(sessionPath(dir), 'not json at all');
    expect(loadSession(dir)).to.equal(null);
    fs.writeFileSync(sessionPath(dir), JSON.stringify({ refreshToken: 42 }));
    expect(loadSession(dir)).to.equal(null);
  });

  it('clears a stored session and tolerates a missing file', () => {
    saveSession(dir, { refreshToken: 'token-1' });
    clearSession(dir);
    expect(loadSession(dir)).to.equal(null);
    expect(() => clearSession(dir)).to.not.throw();
  });

  it('restricts the file to the owner on posix systems', function () {
    if (process.platform === 'win32') {
      this.skip();
    }
    saveSession(dir, { refreshToken: 'token-1' });
    expect(fs.statSync(sessionPath(dir)).mode & 0o777).to.equal(0o600);
  });
});
