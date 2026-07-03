const { expect } = require('chai');
const { isTransientFetchError } = require('./lib/apiErrors');
const { sanitizeJsonKeys, sanitizeObjectId, stringifyRedactedData } = require('./lib/objectIds');

describe('transient API errors', () => {
  it('detects temporary gateway and timeout failures', () => {
    expect(isTransientFetchError({ response: { status: 504 } })).to.equal(true);
    expect(isTransientFetchError({ response: { status: 503 } })).to.equal(true);
    expect(isTransientFetchError({ code: 'ETIMEDOUT' })).to.equal(true);
  });

  it('keeps auth and client failures non-transient', () => {
    expect(isTransientFetchError({ response: { status: 401 } })).to.equal(false);
    expect(isTransientFetchError({ response: { status: 404 } })).to.equal(false);
  });
});

describe('object id sanitization', () => {
  it('removes characters rejected by repository object checks', () => {
    expect(sanitizeObjectId('944035051_00:44916165-443E07559353')).to.equal(
      '944035051_00_44916165-443E07559353',
    );
  });

  it('sanitizes dynamic JSON keys before json2iob sees them', () => {
    expect(sanitizeJsonKeys({ 'bad.key:*': [{ 'x y': 1 }] })).to.deep.equal({
      bad_key_: [{ x_y: 1 }],
    });
  });
});

describe('debug log redaction', () => {
  it('redacts session tokens', () => {
    expect(stringifyRedactedData({ access_token: 'secret', refreshToken: 'secret', ok: true })).to.equal(
      '{"access_token":"<redacted>","refreshToken":"<redacted>","ok":true}',
    );
  });
});
