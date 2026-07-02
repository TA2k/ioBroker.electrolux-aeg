const { expect } = require('chai');
const { isTransientFetchError } = require('./lib/apiErrors');

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
