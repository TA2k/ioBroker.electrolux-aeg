const { expect } = require('chai');
const { isTransientFetchError } = require('./lib/apiErrors');
const { sanitizeJsonKeys, sanitizeObjectId, stringifyRedactedData } = require('./lib/objectIds');
const { buildRemoteStates } = require('./lib/remoteCommands');

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
    expect(sanitizeObjectId('appliance,id')).to.equal('appliance_id');
  });

  it('sanitizes dynamic JSON keys before json2iob sees them', () => {
    expect(sanitizeJsonKeys({ 'bad.key:*': [{ 'x y': 1 }] })).to.deep.equal({
      bad_key_: [{ x_y: 1 }],
    });
  });
});

describe('remote command states', () => {
  it('marks button states as write-only and keeps other roles readable', () => {
    const { states } = buildRemoteStates(
      [
        { command: 'Refresh', name: 'True = Refresh' },
        { command: 'CustomCommand', name: 'Send Custom Command', type: 'string', role: 'json', def: '{}' },
        { command: 'START', name: 'START' },
      ],
      'device.remote',
    );
    const byId = Object.fromEntries(states.map((state) => [state.objectId, state.object.common]));
    expect(byId['device.remote.Refresh']).to.include({ role: 'button', read: false, write: true, type: 'boolean' });
    expect(byId['device.remote.START']).to.include({ role: 'button', read: false, write: true });
    expect(byId['device.remote.CustomCommand']).to.include({ role: 'json', read: true, write: true, type: 'string' });
  });

  it('sanitizes API command names and keeps the raw name for the API call', () => {
    const { states } = buildRemoteStates([{ command: 'STOP:RESET NOW' }], 'device.remote');
    expect(states).to.have.lengthOf(1);
    expect(states[0].objectId).to.equal('device.remote.STOP_RESET_NOW');
    expect(states[0].command).to.equal('STOP:RESET NOW');
    expect(states[0].object.common.name).to.equal('STOP:RESET NOW');
  });

  it('skips command names that sanitize to an already used object id', () => {
    const { states, collisions } = buildRemoteStates(
      [{ command: 'STOP:RESET' }, { command: 'STOP RESET' }, { command: 'STOP:RESET' }],
      'device.remote',
    );
    expect(states.map((state) => state.command)).to.deep.equal(['STOP:RESET']);
    expect(collisions).to.deep.equal([
      { objectId: 'device.remote.STOP_RESET', command: 'STOP RESET', existing: 'STOP:RESET' },
    ]);
  });
});

describe('debug log redaction', () => {
  it('redacts session tokens', () => {
    expect(stringifyRedactedData({ access_token: 'secret', refreshToken: 'secret', ok: true })).to.equal(
      '{"access_token":"<redacted>","refreshToken":"<redacted>","ok":true}',
    );
  });
});
