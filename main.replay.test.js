'use strict';

// Replay of the whole adapter flow against the captured oven fixtures, without a
// cloud account or a running js-controller. See test/fakeAdapter.js.

const fs = require('node:fs');
const path = require('node:path');
const { expect } = require('chai');
const { createTestAdapter, RAW_ID, SAFE_ID, status } = require('./test/fakeAdapter');

/**
 * The adapter only reads `val` and `ack`; the rest of ioBroker.State is not part of the replay.
 *
 * @param {any} val
 * @param {boolean} ack
 * @returns {ioBroker.State}
 */
function state(val, ack) {
  return /** @type {any} */ ({ val: val, ack: ack });
}

/**
 * @param {Array<{method: string, url: string, data: any}>} requests
 * @param {string} fragment
 */
function requestsTo(requests, fragment) {
  return requests.filter((request) => request.url.includes(fragment));
}

describe('adapter flow with the live oven fixtures', () => {
  describe('startup', () => {
    it('logs in and reports the connection when no session is stored', async () => {
      const { adapter, requests } = createTestAdapter();

      await adapter.onReady();

      expect(requestsTo(requests, 'accounts.login')).to.have.length(1);
      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: true, ack: true });
    });

    it('reuses a stored session and still reports the connection', async () => {
      const first = createTestAdapter();
      await first.adapter.onReady();
      expect(fs.existsSync(path.join(first.dataDir, 'session.json'))).to.equal(true);

      // Second start of the same instance: same data directory, stored token still valid.
      const { adapter, requests } = createTestAdapter();
      fs.copyFileSync(path.join(first.dataDir, 'session.json'), path.join(adapter.dataDir(), 'session.json'));

      await adapter.onReady();

      expect(requestsTo(requests, 'accounts.login')).to.have.length(0);
      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: true, ack: true });
    });

    it('keeps the connection down when the login fails', async () => {
      const { adapter } = createTestAdapter({
        routes: { 'accounts.login': Object.assign(new Error('login rejected'), { response: { status: 403, data: {} } }) },
      });

      await adapter.onReady();

      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: false, ack: true });
    });
  });

  describe('answers the cloud sends but the adapter cannot use', () => {
    /**
     * @param {any} adapter
     */
    function log(adapter) {
      return /** @type {any} */ (adapter).logs.join(' ');
    }

    it('stops the login when the answer carries no session', async () => {
      // What Gigya sends for a wrong user name or password: a body, not a rejection.
      const { adapter, requests } = createTestAdapter({
        routes: { 'accounts.login': { errorCode: 403042, errorMessage: 'invalid loginID or password' } },
      });

      await adapter.onReady();

      expect(log(adapter)).to.contain('the answer carries no session');
      expect(requestsTo(requests, 'accounts.getJWT')).to.have.length(0);
      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: false, ack: true });
    });

    it('stops the login when the answer carries no id_token', async () => {
      const { adapter, requests } = createTestAdapter({ routes: { 'accounts.getJWT': { errorCode: 400006 } } });

      await adapter.onReady();

      expect(log(adapter)).to.contain('no id_token');
      expect(requestsTo(requests, 'authorization/api/v1/token')).to.have.length(0);
      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: false, ack: true });
    });

    it('stops the login when the token exchange carries no access token', async () => {
      const { adapter } = createTestAdapter({ routes: { 'authorization/api/v1/token': { message: 'no' } } });

      await adapter.onReady();

      expect(log(adapter)).to.contain('no access token');
      expect(await adapter.getStateAsync('info.connection')).to.deep.equal({ val: false, ack: true });
    });

    it('keeps the appliances of the last run when the list cannot be read', async () => {
      const { adapter } = createTestAdapter({ routes: { 'api-federation': { message: 'nothing here' } } });

      await adapter.onReady();

      expect(log(adapter)).to.contain('no applianceDataResults');
      // No device tree was invented from an answer nobody could read.
      expect(await adapter.getObjectAsync(SAFE_ID)).to.equal(null);
    });

    it('skips an appliance without an id and keeps the others', async () => {
      const { adapter } = createTestAdapter({
        routes: { 'api-federation': { applianceDataResults: [{ applianceData: { applianceName: 'ghost' } }, status] } },
      });

      await adapter.onReady();

      expect(log(adapter)).to.contain('Skipped an appliance without an applianceId');
      expect(/** @type {any} */ (await adapter.getObjectAsync(SAFE_ID)).common.name).to.equal('Backofen');
    });
  });

  describe('configuration', () => {
    it('falls back to the default interval when the value is not a number', async () => {
      // NaN passes every comparison, so without the check it would reach
      // setTimeout(NaN) and reschedule itself without pause.
      const { adapter } = createTestAdapter({ config: { interval: 'every now and then' } });

      await adapter.onReady();

      expect(adapter.config.interval).to.equal(10);
    });

    it('clamps an interval outside the bounds of the admin page', async () => {
      const low = createTestAdapter({ config: { interval: 0.1 } }).adapter;
      const high = createTestAdapter({ config: { interval: 99999 } }).adapter;

      await low.onReady();
      await high.onReady();

      expect(low.config.interval).to.equal(1);
      expect(high.config.interval).to.equal(24 * 60);
    });

    it('refuses to start on an unknown appliance brand instead of throwing later', async () => {
      const { adapter, requests } = createTestAdapter({ config: { type: 'miele' } });

      await adapter.onReady();

      expect(requests).to.have.length(0);
      expect(/** @type {any} */ (adapter).logs.join(' ')).to.contain('Unknown appliance brand "miele"');
    });

    it('watches the control and remote states only, not everything it writes itself', async () => {
      const { adapter } = createTestAdapter();

      await adapter.onReady();

      expect(/** @type {any} */ (adapter).subscriptions).to.deep.equal(['*.control.*', '*.remote.*']);
    });

    it('never writes the password or a token into the log when a request fails', async () => {
      // What an axios error really carries: the request, headers and body included.
      const failure = Object.assign(new Error('Request failed with status code 403'), {
        config: {
          url: 'https://accounts.eu1.gigya.com/accounts.login',
          headers: { Authorization: 'Bearer access-token' },
          data: { loginID: 'user@example.com', password: 'secret' },
        },
        response: { status: 403, data: { errorMessage: 'invalid loginID or password' } },
      });
      const { adapter } = createTestAdapter({ routes: { 'accounts.login': failure } });

      await adapter.onReady();

      const log = /** @type {any} */ (adapter).logs.join(' ');
      expect(log).to.contain('Login request failed');
      expect(log).to.contain('403');
      expect(log).to.not.contain('secret');
      expect(log).to.not.contain('Bearer');
    });
  });

  describe('shutdown', () => {
    it('does not revoke a token it never had', async () => {
      const { adapter, requests } = createTestAdapter({ config: { username: '', password: '' } });

      await adapter.onReady();
      await new Promise((resolve) => adapter.onUnload(() => resolve(null)));

      expect(requestsTo(requests, 'token/revoke')).to.have.length(0);
    });

    it('keeps the session for the next start instead of revoking it', async () => {
      const { adapter, requests, dataDir } = createTestAdapter();

      await adapter.onReady();
      await new Promise((resolve) => adapter.onUnload(() => resolve(null)));

      expect(requestsTo(requests, 'token/revoke')).to.have.length(0);
      expect(fs.existsSync(path.join(dataDir, 'session.json'))).to.equal(true);
    });
  });

  describe('object tree', () => {
    /** @type {any} */
    let adapter;

    before(async () => {
      adapter = createTestAdapter().adapter;
      await adapter.onReady();
    });

    it('creates the device with the name reported by the cloud', async () => {
      const device = await adapter.getObjectAsync(SAFE_ID);
      expect(device.type).to.equal('device');
      expect(device.common.name).to.equal('Backofen');
    });

    it('creates a writable control state per writable capability', async () => {
      const light = await adapter.getObjectAsync(SAFE_ID + '.control.cavityLight');
      expect(light.common).to.include({ type: 'boolean', role: 'switch', write: true });
      const temperature = await adapter.getObjectAsync(SAFE_ID + '.control.targetTemperatureC');
      expect(temperature.common).to.include({ type: 'number', role: 'level.temperature', unit: '°C', write: true });
      // networkInterface carries the command that unregisters the appliance.
      expect(await adapter.getObjectAsync(SAFE_ID + '.control.networkInterface_startUpCommand')).to.equal(null);
    });

    it('mirrors the reported values into the control states', async () => {
      expect(await adapter.getStateAsync(SAFE_ID + '.control.targetTemperatureC')).to.deep.equal({
        val: 150,
        ack: true,
      });
      expect(await adapter.getStateAsync(SAFE_ID + '.control.cavityLight')).to.deep.equal({ val: false, ack: true });
    });

    it('mirrors an ON/OFF capability the oven reports as a boolean', async () => {
      // The live oven reports `cavityLight: true`, not the literal `ON` of the
      // capability, so the string mapping must not turn a lit oven into `false`.
      const lit = JSON.parse(JSON.stringify(status));
      lit.properties.reported.cavityLight = true;
      const { adapter: withLight } = createTestAdapter({
        routes: { 'api-federation': { applianceDataResults: [lit] }, appliance: lit },
      });

      await withLight.onReady();

      expect(await withLight.getStateAsync(SAFE_ID + '.control.cavityLight')).to.deep.equal({ val: true, ack: true });
    });

    it('writes the derived states for an idle oven', async () => {
      expect(await adapter.getStateAsync(SAFE_ID + '.status.running')).to.deep.equal({ val: false, ack: true });
      expect(await adapter.getStateAsync(SAFE_ID + '.status.finishTime')).to.deep.equal({ val: null, ack: true });
      // The remaining time is not derived, the raw value carries it.
      expect(await adapter.getObjectAsync(SAFE_ID + '.status.timeToEndMinutes')).to.equal(null);
      expect(await adapter.getObjectAsync(SAFE_ID + '.status.properties.reported.timeToEnd')).to.not.equal(null);
      expect(await adapter.getStateAsync(SAFE_ID + '.status.cycleFinished')).to.deep.equal({ val: false, ack: true });
    });

    it('initializes a control state the appliance never reports', async () => {
      // The oven only reports `targetFoodProbeTemperatureC` with a probe plugged in,
      // so nothing mirrors it. It must still read as a written, empty state instead
      // of one the adapter never touched.
      expect(await adapter.getStateAsync(SAFE_ID + '.control.targetFoodProbeTemperatureC')).to.deep.equal({
        val: null,
        ack: true,
      });
    });

    it('keeps the empty and frozen shadow halves out of the tree', async () => {
      const withMetadata = JSON.parse(JSON.stringify(status));
      // The device list fills metadata, the per appliance poll does not.
      withMetadata.properties.metadata = { doorState: { timestamp: 1788343012 } };
      const { adapter: fresh } = createTestAdapter({
        routes: { 'api-federation': { applianceDataResults: [withMetadata] }, appliance: withMetadata },
      });
      // Left behind by a version that still parsed the metadata: json2iob creates
      // the channel above every state it writes.
      await fresh.extendObject(SAFE_ID + '.status.properties.metadata', {
        type: 'channel',
        common: { name: 'metadata' },
        native: {},
      });
      await fresh.extendObject(SAFE_ID + '.status.properties.metadata.doorState.timestamp', {
        type: 'state',
        common: { name: 'timestamp', type: 'number', role: 'value', read: true, write: false },
        native: {},
      });

      await fresh.onReady();

      expect(await fresh.getObjectAsync(SAFE_ID + '.status.properties.metadata')).to.equal(null);
      // desired and metadataDesired are empty in every payload of both endpoints.
      expect(await fresh.getObjectAsync(SAFE_ID + '.status.properties.desired')).to.equal(null);
      expect(await fresh.getObjectAsync(SAFE_ID + '.status.properties.metadataDesired')).to.equal(null);
      expect(await fresh.getObjectAsync(SAFE_ID + '.status.properties.metadata.doorState.timestamp')).to.equal(null);
    });

    it('stamps a value that changed during a restart with the moment the oven changed it', async () => {
      const shadow = JSON.parse(JSON.stringify(status));
      shadow.properties.reported.doorState = 'CLOSED';
      shadow.properties.metadata = { doorState: { timestamp: 1788343012 } };
      const { adapter: restarted } = createTestAdapter({
        routes: { 'api-federation': { applianceDataResults: [shadow] }, appliance: shadow },
      });
      // What the previous run left behind: the door was open when the adapter stopped.
      restarted.setState(SAFE_ID + '.status.properties.reported.doorState', 'OPEN', true);

      await restarted.onReady();

      const state = await restarted.getStateAsync(SAFE_ID + '.status.properties.reported.doorState');
      // The parser writes the same value again right after and moves ts to now, but
      // lc stays where the stamp put it: the change lands in the history at 09:56:52
      // instead of at the start of the adapter.
      expect(state).to.deep.include({ val: 'CLOSED', ack: true, lc: 1788343012000 });
    });

    it('leaves a state the previous run never wrote to the poll', async () => {
      const shadow = JSON.parse(JSON.stringify(status));
      shadow.properties.metadata = { doorState: { timestamp: 1788343012 } };
      const { adapter: fresh } = createTestAdapter({
        routes: { 'api-federation': { applianceDataResults: [shadow] }, appliance: shadow },
      });

      await fresh.onReady();

      const state = /** @type {any} */ (await fresh.getStateAsync(SAFE_ID + '.status.properties.reported.doorState'));
      expect(state.val).to.equal('CLOSED');
      expect(state.lc).to.equal(undefined);
    });

    it('adds role and unit to the reported values it knows', async () => {
      const temperature = await adapter.getObjectAsync(SAFE_ID + '.status.properties.reported.displayTemperatureC');
      expect(temperature.common).to.include({ role: 'value.temperature', unit: '°C' });
    });

    it('writes an enum of the capability document as one list state', async () => {
      const object = await adapter.getObjectAsync(SAFE_ID + '.capabilities.applianceState.values');
      expect(object.type).to.equal('state');
      expect(object.common).to.include({ type: 'string', role: 'json' });
      const state = await adapter.getStateAsync(SAFE_ID + '.capabilities.applianceState.values');
      expect(JSON.parse(String(state.val))).to.include.members(['RUNNING', 'READY_TO_START', 'END_OF_CYCLE']);
      // A map whose members carry overrides stays a channel.
      expect((await adapter.getObjectAsync(SAFE_ID + '.capabilities.program.values')).type).to.equal('channel');
    });

    it('replaces the empty channels an older version created for an enum', async () => {
      const { adapter: upgraded } = createTestAdapter();
      const stale = SAFE_ID + '.capabilities.doorState.values';
      // The shape an older version left behind, here and inside a trigger rule, whose
      // object id json2iob invents rather than deriving it from the payload.
      const staleTrigger = SAFE_ID + '.capabilities.applianceState.triggers01.action.executeCommand.values';
      for (const [channel, member] of [[stale, 'OPEN'], [staleTrigger, 'STOPRESET']]) {
        await upgraded.extendObject(channel, { type: 'channel', common: { name: 'values' }, native: {} });
        await upgraded.extendObject(channel + '.' + member, { type: 'channel', common: { name: member }, native: {} });
      }

      await upgraded.onReady();

      for (const [channel, member] of [[stale, 'OPEN'], [staleTrigger, 'STOPRESET']]) {
        expect(/** @type {any} */ (await upgraded.getObjectAsync(channel)).type, channel).to.equal('state');
        expect(await upgraded.getObjectAsync(channel + '.' + member), channel).to.equal(null);
      }
      // A map whose members carry their own settings keeps its channel and its states.
      expect(/** @type {any} */ (await upgraded.getObjectAsync(SAFE_ID + '.capabilities.program.values')).type).to.equal('channel');
      expect(await upgraded.getObjectAsync(SAFE_ID + '.capabilities.program.values.AUGRATIN.targetTemperatureC.max')).to.not.equal(null);
    });

    it('creates the remote buttons of the appliance', async () => {
      const start = await adapter.getObjectAsync(SAFE_ID + '.remote.START');
      expect(start.common).to.include({ type: 'boolean', role: 'button', write: true, read: false });
    });

    it('summarizes the alerts of an appliance without alerts', async () => {
      expect(await adapter.getStateAsync(SAFE_ID + '.status.activeAlertCount')).to.deep.equal({ val: 0, ack: true });
    });
  });

  describe('writing a control state', () => {
    it('sends the capability payload and confirms the state', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();
      const id = adapter.namespace + '.' + SAFE_ID + '.control.targetTemperatureC';

      await adapter.onStateChange(id, state(200, false));

      const commands = requestsTo(requests, '/command?');
      expect(commands).to.have.length(1);
      expect(commands[0].method).to.equal('put');
      expect(commands[0].url).to.include(RAW_ID);
      expect(commands[0].data).to.deep.equal({ targetTemperatureC: 200 });
      expect(await adapter.getStateAsync(id)).to.deep.equal({ val: 200, ack: true });
    });

    it('translates a switch into the ON / OFF vocabulary of the appliance', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.control.cavityLight', state(true, false));

      expect(requestsTo(requests, '/command?')[0].data).to.deep.equal({ cavityLight: 'ON' });
    });

    it('sends the raw command name of a remote button', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.remote.START', state(true, false));

      expect(requestsTo(requests, '/command?')[0].data).to.deep.equal({ executeCommand: 'START' });
    });

    it('releases a button after the press instead of leaving it pressed', async () => {
      const { adapter } = createTestAdapter();
      await adapter.onReady();
      const button = adapter.namespace + '.' + SAFE_ID + '.remote.START';

      await adapter.onStateChange(button, state(true, false));

      expect(await adapter.getStateAsync(SAFE_ID + '.remote.START')).to.deep.equal({ val: false, ack: true });
    });

    it('releases the refresh button and polls the appliance again', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();
      const before = requestsTo(requests, '/appliances/').length;

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.remote.Refresh', state(true, false));

      expect(requestsTo(requests, '/appliances/').length).to.be.greaterThan(before);
      expect(await adapter.getStateAsync(SAFE_ID + '.remote.Refresh')).to.deep.equal({ val: false, ack: true });
    });

    it('keeps a switch at the value that was written, it is a setting and not a press', async () => {
      const { adapter } = createTestAdapter();
      await adapter.onReady();

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.control.cavityLight', state(true, false));

      expect(await adapter.getStateAsync(SAFE_ID + '.control.cavityLight')).to.deep.equal({ val: true, ack: true });
    });

    it('ignores acknowledged values, so a poll does not trigger a command', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.control.cavityLight', state(true, true));

      expect(requestsTo(requests, '/command?')).to.have.length(0);
    });
  });
});

describe('shutdown while a token refresh is in flight', () => {
  it('does not start a socket and a timer that nothing will clean up', async () => {
    const { adapter, sockets } = createTestAdapter({ websocket: true });
    await adapter.onReady();
    const socketsBefore = sockets.length;
    /** @type {any} */ (adapter).timers.length = 0;

    // The refresh was already on its way when the adapter was told to stop.
    /** @type {any} */ (adapter).unloading = true;
    const result = await /** @type {any} */ (adapter).refreshToken();

    expect(result.ok).to.equal(true);
    expect(sockets).to.have.length(socketsBefore);
    expect(/** @type {any} */ (adapter).timers).to.have.length(0);
  });
});

describe('the WebSocket reconnect chain', () => {
  /**
   * The adapter arms the reconnect with a 5 s timer, so a pending timer of that
   * length is what "a reconnect was scheduled" looks like from the outside.
   *
   * @param {any} adapter
   */
  function reconnectsPending(adapter) {
    return /** @type {any} */ (adapter).timers.filter((/** @type {any} */ timer) => timer.ms === 5000).length;
  }

  it('reconnects after every close, not only after the first one', async () => {
    const { adapter, sockets } = createTestAdapter({ websocket: true });
    await adapter.onReady();
    expect(sockets).to.have.length(1);

    // The cloud drops the connection.
    sockets[0].emit('close');
    expect(reconnectsPending(adapter)).to.equal(1);

    // The reconnect runs and replaces the socket. The predecessor is closed on the
    // way, and that close must not count as a connection loss of its own.
    // `timers` is the recorder of the fake adapter, not part of the real base class.
    /** @type {any} */ (adapter).timers.pop().handler();
    expect(sockets).to.have.length(2);
    expect(sockets[0].closed).to.equal(true);
    expect(reconnectsPending(adapter)).to.equal(0);

    // The cloud drops the new connection too. This is the close that used to be
    // swallowed, leaving the adapter on a dead socket until the next restart.
    sockets[1].emit('close');
    expect(reconnectsPending(adapter)).to.equal(1);
  });

  it('ignores a socket that was already replaced', async () => {
    const { adapter, sockets } = createTestAdapter({ websocket: true });
    await adapter.onReady();

    // A token refresh reconnects without waiting for a close.
    adapter.connectWebSocket();
    expect(sockets).to.have.length(2);

    // A late close of the predecessor changes nothing.
    sockets[0].emit('close');
    expect(reconnectsPending(adapter)).to.equal(0);
  });
});
