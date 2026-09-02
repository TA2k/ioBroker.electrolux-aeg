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
      expect(await adapter.getStateAsync(SAFE_ID + '.status.timeToEndMinutes')).to.deep.equal({
        val: null,
        ack: true,
      });
      expect(await adapter.getStateAsync(SAFE_ID + '.status.cycleFinished')).to.deep.equal({ val: false, ack: true });
    });

    it('adds role and unit to the reported values it knows', async () => {
      const temperature = await adapter.getObjectAsync(SAFE_ID + '.status.properties.reported.displayTemperatureC');
      expect(temperature.common).to.include({ role: 'value.temperature', unit: '°C' });
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

    it('ignores acknowledged values, so a poll does not trigger a command', async () => {
      const { adapter, requests } = createTestAdapter();
      await adapter.onReady();

      await adapter.onStateChange(adapter.namespace + '.' + SAFE_ID + '.control.cavityLight', state(true, true));

      expect(requestsTo(requests, '/command?')).to.have.length(0);
    });
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
