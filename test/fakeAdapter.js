'use strict';

// Offline harness for main.js.
//
// main.js is the layer the unit tests in lib/ cannot reach: it wires the HTTP
// responses to objects and states. This replaces `@iobroker/adapter-core` with an
// in-memory adapter and the axios client with a router over the captured oven
// fixtures, so the whole poll path can run in a mocha process without a cloud
// account, a js-controller or a real appliance.

const EventEmitter = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const status = require('./fixtures/ov-status.json');
const capabilities = require('./fixtures/ov-capabilities.json');

const { sanitizeObjectId } = require('../lib/objectIds');

const RAW_ID = status.applianceId;
const SAFE_ID = sanitizeObjectId(RAW_ID);

class FakeAdapter extends EventEmitter {
  constructor(options) {
    super();
    this.name = options.name;
    this.instance = 0;
    this.namespace = options.name + '.0';
    this.config = {};
    /** @type {Array<{handler: () => void, ms: number}>} */
    this.timers = [];
    /** @type {Map<string, any>} */
    this.objects = new Map();
    /** @type {Map<string, {val: any, ack: boolean}>} */
    /** @type {Map<string, {val: any, ack: boolean, ts?: number, lc?: number}>} */
    this.states = new Map();
    /** @type {string[]} */
    this.logs = [];
    const record = (level) => (message) => this.logs.push(level + ': ' + message);
    this.log = { info: record('info'), warn: record('warn'), error: record('error'), debug: record('debug') };
  }

  fullId(id) {
    return String(id).startsWith(this.namespace + '.') ? String(id) : this.namespace + '.' + id;
  }

  async extendObject(id, obj) {
    const key = this.fullId(id);
    const existing = this.objects.get(key);
    const merged = {
      _id: key,
      type: obj.type || (existing && existing.type) || 'state',
      common: { ...(existing && existing.common), ...obj.common },
      native: { ...(existing && existing.native), ...obj.native },
    };
    this.objects.set(key, merged);
    return merged;
  }

  async extendObjectAsync(id, obj) {
    return this.extendObject(id, obj);
  }

  async setObjectNotExistsAsync(id, obj) {
    if (this.objects.has(this.fullId(id))) {
      return null;
    }
    return this.extendObject(id, obj);
  }

  /**
   * Enough of the real view for removeCollapsedValueChannels: the objects of one
   * type whose full id falls into the given key range.
   *
   * @param {string} design
   * @param {string} type
   * @param {{startkey: string, endkey: string}} params
   */
  async getObjectViewAsync(design, type, params) {
    const rows = [];
    for (const [id, object] of this.objects) {
      if (object.type === type && id >= params.startkey && id <= params.endkey) {
        rows.push({ id: id, value: object });
      }
    }
    return { rows: rows };
  }

  async getObjectAsync(id) {
    return this.objects.get(this.fullId(id)) || null;
  }

  async delObjectAsync(id, options) {
    const key = this.fullId(id);
    for (const stored of [...this.objects.keys()]) {
      if (stored === key || (options && options.recursive && stored.startsWith(key + '.'))) {
        this.objects.delete(stored);
        this.states.delete(stored);
      }
    }
  }

  /**
   * js-controller takes either a bare value or a state object, and the adapter uses
   * both: json2iob writes values, stampReportedTimestamps writes `{val, ack, ts}`.
   * A payload value is never an object with a `val` member, so telling the two apart
   * by that member is safe here.
   *
   * `lc` follows the real rule - it moves to `ts` when the value changes and is kept
   * otherwise - because that is what survives the parser writing the same value again.
   * ponytail: only states that were written with an explicit `ts` carry `ts`/`lc` at
   * all, so the plain `{val, ack}` assertions of the other tests stay readable. Give
   * every state a `ts` here if a test ever needs to compare write times.
   *
   * @param {string} id
   * @param {any} val
   * @param {any} ack
   */
  writeState(id, val, ack) {
    const key = this.fullId(id);
    const previous = this.states.get(key);
    if (val === null || typeof val !== 'object' || !('val' in val)) {
      const next = { val: val, ack: !!ack };
      if (previous && previous.lc !== undefined && previous.val === val) {
        /** @type {any} */ (next).lc = previous.lc;
      }
      this.states.set(key, next);
      return;
    }
    const ts = typeof val.ts === 'number' ? val.ts : Date.now();
    this.states.set(key, {
      val: val.val,
      ack: !!val.ack,
      ts: ts,
      lc: previous && previous.val === val.val && previous.lc !== undefined ? previous.lc : ts,
    });
  }

  async setStateAsync(id, val, ack) {
    this.writeState(id, val, ack);
  }

  setState(id, val, ack) {
    this.writeState(id, val, ack);
  }

  async setStateChangedAsync(id, val, ack) {
    const current = this.states.get(this.fullId(id));
    if (current && current.val === val && current.ack === !!ack) {
      return;
    }
    return this.setStateAsync(id, val, ack);
  }

  setStateChanged(id, val, ack) {
    const current = this.states.get(this.fullId(id));
    if (current && current.val === val && current.ack === !!ack) {
      return;
    }
    this.setState(id, val, ack);
  }

  async getStateAsync(id) {
    return this.states.get(this.fullId(id)) || null;
  }

  subscribeStates() {}

  // The adapter arms 20 s command refreshes and the poll interval. Recording the
  // timers instead of running them keeps the tests instant and deterministic.
  setTimeout(handler, ms) {
    const timer = { handler: handler, ms: ms };
    this.timers.push(timer);
    return timer;
  }

  clearTimeout(timer) {
    this.timers = this.timers.filter((entry) => entry !== timer);
  }
}

/**
 * Stand in for the `ws` client. main.js only opens a socket, listens and closes it,
 * so recording the calls and letting the test emit the events is enough to drive the
 * reconnect logic without a cloud connection.
 */
class FakeWebSocket extends EventEmitter {
  constructor(url, options) {
    super();
    this.url = url;
    this.options = options;
    this.closed = false;
    FakeWebSocket.created.push(this);
  }

  // The real client only emits `close` when the socket was not closed already.
  close() {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.emit('close');
  }
}
/** @type {FakeWebSocket[]} */
FakeWebSocket.created = [];

/**
 * Build an adapter instance of main.js that talks to the fixtures.
 *
 * @param {{routes?: Record<string, any>, config?: Record<string, any>, websocket?: boolean}} [options]
 */
function createTestAdapter(options = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'electrolux-aeg-test-'));
  const corePath = require.resolve('@iobroker/adapter-core');
  require.cache[corePath] = /** @type {any} */ ({
    id: corePath,
    filename: corePath,
    loaded: true,
    children: [],
    paths: [],
    exports: { Adapter: FakeAdapter, getAbsoluteInstanceDataDir: () => dataDir },
  });
  const wsPath = require.resolve('ws');
  require.cache[wsPath] = /** @type {any} */ ({ id: wsPath, filename: wsPath, loaded: true, children: [], paths: [], exports: FakeWebSocket });
  FakeWebSocket.created = [];
  delete require.cache[require.resolve('../main.js')];
  const createAdapter = require('../main.js');
  const adapter = createAdapter({});
  adapter.config = { type: 'aeg', username: 'user@example.com', password: 'secret', interval: 10, ...options.config };

  /** @type {Array<{method: string, url: string, data: any}>} */
  const requests = [];
  const routes = {
    'accounts.login': { sessionInfo: { sessionToken: 'gigya-token', sessionSecret: Buffer.from('secret').toString('base64') } },
    'accounts.getJWT': { id_token: 'jwt-token' },
    'authorization/api/v1/token': { accessToken: 'access-token', refreshToken: 'refresh-token', expiresIn: 3600 },
    'api-federation': { applianceDataResults: [status] },
    capabilities: capabilities,
    appliance: status,
    ...options.routes,
  };

  adapter.requestClient = (request) => {
    requests.push({ method: (request.method || 'get').toLowerCase(), url: request.url, data: request.data });
    for (const [fragment, response] of Object.entries(routes)) {
      if (!request.url.includes(fragment)) {
        continue;
      }
      if (response instanceof Error) {
        return Promise.reject(response);
      }
      return Promise.resolve({ status: 200, data: response });
    }
    return Promise.reject(new Error('unrouted request: ' + request.method + ' ' + request.url));
  };
  if (!options.websocket) {
    // The WebSocket is a live connection, not part of the replay.
    adapter.connectWebSocket = () => {};
  }

  return { adapter: adapter, requests: requests, dataDir: dataDir, sockets: FakeWebSocket.created };
}

module.exports = { createTestAdapter, FakeWebSocket, RAW_ID, SAFE_ID, status, capabilities };
