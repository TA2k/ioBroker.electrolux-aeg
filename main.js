'use strict';

/*
 * Created with @iobroker/create-adapter v2.5.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const crypto = require('node:crypto');
const Json2iob = require('json2iob');

const WebSocket = require('ws');
const strictUriEncode = require('strict-uri-encode');
const alertLabels = require('./lib/alertLabels.json');
const { isTransientFetchError } = require('./lib/apiErrors');
const { getActiveAlerts, pickHighestSeverity } = require('./lib/alerts');
const { deriveStatus } = require('./lib/derived');
const { buildCapabilityStates, buildCommandPayload } = require('./lib/capabilities');
const { collectStateMeta } = require('./lib/stateMeta');
const { resolveRegionUrls, DEFAULT_URLS, GLOBAL_API_URL } = require('./lib/regionUrls');
const { loadSession, saveSession, clearSession } = require('./lib/sessionStore');
const { FORBIDDEN_CHARS, sanitizeJsonKeys, sanitizeObjectId, stringifyRedactedData } = require('./lib/objectIds');
const { buildRemoteStates } = require('./lib/remoteCommands');

const REQUEST_TIMEOUT_MS = 30 * 1000;
const LOGOUT_TIMEOUT_MS = 2 * 1000;
const MAX_UPDATE_INTERVAL_MINUTES = 24 * 60;

class ElectroluxAeg extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'electrolux-aeg',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.deviceArray = []; // Raw appliance IDs for API calls.
    this.deviceIdMap = {}; // Sanitized ioBroker ID -> raw appliance ID.
    this.commandIdMap = {}; // Full remote state ID -> raw API command name.
    this.derivedState = {}; // Sanitized ioBroker ID -> last derived status, for edge detection.
    this.capabilityIdMap = {}; // Full control state ID -> {container, key, kind, constValue}.
    this.controlStates = {}; // Sanitized ioBroker ID -> readable control states of that device.
    this.stateMetaDone = new Set(); // Object ids that already received role and unit.
    this.urls = { ...DEFAULT_URLS }; // Regional endpoints, replaced by the identity provider lookup.
    this.regionGigyaApiKey = null; // Gigya api key reported for the account region.
    this.FORBIDDEN_CHARS = FORBIDDEN_CHARS;
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create({ timeout: REQUEST_TIMEOUT_MS });
    /** @type {ioBroker.Timeout | null | undefined} */
    this.updateInterval = null;
    /** @type {ioBroker.Timeout | null | undefined} */
    this.refreshTokenTimeout = null;
    /** @type {ioBroker.Timeout | null | undefined} */
    this.refreshTimeout = null;
    /** @type {ioBroker.Timeout | null | undefined} */
    this.reLoginTimeout = null;
    /** @type {ioBroker.Timeout | null | undefined} */
    this.reconnectWebSocketTimeout = null;
    this.suppressNextWebSocketReconnect = false;
    this.unloading = false;
    this.session = {};
    this.ws = null;
    this.types = {
      electrolux: {
        apikey: '4_JZvZObbVWc1YROHF9e6y8A',
        clientId: 'ElxOneApp',
        'x-api-key': '2AMqwEV5MqVhTKrRCyYfVF8gmKrd2rAmp7cUsfky',
      },
      aeg: {
        apikey: '4_A4U-T1cdVL3JjsFffdPnUg',
        clientId: 'AEGOneApp',
        'x-api-key': 'UcGF9pmUMKUqBL6qcQvTu4K4WBmQ5KJqJXprCTdc',
      },
    };
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setStateChanged('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (this.config.interval > MAX_UPDATE_INTERVAL_MINUTES) {
      this.log.info('Set interval to maximum ' + MAX_UPDATE_INTERVAL_MINUTES);
      this.config.interval = MAX_UPDATE_INTERVAL_MINUTES;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error('Please set username and password in the instance settings');
      return;
    }

    this.subscribeStates('*');

    await this.resolveRegion();
    await this.restoreSession();
    if (!this.session.accessToken) {
      await this.login();
    }

    if (this.session.accessToken) {
      await this.getDeviceList();
      await this.updateDevices();
      this.scheduleUpdateDevices();
      this.connectWebSocket();
      this.scheduleRefreshToken();
    }
  }

  scheduleUpdateDevices() {
    if (this.unloading) {
      return;
    }
    if (this.updateInterval) {
      this.clearTimeout(this.updateInterval);
    }
    this.updateInterval = this.setTimeout(async () => {
      try {
        await this.updateDevices();
      } finally {
        this.scheduleUpdateDevices();
      }
    }, this.config.interval * 60 * 1000);
  }

  scheduleRefreshToken() {
    if (this.refreshTokenTimeout) {
      this.clearTimeout(this.refreshTokenTimeout);
    }
    // Refresh five minutes before the access token expires; fall back to 30 minutes
    // if the server did not advertise an expires_in.
    const fallbackTimeout = 30 * 60 * 1000;
    const expiresIn = Number(this.session.expiresIn);
    const expireTimeout = Number.isFinite(expiresIn) && expiresIn > 0
      ? Math.max(60 * 1000, expiresIn * 1000 - 5 * 60 * 1000)
      : fallbackTimeout;
    this.refreshTokenTimeout = this.setTimeout(async () => {
      await this.refreshToken();
    }, expireTimeout);
  }

  sanitizeObjectId(id) {
    return sanitizeObjectId(id);
  }

  sanitizeJsonKeys(value) {
    return sanitizeJsonKeys(value);
  }

  parseJson(path, data, options) {
    return this.json2iob.parse(this.sanitizeObjectId(path), this.sanitizeJsonKeys(data), options);
  }

  logDebugData(data) {
    this.log.debug(stringifyRedactedData(data));
  }

  async removeOldDeviceObject(rawId, safeId) {
    if (rawId === safeId) {
      return;
    }
    const oldObject = await this.getObjectAsync(rawId);
    if (!oldObject) {
      return;
    }
    await this.delObjectAsync(rawId, { recursive: true });
    this.log.warn('Migrated object id "' + rawId + '" to "' + safeId + '". Please update scripts, aliases and history settings.');
  }

  /**
   * Up to 0.0.14 the WebSocket wrote its payload to `<device>.properties.*` while
   * polling wrote the same values to `<device>.status.properties.*`. Both paths
   * now write to `.status`, so drop the duplicated tree once.
   *
   * @param {string} id - sanitized ioBroker device id
   */
  async removeLegacyWebSocketTree(id) {
    const oldObject = await this.getObjectAsync(id + '.properties');
    if (!oldObject) {
      return;
    }
    await this.delObjectAsync(id + '.properties', { recursive: true });
    this.log.warn(
      'Removed the duplicated WebSocket state tree "' +
        id +
        '.properties". These values now live under "' +
        id +
        '.status". Please update scripts, aliases and history settings.',
    );
  }

  createSignature(secret, method, url, parameters) {
    const parameterNames = Object.keys(parameters)
      .sort()
      .map((key) => `${key}=${strictUriEncode(parameters[key])}`)
      .join('&');

    const postData = [method.toUpperCase(), strictUriEncode(url), strictUriEncode(parameterNames)].join('&');

    const key = Buffer.from(secret, 'base64');
    const payload = Buffer.from(postData, 'utf-8');
    const signature = crypto.createHmac('sha1', key).update(payload).digest('base64');
    return signature;
  }

  /**
   * The OCP token endpoint returns snake_case fields (access_token, refresh_token, expires_in).
   * Expose camelCase aliases so the rest of the adapter can keep using session.accessToken etc.
   * @param {any} raw
   * @returns {any}
   */
  normalizeSession(raw) {
    if (!raw || typeof raw !== 'object') {
      return raw;
    }
    if (raw.access_token && !raw.accessToken) {
      raw.accessToken = raw.access_token;
    }
    if (raw.refresh_token && !raw.refreshToken) {
      raw.refreshToken = raw.refresh_token;
    }
    if (raw.expires_in && !raw.expiresIn) {
      raw.expiresIn = raw.expires_in;
    }
    return raw;
  }

  /**
   * Extract sanitized alert entries from the reported state.
   * @param {any} data
   * @returns {Array<{code: string, severity: string, acknowledgeStatus: string, label: string}>}
   */
  getActiveAlerts(data) {
    return getActiveAlerts(data, alertLabels);
  }

  /**
   * @param {string} id
   * @param {any} data
   */
  async updateActiveAlerts(id, data) {
    const active = this.getActiveAlerts(data);
    const codes = active.map((a) => a.code);
    const labels = active.map((a) => a.label);
    const highest = pickHighestSeverity(active);

    await this.extendObject(id + '.status.activeAlertCodes', {
      type: 'state',
      common: {
        name: 'Active alert codes (comma separated)',
        type: 'string',
        role: 'text',
        read: true,
        write: false,
        def: '',
      },
      native: {},
    });
    await this.extendObject(id + '.status.activeAlertLabels', {
      type: 'state',
      common: {
        name: 'Active alert labels (human readable, comma separated)',
        type: 'string',
        role: 'text',
        read: true,
        write: false,
        def: '',
      },
      native: {},
    });
    await this.extendObject(id + '.status.activeAlerts', {
      type: 'state',
      common: {
        name: 'Active alerts (JSON)',
        type: 'string',
        role: 'json',
        read: true,
        write: false,
        def: '[]',
      },
      native: {},
    });
    await this.extendObject(id + '.status.activeAlertCount', {
      type: 'state',
      common: {
        name: 'Number of active alerts',
        type: 'number',
        role: 'value',
        read: true,
        write: false,
        def: 0,
      },
      native: {},
    });
    await this.extendObject(id + '.status.activeAlertSeverity', {
      type: 'state',
      common: {
        name: 'Highest active alert severity',
        type: 'string',
        role: 'text',
        read: true,
        write: false,
        def: '',
      },
      native: {},
    });

    await this.setStateChangedAsync(id + '.status.activeAlertCodes', codes.join(','), true);
    await this.setStateChangedAsync(id + '.status.activeAlertLabels', labels.join(', '), true);
    await this.setStateChangedAsync(id + '.status.activeAlerts', JSON.stringify(active), true);
    await this.setStateChangedAsync(id + '.status.activeAlertCount', active.length, true);
    await this.setStateChangedAsync(id + '.status.activeAlertSeverity', highest, true);
  }

  /**
   * Create a writable state for every writable capability of an appliance.
   *
   * The states live in a separate `control` channel, so the existing `remote`
   * channel with its buttons and the CustomCommand escape hatch stays untouched.
   *
   * @param {string} id - sanitized ioBroker device id
   * @param {any} capabilities - `/capabilities` response
   */
  async createControlStates(id, capabilities) {
    const { states, skipped, collisions } = buildCapabilityStates(capabilities, id + '.control');
    if (!states.length) {
      return;
    }
    await this.extendObject(id + '.control', {
      type: 'channel',
      common: {
        name: 'Writable appliance settings',
      },
      native: {},
    });
    for (const collision of collisions) {
      this.log.warn(
        'Capability "' +
          collision.name +
          '" maps to the same object id as "' +
          collision.existing +
          '" (' +
          collision.objectId +
          ') and was skipped',
      );
    }
    for (const name of skipped) {
      this.log.debug('Capability "' + name + '" is nested deeper than expected and was skipped');
    }
    for (const state of states) {
      this.capabilityIdMap[this.namespace + '.' + state.objectId] = {
        container: state.container,
        key: state.key,
        kind: state.kind,
        constValue: state.constValue,
      };
      await this.extendObject(state.objectId, state.object);
    }
    // Keep the readable control states around, so their value can be mirrored from
    // the reported state - otherwise they would go stale as soon as somebody
    // changes a setting on the appliance itself.
    this.controlStates[id] = states.filter((state) => state.kind !== 'const');
    this.log.debug('Created ' + states.length + ' control states for ' + id);
  }

  /**
   * Warn when the appliance is known to have remote control switched off.
   *
   * Most appliances only accept commands after remote control was armed on the
   * device itself. Without this the command is simply swallowed by the cloud and
   * the log shows nothing. Only clearly negative values are reported, so an
   * unknown vocabulary does not produce false warnings - the value is logged
   * with it.
   *
   * @param {string} safeDeviceId - sanitized ioBroker device id
   */
  async warnIfRemoteControlDisabled(safeDeviceId) {
    const state = await this.getStateAsync(safeDeviceId + '.status.properties.reported.remoteControl');
    if (!state || state.val === undefined || state.val === null) {
      return;
    }
    const value = state.val;
    const disabled =
      value === false ||
      ['DISABLED', 'OFF', 'NOT_ENABLED', 'FALSE', 'TEMPORARY_LOCKED'].includes(String(value).toUpperCase());
    if (disabled) {
      this.log.warn(
        'Remote control of ' +
          safeDeviceId +
          ' reports "' +
          value +
          '". The appliance will most likely ignore this command until remote start is armed on the device itself.',
      );
    }
  }

  /**
   * Send a command payload to an appliance.
   *
   * @param {string} deviceId - raw appliance id
   * @param {any} data - command payload
   * @returns {Promise<boolean>} true when the cloud accepted the command
   */
  async sendCommand(deviceId, data) {
    return await this.requestClient({
      method: 'put',
      maxBodyLength: Infinity,
      url:
        this.urls.api + '/appliance/api/v2/appliances/' +
        deviceId +
        '/command?brand=' +
        (this.config.type === 'aeg' ? 'aeg' : 'electrolux'),
      headers: {
        Authorization: 'Bearer ' + this.session.accessToken,
        'x-api-key': this.types[this.config.type]['x-api-key'],
        'User-Agent': 'Electrolux/3.2 android/9',
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/json',
        Connection: 'Keep-Alive',
      },
      data: data,
    })
      .then((res) => {
        this.logDebugData(res.data);
        return true;
      })
      .catch((error) => {
        this.log.error("Couldn't send command");
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
        return false;
      });
  }

  /**
   * Single write path for appliance status data. Polling and the WebSocket both
   * go through here, so both produce the same object tree.
   *
   * @param {string} id - sanitized ioBroker device id
   * @param {any} data - appliance payload
   */
  async applyStatus(id, data) {
    await this.parseJson(id + '.status', data, { channelName: 'Interval Status' });
    // WebSocket messages can be partial updates. Only touch the alert states when
    // the payload actually carries an `alerts` key, otherwise a delta without
    // alerts would clear the active alert summary.
    if (data && data.properties && data.properties.reported && data.properties.reported.alerts !== undefined) {
      await this.updateActiveAlerts(id, data);
    }
    await this.applyStateMeta(id, data);
    await this.updateDerivedStates(id, data);
    await this.syncControlStates(id, data);
  }

  /**
   * Add role and unit to the reported states that the adapter knows about.
   *
   * `json2iob` only knows the data type, so without this every value stays a
   * plain `value` state without a unit and the ioBroker type detector, VIS and
   * the history adapters cannot make sense of it. Runs once per state per
   * adapter start, the object does not change afterwards.
   *
   * @param {string} id - sanitized ioBroker device id
   * @param {any} data - appliance payload
   */
  async applyStateMeta(id, data) {
    for (const meta of collectStateMeta(data)) {
      const objectId =
        id + '.status.properties.reported.' + meta.path.map((part) => this.sanitizeObjectId(part)).join('.');
      if (this.stateMetaDone.has(objectId)) {
        continue;
      }
      this.stateMetaDone.add(objectId);
      const object = await this.getObjectAsync(objectId);
      if (!object || object.type !== 'state') {
        continue;
      }
      // A model may report a known capability in another shape. Leave those alone
      // instead of labelling a string as a temperature.
      if (object.common.type !== meta.type) {
        this.log.debug(
          'Skipped metadata for ' + objectId + ': expected type ' + meta.type + ', found ' + object.common.type,
        );
        continue;
      }
      await this.extendObject(objectId, { common: meta.common });
    }
  }

  /**
   * Mirror the reported values into the writable control states, so they show what
   * the appliance actually uses and not only what was written last.
   *
   * @param {string} id - sanitized ioBroker device id
   * @param {any} data - appliance payload
   */
  async syncControlStates(id, data) {
    const states = this.controlStates[id];
    const reported = data && data.properties && data.properties.reported;
    if (!states || !reported) {
      return;
    }
    for (const state of states) {
      const source = state.container ? reported[state.container] : reported;
      if (!source || typeof source !== 'object') {
        continue;
      }
      const value = source[state.key];
      if (value === undefined || value === null) {
        continue;
      }
      const mirrored = state.kind === 'onoff' ? String(value).toUpperCase() === 'ON' : value;
      await this.setStateChangedAsync(state.objectId, mirrored, true);
    }
  }

  /**
   * Create and update the convenience states (`running`, `timeToEndMinutes`,
   * `finishTime`, `cycleFinished`) derived from the raw payload.
   *
   * @param {string} id - sanitized ioBroker device id
   * @param {any} data - appliance payload
   */
  async updateDerivedStates(id, data) {
    if (!this.derivedState[id]) {
      // Restore the previous cycle state after an adapter restart, otherwise the
      // first payload after a restart would look like a fresh program end.
      const running = await this.getStateAsync(id + '.status.running');
      const finishTime = await this.getStateAsync(id + '.status.finishTime');
      this.derivedState[id] = {
        running: !!(running && running.val),
        finishTime: finishTime && typeof finishTime.val === 'string' ? finishTime.val : null,
      };
    }

    const derived = deriveStatus(data, this.derivedState[id]);
    if (!derived) {
      return;
    }

    await this.extendObject(id + '.status.running', {
      type: 'state',
      common: {
        name: 'A program is currently in progress',
        type: 'boolean',
        role: 'indicator.working',
        read: true,
        write: false,
        def: false,
      },
      native: {},
    });
    await this.extendObject(id + '.status.timeToEndMinutes', {
      type: 'state',
      common: {
        name: 'Remaining program time',
        type: 'number',
        role: 'value.interval',
        unit: 'min',
        read: true,
        write: false,
      },
      native: {},
    });
    await this.extendObject(id + '.status.finishTime', {
      type: 'state',
      common: {
        name: 'Estimated end of the running program (ISO 8601)',
        type: 'string',
        role: 'value.datetime',
        read: true,
        write: false,
      },
      native: {},
    });
    await this.extendObject(id + '.status.cycleFinished', {
      type: 'state',
      common: {
        name: 'True for the update in which a program finished',
        type: 'boolean',
        role: 'indicator',
        read: true,
        write: false,
        def: false,
      },
      native: {},
    });

    await this.setStateChangedAsync(id + '.status.running', derived.running, true);
    await this.setStateChangedAsync(id + '.status.timeToEndMinutes', derived.timeToEndMinutes, true);
    await this.setStateChangedAsync(id + '.status.finishTime', derived.finishTime, true);
    await this.setStateChangedAsync(id + '.status.cycleFinished', derived.cycleFinished, true);

    this.derivedState[id] = derived;
  }

  /**
   * Directory for adapter owned files of this instance.
   *
   * @returns {string}
   */
  dataDir() {
    return utils.getAbsoluteInstanceDataDir(this);
  }

  /**
   * Persist the refresh token, so a restart does not need a new Gigya login.
   * Repeated logins are what runs an account into the cloud's rate limit.
   *
   * @returns {boolean} true when the token was stored
   */
  storeSession() {
    const stored = saveSession(this.dataDir(), this.session);
    if (!stored) {
      this.log.debug('Could not store the session, the next start will log in again');
    }
    return stored;
  }

  /**
   * Try to continue the session of the previous adapter run.
   */
  async restoreSession() {
    const stored = loadSession(this.dataDir());
    if (!stored) {
      return;
    }

    // Use the stored access token while it is still good for a few minutes. A
    // refresh right after a restart is what the cloud answers with 429.
    const remaining = stored.expiresAt - Date.now();
    if (stored.accessToken && remaining > 5 * 60 * 1000) {
      this.session = {
        accessToken: stored.accessToken,
        refreshToken: stored.refreshToken,
        expiresIn: Math.floor(remaining / 1000),
      };
      this.log.info('Continued the stored session, the access token is valid for ' + Math.round(remaining / 60000) + ' more minutes');
      return;
    }

    this.session = { refreshToken: stored.refreshToken };
    // The appliance list is not known yet, so the caller connects the websocket.
    const result = await this.refreshToken({ reconnect: false });
    if (this.session.accessToken) {
      this.log.info('Continued the stored session without a new login');
      return;
    }
    // Only a rejected token is a dead token. A rate limit or a network problem
    // must not throw away a session that is still valid.
    if (result.status === 400 || result.status === 401) {
      this.log.info('The stored session was rejected, logging in again');
      clearSession(this.dataDir());
    } else {
      this.log.info('Could not reuse the stored session (' + result.status + '), logging in again and keeping it');
    }
    this.session = {};
  }

  /**
   * Gigya api key for the login. The identity provider lookup reports the key of
   * the account region; the built in key is the European one.
   *
   * @returns {string}
   */
  gigyaApiKey() {
    return this.regionGigyaApiKey || this.types[this.config.type].apikey;
  }

  /**
   * Ask the cloud where the account lives and switch to the endpoints of that
   * region. Every failure keeps the European endpoints, which is what the
   * adapter used before, so a lookup problem cannot break a working setup.
   */
  async resolveRegion() {
    const brand = this.config.type === 'aeg' ? 'aeg' : 'electrolux';
    await this.requestClient({
      method: 'get',
      url:
        GLOBAL_API_URL +
        '/one-account-user/api/v1/identity-providers?brand=' +
        brand +
        '&email=' +
        encodeURIComponent(this.config.username),
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        'Context-Brand': brand,
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'Ktor client',
      },
    })
      .then((res) => {
        this.logDebugData(res.data);
        const region = resolveRegionUrls(res.data, brand);
        this.urls = { gigya: region.gigya, api: region.api, ws: region.ws };
        this.regionGigyaApiKey = region.gigyaApiKey;
        this.log.info('Using the ' + (region.dataCenter || 'EU') + ' region at ' + region.api);
      })
      .catch((error) => {
        // Non EU accounts are the reason this lookup exists. If it keeps failing,
        // the response is what the adapter needs to support the other regions.
        this.log.info(
          'Could not look up the account region (' +
            (error.response ? error.response.status : error.message) +
            '), continuing with the European endpoints',
        );
        error.response && this.log.debug(stringifyRedactedData(error.response.data));
      });
  }

  async login() {
    const loginResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: this.urls.gigya + '/accounts.login',
      headers: {
        connection: 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: {
        apiKey: this.gigyaApiKey(),
        format: 'json',
        httpStatusCodes: 'true',
        loginID: this.config.username,
        nonce: Date.now(),
        password: this.config.password,
        sdk: 'Android_6.2.1',
        targetEnv: 'mobile',
      },
    })
      .then((res) => {
        this.logDebugData(res.data);
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
      });
    if (!loginResponse) {
      this.log.error('Login failed #1');
      this.setStateChanged('info.connection', false, true);

      return;
    }

    const data = {
      apiKey: this.gigyaApiKey(),
      fields: 'country',
      format: 'json',
      httpStatusCodes: 'true',
      nonce: Date.now(),
      oauth_token: loginResponse.sessionInfo.sessionToken,
      sdk: 'Android_6.2.1',
      targetEnv: 'mobile',
      timestamp: Date.now(),
    };
    data.sig = this.createSignature(
      loginResponse.sessionInfo.sessionSecret,
      'POST',
      this.urls.gigya + '/accounts.getJWT',
      data,
    );

    const jwt = await this.requestClient({
      method: 'post',
      url: this.urls.gigya + '/accounts.getJWT',
      headers: {
        connection: 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: data,
    })
      .then((res) => {
        this.logDebugData(res.data);
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
      });
    if (!jwt) {
      this.log.error('Login failed #2');
      this.setState('info.connection', false, true);
      return;
    }
    await this.requestClient({
      method: 'post',
      url: this.urls.api + '/one-account-authorization/api/v1/token',
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer',
        'Origin-Country-Code': 'DE',
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'Ktor client',
        'Content-Type': 'application/x-www-form-urlencoded',
        Connection: 'Keep-Alive',
      },
      data: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: this.types[this.config.type].clientId,
        id_token: jwt.id_token,
        scope: '',
      }).toString(),
    })
      .then((res) => {
        this.logDebugData(res.data);
        this.session = this.normalizeSession(res.data);
        this.log.info('Login successful');
        this.storeSession();
        this.setStateChanged('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
      });
  }

  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      url:
        this.urls.api +
        '/api-federation/api/v2/api-federation?includeApplianceInfo=true&includeProductCard=true&includeOcpAppliances=true',
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer ' + this.session.accessToken,
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'Ktor client',
        Connection: 'Keep-Alive',
      },
    })
      .then(async (res) => {
        this.logDebugData(res.data);
        res.data = res.data.applianceDataResults;

        this.log.info('Found ' + res.data.length + ' devices');
        for (const device of res.data) {
          const rawId = device.applianceId;
          const id = this.sanitizeObjectId(rawId);

          this.deviceArray.push(rawId);
          this.deviceIdMap[id] = rawId;
          let name = rawId;
          if (device.applianceData && device.applianceData.applianceName) {
            name = device.applianceData.applianceName;
          }
          await this.extendObject(id, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.extendObject(id + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });
          await this.removeOldDeviceObject(rawId, id);
          await this.removeLegacyWebSocketTree(id);

          await this.applyStatus(id, device);
          this.log.debug('Fetch capabilities for ' + id);
          await this.requestClient({
            method: 'get',
            url:
              this.urls.api + '/appliance/api/v2/appliances/' +
              rawId +
              '/capabilities?includeConstants=true',
            headers: {
              'x-api-key': this.types[this.config.type]['x-api-key'],
              Authorization: 'Bearer ' + this.session.accessToken,
              Accept: 'application/json',
              'Accept-Charset': 'UTF-8',
              'User-Agent': 'Ktor client',
              Connection: 'Keep-Alive',
            },
          })
            .then(async (res) => {
              this.logDebugData(res.data);

              if (!res.data) {
                return;
              }
              await this.parseJson(id + '.capabilities', res.data);
              const remoteArray = [
                { command: 'Refresh', name: 'True = Refresh' },
                {
                  command: 'CustomCommand',
                  name: 'Send Custom Command',
                  type: 'string',
                  role: 'json',
                  def: `{
    "userSelections": {
        "programUID": "QUICK_20_MIN_PR_20MIN3KG",
        "analogTemperature": "30_CELSIUS",
        "analogSpinSpeed": "1200_RPM",
        "EWX1493A_anticreaseNoSteam": false,
        "EWX1493A_anticreaseWSteam": false,
        "EWX1493A_nightCycle": false,
        "EWX1493A_pod": false,
        "EWX1493A_preWashPhase": false,
        "EWX1493A_rinseHold": false,
        "EWX1493A_stain": false,
        "EWX1493A_tcSensor": false,
        "EWX1493A_wmEconomy": false,
        "extraRinseNumber": "NONE",
        "steamValue": "STEAM_OFF",
        "timeManagerLevel": "NORMAL"
    }
}`,
                },
              ];
              // Not every appliance exposes executeCommand; the control states below
              // must still be created for those.
              const executeCommand = (res.data.executeCommand && res.data.executeCommand.values) || {};
              for (const command in executeCommand) {
                remoteArray.push({ command: command, name: command });
              }
              const { states, collisions } = buildRemoteStates(remoteArray, id + '.remote');
              for (const collision of collisions) {
                this.log.warn(
                  'Remote command "' +
                    collision.command +
                    '" maps to the same object id as "' +
                    collision.existing +
                    '" (' +
                    collision.objectId +
                    ') and was skipped',
                );
              }
              for (const state of states) {
                this.commandIdMap[this.namespace + '.' + state.objectId] = state.command;
                await this.extendObject(state.objectId, state.object);
              }
              await this.createControlStates(id, res.data);
            })
            .catch((error) => {
              this.log.info('Capabilities for ' + id + ' not found');
              error.response && this.log.debug(stringifyRedactedData(error.response.data));
            });
        }
      })
      .catch((error) => {
        this.log.error('Get Device List failed');
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
      });
  }
  async updateDevices() {
    const statusArray = [
      {
        path: 'status',
        desc: 'Interval Status',
        url: this.urls.api + '/appliance/api/v2/appliances/$id',
      },
    ];

    for (const rawId of this.deviceArray) {
      const id = this.sanitizeObjectId(rawId);
      for (const element of statusArray) {
        const url = element.url.replace('$id', rawId);

        await this.requestClient({
          method: element.method || 'get',
          url: url,
          headers: {
            'x-api-key': this.types[this.config.type]['x-api-key'],
            Authorization: 'Bearer ' + this.session.accessToken,
            Accept: 'application/json',
            'Accept-Charset': 'UTF-8',
            'User-Agent': 'Ktor client',
            Connection: 'Keep-Alive',
          },
        })
          .then(async (res) => {
            this.logDebugData(res.data);
            if (!res.data) {
              return;
            }
            await this.applyStatus(id, res.data);
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(stringifyRedactedData(error.response.data));
                this.log.info(element.path + ' receive 401 error. Refresh Token in 60 seconds');
                this.refreshTokenTimeout && this.clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = this.setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }
            }

            if (isTransientFetchError(error)) {
              const status = error.response?.status || error.code || error.message;
              this.log.warn('Temporary API fetch failed for ' + url + ': ' + status);
              error.response && this.log.debug(stringifyRedactedData(error.response.data));
              return;
            }

            this.log.error('Failed to fetch: ' + url);
            this.log.error(error);
            error.response && this.log.error(stringifyRedactedData(error.response.data));
          });
      }
    }
  }
  connectWebSocket() {
    if (this.reconnectWebSocketTimeout) {
      this.clearTimeout(this.reconnectWebSocketTimeout);
      this.reconnectWebSocketTimeout = null;
    }
    if (this.ws) {
      this.suppressNextWebSocketReconnect = true;
      try {
        this.ws.close();
      } catch (e) {
        this.log.debug('ws.close() failed: ' + e);
      }
    }
    const applianceIds = [];
    for (const id of this.deviceArray) {
      applianceIds.push({ applianceId: id });
    }
    this.ws = new WebSocket(this.urls.ws + '/', {
      perMessageDeflate: false,

      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer ' + this.session.accessToken,
        appliances: JSON.stringify(applianceIds),

        version: '2',
        Upgrade: 'websocket',
        Connection: 'Upgrade',
        'User-Agent': 'okhttp/4.10.0',
      },
    });
    this.ws.on('open', () => {
      this.log.info('WebSocket connected');
    });
    this.ws.on('message', async (data, isBinary) => {
      const dataString = isBinary ? data : data.toString();
      let json;
      try {
        json = JSON.parse(dataString);
      } catch (error) {
        this.log.error('Could not parse WebSocket message');
        this.log.error(error);
        return;
      }
      this.logDebugData(json);
      if (json.applianceId) {
        await this.applyStatus(this.sanitizeObjectId(json.applianceId), json);
      }
      if (json.Payload && json.Payload.Appliances && json.Payload.Appliances) {
        for (const appliance of json.Payload.Appliances) {
          await this.parseJson(appliance.ApplianceId + '.events', appliance.Metrics, { channelName: 'Live Events' });
        }
      }
    });
    this.ws.on('close', () => {
      this.log.info('WebSocket closed');
      if (this.suppressNextWebSocketReconnect) {
        this.suppressNextWebSocketReconnect = false;
        return;
      }
      this.scheduleWebSocketReconnect();
    });
    this.ws.on('error', (error) => {
      this.log.error(error);
      try {
        this.ws && this.ws.close();
      } catch (e) {
        this.log.debug('ws.close() failed: ' + e);
      }
      this.scheduleWebSocketReconnect();
    });
  }

  scheduleWebSocketReconnect() {
    if (this.unloading || !this.session.accessToken) {
      return;
    }
    if (this.reconnectWebSocketTimeout) {
      this.clearTimeout(this.reconnectWebSocketTimeout);
    }
    this.log.info('Reconnect WebSocket in 5 seconds');
    this.reconnectWebSocketTimeout = this.setTimeout(() => {
      this.connectWebSocket();
    }, 5000);
  }

  /**
   * @param {{reconnect?: boolean}} [options] - set `reconnect: false` during startup,
   * where the appliance list is not known yet and the caller connects itself
   */
  async refreshToken(options = {}) {
    const reconnect = options.reconnect !== false;
    return await this.requestClient({
      method: 'post',
      url: this.urls.api + '/one-account-authorization/api/v1/token',
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer',
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'User-Agent': 'Ktor client',
        'Content-Type': 'application/x-www-form-urlencoded',
        Connection: 'Keep-Alive',
      },
      data: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.types[this.config.type].clientId,
        refresh_token: this.session.refreshToken,
        scope: '',
      }).toString(),
    })
      .then((res) => {
        this.logDebugData(res.data);
        this.session = this.normalizeSession(res.data);
        this.log.debug('Refresh Token successful');
        this.storeSession();
        if (reconnect) {
          // Reconnect the websocket with the new access token and reschedule the next refresh.
          this.connectWebSocket();
          this.scheduleRefreshToken();
        }
        return { ok: true, status: res.status };
      })
      .catch((error) => {
        this.log.error('Refresh Token failed');
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
        this.setStateChanged('info.connection', false, true);
        return { ok: false, status: error.response ? error.response.status : error.code || 'error' };
      });
  }

  async logout() {
    if (!this.session) {
      return;
    }
    await this.requestClient({
      method: 'post',
      // Shorter than the default timeout: logout runs during unload, which js-controller
      // aborts after stopTimeout (3 s).
      timeout: LOGOUT_TIMEOUT_MS,
      url: this.urls.api + '/one-account-authorization/api/v1/token/revoke',
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer ' + this.session.accessToken,
        'User-Agent': 'Electrolux/2.17 android/13',
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/json',
        Connection: 'Keep-Alive',
      },
      data: {
        token: this.session.refreshToken,
        revokeAll: false,
      },
    })
      .then((res) => {
        this.logDebugData(res.data);
        this.log.info('Logout successful');
      })
      .catch((error) => {
        this.log.error('Logout failed');
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
      });
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  async onUnload(callback) {
    try {
      this.unloading = true;
      this.setStateChanged('info.connection', false, true);
      // Stop all timers and the socket before the logout request, so nothing can
      // rearm itself while the request is still in flight.
      this.refreshTimeout && this.clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && this.clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && this.clearTimeout(this.refreshTokenTimeout);
      this.reconnectWebSocketTimeout && this.clearTimeout(this.reconnectWebSocketTimeout);
      this.updateInterval && this.clearTimeout(this.updateInterval);
      if (this.ws) {
        try {
          this.ws.close();
        } catch (e) {
          this.log.debug('ws.close() failed: ' + e);
        }
      }
      // Keep the session for the next start. Revoking it here would force a fresh
      // Gigya login on every restart, which is what runs an account into the
      // cloud's rate limit. Only hand the token back when it cannot be stored.
      if (!this.storeSession()) {
        await this.logout();
      }

      callback();
    } catch (e) {
      this.log.error('Error onUnload: ' + e);
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const safeDeviceId = id.split('.')[2];
        const deviceId = this.deviceIdMap[safeDeviceId] || safeDeviceId;
        const capability = this.capabilityIdMap[id];
        if (!capability && id.split('.')[3] !== 'remote') {
          return;
        }
        this.log.debug(deviceId);

        /** @type {any} */
        let data;
        if (capability) {
          let programUID;
          if (capability.container === 'userSelections') {
            const program = await this.getStateAsync(
              safeDeviceId + '.status.properties.reported.userSelections.programUID',
            );
            programUID = program ? program.val : undefined;
            if (!programUID) {
              this.log.debug('No programUID known for ' + safeDeviceId + ', sending the change without it');
            }
          }
          data = buildCommandPayload(capability, state.val, programUID);
        } else {
          // The object id segment is sanitized; the API expects the raw command name.
          const command = this.commandIdMap[id] || id.split('.')[4];

          if (command === 'Refresh') {
            this.updateDevices();
            return;
          }
          data = { executeCommand: command };
          if (command === 'CustomCommand') {
            try {
              data = JSON.parse(String(state.val));
            } catch (error) {
              this.log.error(error);
              return;
            }
          }
        }

        await this.warnIfRemoteControlDisabled(safeDeviceId);
        const accepted = await this.sendCommand(deviceId, data);
        if (accepted && capability && capability.kind !== 'const') {
          await this.setStateAsync(id, state.val, true);
        }

        if (this.refreshTimeout) {
          this.clearTimeout(this.refreshTimeout);
        }
        this.refreshTimeout = this.setTimeout(async () => {
          await this.updateDevices();
        }, 20 * 1000);
      }
    }
  }
}

if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new ElectroluxAeg(options);
  module.exports.sanitizeObjectId = sanitizeObjectId;
  module.exports.sanitizeJsonKeys = sanitizeJsonKeys;
  module.exports.stringifyRedactedData = stringifyRedactedData;
} else {
  // otherwise start the instance directly
  new ElectroluxAeg();
}
