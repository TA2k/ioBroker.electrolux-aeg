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
const { FORBIDDEN_CHARS, sanitizeJsonKeys, sanitizeObjectId, stringifyRedactedData } = require('./lib/objectIds');

const REQUEST_TIMEOUT_MS = 30 * 1000;
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

    await this.login();

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

  async login() {
    const loginResponse = await this.requestClient({
      method: 'post',
      maxBodyLength: Infinity,
      url: 'https://accounts.eu1.gigya.com/accounts.login',
      headers: {
        connection: 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: {
        apiKey: this.types[this.config.type].apikey,
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
      apiKey: this.types[this.config.type].apikey,
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
      'https://accounts.eu1.gigya.com/accounts.getJWT',
      data,
    );

    const jwt = await this.requestClient({
      method: 'post',
      url: 'https://accounts.eu1.gigya.com/accounts.getJWT',
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
      url: 'https://api.eu.ocp.electrolux.one/one-account-authorization/api/v1/token',
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
      url: 'https://api.eu.ocp.electrolux.one/api-federation/api/v2/api-federation?includeApplianceInfo=true&includeProductCard=true&includeOcpAppliances=true',
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

          await this.parseJson(id + '.status', device, { channelName: 'Interval Status' });
          await this.updateActiveAlerts(id, device);
          this.log.debug('Fetch capabilities for ' + id);
          await this.requestClient({
            method: 'get',
            url:
              'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/' +
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
              const executeCommand = res.data.executeCommand.values;
              for (const command in executeCommand) {
                remoteArray.push({ command: command, name: command });
              }
              for (const remote of remoteArray) {
                await this.extendObject(id + '.remote.' + remote.command, {
                  type: 'state',
                  common: {
                    name: remote.name || remote.command,
                    type: /** @type {ioBroker.CommonType} */ (remote.type || 'boolean'),
                    role: remote.role || 'button',
                    def: remote.def == null ? false : remote.def,
                    write: true,
                    read: true,
                  },
                  native: {},
                });
              }
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
        url: 'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/$id',
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
            const data = res.data;

            const forceIndex = undefined;
            const preferedArrayName = undefined;

            await this.parseJson(id + '.' + element.path, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
            await this.updateActiveAlerts(id, data);
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
    this.ws = new WebSocket('https://ws.eu.ocp.electrolux.one/', {
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
      this.log.debug(dataString);
      let json;
      try {
        json = JSON.parse(dataString);
      } catch (error) {
        this.log.error('Could not parse WebSocket message');
        this.log.error(error);
        return;
      }
      if (json.applianceId) {
        await this.parseJson(json.applianceId, json);
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

  async refreshToken() {
    await this.requestClient({
      method: 'post',
      url: 'https://api.eu.ocp.electrolux.one/one-account-authorization/api/v1/token',
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
        // Reconnect the websocket with the new access token and reschedule the next refresh.
        this.connectWebSocket();
        this.scheduleRefreshToken();
      })
      .catch((error) => {
        this.log.error('Refresh Token failed');
        this.log.error(error);
        error.response && this.log.error(stringifyRedactedData(error.response.data));
        this.setStateChanged('info.connection', false, true);
      });
  }

  async logout() {
    if (!this.session) {
      return;
    }
    this.requestClient({
      method: 'post',
      url: 'https://api.eu.ocp.electrolux.one/one-account-authorization/api/v1/token/revoke',
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
  onUnload(callback) {
    try {
      this.unloading = true;
      this.setStateChanged('info.connection', false, true);
      this.logout();
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
        const command = id.split('.')[4];
        if (id.split('.')[3] !== 'remote') {
          return;
        }

        if (command === 'Refresh') {
          this.updateDevices();
          return;
        }
        this.log.debug(deviceId);
        let data = {
          executeCommand: command,
        };
        if (command === 'CustomCommand') {
          try {
            data = JSON.parse(String(state.val));
          } catch (error) {
            this.log.error(error);
            return;
          }
        }

        await this.requestClient({
          method: 'put',
          maxBodyLength: Infinity,
          url:
            'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/' +
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
          })
          .catch((error) => {
            this.log.error("Couldn't send command");
            this.log.error(error);
            error.response && this.log.error(stringifyRedactedData(error.response.data));
          });

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
