'use strict';

/*
 * Created with @iobroker/create-adapter v2.5.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const crypto = require('crypto');
const Json2iob = require('json2iob');
const strictUriEncode = require('strict-uri-encode');

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
    this.deviceArray = [];
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create();
    this.types = {
      electrolux: {
        apikey: '4_JZvZObbVWc1YROHF9e6y8A',
        clientId: 'ElxOneApp',
        'x-api-key': 'UcGF9pmUMKUqBL6qcQvTu4K4WBmQ5KJqJXprCTdc',
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
    this.setState('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error('Please set username and password in the instance settings');
      return;
    }

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates('*');

    await this.login();

    if (this.session.accessToken) {
      await this.getDeviceList();
      await this.updateDevices();
      this.updateInterval = setInterval(
        async () => {
          await this.updateDevices();
        },
        this.config.interval * 60 * 1000,
      );
    }
    let expireTimeout = 30 * 60 * 60 * 1000;
    if (this.session.expiresIn) {
      expireTimeout = this.session.expiresIn * 1000;
    }
    this.refreshTokenInterval = setInterval(() => {
      this.refreshToken();
    }, expireTimeout);
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
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    if (!loginResponse) {
      this.log.error('Login failed #1');
      this.setState('info.connection', false, true);

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
        this.log.debug(JSON.stringify(res.data));
        return res.data;
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
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
        'Content-Type': 'application/json',
        Connection: 'Keep-Alive',
      },
      data: {
        grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
        clientId: this.types[this.config.type].clientId,
        idToken: jwt.id_token,
        scope: '',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = res.data;
        this.log.info('Login successful');
        this.setState('info.connection', true, true);
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList() {
    await this.requestClient({
      method: 'get',
      url: 'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances?includeMetadata=true',
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
        this.log.debug(JSON.stringify(res.data));
        this.log.info('Found ' + res.data.length + ' devices');
        for (const device of res.data) {
          const id = device.applianceId;

          this.deviceArray.push(id);
          const name = id;

          await this.setObjectNotExistsAsync(id, {
            type: 'device',
            common: {
              name: name,
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + '.remote', {
            type: 'channel',
            common: {
              name: 'Remote Controls',
            },
            native: {},
          });
          await this.setObjectNotExistsAsync(id + '.json', {
            type: 'state',
            common: {
              name: 'Raw JSON',
              write: false,
              read: true,
              type: 'string',
              role: 'json',
            },
            native: {},
          });

          const remoteArray = [{ command: 'Refresh', name: 'True = Refresh' }];
          remoteArray.forEach((remote) => {
            this.setObjectNotExists(id + '.remote.' + remote.command, {
              type: 'state',
              common: {
                name: remote.name || '',
                type: remote.type || 'boolean',
                role: remote.role || 'boolean',
                def: remote.def || false,
                write: true,
                read: true,
              },
              native: {},
            });
          });
          this.json2iob.parse(id, device);
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async updateDevices() {
    const statusArray = [
      {
        path: '',
        url: '',
        desc: 'Graph data of the device',
      },
    ];

    for (const id of this.deviceArray) {
      for (const element of statusArray) {
        const url = element.url.replace('$id', id);

        await this.requestClient({
          method: element.method || 'get',
          url: url,
          headers: {
            accept: '*/*',
            'content-type': 'application/json',
            'user-agent': '',
            authorization: 'Bearer ' + this.session.accessToken,
            'accept-language': 'de-de',
          },
        })
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data;

            const forceIndex = true;
            const preferedArrayName = null;

            this.setState(id + '.json', JSON.stringify(data), true);
            this.json2iob.parse(id, data, {
              forceIndex: forceIndex,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401 error. Refresh Token in 60 seconds');
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }
            }
            this.log.error(url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }

  async refreshToken() {
    await this.login();
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
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
        const deviceId = id.split('.')[2];
        const command = id.split('.')[4];
        if (id.split('.')[3] !== 'remote') {
          return;
        }

        if (command === 'Refresh') {
          this.updateDevices();
          return;
        }
        this.log.debug(deviceId);

        clearTimeout(this.refreshTimeout);
        this.refreshTimeout = setTimeout(async () => {
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
} else {
  // otherwise start the instance directly
  new ElectroluxAeg();
}
