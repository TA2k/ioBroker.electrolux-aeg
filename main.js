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

const WebSocket = require('ws');
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
    this.ws = null;
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
      this.connectWebSocket();
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
      url: 'https://api.eu.ocp.electrolux.one/api-federation/api/v1/api-federation?includeApplianceInfo=true&includeProductCard=true&includeMetadata=true',
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
        res.data = res.data.applianceDataResults;
        /*
        [
  {
    applianceId: "x:x-x",
    applianceData: {
      applianceName: "x",
      created: "2024-07-21T10:56:47.334Z",
      modelName: "OV",
    },
    properties: {
      desired: {
      },
      reported: {
        doorState: "CLOSED",
        timeToEnd: -1,
        remoteControl: "NOT_SAFETY_RELEVANT_ENABLED",
        targetTemperatureF: 302,
        targetTemperatureC: 150,
        program: "TRUE_FAN",
        targetMicrowavePower: 65535,
        displayFoodProbeTemperatureC: -17.833333333333332,
        waterTrayInsertionState: "INSERTED",
        waterTankEmpty: "STEAM_TANK_FULL",
        targetDuration: 0,
        startTime: -1,
        applianceInfo: {
          applianceType: "OV",
        },
        displayFoodProbeTemperatureF: -0.1,
        targetFoodProbeTemperatureC: -17.833333333333332,
        targetFoodProbeTemperatureF: -0.1,
        runningTime: 0,
        applianceState: "READY_TO_START",
        alerts: [
        ],
        displayTemperatureC: 30,
        networkInterface: {
          swVersion: "v3.0.0S_argo",
          otaState: "IDLE",
          linkQualityIndicator: "EXCELLENT",
          niuSwUpdateCurrentDescription: "x-x",
          swAncAndRevision: "x",
        },
        foodProbeInsertionState: "NOT_INSERTED",
        displayTemperatureF: 86,
        cavityLight: false,
        processPhase: "NONE",
        connectivityState: "connected",
      },
      metadata: {
        connectivityState: {
          timestamp: 1729294062,
        },
        applianceInfo: {
          applianceType: {
            timestamp: 1729508665,
          },
        },
        doorState: {
          timestamp: 1729508659,
        },
        targetFoodProbeTemperatureC: {
          timestamp: 1729508663,
        },
        targetTemperatureF: {
          timestamp: 1729508659,
        },
        targetFoodProbeTemperatureF: {
          timestamp: 1729508663,
        },
        targetTemperatureC: {
          timestamp: 1729508659,
        },
        runningTime: {
          timestamp: 1729508653,
        },
        applianceState: {
          timestamp: 1729508653,
        },
        networkInterface: {
          swVersion: {
            timestamp: 1729294066,
          },
          otaState: {
            timestamp: 1729428649,
          },
          linkQualityIndicator: {
            timestamp: 1729294066,
          },
          niuSwUpdateCurrentDescription: {
            timestamp: 1729294066,
          },
          swAncAndRevision: {
            timestamp: 1729294066,
          },
        },
        foodProbeInsertionState: {
          timestamp: 1729508664,
        },
        cavityLight: {
          timestamp: 1729508660,
        },
        waterTrayInsertionState: {
          timestamp: 1729508662,
        },
        waterTankEmpty: {
          timestamp: 1729508661,
        },
        targetDuration: {
          timestamp: 1729508656,
        },
        startTime: {
          timestamp: 1729508655,
        },
        alerts: [
        ],
        remoteControl: {
          timestamp: 1729440371,
        },
        processPhase: {
          timestamp: 1729440788,
        },
        program: {
          timestamp: 1729436948,
        },
        targetMicrowavePower: {
          timestamp: 1729508665,
        },
        timeToEnd: {
          timeToEnd: {
            timestamp: 1729508654462,
          },
        },
        displayTemperatureC: {
          displayTemperatureC: {
            timestamp: 1729447800154,
          },
        },
        displayFoodProbeTemperatureC: {
          displayFoodProbeTemperatureC: {
            timestamp: 1729508663136,
          },
        },
        displayTemperatureF: {
          displayTemperatureF: {
            timestamp: 1729447800154,
          },
        },
        displayFoodProbeTemperatureF: {
          displayFoodProbeTemperatureF: {
            timestamp: 1729508663136,
          },
        },
      },
    },
    status: "enabled",
    connectionState: "connected",
  },
  {
    applianceId: "x:x-x",
    applianceData: {
      applianceName: "x x",
      created: "2024-07-17T18:38:22.529Z",
      modelName: "DW",
    },
    properties: {
      desired: {
      },
      reported: {
        waterHardness: "STEP_5",
        applianceInfo: {
          applianceType: "DW",
        },
        doorState: "OPEN",
        timeToEnd: 0,
        rinseAidLevel: 6,
        remoteControl: "NOT_SAFETY_RELEVANT_ENABLED",
        displayOnFloor: "GREEN",
        applianceState: "OFF",
        applianceMode: "NORMAL",
        totalCycleCounter: 84,
        alerts: [
          {
            severity: "WARNING",
            acknowledgeStatus: "NOT_NEEDED",
            code: "DISH_ALARM_SALT_MISSING",
          },
          {
            severity: "WARNING",
            acknowledgeStatus: "NOT_NEEDED",
            code: "DISH_ALARM_RINSE_AID_LOW",
          },
        ],
        cyclePhase: "UNAVAILABLE",
        keyTone: true,
        preSelectLast: false,
        applianceCareAndMaintenance0: {
        },
        networkInterface: {
          swVersion: "v3.0.0S_argo",
          otaState: "IDLE",
          linkQualityIndicator: "EXCELLENT",
          niuSwUpdateCurrentDescription: "x-x",
          swAncAndRevision: "x",
        },
        endOfCycleSound: "NO_SOUND",
        startTime: -1,
        miscellaneousState: {
          ecoMode: false,
        },
        userSelections: {
          extraPowerOption: false,
          energyScore: 1,
          sprayZoneOption: false,
          waterScore: 1,
          extraSilentOption: false,
          autoDoorOpener: true,
          sanitizeOption: false,
          ecoScore: 5,
          glassCareOption: false,
          programUID: "AUTO",
        },
        connectivityState: "disconnected",
      },
      metadata: {
        connectivityState: {
          timestamp: 1729497408,
        },
        waterHardness: {
          timestamp: 1729488348,
        },
        applianceInfo: {
          applianceType: {
            timestamp: 1729497318,
          },
        },
        doorState: {
          timestamp: 1729494677,
        },
        rinseAidLevel: {
          timestamp: 1729488349,
        },
        applianceState: {
          timestamp: 1729497318,
        },
        applianceMode: {
          timestamp: 1729488340,
        },
        keyTone: {
          timestamp: 1729488340,
        },
        preSelectLast: {
          timestamp: 1729488342,
        },
        applianceCareAndMaintenance0: {
        },
        networkInterface: {
          swVersion: {
            timestamp: 1729488340,
          },
          otaState: {
            timestamp: 1729488360,
          },
          linkQualityIndicator: {
            timestamp: 1729488340,
          },
          niuSwUpdateCurrentDescription: {
            timestamp: 1729488351,
          },
          swAncAndRevision: {
            timestamp: 1729488340,
          },
        },
        startTime: {
          timestamp: 1729488346,
        },
        miscellaneousState: {
          ecoMode: {
            timestamp: 1729488345,
          },
        },
        userSelections: {
          extraPowerOption: {
            timestamp: 1729488345,
          },
          energyScore: {
            timestamp: 1729488345,
          },
          sprayZoneOption: {
            timestamp: 1729488345,
          },
          waterScore: {
            timestamp: 1729488345,
          },
          extraSilentOption: {
            timestamp: 1729488345,
          },
          autoDoorOpener: {
            timestamp: 1729488345,
          },
          sanitizeOption: {
            timestamp: 1729488345,
          },
          ecoScore: {
            timestamp: 1729488345,
          },
          glassCareOption: {
            timestamp: 1729488345,
          },
          programUID: {
            timestamp: 1729488345,
          },
        },
        alerts: [
          {
            severity: {
              timestamp: 1729421135,
            },
            acknowledgeStatus: {
              timestamp: 1729421135,
            },
            code: {
              timestamp: 1729421135,
            },
          },
          {
            severity: {
              timestamp: 1729421135,
            },
            acknowledgeStatus: {
              timestamp: 1729421135,
            },
            code: {
              timestamp: 1729421135,
            },
          },
        ],
        cyclePhase: {
          timestamp: 1729497316,
        },
        remoteControl: {
          timestamp: 1729494687,
        },
        endOfCycleSound: {
          timestamp: 1729421135,
        },
        displayOnFloor: {
          timestamp: 1729421135,
        },
        totalCycleCounter: {
          timestamp: 1729421135,
        },
        timeToEnd: {
          timeToEnd: {
            timestamp: 1729497315596,
          },
        },
      },
    },
    status: "enabled",
    connectionState: "disconnected",
  },
  {
    applianceId: "x:x-x",
    applianceData: {
      applianceName: "x x",
      created: "2024-07-17T18:36:28.171Z",
      modelName: "DW",
    },
    properties: {
      desired: {
      },
      reported: {
        waterHardness: "STEP_5",
        applianceInfo: {
          applianceType: "DW",
        },
        doorState: "OPEN",
        timeToEnd: 0,
        rinseAidLevel: 6,
        remoteControl: "NOT_SAFETY_RELEVANT_ENABLED",
        displayOnFloor: "GREEN",
        applianceState: "OFF",
        applianceMode: "NORMAL",
        totalCycleCounter: 88,
        alerts: [
          {
            severity: "WARNING",
            acknowledgeStatus: "NOT_NEEDED",
            code: "DISH_ALARM_SALT_MISSING",
          },
          {
            severity: "WARNING",
            acknowledgeStatus: "NOT_NEEDED",
            code: "DISH_ALARM_RINSE_AID_LOW",
          },
        ],
        cyclePhase: "UNAVAILABLE",
        keyTone: true,
        preSelectLast: false,
        applianceCareAndMaintenance0: {
        },
        networkInterface: {
          swVersion: "v3.0.0S_argo",
          otaState: "IDLE",
          linkQualityIndicator: "EXCELLENT",
          niuSwUpdateCurrentDescription: "xx-xx",
          swAncAndRevision: "xx",
        },
        endOfCycleSound: "NO_SOUND",
        startTime: -1,
        miscellaneousState: {
          ecoMode: false,
        },
        userSelections: {
          extraPowerOption: true,
          energyScore: 1,
          sprayZoneOption: false,
          waterScore: 1,
          extraSilentOption: false,
          autoDoorOpener: true,
          sanitizeOption: true,
          ecoScore: 1,
          glassCareOption: false,
          programUID: "NORMAL90",
        },
        connectivityState: "disconnected",
      },
      metadata: {
        connectivityState: {
          timestamp: 1729450096,
        },
        waterHardness: {
          timestamp: 1729440471,
        },
        applianceInfo: {
          applianceType: {
            timestamp: 1729450006,
          },
        },
        doorState: {
          timestamp: 1729449463,
        },
        rinseAidLevel: {
          timestamp: 1729440471,
        },
        applianceState: {
          timestamp: 1729450006,
        },
        applianceMode: {
          timestamp: 1729440471,
        },
        keyTone: {
          timestamp: 1729440463,
        },
        preSelectLast: {
          timestamp: 1729440465,
        },
        applianceCareAndMaintenance0: {
        },
        networkInterface: {
          swVersion: {
            timestamp: 1729440463,
          },
          otaState: {
            timestamp: 1729440484,
          },
          linkQualityIndicator: {
            timestamp: 1729440463,
          },
          niuSwUpdateCurrentDescription: {
            timestamp: 1729440475,
          },
          swAncAndRevision: {
            timestamp: 1729440463,
          },
        },
        startTime: {
          timestamp: 1729440469,
        },
        miscellaneousState: {
          ecoMode: {
            timestamp: 1729440467,
          },
        },
        userSelections: {
          extraPowerOption: {
            timestamp: 1729440468,
          },
          energyScore: {
            timestamp: 1729440468,
          },
          sprayZoneOption: {
            timestamp: 1729440468,
          },
          waterScore: {
            timestamp: 1729440468,
          },
          extraSilentOption: {
            timestamp: 1729440468,
          },
          autoDoorOpener: {
            timestamp: 1729440468,
          },
          sanitizeOption: {
            timestamp: 1729440468,
          },
          ecoScore: {
            timestamp: 1729440468,
          },
          glassCareOption: {
            timestamp: 1729440468,
          },
          programUID: {
            timestamp: 1729440468,
          },
        },
        alerts: [
          {
            severity: {
              timestamp: 1729316810,
            },
            acknowledgeStatus: {
              timestamp: 1729316810,
            },
            code: {
              timestamp: 1729316810,
            },
          },
          {
            severity: {
              timestamp: 1729316810,
            },
            acknowledgeStatus: {
              timestamp: 1729316810,
            },
            code: {
              timestamp: 1729316810,
            },
          },
        ],
        cyclePhase: {
          timestamp: 1729450005,
        },
        remoteControl: {
          timestamp: 1729449473,
        },
        endOfCycleSound: {
          timestamp: 1729316810,
        },
        displayOnFloor: {
          timestamp: 1729316810,
        },
        totalCycleCounter: {
          timestamp: 1729316810,
        },
        timeToEnd: {
          timeToEnd: {
            timestamp: 1729450004604,
          },
        },
      },
    },
    status: "enabled",
    connectionState: "disconnected",
  },
]*/
        this.log.info('Found ' + res.data.length + ' devices');
        for (const device of res.data) {
          const id = device.applianceId;

          this.deviceArray.push(id);
          let name = id;
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

          this.json2iob.parse(id, device, { channelName: name });
          this.log.debug('Fetch capabilities for ' + id);
          await this.requestClient({
            method: 'get',
            url:
              'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/' +
              id +
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
              this.log.debug(JSON.stringify(res.data));

              if (!res.data) {
                return;
              }
              this.json2iob.parse(id + '.capabilities', res.data);
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
                this.extendObject(id + '.remote.' + remote.command, {
                  type: 'state',
                  common: {
                    name: remote.name || remote.command,
                    type: remote.type || 'boolean',
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
              error.response && this.log.debug(JSON.stringify(error.response.data));
            });
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
        path: 'states',
        desc: 'Interval Status',
        url: 'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/$id',
      },
    ];

    for (const id of this.deviceArray) {
      for (const element of statusArray) {
        const url = element.url.replace('$id', id);

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
          .then((res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            const data = res.data;

            const forceIndex = null;
            const preferedArrayName = null;

            this.json2iob.parse(id + '.' + element.path, data, {
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
  connectWebSocket() {
    if (this.ws) {
      this.ws.close();
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
    this.ws.on('message', (data, isBinary) => {
      const dataString = isBinary ? data : data.toString();
      this.log.debug(dataString);
      const json = JSON.parse(dataString);
      if (json.applianceId) {
        this.json2iob.parse(json.applianceId, json);
      }
      if (json.Payload && json.Payload.Appliances && json.Payload.Appliances) {
        for (const appliance of json.Payload.Appliances) {
          // for (const metric of appliance.Metrics) {
          this.json2iob.parse(appliance.ApplianceId + '.events', appliance.Metrics, { channelName: 'Live Events' });
          // }
        }
      }
    });
    this.ws.on('close', () => {
      this.log.info('WebSocket closed');
      // this.connectWebSocket();
    });
    this.ws.on('error', (error) => {
      this.log.error(error);
      this.log.info('Reconnect in 5 seconds');
      try {
        this.ws && this.ws.close();
        this.setTimeout(() => {
          // this.connectWebSocket();
        }, 5000);
      } catch (error) {
        this.log.error(error);
      }
    });
  }

  async refreshToken() {
    await this.requestClient({
      method: 'post',
      url: 'https://api.eu.ocp.electrolux.one/one-account-authorization/api/v1/token',
      headers: {
        'x-api-key': this.types[this.config.type]['x-api-key'],
        Authorization: 'Bearer',
        'User-Agent': 'Electrolux/2.17 android/13',
        Accept: 'application/json',
        'Accept-Charset': 'UTF-8',
        'Content-Type': 'application/json',
        Connection: 'Keep-Alive',
      },
      data: {
        grantType: 'refresh_token',
        clientId: 'ElxOneApp',
        refreshToken: this.session.refreshToken,
        scope: '',
      },
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        this.session = res.data;
        this.log.debug('Refresh Token successful');
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
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
        this.log.debug(JSON.stringify(res.data));
        this.log.info('Logout successful');
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
    // this.requestClient({
    //   method: 'post',
    //   maxBodyLength: Infinity,
    //   url: 'https://accounts.eu1.gigya.com/accounts.logout',
    //   headers: {
    //     connection: 'close',
    //     'Content-Type': 'application/x-www-form-urlencoded',
    //     'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 4a Build/TQ3A.230805.001.S1)',
    //   },
    //   data: {
    //     apiKey: this.types[this.config.type].apikey,
    //     format: 'json',
    //     gmid: ',
    //     httpStatusCodes: 'false',
    //     nonce: Date.now() + '_-844501876',
    //     sdk: 'Android_6.2.1',
    //     targetEnv: 'mobile',
    //     ucid: '',
    //   },
    // })
    //   .then((res) => {
    //     this.log.debug(JSON.stringify(res.data));
    //     this.log.info('Logout successful');
    //   })
    //   .catch((error) => {
    //     this.log.error(error);
    //     error.response && this.log.error(JSON.stringify(error.response.data));
    //   });
  }
  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.logout();
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);

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
        let data = {
          executeCommand: command,
        };
        if (command === 'CustomCommand') {
          try {
            data = JSON.parse(state.val);
          } catch (error) {
            this.log.error(error);
            return;
          }
        }

        await this.requestClient({
          method: 'put',
          maxBodyLength: Infinity,
          url:
            'https://api.eu.ocp.electrolux.one/appliance/api/v2/appliances/' + deviceId + '/command?brand=electrolux',
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
            this.log.debug(JSON.stringify(res.data));
          })
          .catch((error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });

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
