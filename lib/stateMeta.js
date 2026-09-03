'use strict';

const SECONDS = { role: 'value.interval', unit: 's', type: 'number' };
const CELSIUS = { role: 'value.temperature', unit: '°C', type: 'number' };
const PERCENT = { role: 'value.humidity', unit: '%', type: 'number' };
const FAHRENHEIT = { role: 'value.temperature', unit: '°F', type: 'number' };
const CONCENTRATION = { role: 'value', unit: 'µg/m³', type: 'number' };
const TEXT = { role: 'text', type: 'string' };

/**
 * Roles and units for the reported values the adapter knows about.
 *
 * `json2iob` can only derive the data type from the payload, so every value ends
 * up as a plain `value` state without a unit. This table adds the missing
 * metadata for the well known capabilities, which is what the ioBroker type
 * detector, VIS and the history adapters look at.
 *
 * Entries are keyed by the reported capability name. An entry is only applied
 * when the existing state has the expected type, so a model that reports a
 * capability in another shape is left alone instead of being mislabelled.
 */
const STATE_META = {
  // Washing machines, dryers, dishwashers, ovens
  timeToEnd: SECONDS,
  runningTime: SECONDS,
  startTime: SECONDS,
  totalWashingTime: SECONDS,
  applianceTotalWorkingTime: SECONDS,
  fastModeTimeToEnd: SECONDS,
  airFilterLifeTime: SECONDS,
  waterFilterLifeTime: SECONDS,
  totalCycleCounter: { role: 'value', type: 'number' },
  applianceState: TEXT,
  cyclePhase: TEXT,
  cycleSubPhase: TEXT,
  ovenProcessIdentifier: TEXT,
  remoteControl: TEXT,

  // Ovens
  targetDuration: SECONDS,
  processPhase: TEXT,
  program: TEXT,

  // Temperatures
  targetTemperatureC: CELSIUS,
  ambientTemperatureC: CELSIUS,
  defrostTemperature: CELSIUS,
  displayTemperatureC: CELSIUS,
  displayFoodProbeTemperature: CELSIUS,
  displayFoodProbeTemperatureC: CELSIUS,
  targetFoodProbeTemperatureC: CELSIUS,
  sensorTemperature: CELSIUS,
  Temp: CELSIUS,
  targetTemperatureF: FAHRENHEIT,
  displayTemperatureF: FAHRENHEIT,
  displayFoodProbeTemperatureF: FAHRENHEIT,
  targetFoodProbeTemperatureF: FAHRENHEIT,

  // Air treatment
  sensorHumidity: PERCENT,
  Humidity: PERCENT,
  FilterLife: { role: 'value', unit: '%', type: 'number' },
  PM1: CONCENTRATION,
  PM2_5: CONCENTRATION,
  PM10: CONCENTRATION,
  TVOC: { role: 'value', unit: 'ppb', type: 'number' },
  ECO2: { role: 'value.co2', unit: 'ppm', type: 'number' },
};

/**
 * Collect the metadata that applies to a reported payload.
 *
 * Looks at the reported values and one level of containers, which is as deep as
 * the documented capability schema goes.
 *
 * @param {any} data - appliance payload
 * @returns {Array<{path: string[], type: string, common: {role: string, unit?: string}}>}
 */
function collectStateMeta(data) {
  const reported = data && data.properties && data.properties.reported;
  if (!reported || typeof reported !== 'object') {
    return [];
  }

  /** @type {Array<{path: string[], type: string, common: {role: string, unit?: string}}>} */
  const result = [];

  /**
   * @param {string} key
   * @param {string[]} path
   */
  const add = (key, path) => {
    const meta = STATE_META[key];
    if (!meta) {
      return;
    }
    const common = meta.unit ? { role: meta.role, unit: meta.unit } : { role: meta.role };
    result.push({ path: path, type: meta.type, common: common });
  };

  for (const [key, value] of Object.entries(reported)) {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const subKey of Object.keys(value)) {
        add(subKey, [key, subKey]);
      }
      continue;
    }
    add(key, [key]);
  }

  return result;
}

/**
 * Read the shadow timestamp of one metadata node, in milliseconds.
 *
 * Two shapes appear in the same payload: most leaves are `<key>: {timestamp}` and
 * count in seconds, while `displayTemperatureC`, `displayTemperatureF` and
 * `timeToEnd` repeat their own key one level deeper (`<key>: {<key>: {timestamp}}`)
 * and count in milliseconds. Anything else is ignored rather than guessed at.
 *
 * @param {any} node - metadata node belonging to a reported value
 * @param {string} key - name of that reported value
 * @returns {number|null}
 */
function readShadowTimestamp(node, key) {
  if (!node || typeof node !== 'object') {
    return null;
  }
  const leaf = typeof node.timestamp === 'number' ? node : node[key];
  const raw = leaf && typeof leaf.timestamp === 'number' ? leaf.timestamp : null;
  if (raw === null || !Number.isFinite(raw) || raw <= 0) {
    return null;
  }
  // Seconds became milliseconds in 2001, so anything below that is a second count.
  return raw > 1e12 ? raw : raw * 1000;
}

/**
 * Pair every reported value with the moment the appliance last changed it.
 *
 * The shadow's `metadata` mirrors `reported` and hangs a timestamp on every leaf.
 * That is the timestamp ioBroker wants as `ts` after a restart: polling alone
 * would stamp everything with the start time, so a change that happened while the
 * adapter was down would look like it happened at startup.
 *
 * Only scalar values are paired. An array such as `alerts` has no single value to
 * write, and the alert summary states cover it.
 *
 * @param {any} data - appliance payload
 * @returns {Array<{path: string[], value: string|number|boolean|null, ts: number}>}
 */
function collectShadowTimestamps(data) {
  const properties = data && data.properties;
  const reported = properties && properties.reported;
  const metadata = properties && properties.metadata;
  if (!reported || typeof reported !== 'object' || !metadata || typeof metadata !== 'object') {
    return [];
  }

  /** @type {Array<{path: string[], value: string|number|boolean|null, ts: number}>} */
  const result = [];

  /**
   * @param {string[]} path
   * @param {any} value
   * @param {any} node
   */
  const add = (path, value, node) => {
    if (value !== null && typeof value === 'object') {
      return;
    }
    const ts = readShadowTimestamp(node, path[path.length - 1]);
    if (ts !== null) {
      result.push({ path: path, value: value, ts: ts });
    }
  };

  for (const [key, value] of Object.entries(reported)) {
    const node = metadata[key];
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const [subKey, subValue] of Object.entries(value)) {
        add([key, subKey], subValue, node && node[subKey]);
      }
      continue;
    }
    add([key], value, node);
  }

  return result;
}

module.exports = {
  collectStateMeta,
  collectShadowTimestamps,
  STATE_META,
};
