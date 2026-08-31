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

module.exports = {
  collectStateMeta,
  STATE_META,
};
