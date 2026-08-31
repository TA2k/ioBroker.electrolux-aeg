'use strict';

const { sanitizeObjectId } = require('./objectIds');
const { STATE_META } = require('./stateMeta');

/**
 * Capabilities that are handled elsewhere and must not become control states.
 * `executeCommand` is turned into buttons by `lib/remoteCommands.js`.
 */
const IGNORED_CAPABILITIES = new Set(['executeCommand']);

/**
 * Containers that are never turned into control states.
 *
 * `networkInterface` carries the connectivity commands of the appliance, among
 * them `startUpCommand: {UNINSTALL}`, which unregisters the appliance from the
 * account. None of that belongs on a button in a home automation tree.
 */
const IGNORED_CONTAINERS = new Set(['networkInterface']);

const NUMBER_TYPES = new Set(['number', 'int', 'temperature']);

function isLeaf(value) {
  return !!value && typeof value === 'object' && typeof value.access === 'string' && typeof value.type === 'string';
}

function isOnOff(values) {
  const keys = Object.keys(values || {});
  return keys.length === 2 && keys.every((key) => ['ON', 'OFF'].includes(String(key).toUpperCase()));
}

/**
 * Translate a single capability definition into the common part of an ioBroker
 * state object.
 *
 * The cloud describes every capability with `access` (read / readwrite / write /
 * constant), `type` (string, int, number, temperature, boolean, alert) and
 * optionally a `values` map or `min` / `max` / `step`. Read-only and constant
 * capabilities are skipped: they already appear in the status tree.
 *
 * @param {string} key - capability name
 * @param {string|null} container - parent capability name, e.g. `userSelections`
 * @param {any} definition - capability definition
 * @returns {{kind: string, constValue?: string, common: Record<string, any>}|null}
 */
function describeCapability(key, container, definition) {
  const access = definition.access;
  if (access !== 'readwrite' && access !== 'write') {
    return null;
  }
  const type = definition.type;
  if (type === 'alert') {
    return null;
  }
  const values = definition.values && typeof definition.values === 'object' ? definition.values : null;
  const valueKeys = values ? Object.keys(values) : [];
  const name = container ? container + ' ' + key : key;
  const readable = access !== 'write';

  // A write-only capability with a single value is a trigger, not a choice.
  if (access === 'write' && valueKeys.length === 1) {
    return {
      kind: 'const',
      constValue: valueKeys[0],
      // States with role `button` are write-only per ioBroker state role spec.
      common: { name: name, type: 'boolean', role: 'button', def: false, read: false, write: true },
    };
  }

  if (values && isOnOff(values)) {
    return {
      kind: 'onoff',
      common: { name: name, type: 'boolean', role: 'switch', read: readable, write: true },
    };
  }

  if (valueKeys.length > 0) {
    /** @type {Record<string, string>} */
    const states = {};
    for (const value of valueKeys) {
      states[value] = value;
    }
    return {
      kind: 'plain',
      common: { name: name, type: 'string', role: 'level.mode', states: states, read: readable, write: true },
    };
  }

  if (NUMBER_TYPES.has(type)) {
    /** @type {Record<string, any>} */
    const common = {
      name: name,
      type: 'number',
      role: type === 'temperature' ? 'level.temperature' : 'level',
      read: readable,
      write: true,
    };
    if (typeof definition.min === 'number') {
      common.min = definition.min;
    }
    if (typeof definition.max === 'number') {
      common.max = definition.max;
    }
    if (typeof definition.step === 'number') {
      common.step = definition.step;
    }
    if (type === 'temperature') {
      common.unit = '°C';
    } else if (STATE_META[key] && STATE_META[key].unit && STATE_META[key].type === 'number') {
      // A writable duration is the same quantity as the reported one, so it gets
      // the same unit instead of being a bare number.
      common.unit = STATE_META[key].unit;
    }
    return { kind: 'plain', common: common };
  }

  if (type === 'boolean') {
    return {
      kind: 'plain',
      common: { name: name, type: 'boolean', role: 'switch', read: readable, write: true },
    };
  }

  if (type === 'string') {
    return {
      kind: 'plain',
      common: { name: name, type: 'string', role: 'text', read: readable, write: true },
    };
  }

  return null;
}

/**
 * Build the control states for every writable capability of an appliance.
 *
 * Capability names come from the cloud, so they are untrusted input and are
 * sanitized before use as an object id. The raw container / key pair is kept,
 * because the command payload has to use the raw names.
 *
 * @param {any} capabilities - `/capabilities` response
 * @param {string} controlPath - object id of the control channel, e.g. `<device>.control`
 * @returns {{states: Array<{objectId: string, container: string|null, key: string, kind: string, constValue?: string, object: ioBroker.SettableStateObject}>, skipped: string[], collisions: Array<{objectId: string, name: string, existing: string}>}}
 */
function buildCapabilityStates(capabilities, controlPath) {
  /** @type {Array<{objectId: string, container: string|null, key: string, kind: string, constValue?: string, object: ioBroker.SettableStateObject}>} */
  const states = [];
  /** @type {string[]} */
  const skipped = [];
  /** @type {Array<{objectId: string, name: string, existing: string}>} */
  const collisions = [];
  /** @type {Map<string, string>} */
  const seen = new Map();

  if (!capabilities || typeof capabilities !== 'object') {
    return { states, skipped, collisions };
  }

  /**
   * @param {string} key
   * @param {string|null} container
   * @param {any} definition
   */
  const add = (key, container, definition) => {
    if (IGNORED_CAPABILITIES.has(key)) {
      return;
    }
    const described = describeCapability(key, container, definition);
    if (!described) {
      return;
    }
    const fullName = container ? container + '/' + key : key;
    const objectId = controlPath + '.' + sanitizeObjectId(container ? container + '_' + key : key);
    const existing = seen.get(objectId);
    if (existing !== undefined) {
      if (existing !== fullName) {
        collisions.push({ objectId: objectId, name: fullName, existing: existing });
      }
      return;
    }
    seen.set(objectId, fullName);
    states.push({
      objectId: objectId,
      container: container,
      key: key,
      kind: described.kind,
      constValue: described.constValue,
      object: {
        type: 'state',
        common: /** @type {ioBroker.StateCommon} */ (described.common),
        native: {},
      },
    });
  };

  for (const [key, value] of Object.entries(capabilities)) {
    if (isLeaf(value)) {
      add(key, null, value);
      continue;
    }
    if (!value || typeof value !== 'object' || IGNORED_CONTAINERS.has(key)) {
      continue;
    }
    for (const [subKey, subValue] of Object.entries(value)) {
      if (isLeaf(subValue)) {
        add(subKey, key, subValue);
      } else if (subValue && typeof subValue === 'object') {
        // Deeper nesting is not part of the documented schema. Report it instead
        // of guessing a command payload for it.
        skipped.push(key + '/' + subKey);
      }
    }
  }

  return { states, skipped, collisions };
}

/**
 * Build the command payload for a control state write.
 *
 * The cloud expects `{key: value}` for a top level capability and
 * `{container: {key: value}}` for a nested one. `userSelections` additionally
 * requires the currently selected program, otherwise the command is discarded.
 *
 * @param {{container: string|null, key: string, kind: string, constValue?: string}} meta
 * @param {any} value - value written to the ioBroker state
 * @param {any} [programUID] - current `userSelections.programUID`
 * @returns {any}
 */
function buildCommandPayload(meta, value, programUID) {
  let payload = value;
  if (meta.kind === 'onoff') {
    payload = value ? 'ON' : 'OFF';
  } else if (meta.kind === 'const') {
    payload = meta.constValue;
  }

  if (!meta.container) {
    return { [meta.key]: payload };
  }
  if (meta.container === 'userSelections') {
    const selections = programUID ? { programUID: programUID } : {};
    return { userSelections: { ...selections, [meta.key]: payload } };
  }
  return { [meta.container]: { [meta.key]: payload } };
}

module.exports = {
  buildCapabilityStates,
  buildCommandPayload,
};
