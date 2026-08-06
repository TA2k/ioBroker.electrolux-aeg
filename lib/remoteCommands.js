'use strict';

const { sanitizeObjectId } = require('./objectIds');

/**
 * Build the ioBroker state objects for the remote command channel.
 *
 * Command names come from the cloud API (`executeCommand.values`), so they are
 * untrusted input and must be sanitized before they are used as an object id.
 * The raw name is returned alongside the id, because the command sent back to
 * the API has to be the raw one.
 *
 * @param {Array<{command: string, name?: string, type?: string, role?: string, def?: any}>} remoteArray
 * @param {string} remotePath - object id of the remote channel, e.g. `<device>.remote`
 * @returns {{states: Array<{objectId: string, command: string, object: ioBroker.SettableStateObject}>, collisions: Array<{objectId: string, command: string, existing: string}>}}
 */
function buildRemoteStates(remoteArray, remotePath) {
  /** @type {Array<{objectId: string, command: string, object: ioBroker.SettableStateObject}>} */
  const states = [];
  /** @type {Array<{objectId: string, command: string, existing: string}>} */
  const collisions = [];
  /** @type {Map<string, string>} */
  const seen = new Map();

  for (const remote of remoteArray) {
    const objectId = remotePath + '.' + sanitizeObjectId(remote.command);
    const existing = seen.get(objectId);
    if (existing !== undefined) {
      if (existing !== remote.command) {
        collisions.push({ objectId, command: remote.command, existing });
      }
      continue;
    }
    seen.set(objectId, remote.command);

    const role = remote.role || 'button';
    states.push({
      objectId,
      command: remote.command,
      object: {
        type: 'state',
        common: {
          name: remote.name || remote.command,
          type: /** @type {ioBroker.CommonType} */ (remote.type || 'boolean'),
          role,
          def: remote.def == null ? false : remote.def,
          write: true,
          // States with role `button` are write-only per ioBroker state role spec.
          read: role !== 'button',
        },
        native: {},
      },
    });
  }

  return { states, collisions };
}

module.exports = {
  buildRemoteStates,
};
