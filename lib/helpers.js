'use strict';

function parseRemoteStateId(id) {
  const stateParts = id.split('.');
  const remoteIndex = stateParts.indexOf('remote');
  if (remoteIndex < 0 || remoteIndex < 3 || remoteIndex === stateParts.length - 1) {
    return null;
  }
  return {
    deviceId: stateParts.slice(2, remoteIndex).join('.'),
    command: stateParts.slice(remoteIndex + 1).join('.'),
  };
}

function getCommandBrand(type) {
  return type === 'aeg' ? 'aeg' : 'electrolux';
}

module.exports = {
  getCommandBrand,
  parseRemoteStateId,
};
