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

function getActiveAlerts(data) {
  const alerts = data && data.properties && data.properties.reported && data.properties.reported.alerts;
  if (!Array.isArray(alerts)) {
    return [];
  }
  return alerts
    .filter((alert) => alert && typeof alert === 'object')
    .map((alert) => ({
      severity: typeof alert.severity === 'string' ? alert.severity : '',
      acknowledgeStatus: typeof alert.acknowledgeStatus === 'string' ? alert.acknowledgeStatus : '',
      code: typeof alert.code === 'string' ? alert.code : '',
    }))
    .filter((alert) => alert.code);
}

function getActiveAlertCodes(data) {
  return getActiveAlerts(data)
    .map((alert) => alert.code)
    .join(',');
}

module.exports = {
  getActiveAlertCodes,
  getActiveAlerts,
  getCommandBrand,
  parseRemoteStateId,
};
