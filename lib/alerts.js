'use strict';

/**
 * Convert a raw appliance status payload (`data.properties.reported.alerts`)
 * into a normalized list of `{code, severity, acknowledgeStatus, label}` objects.
 * Filters out non-object entries and entries without a string `code`.
 *
 * @param {any} data
 * @param {Record<string, string>} [labels] - code -> human-readable label map
 * @returns {Array<{code: string, severity: string, acknowledgeStatus: string, label: string}>}
 */
function getActiveAlerts(data, labels = {}) {
  const alerts = data && data.properties && data.properties.reported && data.properties.reported.alerts;
  if (!Array.isArray(alerts)) {
    return [];
  }
  return alerts
    .filter((alert) => alert && typeof alert === 'object')
    .map((alert) => {
      const code = typeof alert.code === 'string' ? alert.code : '';
      return {
        code,
        severity: typeof alert.severity === 'string' ? alert.severity : '',
        acknowledgeStatus: typeof alert.acknowledgeStatus === 'string' ? alert.acknowledgeStatus : '',
        label: labels[code] || code,
      };
    })
    .filter((alert) => alert.code);
}

/**
 * Pick the most relevant severity from a list of alerts. ERROR > WARNING > INFO,
 * with any other non-empty severity used as fallback when none of those match.
 *
 * @param {Array<{severity: string}>} alerts
 * @returns {string}
 */
function pickHighestSeverity(alerts) {
  const severities = alerts.map((a) => a.severity).filter(Boolean);
  for (const sev of ['ERROR', 'WARNING', 'INFO']) {
    if (severities.includes(sev)) {
      return sev;
    }
  }
  return severities[0] || '';
}

module.exports = {
  getActiveAlerts,
  pickHighestSeverity,
};
