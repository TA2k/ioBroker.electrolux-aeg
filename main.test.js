'use strict';

const { expect } = require('chai');
const { getActiveAlertCodes, getActiveAlerts } = require('./lib/helpers');

describe('alert summary helpers', () => {
  it('extracts active alert codes from appliance status', () => {
    const data = {
      properties: {
        reported: {
          alerts: [
            {
              severity: 'WARNING',
              acknowledgeStatus: 'NOT_NEEDED',
              code: 'WM_AUTODOSE_TANK_LOW',
            },
            {
              severity: 'WARNING',
              acknowledgeStatus: 'NOT_NEEDED',
              code: 'WM_AUTODOSE_SOFTENER_LOW',
            },
          ],
        },
      },
    };

    expect(getActiveAlertCodes(data)).to.equal('WM_AUTODOSE_TANK_LOW,WM_AUTODOSE_SOFTENER_LOW');
  });

  it('keeps alert details as json friendly objects', () => {
    const data = {
      properties: {
        reported: {
          alerts: [
            {
              severity: 'WARNING',
              acknowledgeStatus: 'NOT_NEEDED',
              code: 'WM_AUTODOSE_TANK_LOW',
            },
          ],
        },
      },
    };

    expect(getActiveAlerts(data)).to.deep.equal([
      {
        severity: 'WARNING',
        acknowledgeStatus: 'NOT_NEEDED',
        code: 'WM_AUTODOSE_TANK_LOW',
      },
    ]);
  });

  it('returns empty summaries when alerts are missing', () => {
    expect(getActiveAlertCodes({})).to.equal('');
    expect(getActiveAlerts({})).to.deep.equal([]);
  });
});
