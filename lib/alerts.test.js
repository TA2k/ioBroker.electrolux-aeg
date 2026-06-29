'use strict';

const { expect } = require('chai');
const { getActiveAlerts, pickHighestSeverity } = require('./alerts');

describe('lib/alerts', () => {
  describe('getActiveAlerts', () => {
    it('returns empty array when alerts are missing or wrong type', () => {
      expect(getActiveAlerts(undefined)).to.deep.equal([]);
      expect(getActiveAlerts({})).to.deep.equal([]);
      expect(getActiveAlerts({ properties: {} })).to.deep.equal([]);
      expect(getActiveAlerts({ properties: { reported: {} } })).to.deep.equal([]);
      expect(getActiveAlerts({ properties: { reported: { alerts: 'oops' } } })).to.deep.equal([]);
    });

    it('extracts code, severity, acknowledgeStatus and applies labels', () => {
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
      const labels = {
        WM_AUTODOSE_TANK_LOW: 'Autodose tank low',
        WM_AUTODOSE_SOFTENER_LOW: 'Low softener',
      };
      expect(getActiveAlerts(data, labels)).to.deep.equal([
        {
          code: 'WM_AUTODOSE_TANK_LOW',
          severity: 'WARNING',
          acknowledgeStatus: 'NOT_NEEDED',
          label: 'Autodose tank low',
        },
        {
          code: 'WM_AUTODOSE_SOFTENER_LOW',
          severity: 'WARNING',
          acknowledgeStatus: 'NOT_NEEDED',
          label: 'Low softener',
        },
      ]);
    });

    it('falls back to raw code when no label is mapped', () => {
      const data = {
        properties: {
          reported: {
            alerts: [{ code: 'UNKNOWN_NEW_CODE', severity: 'INFO', acknowledgeStatus: '' }],
          },
        },
      };
      const [first] = getActiveAlerts(data);
      expect(first.label).to.equal('UNKNOWN_NEW_CODE');
    });

    it('drops entries without a string code', () => {
      const data = {
        properties: {
          reported: {
            alerts: [
              null,
              { severity: 'WARNING' },
              { code: 42 },
              { code: 'GOOD', severity: 'INFO', acknowledgeStatus: 'NOT_NEEDED' },
            ],
          },
        },
      };
      const result = getActiveAlerts(data);
      expect(result).to.have.lengthOf(1);
      expect(result[0].code).to.equal('GOOD');
    });
  });

  describe('pickHighestSeverity', () => {
    it('prefers ERROR over WARNING over INFO', () => {
      expect(pickHighestSeverity([{ severity: 'INFO' }, { severity: 'WARNING' }])).to.equal('WARNING');
      expect(pickHighestSeverity([{ severity: 'WARNING' }, { severity: 'ERROR' }])).to.equal('ERROR');
      expect(pickHighestSeverity([{ severity: 'INFO' }])).to.equal('INFO');
    });

    it('falls back to the first non-empty severity when none of the known levels match', () => {
      expect(pickHighestSeverity([{ severity: 'CUSTOM' }])).to.equal('CUSTOM');
    });

    it('returns empty string when nothing is present', () => {
      expect(pickHighestSeverity([])).to.equal('');
      expect(pickHighestSeverity([{ severity: '' }])).to.equal('');
    });
  });
});
