'use strict';

const { expect } = require('chai');
const { getCommandBrand, parseRemoteStateId } = require('./lib/helpers');

describe('ElectroluxAeg helpers', () => {
  describe('parseRemoteStateId', () => {
    it('parses normal remote state ids', () => {
      expect(parseRemoteStateId('electrolux-aeg.0.appliance-1.remote.Refresh')).to.deep.equal({
        deviceId: 'appliance-1',
        command: 'Refresh',
      });
    });

    it('keeps dots inside appliance ids and commands', () => {
      expect(parseRemoteStateId('electrolux-aeg.0.a.b.remote.Custom.Command')).to.deep.equal({
        deviceId: 'a.b',
        command: 'Custom.Command',
      });
    });

    it('ignores non remote states', () => {
      expect(parseRemoteStateId('electrolux-aeg.0.appliance-1.status.applianceState')).to.equal(null);
    });
  });

  describe('getCommandBrand', () => {
    it('uses aeg for AEG instances', () => {
      expect(getCommandBrand('aeg')).to.equal('aeg');
    });

    it('falls back to electrolux', () => {
      expect(getCommandBrand('electrolux')).to.equal('electrolux');
    });
  });
});
