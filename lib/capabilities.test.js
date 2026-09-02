'use strict';

const { expect } = require('chai');
const { buildCapabilityStates, buildCommandPayload } = require('./capabilities');

const PATH = 'device.control';

function build(capabilities) {
  return buildCapabilityStates(capabilities, PATH);
}

function byId(result, objectId) {
  return result.states.find((state) => state.objectId === objectId);
}

describe('lib/capabilities', () => {
  describe('buildCapabilityStates', () => {
    it('survives a missing or malformed capabilities response', () => {
      expect(build(undefined).states).to.deep.equal([]);
      expect(build(null).states).to.deep.equal([]);
      expect(build('nope').states).to.deep.equal([]);
      expect(build({}).states).to.deep.equal([]);
    });

    it('ignores read-only, constant and alert capabilities', () => {
      const result = build({
        applianceState: { access: 'read', type: 'string', values: { OFF: {}, RUNNING: {} } },
        model: { access: 'constant', type: 'string' },
        alerts: { access: 'read', type: 'alert' },
      });
      expect(result.states).to.deep.equal([]);
    });

    it('ignores executeCommand, which is handled as remote buttons', () => {
      const result = build({
        executeCommand: { access: 'readwrite', type: 'string', values: { START: {}, STOPRESET: {} } },
      });
      expect(result.states).to.deep.equal([]);
    });

    it('turns a values map into a string state with common.states', () => {
      const result = build({
        endOfCycleSound: { access: 'readwrite', type: 'string', values: { NO_SOUND: {}, SHORT_SOUND: {} } },
      });
      const state = byId(result, 'device.control.endOfCycleSound');
      expect(state.kind).to.equal('plain');
      expect(state.container).to.equal(null);
      expect(state.object.common.type).to.equal('string');
      expect(state.object.common.role).to.equal('text');
      expect(state.object.common.states).to.deep.equal({ NO_SOUND: 'NO_SOUND', SHORT_SOUND: 'SHORT_SOUND' });
      expect(state.object.common.write).to.equal(true);
    });

    it('turns an ON/OFF values map into a switch', () => {
      const result = build({ fastMode: { access: 'readwrite', type: 'string', values: { ON: {}, OFF: {} } } });
      const state = byId(result, 'device.control.fastMode');
      expect(state.kind).to.equal('onoff');
      expect(state.object.common.type).to.equal('boolean');
      expect(state.object.common.role).to.equal('switch');
    });

    it('maps numbers and temperatures with their range', () => {
      const result = build({
        targetTemperatureC: { access: 'readwrite', type: 'temperature', min: 30, max: 250, step: 5 },
        targetMicrowavePower: { access: 'readwrite', type: 'int', min: 0, max: 1000 },
      });
      const temperature = byId(result, 'device.control.targetTemperatureC');
      expect(temperature.object.common.type).to.equal('number');
      expect(temperature.object.common.role).to.equal('level.temperature');
      expect(temperature.object.common.unit).to.equal('°C');
      expect(temperature.object.common.min).to.equal(30);
      expect(temperature.object.common.max).to.equal(250);
      expect(temperature.object.common.step).to.equal(5);

      const power = byId(result, 'device.control.targetMicrowavePower');
      expect(power.object.common.role).to.equal('level');
      expect(power.object.common.unit).to.equal(undefined);
    });

    it('turns a write-only single value capability into a button', () => {
      const result = build({ airFilterStateReset: { access: 'write', type: 'string', values: { RESET: {} } } });
      const state = byId(result, 'device.control.airFilterStateReset');
      expect(state.kind).to.equal('const');
      expect(state.constValue).to.equal('RESET');
      expect(state.object.common.role).to.equal('button');
      expect(state.object.common.read).to.equal(false);
    });

    it('flattens one level of containers into container_key ids', () => {
      const result = build({
        userSelections: {
          analogTemperature: { access: 'readwrite', type: 'string', values: { '30_CELSIUS': {}, '40_CELSIUS': {} } },
        },
      });
      const state = byId(result, 'device.control.userSelections_analogTemperature');
      expect(state.container).to.equal('userSelections');
      expect(state.key).to.equal('analogTemperature');
    });

    it('sanitizes ids and reports collisions instead of overwriting', () => {
      const result = build({
        'a:b': { access: 'readwrite', type: 'boolean' },
        a_b: { access: 'readwrite', type: 'boolean' },
      });
      expect(result.states).to.have.lengthOf(1);
      expect(result.collisions).to.have.lengthOf(1);
      expect(result.collisions[0].objectId).to.equal('device.control.a_b');
    });

    it('never turns the network interface commands into control states', () => {
      const result = build({
        networkInterface: {
          command: { access: 'write', type: 'string', values: { START: {}, USER_AUTHORIZE: {} } },
          startUpCommand: { access: 'write', type: 'string', values: { UNINSTALL: {} } },
        },
      });
      expect(result.states).to.deep.equal([]);
    });

    it('reports nesting deeper than one container instead of guessing', () => {
      const result = build({ outer: { inner: { deep: { access: 'readwrite', type: 'boolean' } } } });
      expect(result.states).to.deep.equal([]);
      expect(result.skipped).to.deep.equal(['outer/inner']);
    });
  });

  describe('buildCommandPayload', () => {
    it('builds a flat payload for a top level capability', () => {
      expect(buildCommandPayload({ container: null, key: 'waterHardness', kind: 'plain' }, 'HIGH')).to.deep.equal({
        waterHardness: 'HIGH',
      });
    });

    it('nests the payload for a container capability', () => {
      const meta = { container: 'fCMiscellaneousState', key: 'tankAReserve', kind: 'plain' };
      expect(buildCommandPayload(meta, 5)).to.deep.equal({ fCMiscellaneousState: { tankAReserve: 5 } });
    });

    it('always sends programUID along with a userSelections change', () => {
      const meta = { container: 'userSelections', key: 'analogTemperature', kind: 'plain' };
      expect(buildCommandPayload(meta, '40_CELSIUS', 'COTTON')).to.deep.equal({
        userSelections: { programUID: 'COTTON', analogTemperature: '40_CELSIUS' },
      });
    });

    it('omits programUID when it is unknown', () => {
      const meta = { container: 'userSelections', key: 'analogTemperature', kind: 'plain' };
      expect(buildCommandPayload(meta, '40_CELSIUS', null)).to.deep.equal({
        userSelections: { analogTemperature: '40_CELSIUS' },
      });
    });

    it('translates a switch into ON / OFF', () => {
      const meta = { container: null, key: 'fastMode', kind: 'onoff' };
      expect(buildCommandPayload(meta, true)).to.deep.equal({ fastMode: 'ON' });
      expect(buildCommandPayload(meta, false)).to.deep.equal({ fastMode: 'OFF' });
    });

    it('sends the fixed value for a button', () => {
      const meta = { container: null, key: 'airFilterStateReset', kind: 'const', constValue: 'RESET' };
      expect(buildCommandPayload(meta, true)).to.deep.equal({ airFilterStateReset: 'RESET' });
    });
  });
});
