'use strict';

// Regression tests against payloads captured from a live AEG built-in oven
// (TE7PB63ZAB, applianceType OV) on 2026-08-31. Ids and the capability hash are
// anonymized, everything else is what the cloud actually sent.

const { expect } = require('chai');
const status = require('../test/fixtures/ov-status.json');
const capabilities = require('../test/fixtures/ov-capabilities.json');
const { deriveStatus } = require('./derived');
const { buildCapabilityStates, buildCommandPayload } = require('./capabilities');
const { collectStateMeta } = require('./stateMeta');

/**
 * deriveStatus returns null only for payloads without applianceState, which the
 * fixtures always carry.
 *
 * @param {any} data
 * @param {any} [prev]
 * @returns {Exclude<ReturnType<typeof deriveStatus>, null>}
 */
function derive(data, prev) {
  const result = deriveStatus(data, prev);
  expect(result).to.not.equal(null);
  return /** @type {Exclude<ReturnType<typeof deriveStatus>, null>} */ (result);
}

describe('live oven payload', () => {
  describe('derived states', () => {
    it('reports an idle oven without a remaining time', () => {
      const result = derive(status, {});
      expect(result.applianceState).to.equal('READY_TO_START');
      expect(result.running).to.equal(false);
      expect(result.timeToEndMinutes).to.equal(null);
      expect(result.finishTime).to.equal(null);
    });

    it('knows every appliance state this oven can report', () => {
      const values = Object.keys(capabilities.applianceState.values);
      expect(values).to.include.members(['RUNNING', 'PAUSED', 'DELAYED_START', 'END_OF_CYCLE', 'READY_TO_START']);
      for (const value of values) {
        const derived = derive({ properties: { reported: { applianceState: value } } }, { running: true });
        // ALARM is deliberately neither running nor finished.
        if (value === 'ALARM') {
          expect(derived.cycleFinished, value).to.equal(false);
          continue;
        }
        expect(derived.running || derived.cycleFinished, value).to.equal(true);
      }
    });

    it('fires cycleFinished when the oven reaches END_OF_CYCLE', () => {
      const running = derive(
        { properties: { reported: { applianceState: 'RUNNING', timeToEnd: 600 } } },
        {},
      );
      expect(running.running).to.equal(true);
      expect(running.timeToEndMinutes).to.equal(10);
      const finished = derive({ properties: { reported: { applianceState: 'END_OF_CYCLE' } } }, running);
      expect(finished.cycleFinished).to.equal(true);
    });
  });

  describe('control states', () => {
    const { states } = buildCapabilityStates(capabilities, 'oven.control');
    const ids = states.map((state) => state.objectId);
    /**
     * @param {string} key
     * @returns {(typeof states)[number]}
     */
    const state = (key) => {
      const found = states.find((entry) => entry.key === key);
      expect(found, key).to.not.equal(undefined);
      return /** @type {(typeof states)[number]} */ (found);
    };

    it('creates the writable oven settings', () => {
      expect(ids).to.have.members([
        'oven.control.cavityLight',
        'oven.control.program',
        'oven.control.targetDuration',
        'oven.control.targetFoodProbeTemperatureC',
        'oven.control.targetTemperatureC',
      ]);
    });

    it('never exposes the network interface commands', () => {
      // networkInterface.startUpCommand carries UNINSTALL, which unregisters the
      // appliance from the account.
      expect(ids.join(' ')).to.not.contain('networkInterface');
    });

    it('offers the oven programs as a selection', () => {
      const program = state('program');
      expect(program.object.common.type).to.equal('string');
      expect(Object.keys(program.object.common.states || {})).to.include.members([
        'TRUE_FAN',
        'PIZZA',
        'GRILL',
        'CONVENTIONAL_COOKING',
      ]);
    });

    it('takes the range of the duration and food probe from the capability', () => {
      const duration = state('targetDuration');
      expect(duration.object.common.min).to.equal(0);
      expect(duration.object.common.max).to.equal(86340);
      expect(duration.object.common.step).to.equal(60);
      expect(duration.object.common.unit).to.equal('s');

      const probe = state('targetFoodProbeTemperatureC');
      expect(probe.object.common.unit).to.equal('°C');
      expect(probe.object.common.min).to.equal(30);
      expect(probe.object.common.max).to.equal(99);
    });

    it('sends a flat payload for an oven setting', () => {
      const program = state('program');
      expect(buildCommandPayload(program, 'PIZZA')).to.deep.equal({ program: 'PIZZA' });
      const light = state('cavityLight');
      expect(buildCommandPayload(light, true)).to.deep.equal({ cavityLight: 'ON' });
    });
  });

  describe('state metadata', () => {
    const meta = collectStateMeta(status);
    const byPath = Object.fromEntries(meta.map((entry) => [entry.path.join('.'), entry]));

    it('labels the times and temperatures the oven reports', () => {
      expect(byPath.timeToEnd.common).to.deep.equal({ role: 'value.interval', unit: 's' });
      expect(byPath.runningTime.common).to.deep.equal({ role: 'value.interval', unit: 's' });
      expect(byPath.targetDuration.common).to.deep.equal({ role: 'value.interval', unit: 's' });
      expect(byPath.targetTemperatureC.common).to.deep.equal({ role: 'value.temperature', unit: '°C' });
      expect(byPath.displayTemperatureC.common).to.deep.equal({ role: 'value.temperature', unit: '°C' });
      expect(byPath.displayTemperatureF.common).to.deep.equal({ role: 'value.temperature', unit: '°F' });
    });

    it('expects the type the oven really sends', () => {
      // linkQualityIndicator is a string here (VERY_GOOD), not a number.
      expect(byPath['networkInterface.linkQualityIndicator']).to.equal(undefined);
      expect(byPath.timeToEnd.type).to.equal('number');
    });
  });
});
