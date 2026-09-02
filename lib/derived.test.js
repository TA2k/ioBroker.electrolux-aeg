'use strict';

const { expect } = require('chai');
const { deriveStatus, metricsToReported } = require('./derived');

const NOW = Date.parse('2026-01-01T12:00:00.000Z');

function payload(reported) {
  return { properties: { reported: reported } };
}

/**
 * Call deriveStatus and assert it produced a result, so the tests below can use
 * the fields without null checks.
 *
 * @param {any} data
 * @param {any} [prev]
 * @param {number} [now]
 * @returns {Exclude<ReturnType<typeof deriveStatus>, null>}
 */
function derive(data, prev, now) {
  const result = deriveStatus(data, prev, now);
  expect(result).to.not.equal(null);
  return /** @type {Exclude<ReturnType<typeof deriveStatus>, null>} */ (result);
}

describe('lib/derived', () => {
  it('returns null when the payload carries no applianceState', () => {
    expect(deriveStatus(undefined)).to.equal(null);
    expect(deriveStatus({})).to.equal(null);
    expect(deriveStatus(payload({}))).to.equal(null);
    expect(deriveStatus(payload({ applianceState: '' }))).to.equal(null);
    expect(deriveStatus(payload({ timeToEnd: 600 }))).to.equal(null);
  });

  it('reports a running appliance with remaining time and finish time', () => {
    const result = derive(payload({ applianceState: 'RUNNING', timeToEnd: 1800 }), {}, NOW);
    expect(result.running).to.equal(true);
    expect(result.timeToEndMinutes).to.equal(30);
    expect(result.finishTime).to.equal('2026-01-01T12:30:00.000Z');
    expect(result.cycleFinished).to.equal(false);
  });

  it('treats PAUSED and DELAYED_START as running', () => {
    expect(derive(payload({ applianceState: 'PAUSED' }), {}, NOW).running).to.equal(true);
    expect(derive(payload({ applianceState: 'DELAYED_START' }), {}, NOW).running).to.equal(true);
  });

  it('clears remaining time when idle or when the appliance reports -1', () => {
    const idle = derive(payload({ applianceState: 'OFF', timeToEnd: -1 }), {}, NOW);
    expect(idle.running).to.equal(false);
    expect(idle.timeToEndMinutes).to.equal(null);
    expect(idle.finishTime).to.equal(null);

    const running = derive(payload({ applianceState: 'RUNNING', timeToEnd: -1 }), {}, NOW);
    expect(running.timeToEndMinutes).to.equal(null);
    expect(running.finishTime).to.equal(null);

    const zero = derive(payload({ applianceState: 'RUNNING', timeToEnd: 0 }), {}, NOW);
    expect(zero.timeToEndMinutes).to.equal(null);
  });

  it('fires cycleFinished exactly once on the running to finished transition', () => {
    const prev = { running: true };
    const first = derive(payload({ applianceState: 'END' }), prev, NOW);
    expect(first.cycleFinished).to.equal(true);

    const second = derive(payload({ applianceState: 'END' }), first, NOW);
    expect(second.cycleFinished).to.equal(false);
  });

  it('never fires cycleFinished for an unknown appliance state', () => {
    const result = derive(payload({ applianceState: 'SOME_NEW_STATE' }), { running: true }, NOW);
    expect(result.running).to.equal(false);
    expect(result.cycleFinished).to.equal(false);
  });

  it('keeps the previous finishTime while the estimate only jitters', () => {
    const first = derive(payload({ applianceState: 'RUNNING', timeToEnd: 1800 }), {}, NOW);
    // Poll 10 s later, appliance still reports a full 1800 s -> estimate drifts by 10 s.
    const second = derive(payload({ applianceState: 'RUNNING', timeToEnd: 1800 }), first, NOW + 10000);
    expect(second.finishTime).to.equal(first.finishTime);

    // A real change of more than a minute is written through.
    const third = derive(payload({ applianceState: 'RUNNING', timeToEnd: 3600 }), second, NOW + 10000);
    expect(third.finishTime).to.equal('2026-01-01T13:00:10.000Z');
  });

  it('uppercases the reported state', () => {
    expect(derive(payload({ applianceState: 'running' }), {}, NOW).applianceState).to.equal('RUNNING');
    expect(derive(payload({ applianceState: 'running' }), {}, NOW).running).to.equal(true);
  });
});

describe('metricsToReported', () => {
  it('turns a WebSocket metrics array into the reported shape of a poll', () => {
    const metrics = [
      { Name: 'applianceState', Value: 'RUNNING', Timestamp: '2026-09-02T10:25:05.000Z' },
      { Name: 'timeToEnd', Value: 120 },
      { Name: 'cavityLight', Value: true },
    ];

    expect(metricsToReported(metrics)).to.deep.equal({
      applianceState: 'RUNNING',
      timeToEnd: 120,
      cavityLight: true,
    });
    // The result feeds the same code path as a poll payload.
    expect(derive({ properties: { reported: metricsToReported(metrics) } }, {}, NOW).timeToEndMinutes).to.equal(2);
  });

  it('drops the empty values of a sensor the appliance has no reading for', () => {
    // The oven pushes this while the food probe is not inserted.
    const metrics = [
      { Name: 'displayFoodProbeTemperatureC', Value: '' },
      { Name: 'displayTemperatureC', Value: 115 },
      { Name: 'targetDuration', Value: 0 },
    ];

    expect(metricsToReported(metrics)).to.deep.equal({ displayTemperatureC: 115, targetDuration: 0 });
  });

  it('survives a push without a usable metrics array', () => {
    expect(metricsToReported(undefined)).to.deep.equal({});
    expect(metricsToReported([null, {}, { Value: 5 }])).to.deep.equal({});
  });
});
