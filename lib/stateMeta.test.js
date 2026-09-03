'use strict';

const { expect } = require('chai');
const { collectStateMeta, collectShadowTimestamps } = require('./stateMeta');

function payload(reported) {
  return { properties: { reported: reported } };
}

describe('lib/stateMeta', () => {
  it('returns nothing for a payload without a reported section', () => {
    expect(collectStateMeta(undefined)).to.deep.equal([]);
    expect(collectStateMeta({})).to.deep.equal([]);
    expect(collectStateMeta({ properties: {} })).to.deep.equal([]);
    expect(collectStateMeta(payload('nope'))).to.deep.equal([]);
  });

  it('describes known top level values', () => {
    const result = collectStateMeta(payload({ timeToEnd: 1800, targetTemperatureC: 180 }));
    expect(result).to.deep.include({
      path: ['timeToEnd'],
      type: 'number',
      common: { role: 'value.interval', unit: 's' },
    });
    expect(result).to.deep.include({
      path: ['targetTemperatureC'],
      type: 'number',
      common: { role: 'value.temperature', unit: '°C' },
    });
  });

  it('looks one container deep', () => {
    const result = collectStateMeta(payload({ fridge: { targetTemperatureC: 4 } }));
    expect(result).to.deep.equal([
      { path: ['fridge', 'targetTemperatureC'], type: 'number', common: { role: 'value.temperature', unit: '°C' } },
    ]);
  });

  it('ignores unknown capabilities and arrays', () => {
    const result = collectStateMeta(payload({ somethingNew: 5, alerts: [{ code: 'X' }] }));
    expect(result).to.deep.equal([]);
  });

  it('omits the unit for values that have none', () => {
    const result = collectStateMeta(payload({ applianceState: 'RUNNING' }));
    expect(result).to.deep.equal([{ path: ['applianceState'], type: 'string', common: { role: 'text' } }]);
  });
});

describe('collectShadowTimestamps', () => {
  /**
   * @param {any} reported
   * @param {any} metadata
   */
  function shadow(reported, metadata) {
    return { properties: { reported: reported, metadata: metadata } };
  }

  it('returns nothing without a reported or a metadata section', () => {
    expect(collectShadowTimestamps(undefined)).to.deep.equal([]);
    expect(collectShadowTimestamps({ properties: { reported: { doorState: 'CLOSED' } } })).to.deep.equal([]);
    expect(collectShadowTimestamps({ properties: { metadata: { doorState: { timestamp: 1 } } } })).to.deep.equal([]);
  });

  it('reads the seconds of a plain leaf', () => {
    expect(collectShadowTimestamps(shadow({ doorState: 'CLOSED' }, { doorState: { timestamp: 1788343012 } }))).to.deep.equal([
      { path: ['doorState'], value: 'CLOSED', ts: 1788343012000 },
    ]);
  });

  it('reads the milliseconds of a leaf that repeats its own key', () => {
    // The oven ships displayTemperatureC, displayTemperatureF and timeToEnd this way.
    const result = collectShadowTimestamps(
      shadow({ displayTemperatureC: 30 }, { displayTemperatureC: { displayTemperatureC: { timestamp: 1788349904928 } } }),
    );
    expect(result).to.deep.equal([{ path: ['displayTemperatureC'], value: 30, ts: 1788349904928 }]);
  });

  it('looks one container deep', () => {
    const result = collectShadowTimestamps(
      shadow({ networkInterface: { otaState: 'IDLE' } }, { networkInterface: { otaState: { timestamp: 1788341488 } } }),
    );
    expect(result).to.deep.equal([{ path: ['networkInterface', 'otaState'], value: 'IDLE', ts: 1788341488000 }]);
  });

  it('skips arrays, unknown shapes and unusable timestamps', () => {
    const result = collectShadowTimestamps(
      shadow(
        { alerts: [{ code: 'X' }], doorState: 'CLOSED', program: 'TRUE_FAN', cpv: '00' },
        { alerts: {}, doorState: {}, program: { timestamp: 0 }, cpv: { timestamp: 'nope' } },
      ),
    );
    expect(result).to.deep.equal([]);
  });

  it('pairs every reported value of the live oven payload it has a timestamp for', () => {
    const result = collectShadowTimestamps({
      properties: {
        reported: { doorState: 'CLOSED', timeToEnd: -1, alerts: [] },
        metadata: { doorState: { timestamp: 1788343012 }, timeToEnd: { timeToEnd: { timestamp: 1788344791996 } } },
      },
    });
    expect(result).to.deep.equal([
      { path: ['doorState'], value: 'CLOSED', ts: 1788343012000 },
      { path: ['timeToEnd'], value: -1, ts: 1788344791996 },
    ]);
  });
});
