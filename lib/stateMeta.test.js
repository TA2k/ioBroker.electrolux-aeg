'use strict';

const { expect } = require('chai');
const { collectStateMeta } = require('./stateMeta');

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
