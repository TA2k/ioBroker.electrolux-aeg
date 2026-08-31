'use strict';

const { expect } = require('chai');
const { resolveRegionUrls, DEFAULT_URLS } = require('./regionUrls');

const EU = {
  domain: 'eu1.gigya.com',
  apiKey: '4_JZvZObbVWc1YROHF9e6y8A',
  brand: 'electrolux',
  httpRegionalBaseUrl: 'https://api.eu.ocp.electrolux.one',
  webSocketRegionalBaseUrl: 'wss://ws.eu.ocp.electrolux.one',
  dataCenter: 'EU',
};

const US = {
  domain: 'us1.gigya.com',
  apiKey: 'us-api-key',
  brand: 'electrolux',
  httpRegionalBaseUrl: 'https://api.us.ocp.electrolux.one',
  webSocketRegionalBaseUrl: 'wss://ws.us.ocp.electrolux.one',
  dataCenter: 'US',
};

describe('lib/regionUrls', () => {
  it('falls back to the European endpoints for an unusable response', () => {
    for (const response of [undefined, null, [], 'nope', [null]]) {
      const result = resolveRegionUrls(response, 'electrolux');
      expect(result.gigya).to.equal(DEFAULT_URLS.gigya);
      expect(result.api).to.equal(DEFAULT_URLS.api);
      expect(result.ws).to.equal(DEFAULT_URLS.ws);
      expect(result.gigyaApiKey).to.equal(null);
    }
  });

  it('reads the endpoints of the returned provider', () => {
    const result = resolveRegionUrls([US], 'electrolux');
    expect(result.gigya).to.equal('https://us1.gigya.com');
    expect(result.api).to.equal('https://api.us.ocp.electrolux.one');
    expect(result.ws).to.equal('wss://ws.us.ocp.electrolux.one');
    expect(result.gigyaApiKey).to.equal('us-api-key');
    expect(result.dataCenter).to.equal('US');
  });

  it('prefers the provider of the configured brand', () => {
    const aeg = { ...EU, brand: 'aeg', domain: 'aeg.gigya.com' };
    expect(resolveRegionUrls([US, aeg], 'aeg').gigya).to.equal('https://aeg.gigya.com');
    expect(resolveRegionUrls([US, aeg], 'AEG').gigya).to.equal('https://aeg.gigya.com');
  });

  it('uses the first provider when no brand matches', () => {
    expect(resolveRegionUrls([US], 'aeg').api).to.equal('https://api.us.ocp.electrolux.one');
  });

  it('accepts a single object instead of a list', () => {
    expect(resolveRegionUrls(US, 'electrolux').api).to.equal('https://api.us.ocp.electrolux.one');
  });

  it('fills missing fields from the European defaults', () => {
    const partial = { brand: 'electrolux', httpRegionalBaseUrl: 'https://api.apac.ocp.electrolux.one' };
    const result = resolveRegionUrls([partial], 'electrolux');
    expect(result.api).to.equal('https://api.apac.ocp.electrolux.one');
    expect(result.gigya).to.equal(DEFAULT_URLS.gigya);
    expect(result.ws).to.equal(DEFAULT_URLS.ws);
    expect(result.gigyaApiKey).to.equal(null);
  });
});
