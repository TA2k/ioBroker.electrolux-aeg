'use strict';

/**
 * Global entry point of the cloud. Region independent, used to ask where the
 * account actually lives.
 */
const GLOBAL_API_URL = 'https://api.ocp.electrolux.one';

/**
 * Endpoints of the European region. Used until the identity provider lookup
 * says otherwise, because that is what the adapter always used.
 */
const DEFAULT_URLS = {
  gigya: 'https://accounts.eu1.gigya.com',
  api: 'https://api.eu.ocp.electrolux.one',
  ws: 'https://ws.eu.ocp.electrolux.one',
};

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Pick the endpoints for an account from an identity provider response.
 *
 * The cloud answers `/one-account-user/api/v1/identity-providers` with a list of
 * providers, each carrying the Gigya domain, the regional API base url, the
 * regional WebSocket base url and the Gigya api key for that brand and region.
 * Anything missing falls back to the European endpoints, so a partial answer
 * cannot break the login.
 *
 * @param {any} providers - parsed response body
 * @param {string} [brand] - configured brand, e.g. `electrolux` or `aeg`
 * @returns {{gigya: string, api: string, ws: string, gigyaApiKey: string|null, dataCenter: string|null}}
 */
function resolveRegionUrls(providers, brand) {
  const list = Array.isArray(providers) ? providers : [providers];
  const candidates = list.filter((entry) => entry && typeof entry === 'object');
  const provider =
    candidates.find((entry) => isNonEmptyString(entry.brand) && entry.brand.toLowerCase() === String(brand).toLowerCase()) ||
    candidates[0];

  if (!provider) {
    return { ...DEFAULT_URLS, gigyaApiKey: null, dataCenter: null };
  }

  return {
    gigya: isNonEmptyString(provider.domain) ? 'https://' + provider.domain : DEFAULT_URLS.gigya,
    api: isNonEmptyString(provider.httpRegionalBaseUrl) ? provider.httpRegionalBaseUrl : DEFAULT_URLS.api,
    ws: isNonEmptyString(provider.webSocketRegionalBaseUrl) ? provider.webSocketRegionalBaseUrl : DEFAULT_URLS.ws,
    gigyaApiKey: isNonEmptyString(provider.apiKey) ? provider.apiKey : null,
    dataCenter: isNonEmptyString(provider.dataCenter) ? provider.dataCenter : null,
  };
}

module.exports = {
  resolveRegionUrls,
  DEFAULT_URLS,
  GLOBAL_API_URL,
};
