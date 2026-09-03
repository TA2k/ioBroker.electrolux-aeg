'use strict';

/**
 * Endpoints of the European region.
 *
 * The cloud has exactly two regions, `eu` and `us` (`api.<region>.ocp.electrolux.one`
 * and `ws.<region>...`; no other region host resolves). Only the European ones are
 * reachable with the built in Gigya api keys, which Gigya reports as bound to the
 * `eu1` data centre, so a US account needs a key this adapter does not have.
 *
 * There used to be a lookup of `/one-account-user/api/v1/identity-providers` that was
 * meant to discover the region at runtime. That route requires a bearer token while the
 * lookup ran before the login, so it answered 401 on every start and never did anything.
 */
const DEFAULT_URLS = {
  gigya: 'https://accounts.eu1.gigya.com',
  api: 'https://api.eu.ocp.electrolux.one',
  ws: 'https://ws.eu.ocp.electrolux.one',
};

module.exports = {
  DEFAULT_URLS,
};
