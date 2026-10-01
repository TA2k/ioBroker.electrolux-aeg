'use strict';

// Gigya error codes that mean the credentials themselves were refused: invalid login id or
// password, an old password, a wrong password for a known login id.
const LOGIN_REJECTED_CODES = [403042, 401030, 401020];

/**
 * @param {any} error
 * @returns {boolean}
 */
function isTransientFetchError(error) {
  return [502, 503, 504].includes(error?.response?.status) || ['ECONNABORTED', 'ETIMEDOUT'].includes(error?.code);
}

/**
 * Sort the outcome of a Gigya `accounts.login` request.
 *
 * With `httpStatusCodes: true` Gigya refuses wrong credentials with a 403 whose body carries the
 * error code; without it the same body arrives with a 200. Both shapes are handled.
 *
 * @param {any} data - response body of a request that was answered with 2xx
 * @param {any} [error] - the rejection of a request that failed
 * @returns {'ok' | 'rejected' | 'failed' | 'unreachable'}
 */
function classifyLoginAnswer(data, error) {
  if (error) {
    const response = error.response;
    if (!response || response.status >= 500) {
      return 'unreachable';
    }
    data = response.data;
  }
  const session = data && data.sessionInfo;
  if (session && session.sessionToken && session.sessionSecret) {
    return 'ok';
  }
  return LOGIN_REJECTED_CODES.includes(Number(data && data.errorCode)) ? 'rejected' : 'failed';
}

module.exports = {
  classifyLoginAnswer,
  isTransientFetchError,
};
