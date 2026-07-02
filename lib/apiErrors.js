'use strict';

/**
 * @param {any} error
 * @returns {boolean}
 */
function isTransientFetchError(error) {
  return [502, 503, 504].includes(error?.response?.status) || ['ECONNABORTED', 'ETIMEDOUT'].includes(error?.code);
}

module.exports = {
  isTransientFetchError,
};
