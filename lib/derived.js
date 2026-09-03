'use strict';

/**
 * Appliance states that mean "a program is currently in progress". `PAUSED` and
 * `DELAYED_START` count as running on purpose: a paused cycle has not finished,
 * so leaving them out would fire `cycleFinished` in the middle of a program.
 */
const RUNNING_STATES = new Set(['RUNNING', 'PAUSED', 'DELAYED_START', 'PREHEATING', 'RINSE_HOLD', 'WRINKLE_GUARD']);

/**
 * Appliance states that mean "no program in progress". Only a transition into
 * one of these fires `cycleFinished` - an unknown state never does, so a
 * vocabulary the adapter does not know yet cannot produce false triggers.
 *
 * The oven reports `READY_TO_START` both when a program runs to its end and when
 * it is aborted by hand (verified on the appliance, 2026-09-02), so the two cases
 * are indistinguishable from the payload. `cycleFinished` therefore means "stopped
 * running", not "completed successfully".
 */
const FINISHED_STATES = new Set(['END', 'ENDOFCYCLE', 'END_OF_CYCLE', 'OFF', 'IDLE', 'READY_TO_START', 'STANDBY']);

/**
 * Rewriting `finishTime` on every poll would flood history with sub-minute
 * jitter, so keep the previous value while the estimate stays this close.
 */
const FINISH_TIME_TOLERANCE_MS = 60 * 1000;

/**
 * Derive the convenience states from a raw appliance payload.
 *
 * Returns `null` when the payload carries no `applianceState` - WebSocket
 * messages can be partial updates, and those must not reset the derived states.
 *
 * There is deliberately no remaining-time state here: `properties.reported.timeToEnd`
 * already carries it in seconds with role and unit, and `finishTime` is the part
 * the payload does not have - the absolute instant the program ends.
 *
 * @param {any} data - appliance payload (`properties.reported.*`)
 * @param {{running?: boolean, finishTime?: number|null}} [prev] - last derived result for this appliance
 * @param {number} [now] - current time in ms, injectable for tests
 * @returns {{applianceState: string, running: boolean, finishTime: number|null, cycleFinished: boolean}|null}
 */
function deriveStatus(data, prev = {}, now = Date.now()) {
  const reported = (data && data.properties && data.properties.reported) || {};
  if (typeof reported.applianceState !== 'string' || !reported.applianceState) {
    return null;
  }
  const applianceState = reported.applianceState.toUpperCase();
  const running = RUNNING_STATES.has(applianceState);
  const cycleFinished = prev.running === true && FINISHED_STATES.has(applianceState);

  const timeToEnd = Number(reported.timeToEnd);
  const hasTimeToEnd = running && Number.isFinite(timeToEnd) && timeToEnd > 0;

  let finishTime = null;
  if (hasTimeToEnd) {
    const estimate = now + timeToEnd * 1000;
    const previous = Number(prev.finishTime);
    finishTime =
      Number.isFinite(previous) && previous > 0 && Math.abs(estimate - previous) < FINISH_TIME_TOLERANCE_MS
        ? previous
        : estimate;
  }

  return {
    applianceState,
    running,
    finishTime,
    cycleFinished,
  };
}

/**
 * Turn the `Metrics` array of a WebSocket push into the `properties.reported`
 * shape the poll delivers, so both feed the same write path.
 *
 * A metric the appliance has no value for arrives as an empty string (the food
 * probe does this while it is not inserted). Those are dropped: writing them
 * would turn a numeric state into a string one and overwrite the last real value.
 *
 * @param {any} metrics - `Payload.Appliances[].Metrics`
 * @returns {Record<string, any>}
 */
function metricsToReported(metrics) {
  /** @type {Record<string, any>} */
  const reported = {};
  if (!Array.isArray(metrics)) {
    return reported;
  }
  for (const metric of metrics) {
    if (!metric || typeof metric.Name !== 'string' || !metric.Name) {
      continue;
    }
    if (metric.Value === undefined || metric.Value === null || metric.Value === '') {
      continue;
    }
    reported[metric.Name] = metric.Value;
  }
  return reported;
}

module.exports = {
  deriveStatus,
  metricsToReported,
  RUNNING_STATES,
  FINISHED_STATES,
};
