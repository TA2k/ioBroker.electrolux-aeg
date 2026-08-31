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
 * @param {any} data - appliance payload (`properties.reported.*`)
 * @param {{running?: boolean, finishTime?: string|null}} [prev] - last derived result for this appliance
 * @param {number} [now] - current time in ms, injectable for tests
 * @returns {{applianceState: string, running: boolean, timeToEndMinutes: number|null, finishTime: string|null, cycleFinished: boolean}|null}
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
    const previous = prev.finishTime ? Date.parse(prev.finishTime) : NaN;
    finishTime =
      Number.isFinite(previous) && Math.abs(estimate - previous) < FINISH_TIME_TOLERANCE_MS
        ? prev.finishTime || null
        : new Date(estimate).toISOString();
  }

  return {
    applianceState,
    running,
    timeToEndMinutes: hasTimeToEnd ? Math.round(timeToEnd / 60) : null,
    finishTime,
    cycleFinished,
  };
}

module.exports = {
  deriveStatus,
  RUNNING_STATES,
  FINISHED_STATES,
};
