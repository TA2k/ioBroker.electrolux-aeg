# Older changes
## 0.0.10 (2026-07-03)

- Republish the 0.0.9 migration fixes with npm provenance.

## 0.0.9 (2026-07-03)

- Breaking: sanitize appliance object IDs. Characters like `:` are replaced with `_`; update scripts, aliases, VIS and history settings that reference old IDs.
- Remove old unsanitized appliance object trees after creating the new sanitized objects.
- Handle temporary Electrolux API gateway timeouts without error log spam

## 0.0.8 (2026-06-29)

- Hardened login, token refresh and WebSocket reconnect
- Added active alert summary states under `.status.activeAlert*`
- Fixed brand parameter for AEG accounts

## 0.0.6 (2025-12-09)

- fix refresh token


## 0.0.5

- (TA2k) fix remote controls

## 0.0.2

- (TA2k) initial release
