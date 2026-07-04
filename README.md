![Logo](admin/electrolux-aeg.png)

# ioBroker.electrolux-aeg

[![NPM version](https://img.shields.io/npm/v/iobroker.electrolux-aeg.svg)](https://www.npmjs.com/package/iobroker.electrolux-aeg)
[![Downloads](https://img.shields.io/npm/dm/iobroker.electrolux-aeg.svg)](https://www.npmjs.com/package/iobroker.electrolux-aeg)
![Number of Installations](https://iobroker.live/badges/electrolux-aeg-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/electrolux-aeg-stable.svg)

[![NPM](https://nodei.co/npm/iobroker.electrolux-aeg.png?downloads=true)](https://nodei.co/npm/iobroker.electrolux-aeg/)

**Tests:** ![Test and Release](https://github.com/TA2k/ioBroker.electrolux-aeg/workflows/Test%20and%20Release/badge.svg)

## electrolux-aeg adapter for ioBroker

Adapter for Electrolux and AEG

Supported appliances are managed through the official [Electrolux](https://www.electrolux.com/) and [AEG](https://www.aeg.com/) connected appliance services.

**This adapter uses Sentry libraries to automatically report exceptions and code errors to the developers.** For more details and for information how to disable the error reporting see [Sentry-Plugin Documentation](https://github.com/ioBroker/plugin-sentry#plugin-sentry)! Sentry reporting is used starting with js-controller 3.0.

## Control

electrolux-aeg.0.XXXX.remote

## Status

electrolux-aeg.0.XXXX.status

## Live Events

electrolux-aeg.0.XXXX.events

## Changelog
### 0.0.12 (2026-07-04)

- Exclude `CHANGELOG_OLD.md` and test files from npm publishing.
- Tighten object ID sanitization to replace commas.
- Remove stale commented-out logout code and document raw/sanitized appliance ID mapping.

### 0.0.11 (2026-07-03)

- Republish the latest repository review fixes with npm provenance.
- Remove obsolete ESLint and Prettier dependencies after migrating to `@iobroker/eslint-config`.

### 0.0.10 (2026-07-03)

- Republish the 0.0.9 migration fixes with npm provenance.

### 0.0.9 (2026-07-03)

- Breaking: sanitize appliance object IDs. Characters like `:` are replaced with `_`; update scripts, aliases, VIS and history settings that reference old IDs.
- Remove old unsanitized appliance object trees after creating the new sanitized objects.
- Handle temporary Electrolux API gateway timeouts without error log spam

### 0.0.8 (2026-06-29)

- Hardened login, token refresh and WebSocket reconnect
- Added active alert summary states under `.status.activeAlert*`
- Fixed brand parameter for AEG accounts

### 0.0.6 (2025-12-09)

- fix refresh token

### 0.0.5 (2025-03-08)

- fix remote controls

Older changes are documented in [CHANGELOG_OLD.md](CHANGELOG_OLD.md).

## License

MIT License

Copyright (c) 2023-2026 TA2k <tombox2020@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
