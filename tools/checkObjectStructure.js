'use strict';

// Runs @iobroker/repochecker's object structure check, the same check the
// ioBroker.repositories bot runs against a live instance dump. lint and tsc do not
// see role / type mismatches or missing channel objects, they only surface here.
//
//   npm run pr:objects             # objects replayed from the fixtures
//   npm run pr:objects dump.json   # objects exported from a real instance
//
// Without an argument the tree is built by running the adapter against the captured
// oven payloads (test/fakeAdapter.js), so the check needs no appliance and no account.
//
// The checker is not a dependency: `npm run pr:objects` fetches it through npx.

const fs = require('node:fs');
const path = require('node:path');
const ioPackage = require('../io-package.json');

/**
 * `npx --package` only puts the package's `.bin` on PATH, so resolve the library
 * next to it. A locally installed checker still wins.
 *
 * @returns {(objects: any, adapter: string) => {objectCount: number, errors: {code: string, message: string}[], warnings: {code: string, message: string}[]}}
 */
function loadChecker() {
  const library = '@iobroker/repochecker/lib/objectStructure.js';
  try {
    return require(library).checkObjectStructure;
  } catch {
    for (const entry of (process.env.PATH || '').split(path.delimiter)) {
      if (!entry.endsWith(path.join('node_modules', '.bin'))) {
        continue;
      }
      const candidate = path.join(entry, '..', ...library.split('/'));
      if (fs.existsSync(candidate)) {
        return require(candidate).checkObjectStructure;
      }
    }
  }
  throw new Error('@iobroker/repochecker not found, run: npm run pr:objects');
}

async function buildDump() {
  const { createTestAdapter } = require('../test/fakeAdapter');
  const { adapter } = createTestAdapter();
  await adapter.onReady();

  /** @type {Record<string, any>} */
  const dump = {};
  for (const object of ioPackage.instanceObjects || []) {
    dump[adapter.namespace + '.' + object._id] = { ...object, _id: adapter.namespace + '.' + object._id };
  }
  // `objects` is the in-memory store of the fake adapter, not part of the real base class.
  for (const [id, object] of /** @type {Map<string, any>} */ (/** @type {any} */ (adapter).objects)) {
    dump[id] = object;
  }
  // A real dump is JSON, and JSON drops undefined members. Round trip so the check
  // sees the objects as js-controller would have stored them.
  return JSON.parse(JSON.stringify(dump));
}

async function main() {
  const file = process.argv[2];
  const dump = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : await buildDump();
  const result = loadChecker()(dump, ioPackage.common.name);

  console.log(
    'Checked ' + result.objectCount + ' objects: ' + result.errors.length + ' errors, ' + result.warnings.length + ' warnings',
  );
  for (const warning of result.warnings) {
    console.log('WARNING ' + warning.code + ' ' + warning.message);
  }
  for (const error of result.errors) {
    console.log('ERROR ' + error.code + ' ' + error.message);
  }
  // The repositories bot fails the `objects` label on warnings too.
  process.exit(result.errors.length + result.warnings.length ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
