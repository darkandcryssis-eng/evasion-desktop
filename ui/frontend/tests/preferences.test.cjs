const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

const source = readFileSync(path.join(__dirname, "../src/preferences.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const defaults = { voice: "ttl", quic: "off", observe: false, restartDiscord: true };

function load(value, denied = false) {
  const exports = {};
  const storage = new Map([["evasion-connection-options", value]]);
  const localStorage = {
    getItem: (key) => { if (denied) throw Error("storage disabled"); return storage.get(key) ?? null; },
    setItem: (key, next) => { if (denied) throw Error("storage full"); storage.set(key, next); },
  };
  vm.runInNewContext(code, { exports, require, window: { localStorage } });
  return exports;
}

for (const value of [null, "null", "{broken", "[]", "42"]) {
  test(`invalid saved options fall back safely: ${value}`, () => {
    assert.deepEqual({ ...load(value).loadOptions() }, defaults);
  });
}

test("connection choices survive reload, including false flags", () => {
  const selected = { voice: "badsum-quic", quic: "desync", observe: true, restartDiscord: false };
  assert.deepEqual({ ...load(JSON.stringify(selected)).loadOptions() }, selected);
});

test("unknown modes and non-boolean flags are rejected individually", () => {
  const invalid = { voice: "unknown", quic: "block", observe: "true", restartDiscord: 0 };
  assert.deepEqual({ ...load(JSON.stringify(invalid)).loadOptions() }, { ...defaults, quic: "block" });
});

test("unavailable storage does not prevent launching the interface", () => {
  const preferences = load(null, true);
  assert.deepEqual({ ...preferences.loadOptions() }, defaults);
  assert.doesNotThrow(() => preferences.savePreference("theme", "black"));
});

test("changing connection options notifies the tray bridge", () => {
  const exports = {}, events = [];
  vm.runInNewContext(code, { exports, require, Event: class { constructor(type) { this.type = type; } }, window: { localStorage: { setItem() {} }, dispatchEvent: (event) => events.push(event.type) } });
  exports.savePreference("evasion-connection-options", JSON.stringify(defaults));
  exports.savePreference("evasion-ui-theme", "black");
  assert.deepEqual(events, ["evasion:options-changed"]);
});
