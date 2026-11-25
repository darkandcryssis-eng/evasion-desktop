const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

const source = readFileSync(path.join(__dirname, "../src/windowActivity.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const settled = () => new Promise(setImmediate);

function fixture() {
  const exports = {}, document = new EventTarget(), timers = new Map();
  let id = 0;
  const window = {
    setTimeout(fn, ms) { timers.set(++id, { fn, ms }); return id; },
    clearTimeout(key) { timers.delete(key); },
  };
  vm.runInNewContext(code, { exports, document, window, EventTarget, Event });
  const hideDocument = (hidden) => {
    document.hidden = hidden;
    document.dispatchEvent(new Event("visibilitychange"));
  };
  return { ...exports, hideDocument, timers };
}

test("hiding either window surface stops timers; showing starts work immediately", async () => {
  const { startVisibleLoop, setTrayHidden, hideDocument, timers } = fixture();
  let calls = 0;
  const loop = startVisibleLoop(() => { calls++; }, () => 500);
  await settled();
  assert.equal(calls, 1);
  assert.equal(timers.values().next().value.ms, 500);
  setTrayHidden(true);
  assert.equal(timers.size, 0);
  hideDocument(true);
  hideDocument(false);
  await loop.run();
  assert.equal(calls, 1);
  setTrayHidden(false);
  assert.equal(calls, 2);
  await settled();
  hideDocument(true);
  assert.equal(timers.size, 0);
  hideDocument(false);
  assert.equal(calls, 3);
  loop.stop();
  await settled();
  setTrayHidden(true);
  setTrayHidden(false);
  assert.equal(calls, 3);
  assert.equal(timers.size, 0);
});

test("a show during an in-flight poll refreshes after it without overlap", async () => {
  const { startVisibleLoop, setTrayHidden, timers } = fixture();
  let calls = 0, finish;
  const loop = startVisibleLoop(() => new Promise((resolve) => { calls++; finish = resolve; }), 2000);
  setTrayHidden(true);
  setTrayHidden(false);
  assert.equal(calls, 1);
  finish();
  await settled();
  assert.equal(calls, 2);
  assert.equal(timers.size, 0);
  loop.stop();
  finish();
  await settled();
  assert.equal(timers.size, 0);
});
