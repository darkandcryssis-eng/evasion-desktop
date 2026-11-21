const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

const source = readFileSync(path.join(__dirname, "../src/telegramBadge.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const exportsObject = {};
vm.runInNewContext(code, { exports: exportsObject });
const badge = (state) => ({ ...exportsObject.telegramBadge({ running: true, connections: 1, failures: 0, ...state }) });

test("a healthy remaining channel stays green despite previous failures", () => {
  assert.deepEqual(badge({ phase: "online", failures: 10 }), { label: "Есть обмен данными", tone: "success" });
});
test("an interrupted channel and its next attempt use the recovery badge", () => {
  for (const phase of ["degraded", "connecting"]) {
    assert.deepEqual(badge({ phase, failures: 1 }), { label: "Возобновление", tone: "warning" });
  }
});
test("first connection is not reported as recovery", () => {
  assert.deepEqual(badge({ phase: "connecting", connections: 0 }), { label: "Выбираем маршрут…", tone: "neutral" });
});
test("stopping the proxy ends the recovery indication", () => {
  assert.deepEqual(badge({ phase: "degraded", running: false, failures: 10 }), { label: "Выключен", tone: "neutral" });
});
