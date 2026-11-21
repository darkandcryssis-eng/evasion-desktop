const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");
const source = readFileSync(path.join(__dirname, "../src/speedChart.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const exportsObject = {};
vm.runInNewContext(code, { exports: exportsObject });
const chart = exportsObject.speedChart;

test("empty speed history stays empty without synthetic activity", () => {
  const result = chart([]);
  assert.equal(result.count, 0);
  assert.equal(result.up, "");
  assert.equal(result.scale, 1024);
});
test("speed chart rejects malformed values and clips history to two minutes", () => {
  const samples = [
    { at: "2026-11-11T10:00:00Z", up: 100, down: 100 },
    { at: "2026-11-11T10:03:00Z", up: 512, down: 2048 },
    { at: "bad", up: 3, down: 4 },
    { at: "2026-11-11T10:03:01Z", up: -1, down: Infinity },
  ];
  const result = chart(samples);
  assert.equal(result.count, 1);
  assert.equal(result.scale, 2048);
  assert.equal(result.down, "600,8");
  assert.equal(result.current.up, 512);
});
test("idle traffic produces a flat zero line", () => {
  const result = chart([0, 1].map((second) => ({ at: `2026-11-11T10:00:0${second}Z`, up: 0, down: 0 })));
  assert.equal(result.down, "595,104 600,104");
});
