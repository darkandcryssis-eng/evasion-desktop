const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

const source = readFileSync(path.join(__dirname, "../src/greeting.ts"), "utf8");
const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
const exportsObject = {};
vm.runInNewContext(code, { exports: exportsObject });

test("greeting changes at local time boundaries", () => {
  for (const [hour, minute, expected] of [
    [0, 0, "Доброй ночи, сова"], [4, 59, "Доброй ночи, сова"],
    [5, 0, "Доброе утро"], [11, 59, "Доброе утро"],
    [12, 0, "Добрый день"], [17, 59, "Добрый день"],
    [18, 0, "Добрый вечер"], [22, 59, "Добрый вечер"], [23, 0, "Доброй ночи, сова"],
  ]) {
    assert.equal(exportsObject.greetingAt(new Date(2026, 0, 1, hour, minute)), expected);
  }
});
