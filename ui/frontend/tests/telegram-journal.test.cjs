const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const source = (file) => readFileSync(path.join(__dirname, "../src", file), "utf8");

test("the routed Telegram screen passes live state to the disconnect journal", () => {
  const app = source("App.tsx");
  assert.match(app, /import\s*\{[^}]*\bTelegramScreen\b[^}]*\}\s*from "\.\/screens\/Pages"/);
  assert.match(app, /case "telegram":\s*return <TelegramScreen\b/);

  const pages = source("screens/Pages.tsx");
  const telegram = pages.slice(pages.indexOf("export function TelegramScreen"));
  assert.match(telegram, /<DisconnectJournalPanel\s+disconnects=\{state\?\.disconnects\}\s+switches=\{state\?\.switches\}/);
});
