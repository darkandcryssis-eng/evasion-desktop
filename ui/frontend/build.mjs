// Сборка интерфейса без Vite: esbuild → dist/. Нужна там, где нет node_modules
// проекта (CI, чистая машина). Обычная сборка — `npm run build` (Vite).
import { createRequire } from "node:module";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const extra = (process.env.NODE_PATH || "").split(/[:;]/).filter(Boolean);
const require = createRequire(join(root, "package.json"));
const esbuild = require(require.resolve("esbuild", { paths: [root, ...extra] }));
const dist = join(root, "dist");
rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, "assets"), { recursive: true });
await esbuild.build({
  absWorkingDir: root,
  entryPoints: ["src/main.tsx"],
  bundle: true,
  minify: true,
  format: "esm",
  target: ["chrome110"],
  outdir: "dist/assets",
  entryNames: "app",
  assetNames: "[name]-[hash]",
  publicPath: "/assets",
  jsx: "automatic",
  nodePaths: extra,
  loader: { ".jpg": "file", ".woff": "file", ".mp4": "file" },
  define: { "process.env.NODE_ENV": '"production"' },
  logLevel: "info",
});
writeFileSync(join(dist, "index.html"), `<!doctype html>
<html lang="ru">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#18181a" />
    <title>Evasion</title>
    <link rel="stylesheet" href="/assets/app.css" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/assets/app.js"></script>
  </body>
</html>
`);
