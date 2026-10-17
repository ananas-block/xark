// Open a URL in a Playwright engine and keep it open until terminated (run.py's
// launcher for non-Chrome browsers). Usage: node pw_launch.mjs <engine> <url>
import { createRequire } from "node:module";

const require = createRequire(`${process.env.PLAYWRIGHT_DIR ?? process.cwd()}/`);
const pw = require("playwright");
const [engine, url] = process.argv.slice(2);
const browser = await pw[engine].launch();
const page = await browser.newPage();
await page.goto(url);
const close = async () => {
  await browser.close();
  process.exit(0);
};
process.on("SIGTERM", close);
process.on("SIGINT", close);
await new Promise(() => {});
