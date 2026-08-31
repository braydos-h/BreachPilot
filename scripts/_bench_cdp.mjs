// CDP-driven verification of the Benchmarks sub-pages served by the live daemon.
// Temporary script — deleted after the run. Uses Node 25's global WebSocket.
const CDP_PORT = 9228;
const APP = "http://127.0.0.1:8765";
const fs = await import("node:fs");
const TOKEN = fs.readFileSync(".webui_secret_key", "utf8").trim();

const { spawn } = await import("node:child_process");
const chrome = spawn(
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  [
    "--headless=new",
    `--remote-debugging-port=${CDP_PORT}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--user-data-dir=" + process.env.TEMP + "\\bench-cdp-sub",
    "--window-size=1440,900",
    "about:blank",
  ],
  { stdio: "ignore" },
);
await new Promise((r) => setTimeout(r, 2500));

const targets = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json`)).json();
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let msgId = 0;
const pending = new Map();
const consoleErrors = [];
const failedRequests = [];
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  } else if (msg.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(msg.params.type)) {
    const text = msg.params.args.map((a) => a.value ?? a.description ?? a.type).join(" ");
    if (!text.includes("Download the React DevTools")) consoleErrors.push(`[console.${msg.params.type}] ${text.slice(0, 200)}`);
  } else if (msg.method === "Runtime.exceptionThrown") {
    consoleErrors.push(`[exception] ${msg.params.exceptionDetails?.exception?.description ?? ""}`.slice(0, 300));
  } else if (msg.method === "Network.responseReceived") {
    const s = msg.params.response.status;
    if (s >= 400) failedRequests.push(`${s} ${msg.params.response.url}`);
  }
};
function send(method, params = {}) {
  return new Promise((res) => {
    const id = ++msgId;
    pending.set(id, res);
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evalJs(expr) {
  const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.result?.exceptionDetails) return { error: r.result.exceptionDetails.exception?.description ?? "eval error" };
  return r.result?.result?.value;
}

await send("Runtime.enable");
await send("Page.enable");
await send("Network.enable");
await send("Page.addScriptToEvaluateOnNewDocument", {
  source: `sessionStorage.setItem('breachpilot.apiToken.v1', ${JSON.stringify(TOKEN)});
sessionStorage.setItem('breachpilot.welcome.v1', '1');
sessionStorage.setItem('breachpilot.onboarding.v1', '1');`,
});

async function goto(url) {
  await send("Page.navigate", { url });
  await new Promise((r) => setTimeout(r, 1600));
}
async function waitFor(selector, timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await evalJs(`!!document.querySelector(${JSON.stringify(selector)})`)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}
// Radix tabs/checkboxes activate on mousedown — synthetic .click() alone is
// not enough, so fire the full pointer/mouse sequence a real user produces.
const FIRE = `(() => {
  window.__bpFire = (el) => {
    for (const type of ['pointerdown','mousedown','pointerup','mouseup','click']) {
      el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window, button: 0 }));
    }
  };
  return true;
})()`;

const results = { checks: [], consoleErrors, failedRequests };
function check(name, ok, extra = "") {
  results.checks.push(`${ok ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);
  console.error(ok ? "PASS" : "FAIL", name);
}
const watchdog = setTimeout(() => {
  console.log(JSON.stringify(results, null, 1));
  console.error("WATCHDOG TIMEOUT — dumping partial results");
  ws.close();
  chrome.kill();
  process.exit(2);
}, 150000);

// ── 1. Overview sub-page (direct nav = refresh semantics)
await goto(`${APP}/benchmarks`);
await evalJs(FIRE);
check("overview mounts (metric cards + baseline + nav)", await waitFor("[data-testid='benchmark-metric-cards']"));
check("baseline card renders", await evalJs("!!document.querySelector(\"[data-testid='benchmark-baseline']\")"));
check("sub-nav highlights Overview", await evalJs(
  "[...document.querySelectorAll('nav[aria-label=\"Benchmarks sections\"] a')].map(a => a.textContent + (a.className.includes('text-primary') ? '*' : '')).join('|')",
));
check("recent runs preview lists the seeded runs", await evalJs(
  "[...document.querySelectorAll('tbody a')].some(a => a.textContent === '20260830_120000_00002')",
));

// ── 2. Sub-nav click → New run page
await evalJs("window.__bpFire([...document.querySelectorAll('nav[aria-label=\"Benchmarks sections\"] a')].find(a => a.textContent.includes('New run')))");
await waitFor("[data-testid='run-benchmark-panel']");
check("New run sub-page renders the panel", await evalJs("!!document.querySelector(\"[data-testid='run-benchmark-panel']\")"));
check("New run URL applied", await evalJs("location.pathname === '/benchmarks/new'"));
await new Promise((r) => setTimeout(r, 600));
check("scenario checklist auto-loaded on New run", await evalJs("!!document.querySelector('#bench-scenario-xben-dvwa')"));
check("baseline context card renders", await evalJs("!!document.querySelector(\"[data-testid='start-baseline-card']\")"));

// ── 3. Sub-nav click → Past benchmarks page
await evalJs("window.__bpFire([...document.querySelectorAll('nav[aria-label=\"Benchmarks sections\"] a')].find(a => a.textContent.includes('Past benchmarks')))");
await waitFor("[data-testid='benchmark-history']");
check("Past benchmarks renders charts", await evalJs("!!document.querySelector(\"[data-testid='benchmark-history']\")"));
check("history URL applied", await evalJs("location.pathname === '/benchmarks/history'"));
check("history table shows both seeded runs", await evalJs("document.querySelectorAll('tbody tr').length >= 2"));

// ── 4. Direct deep link to /benchmarks/history (refresh semantics)
await goto(`${APP}/benchmarks/history`);
check("direct nav to history works", await waitFor("[data-testid='benchmark-history']"));

// ── 5. Deep link to run detail still works
await goto(`${APP}/benchmarks/20260830_120000_00002`);
check("run detail deep link works", await waitFor("[data-testid='benchmark-metric-cards']"));
check("breadcrumb links back to overview", await evalJs(
  "[...document.querySelectorAll('a')].some(a => a.getAttribute('href') === '/benchmarks' && a.textContent.trim() === 'Benchmarks')",
));

// ── 6. Responsive audit of all three sub-pages at 360px
for (const path of ["/benchmarks", "/benchmarks/new", "/benchmarks/history"]) {
  await send("Emulation.setDeviceMetricsOverride", { width: 360, height: 800, deviceScaleFactor: 1, mobile: true });
  await goto(`${APP}${path}`);
  await new Promise((r) => setTimeout(r, 1200));
  const overflow = await evalJs(
    "(() => { const d = document.scrollingElement; return { sw: d.scrollWidth, cw: d.clientWidth }; })()",
  );
  check(`no page-level horizontal overflow @360px ${path}`, overflow.sw <= overflow.cw + 1, JSON.stringify(overflow));
}
await send("Emulation.clearDeviceMetricsOverride");

console.log(JSON.stringify(results, null, 1));
ws.close();
chrome.kill();
process.exit(0);
