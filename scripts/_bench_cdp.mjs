// CDP-driven verification of the Benchmarks UI served by the live daemon.
// Temporary script — deleted after the run. Uses Node 25's global WebSocket.
const CDP_PORT = 9223;
const APP = "http://127.0.0.1:8765";
const TOKEN = (await import("node:fs")).readFileSync(".webui_secret_key", "utf8").trim();

const { spawn } = await import("node:child_process");
const chrome = spawn(
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  [
    "--headless=new",
    `--remote-debugging-port=${CDP_PORT}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--user-data-dir=" + process.env.TEMP + "\\bench-cdp-profile",
    "--window-size=1440,900",
    "about:blank",
  ],
  { stdio: "ignore" },
);
await new Promise((r) => setTimeout(r, 2500));

const targets = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json`)).json();
console.error("targets:", targets.map((t) => `${t.type}:${t.url}`).join(" | "));
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
console.error("ws connecting…");
await new Promise((res, rej) => { ws.onopen = () => { console.error("ws open"); res(); }; ws.onerror = (e) => rej(new Error("ws error")); });
console.error("ws connected");

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
    if (!text.includes("Download the React DevTools")) consoleErrors.push(`[console.${msg.params.type}] ${text}`);
  } else if (msg.method === "Runtime.exceptionThrown") {
    consoleErrors.push(`[exception] ${msg.params.exceptionDetails?.exception?.description ?? JSON.stringify(msg.params.exceptionDetails).slice(0, 300)}`);
  } else if (msg.method === "Network.responseReceived") {
    const s = msg.params.response.status;
    if (s >= 400 && !msg.params.response.url.includes("/api/v1/benchmarks/compare?run_a=2026")) {
      failedRequests.push(`${s} ${msg.params.response.url}`);
    }
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
// Seed the session token before any app script runs.
await send("Page.addScriptToEvaluateOnNewDocument", {
  source: `sessionStorage.setItem('breachpilot.apiToken.v1', ${JSON.stringify(TOKEN)});
sessionStorage.setItem('breachpilot.welcome.v1', '1');
sessionStorage.setItem('breachpilot.onboarding.v1', '1');`,
});

async function goto(url) {
  await send("Page.navigate", { url });
  await new Promise((r) => setTimeout(r, 1500));
}
async function waitFor(selector, timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (await evalJs(`!!document.querySelector(${JSON.stringify(selector)})`)) return true;
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

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
}, 120000);

// ── 1. Direct navigation to /benchmarks (fresh load = refresh equivalent)
await goto(`${APP}/benchmarks`);
const appMounted = await waitFor("[data-testid='run-benchmark-panel']");
check("direct nav mounts the app on /benchmarks", appMounted);
await waitFor("[data-testid='benchmark-metric-cards']");
check("overview + latest-run data renders (metric cards)", await evalJs("!!document.querySelector(\"[data-testid='benchmark-metric-cards']\")"));
check("history charts render", await evalJs("!!document.querySelector(\"[data-testid='benchmark-history']\")"));
check("baseline card renders from overview.baseline", await evalJs("!!document.querySelector(\"[data-testid='benchmark-baseline']\")"));
check("history table shows both seeded runs", await evalJs("document.querySelectorAll(\"tbody tr\").length >= 2"));
check("suite select is pre-populated", await evalJs("document.querySelector('#bench-suite')?.value === 'xben'"));
await new Promise((r) => setTimeout(r, 800));
check("scenario checklist auto-loaded for default suite", await evalJs("!!document.querySelector('#bench-scenario-xben-dvwa')"));

// ── 2. Explicit refresh on the route
await send("Page.reload");
await waitFor("[data-testid='run-benchmark-panel']");
check("refresh on /benchmarks keeps working", await evalJs("!!document.querySelector(\"[data-testid='run-benchmark-panel']\")"));

// ── 3. Deep link to a run detail (direct navigation)
await goto(`${APP}/benchmarks/20260830_120000_00002`);
await waitFor("[data-testid='benchmark-metric-cards']");
check("deep link to run detail renders summary", await evalJs("!!document.querySelector(\"[data-testid='benchmark-metric-cards']\")"));
check("run page shows no interrupted banner for completed run", await evalJs("!document.querySelector(\"[data-testid='benchmark-interrupted-banner']\")"));
check("trials tab shows the recorded trial", await evalJs("document.body.textContent.includes('xben-dvwa')"));

// ── 4. Deep link to an orphaned (stale 'running') run
await goto(`${APP}/benchmarks/20260831_010450_09800`);
await waitFor("[data-testid='benchmark-interrupted-banner']");
check("orphaned run shows interrupted banner", await evalJs("!!document.querySelector(\"[data-testid='benchmark-interrupted-banner']\")"));
check("orphaned run shows no live pill", await evalJs("!document.body.textContent.includes('live ·')"));

// ── 5. Responsive audit at 3 widths (page must not overflow horizontally)
for (const w of [1440, 768, 360]) {
  await send("Emulation.setDeviceMetricsOverride", { width: w, height: 900, deviceScaleFactor: 1, mobile: w < 700 });
  await goto(`${APP}/benchmarks`);
  await waitFor("[data-testid='run-benchmark-panel']");
  const overflow = await evalJs(
    "(() => { const d = document.scrollingElement; return { sw: d.scrollWidth, cw: d.clientWidth }; })()",
  );
  check(`no page-level horizontal overflow @${w}px`, overflow.sw <= overflow.cw + 1, JSON.stringify(overflow));
}
await send("Emulation.clearDeviceMetricsOverride");

// ── 6. Comparison interaction: pick two runs and compare
await goto(`${APP}/benchmarks`);
await waitFor("[data-testid='benchmark-comparison']");
const picked = await evalJs(
  `(() => {
     const sels = [...document.querySelectorAll("[data-testid='benchmark-comparison'] select")];
     if (sels.length < 2) return "missing selects";
     const opts = [...sels[0].querySelectorAll("option")].filter(o => o.value);
     if (opts.length < 2) return "not enough runs";
     const setVal = (el, v) => {
       const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set;
       setter.call(el, v);
       el.dispatchEvent(new Event('change', { bubbles: true }));
     };
     setVal(sels[0], opts[0].value);
     setVal(sels[1], opts[1].value);
     return { a: opts[0].value, b: opts[1].value };
   })()`,
);
check("comparison pickers populated", typeof picked === "object", JSON.stringify(picked));
const cmpBtn = await evalJs(
  "[...document.querySelectorAll(\"[data-testid='benchmark-comparison'] button\")].find(b => b.textContent.includes('Compare'))?.textContent ?? 'missing'",
);
check("compare button present", String(cmpBtn).includes("Compare"), String(cmpBtn));
await evalJs(
  "(() => { const b=[...document.querySelectorAll(\"[data-testid='benchmark-comparison'] button\")].find(b => b.textContent.includes('Compare')); b.click(); return 'ok'; })()",
);
await new Promise((r) => setTimeout(r, 1200));
check("comparison table renders metric rows", await evalJs("document.querySelectorAll(\"[data-testid='benchmark-comparison'] tbody tr\").length >= 6"));

// ── 7. Sorting + filtering on the run detail trials table
await goto(`${APP}/benchmarks/20260830_120000_00002`);
await waitFor("[data-testid='scenario-results-table']");
const sorted = await evalJs(
  `(() => {
     const th = [...document.querySelectorAll("[data-testid='scenario-results-table'] th button")];
     const time = th.find(b => b.textContent.includes('Time'));
     time.click();
     const th2 = time.closest('th');
     return { ariaSort: th2.getAttribute('aria-sort'), isButton: true };
   })()`,
);
check("sortable headers are keyboard-accessible buttons with aria-sort", sorted?.ariaSort === "ascending", JSON.stringify(sorted));

// ── 8. Accessibility spot checks
await goto(`${APP}/benchmarks`);
await waitFor("[data-testid='run-benchmark-panel']");
const a11y = await evalJs(
  `(() => {
     const buttons = [...document.querySelectorAll('button')].filter(b => !b.textContent.trim() && !b.getAttribute('aria-label'));
     const selectsNoLabel = [...document.querySelectorAll('select')].filter(s => !s.labels?.length && !s.getAttribute('aria-label'));
     return { unlabeledIconButtons: buttons.length, selectsNoLabel: selectsNoLabel.length };
   })()`,
);
check("no unlabeled icon buttons on dashboard", a11y.unlabeledIconButtons === 0, JSON.stringify(a11y));
check("all selects have accessible names", a11y.selectsNoLabel === 0, JSON.stringify(a11y));

console.log(JSON.stringify(results, null, 1));
ws.close();
chrome.kill();
process.exit(0);
