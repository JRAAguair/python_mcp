const readline = require("node:readline");
const { chromium, firefox, webkit } = require("playwright");

const bootstrap = require("../handlers/bootstrap");
const shutdown = require("../handlers/shutdown");
const navigate = require("../handlers/navigate");
const getPageInfo = require("../handlers/get_page_info");
const snapshotDom = require("../handlers/snapshot_dom");
const collectScripts = require("../handlers/collect_scripts");
const collectNetwork = require("../handlers/collect_network");
const getCookies = require("../handlers/get_cookies");
const getStorage = require("../handlers/get_storage");
const evalJs = require("../handlers/eval_js");
const cancelOperation = require("../handlers/cancel_operation");
const getSessionState = require("../handlers/get_session_state.js");

const state = {
  browser: null,
  context: null,
  page: null,
  currentUrl: "",
  previousUrl: "",
  title: "",
  pageLoaded: false,
  authenticated: false,
  javascriptEnabled: true,
  visitedUrls: [],
  recentUrls: [],
  networkEntries: [],
  discoveredEndpoints: new Set(),
  pendingOperations: new Map(),
};

function debugStderr(msg){
  process.stderr.write(String(msg) + "\n");
}
function nowIso() {
  return new Date().toISOString();
}

function writeReply(id, ok, payload = {}, error = "") {
  process.stdout.write(
    JSON.stringify({
      type: "reply",
      id,
      ok,
      payload,
      error,
    }) + "\n"
  );
}

function writeEvent(event, payload = {}) {
  process.stdout.write(
    JSON.stringify({
      type: "event",
      event,
      timestamp: nowIso(),
      payload,
    }) + "\n"
  );
}

function writeError(error) {
  process.stdout.write(
    JSON.stringify({
      type: "error",
      error: String(error || "unknown_error"),
    }) + "\n"
  );
}

const ctx = {
  state,
  engines: { chromium, firefox, webkit },
  writeEvent,
};

const handlers = {
  bootstrap,
  shutdown,
  navigate,
  get_page_info: getPageInfo,
  snapshot_dom: snapshotDom,
  collect_scripts: collectScripts,
  collect_network: collectNetwork,
  get_cookies: getCookies,
  get_storage: getStorage,
  eval_js: evalJs,
  cancel_operation: cancelOperation,
  get_session_state: getSessionState,
};

async function dispatchMessage(msg) {
  const id = msg?.id ?? null;
  const cmd = msg?.cmd ?? "";
  const payload = msg?.payload ?? {};

  const handler = handlers[cmd];
  if (!handler || typeof handler.handle !== "function") {
    writeReply(id, false, {}, `unknown_command: ${cmd}`);
    return;
  }

  try {
    const result = await handler.handle(ctx, payload);
    writeReply(id, true, result ?? {}, "");
  } catch (err) {
    writeReply(id, false, {}, err?.message || String(err));
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

let commandChain = Promise.resolve();
rl.on("line", (line) => {
  if(!line.trim()) return;
commandChain = commandChain.then(async()=>{
    let msg;
    try{
      msg = JSON.parse(line);
    }catch(err){
      writeError(`invalid_json: ${String(err)}`);
      return;
    }
    await dispatchMessage(msg);
  }).catch((err) =>{
  writeError(`dispatch_chain_error: ${err?.stack || String(err)}`);
  });
});

process.on("uncaughtException", (err) => {
  writeError(`uncaught_exception: ${err?.stack || String(err)}`);
});

process.on("unhandledRejection", (err) => {
  writeError(`unhandled_rejection: ${err?.stack || String(err)}`);
});
