function makeRequestIdFactory() {
  let seq = 0;
  return () => {
    seq += 1;
    return `req-${Date.now()}-${seq}`;
  };
}

function truncateText(value, maxLen = 8192) {
  if (typeof value !== "string") {
    return { text: "", truncated: false };
  }

  if (value.length <= maxLen) {
    return { text: value, truncated: false };
  }

  return {
    text: value.slice(0, maxLen),
    truncated: true,
  };
}

function safeUrlPath(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}

async function safeClose(target) {
  if (!target || typeof target.close !== "function") return;
  try {
    await target.close();
  } catch {}
}

async function safeAllHeaders(response) {
  try {
    const headers = await response.allHeaders();
    return Object.entries(headers).map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

async function safePageTitle(page) {
  if (!page || page.isClosed?.()) return "";
  try {
    return await page.title();
  } catch {
    return "";
  }
}

async function resetPreviousSession(ctx) {
  await safeClose(ctx.state.page);
  await safeClose(ctx.state.context);
  await safeClose(ctx.state.browser);

  ctx.state.browser = null;
  ctx.state.context = null;
  ctx.state.page = null;

  ctx.state.currentUrl = "";
  ctx.state.previousUrl = "";
  ctx.state.title = "";
  ctx.state.pageLoaded = false;
  ctx.state.authenticated = false;
  ctx.state.javascriptEnabled = true;
  ctx.state.visitedUrls = [];
  ctx.state.recentUrls = [];
  ctx.state.networkEntries = [];
  ctx.state.discoveredEndpoints = new Set();
  ctx.state.pendingOperations = new Map();
}

function buildLaunchOptions(payload) {
  const proxyEnabled = payload?.proxy?.enabled !== false && !!payload?.proxy?.server;

  const launchOptions = {
    headless: payload.headless !== false,
    devtools: !!payload.devtools,
  };

  if (proxyEnabled) {
    launchOptions.proxy = {
      server: payload.proxy.server,
      bypass: payload.proxy.bypass || undefined,
      username: payload.proxy.username || undefined,
      password: payload.proxy.password || undefined,
    };
  }

  return launchOptions;
}

function buildContextOptions(payload, proxyEnabled) {
  const ignoreHTTPSErrors =
    payload.ignore_https_errors !== undefined
      ? !!payload.ignore_https_errors
      : proxyEnabled;

  return {
    ignoreHTTPSErrors,
    javaScriptEnabled: payload.enable_javascript !== false,
    userAgent: payload.user_agent || undefined,
    locale: payload.locale || undefined,
    timezoneId: payload.timezone_id || undefined,
    viewport: payload.viewport || undefined,
    recordHar: payload.record_har || undefined,
  };
}

function attachPageObserversToPage(ctx, page) {
  const makeRequestId = makeRequestIdFactory();
  const requestIds = new WeakMap();
  const requestStartedAt = new Map();
  const entriesById = new Map();

  page.on("request", async (request) => {
    const requestId = makeRequestId();
    const startedAt = Date.now();

    requestIds.set(request, requestId);
    requestStartedAt.set(requestId, startedAt);

    const rawBody =
      typeof request.postData === "function" ? request.postData() || "" : "";
    const body = truncateText(rawBody);

    const entry = {
      id: requestId,
      frame_url: request.frame()?.url() || "",
      failed: false,
      failure_text: "",
      duration_ms: 0,
      request: {
        id: requestId,
        url: request.url(),
        method: request.method(),
        resource_type: request.resourceType?.() || "unknown",
        headers: Object.entries(request.headers()).map(([name, value]) => ({
          name,
          value,
        })),
        body: body.text,
        truncated: body.truncated,
      },
      response: {
        status: 0,
        status_text: "",
        headers: [],
        body: "",
        truncated: false,
      },
    };

    entriesById.set(requestId, entry);
    ctx.state.networkEntries.push(entry);

    const path = safeUrlPath(request.url());
    if (path) {
      ctx.state.discoveredEndpoints.add(path);
    }

    ctx.writeEvent("request_started", {
      request_id: requestId,
      url: request.url(),
      method: request.method(),
      message: "request started",
    });
  });

  page.on("response", async (response) => {
    const request = response.request();
    const requestId = requestIds.get(request) || "";
    const entry = requestId ? entriesById.get(requestId) : null;

    if (entry) {
      entry.response.status = response.status();
      entry.response.status_text = response.statusText();
      entry.response.headers = await safeAllHeaders(response);
    }

    ctx.writeEvent("response_received", {
      request_id: requestId,
      url: response.url(),
      method: request.method(),
      status: response.status(),
      message: "response received",
    });
  });

  page.on("requestfinished", (request) => {
    const requestId = requestIds.get(request) || "";
    const entry = requestId ? entriesById.get(requestId) : null;
    const startedAt = requestStartedAt.get(requestId);

    if (entry && typeof startedAt === "number") {
      entry.duration_ms = Math.max(0, Date.now() - startedAt);
    }

    if (requestId) {
      requestStartedAt.delete(requestId);
    }
  });

  page.on("requestfailed", (request) => {
    const requestId = requestIds.get(request) || "";
    const entry = requestId ? entriesById.get(requestId) : null;
    const startedAt = requestStartedAt.get(requestId);

    if (entry) {
      entry.failed = true;
      entry.failure_text = request.failure()?.errorText || "request failed";
      if (typeof startedAt === "number") {
        entry.duration_ms = Math.max(0, Date.now() - startedAt);
      }
    }

    if (requestId) {
      requestStartedAt.delete(requestId);
    }

    ctx.writeEvent("request_failed", {
      request_id: requestId,
      url: request.url(),
      method: request.method(),
      message: request.failure()?.errorText || "request failed",
    });
  });

  page.on("domcontentloaded", async () => {
    ctx.state.previousUrl = ctx.state.currentUrl;
    ctx.state.currentUrl = page.url();

    ctx.writeEvent("dom_content_loaded", {
      url: ctx.state.currentUrl,
      message: "DOMContentLoaded",
    });
  });

  page.on("load", async () => {
    ctx.state.previousUrl = ctx.state.currentUrl;
    ctx.state.currentUrl = page.url();
    ctx.state.title = await safePageTitle(page);
    ctx.state.pageLoaded = true;

    ctx.writeEvent("load_finished", {
      url: ctx.state.currentUrl,
      message: "load event",
    });
  });

  page.on("console", (msg) => {
    ctx.writeEvent("console_message", {
      url: page.url(),
      message: msg.text(),
    });
  });

  page.on("pageerror", (err) => {
    ctx.writeEvent("runtime_error", {
      url: page.url(),
      message: err?.message || String(err),
    });
  });
}

function attachPageObservers(ctx){
  attachPageObserversToPage(ctx, ctx.state.page);
    ctx.state.context.on("page", async (newPage) => {
    ctx.state.page = newPage;
    attachPageObserversToPage(ctx, newPage);
    ctx.writeEvent("new_page_attached", {
      url: newPage.url(),
      message: "new page attached",
    });
  });
}
async function handle(ctx, payload = {}) {
  await resetPreviousSession(ctx);

  const browserName = payload.browser || "chromium";
  const engine = ctx.engines[browserName] || ctx.engines.chromium;

  const proxyEnabled =
    payload?.proxy?.enabled !== false && !!payload?.proxy?.server;

  const launchOptions = buildLaunchOptions(payload);
  const contextOptions = buildContextOptions(payload, proxyEnabled);

  ctx.state.browser = await engine.launch(launchOptions);
  ctx.state.context = await ctx.state.browser.newContext(contextOptions);
  ctx.state.page = await ctx.state.context.newPage();

  attachPageObservers(ctx);

  if (payload.start_url) {
    await ctx.state.page.goto(payload.start_url, {
      waitUntil: "domcontentloaded",
    });

    ctx.state.currentUrl = ctx.state.page.url();
    ctx.state.title = await safePageTitle(ctx.state.page);
    ctx.state.pageLoaded = true;
    ctx.state.visitedUrls.push(ctx.state.currentUrl);
    ctx.state.recentUrls.push(ctx.state.currentUrl);
  }

  return {
    ok: true,
    current_url: ctx.state.currentUrl,
    title: ctx.state.title,
    page_loaded: ctx.state.pageLoaded,
    javascript_enabled: ctx.state.javascriptEnabled,
  };
}

module.exports = { handle };