function waitUntilFromInt(value) {
  if (value === 1) return "domcontentloaded";
  if (value === 2) return "load";
  if (value === 3) return "networkidle";
  return "load";
}

async function handle(ctx, payload) {
  if (!ctx.state.page) {
    throw new Error("page_not_initialized");
  }

  const url = payload.url;
  if (!url) {
    throw new Error("missing_url");
  }

  ctx.state.previousUrl = ctx.state.currentUrl;

  ctx.writeEvent("navigation_started", {
    url,
    message: "navigation started",
  });

  const startedAt = Date.now();

  const response = await ctx.state.page.goto(url, {
    waitUntil: waitUntilFromInt(payload.wait_until),
    timeout: payload.timeout_ms || 30000,
  });

  ctx.state.currentUrl = ctx.state.page.url();
  ctx.state.title = await ctx.state.page.title();
  ctx.state.pageLoaded = true;

  if (payload.record_in_history !== false) {
    ctx.state.visitedUrls.push(ctx.state.currentUrl);
    ctx.state.recentUrls.push(ctx.state.currentUrl);
    if (ctx.state.recentUrls.length > 16) {
      ctx.state.recentUrls.shift();
    }
  }

  ctx.writeEvent("navigation_finished", {
    url: ctx.state.currentUrl,
    status: response ? response.status() : 0,
    message: "navigation finished",
  });

  return {
    url: ctx.state.currentUrl,
    title: ctx.state.title,
    http_status: response ? response.status() : 0,
    duration_ms: Date.now() - startedAt,
    page_loaded: true,
    navigation_committed: true,
  };
}

module.exports = { handle };
