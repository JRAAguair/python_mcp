async function handle(ctx) {
  if (ctx.state.page) {
    try {
      await ctx.state.page.close();
    } catch {}
  }

  if (ctx.state.context) {
    try {
      await ctx.state.context.close();
    } catch {}
  }

  if (ctx.state.browser) {
    try {
      await ctx.state.browser.close();
    } catch {}
  }

  ctx.writeEvent("session_stopped", {
    url: ctx.state.currentUrl,
    message: "browser session stopped",
  });

  setTimeout(() => process.exit(0), 10);

  return { ok: true };
}

module.exports = { handle };
