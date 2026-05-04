async function handle(ctx) {
  if (!ctx.state.page) {
    throw new Error("page_not_initialized");
  }

  const localStorageItems = await ctx.state.page.evaluate(() => {
    return Object.entries(localStorage).map(([key, value]) => ({ key, value }));
  });

  const sessionStorageItems = await ctx.state.page.evaluate(() => {
    return Object.entries(sessionStorage).map(([key, value]) => ({ key, value }));
  });

  return {
    local_storage: localStorageItems,
    session_storage: sessionStorageItems,
  };
}

module.exports = { handle };
