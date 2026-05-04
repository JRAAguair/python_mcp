async function handle(ctx, payload) {
  if (!ctx.state.page) {
    throw new Error("page_not_initialized");
  }

  const startedAt = Date.now();

  try {
    const value = await ctx.state.page.evaluate(async (code) => {
      return await eval(code);
    }, payload.code);

    return {
      value_json: value,
      console_text: "",
      exception_text: "",
      duration_ms: Date.now() - startedAt,
    };
  } catch (err) {
    return {
      value_json: null,
      console_text: "",
      exception_text: err?.message || String(err),
      duration_ms: Date.now() - startedAt,
    };
  }
}

module.exports = { handle };
