async function handle(ctx, payload) {
  if (!ctx.state.page) {
    throw new Error("page_not_initialized");
  }

  const scripts = await ctx.state.page.evaluate((includeContent) => {
    return Array.from(document.scripts).map((s, idx) => ({
      id: `script-${idx}`,
      kind: s.src ? "external" : "inline",
      url: s.src || "",
      source_code: includeContent && !s.src ? (s.textContent || "") : "",
      integrity: s.integrity || "",
      type: s.type || "",
      async_attr: !!s.async,
      defer_attr: !!s.defer,
      module: s.type === "module",
      truncated: false,
    }));
  }, !!payload.include_content);

  const discoveredScriptUrls = scripts
    .filter((s) => s.url)
    .map((s) => s.url);

  return {
    url: ctx.state.page.url(),
    scripts,
    discovered_script_urls: discoveredScriptUrls,
    inline_count: scripts.filter((s) => s.kind === "inline").length,
    external_count: scripts.filter((s) => s.kind === "external").length,
    truncated: false,
  };
}

module.exports = { handle };
