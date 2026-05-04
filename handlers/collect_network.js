async function handle(ctx) {
  return {
    page_url: ctx.state.currentUrl,
    entries: ctx.state.networkEntries,
    discovered_endpoints: Array.from(ctx.state.discoveredEndpoints),
    truncated: false,
  };
}

module.exports = { handle };
