module.exports = {
  handle: async (ctx) => {
    return {
      current_url: ctx.state.currentUrl,
      previous_url: ctx.state.previousUrl,
      title: ctx.state.title,
      page_loaded: ctx.state.pageLoaded,
      authenticated: ctx.state.authenticated,
      javascript_enabled: ctx.state.javascriptEnabled,
      visited_urls: ctx.state.visitedUrls,
      network_entries: ctx.state.networkEntries,
      discovered_endpoints: Array.from(ctx.state.discoveredEndpoints),
      pending_operations: Array.from(ctx.state.pendingOperations.keys()),
    };
  },
};
