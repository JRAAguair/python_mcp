async function handle(ctx) {
  return {
    current_url: ctx.state.currentUrl,
    previous_url: ctx.state.previousUrl,
    title: ctx.state.title,
    page_loaded: ctx.state.pageLoaded,
    authenticated: ctx.state.authenticated,
    javascript_enabled: ctx.state.javascriptEnabled,
    visited_urls: ctx.state.visitedUrls,
    recent_urls: ctx.state.recentUrls,
  };
}

module.exports = { handle };
