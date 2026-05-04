async function handle(ctx) {
  if (!ctx.state.context) {
    throw new Error("context_not_initialized");
  }

  const cookies = await ctx.state.context.cookies();

  return {
    cookies: cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      same_site: c.sameSite || "",
      secure: !!c.secure,
      http_only: !!c.httpOnly,
      session: !!c.session,
      expires_unix: Number.isFinite(c.expires) ? Math.trunc(c.expires) : 0,
    })),
  };
}

module.exports = { handle };
