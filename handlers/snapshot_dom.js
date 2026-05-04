async function handle(ctx, payload) {
  if (!ctx.state.page) {
    throw new Error("page_not_initialized");
  }

  const html = payload.include_html
    ? await ctx.state.page.content()
    : "";

  const visibleText = payload.include_text
    ? await ctx.state.page.evaluate(() => document.body?.innerText || "")
    : "";

  const forms = payload.include_forms
    ? await ctx.state.page.evaluate(() => {
        return Array.from(document.querySelectorAll("input, textarea, select")).map((el) => ({
          tag: el.tagName.toLowerCase(),
          type: el.getAttribute("type") || "",
          name: el.getAttribute("name") || "",
          id: el.getAttribute("id") || "",
          value: "value" in el ? String(el.value || "") : "",
          placeholder: el.getAttribute("placeholder") || "",
          required: !!el.required,
          disabled: !!el.disabled,
        }));
      })
    : [];

  const links = payload.include_links
    ? await ctx.state.page.evaluate(() => {
        return Array.from(document.querySelectorAll("a[href]")).map((a) => {
          const href = a.href || "";
          let sameOrigin = false;
          try {
            sameOrigin = new URL(href).origin === window.location.origin;
          } catch {}
          return {
            text: (a.innerText || "").trim(),
            href,
            same_origin: sameOrigin,
          };
        });
      })
    : [];

  const importantNodes = await ctx.state.page.evaluate(() => {
    return Array.from(document.querySelectorAll("form, button, input, textarea, select, a"))
      .slice(0, 128)
      .map((el) => ({
        tag: el.tagName.toLowerCase(),
        id: el.id || "",
        classes: Array.from(el.classList || []),
        text_excerpt: (el.innerText || el.textContent || "").trim().slice(0, 200),
      }));
  });

  return {
    url: ctx.state.page.url(),
    title: await ctx.state.page.title(),
    html,
    visible_text: visibleText,
    forms,
    links,
    important_nodes: importantNodes,
    node_count: importantNodes.length,
    truncated: false,
  };
}

module.exports = { handle };
