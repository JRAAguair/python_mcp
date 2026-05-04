async function handle(ctx, payload) {
  const operationId = payload.operation_id;
  if (!operationId) {
    return { cancelled: false };
  }

  const token = ctx.state.pendingOperations.get(String(operationId));
  if (!token) {
    return { cancelled: false };
  }

  token.cancelled = true;
  return { cancelled: true };
}

module.exports = { handle };
