# API responses

Shapes of `POST /api/public/v1/subscription/status` (tunnelsats-v2-web, `src/app/api/public/v1/subscription/status/route.ts`): the 200 body is a flat object (`expiry`, `bandwidth_used_gb`, `bandwidth_limit_gb`, `bandwidth_resets_this_month`, `max_resets_per_month`, `status`, `server_domain`, `vpn_port`, `last_synced_at`); errors use `{"error": "ERR_...", "message": ...}` (404 `ERR_RESOURCE_NOT_FOUND`, 503 `ERR_SERVICE_UNAVAILABLE` with `Retry-After`, 429 `ERR_RATE_LIMIT_EXCEEDED`, 403 `ERR_MIGRATION_REQUIRED`, 500 `ERR_INTERNAL_ERROR`).
