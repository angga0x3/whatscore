# Configuration

All configuration is provided through environment variables — the same
binary works unchanged in Docker, bare metal, and CI. Copy
[`.env.example`](../.env.example) to `.env` and adjust.

## Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | `WhatsCore` | Instance name, reported by `/version`. |
| `APP_ENV` | `development` | `production` enables JSON logs and strict validation. |
| `APP_PORT` | `8080` | HTTP listen port (1–65535). |
| `APP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `DATABASE_URL` | — (required) | PostgreSQL connection string, e.g. `postgres://whatscore:password@localhost:5432/whatscore?sslmode=disable`. |
| `DB_MIGRATE_ON_STARTUP` | `true` | Apply embedded schema migrations at startup. Set `false` when you apply migrations out-of-band. |
| `API_KEY_REQUIRED` | `true` | Enforce Bearer authentication on `/api/v1` endpoints. |
| `WHATSAPP_SESSION_LIMIT` | `10` | Maximum concurrent sessions. |
| `MEDIA_STORAGE` | `local` | Media backend (`local` for MVP). |
| `MEDIA_PATH` | `./storage/media` | Filesystem path for media binaries. |
| `MEDIA_MAX_SIZE_MB` | `50` | Upload size limit. |
| `WEBHOOK_TIMEOUT_SECONDS` | `10` | Per-request timeout for webhook deliveries. |
| `WEBHOOK_MAX_RETRIES` | `10` | Maximum delivery attempts per event. |
| `ENCRYPTION_KEY` | — | Secret for encrypting webhook signing secrets at rest. **Required when `APP_ENV=production`.** |

## Secrets

- Generate encryption keys with `openssl rand -base64 32`.
- Never commit `.env`. The default `ENCRYPTION_KEY` is intentionally empty:
  the server refuses to start in production without a real secret.
- `DATABASE_URL` and `POSTGRES_PASSWORD` are credentials — treat them like
  passwords. WhatsCore logs only the host portion, never credentials.

## Docker Compose specifics

`docker-compose.yml` consumes `.env` for both containers:

- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` configure the
  PostgreSQL container.
- `DATABASE_URL` must use host `postgres` (the Compose service name) when
  running the full stack; use `localhost` only for bare-metal runs.
- `APP_PORT` maps the published port.

## Applying migrations without startup auto-migration

The binary embeds its migrations, so `DB_MIGRATE_ON_STARTUP=true` (default)
is the zero-ops path. Operators who prefer explicit control can set
`DB_MIGRATE_ON_STARTUP=false` and apply the same files with the
golang-migrate CLI:

```bash
migrate -path ./migrations -database "$DATABASE_URL" up
```

## Validation behavior

Invalid values fail fast at startup with a descriptive error (wrong port
range, unknown log level, non-boolean flags, missing required variables).
The process exits before opening a port — misconfiguration never half-boots.
