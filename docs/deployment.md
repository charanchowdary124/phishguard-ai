# Deployment

## Local Development

Requires JDK 21 or later. The standard Maven Wrapper downloads Maven 3.9.11 on first use, so a
separate Maven installation is not required. Internet access is required for the initial download.

```powershell
$env:JAVA_HOME="C:\Path\To\Your\JDK-21"
$env:PATH="$env:JAVA_HOME\bin;$env:PATH"
.\mvnw.cmd clean test
.\mvnw.cmd spring-boot:run
```

Open `http://localhost:8080/login`.

## Docker Compose

Copy `.env.example` to `.env` only if `.env` does not already exist, then set a unique local
`DB_PASSWORD`. The example intentionally leaves it blank so Compose refuses to start until it is
configured. Never overwrite an existing `.env` or commit it. The sample Compose configuration uses
HTTP on loopback and sets `SESSION_COOKIE_SECURE=false` for local browser testing only.

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
docker compose -p phishguard-demo up --build -d
```

The compose configuration binds the application only to `127.0.0.1:8080`. PostgreSQL is not
published to a host port. This is an HTTP-only local demo; do not expose it publicly.

## Production Configuration

Set:

- `SPRING_PROFILES_ACTIVE=prod`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `SESSION_TIMEOUT_MINUTES`
- `SESSION_COOKIE_SECURE=true` (required outside the local HTTP demo)
- `TRUSTED_PROXY_INTERNALS` to a narrow Tomcat regular expression matching only the trusted
  reverse proxy's source address as seen by the application
- `PORT` to the hosting platform's assigned HTTP port when deploying to a platform that supplies
  one; `SERVER_PORT` remains the fallback for local/container deployments

The production profile defaults `SESSION_COOKIE_SECURE=true`. For Docker Compose deployments, use
the production override, which forces the setting to true while leaving the local HTTP demo
unchanged:

```powershell
$env:TRUSTED_PROXY_INTERNALS = "<regex matching only the trusted proxy source address>"
docker compose -p phishguard-prod -f compose.yml -f compose.prod.yml up -d
```

Terminate TLS at a trusted reverse proxy or platform before traffic reaches the application. This
project does not configure TLS certificates or terminate HTTPS itself; the command above does not
make HTTPS active. Keep the application reachable only from the trusted proxy, and configure that
proxy to remove or overwrite client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`,
and `X-Forwarded-Proto` headers before adding its own. Tomcat's native forwarded-header handling
uses `TRUSTED_PROXY_INTERNALS` to accept those headers only from matching peer addresses. Do not
use a broad private-network range unless every matching host is trusted. The production Compose
override requires an explicit proxy allowlist and forces secure session cookies; keep the local
HTTP Compose configuration for local browser testing only.

Keep database credentials in a secret manager, and restrict network access to the application and
database. If the trusted proxy does not forward a recognized HTTPS scheme, Spring Security will
not emit HSTS based on the request; configure HSTS at the TLS-terminating proxy in that case.

## Render demo blueprint

The root `render.yaml` prepares a Render Docker web service and PostgreSQL database. The web
service uses the public health endpoint, the `prod` profile, a secure session cookie, and Render's
assigned `PORT`. The database is configured for private-network-only access and its connection
values are injected by Render rather than stored in this repository.

The blueprint requires a `TRUSTED_PROXY_INTERNALS` value at creation. Supply only a narrow,
verified expression for the actual trusted proxy source address; do not use `.*` or a broad
private-network expression. Confirm the source address with Render before treating forwarded
headers or application-generated HSTS as trusted. Render terminates public TLS for deployed web
services, but no service, certificate, or public URL is configured or verified by this repository
change.

The blueprint selects free plans so it does not provision paid resources. Render's free web
service can spin down while idle, and its free PostgreSQL database expires after 30 days. This
option is suitable only for a temporary demonstration and does not provide durable production
storage. Before creating resources, review Render's current plan limits and explicitly choose a
paid persistent database if long-term data retention is required.

Before creating the blueprint, confirm that the resource names in `render.yaml` do not collide
with existing Render services or databases. Blueprint synchronization can modify resources with
matching names.

Flyway baselines an existing non-empty schema at version 1, then applies later migrations.
Fresh databases run the complete migration chain. Hibernate validates the schema instead of
automatically changing it. Confirm the configured database target before first startup; migrations
must run against the intended database.

### Existing PostgreSQL installations

Before deploying this migration to an existing installation:

1. Take and verify a restorable database backup, and test the upgrade against a staging copy.
2. Confirm `DB_HOST`, `DB_PORT`, and `DB_NAME` identify the intended database. Stop if the
   existing schema does not match the application's pre-migration schema.
3. If the schema contains application tables but no `flyway_schema_history`, the production
   profile baselines it at version 1. Flyway records that baseline; it does not execute V1
   against the existing tables.
4. Flyway then applies V2, which only adds the nullable `users.locked_until` column if absent.
   The migration does not drop, truncate, recreate, or delete application data.
5. If `flyway_schema_history` already exists, do not baseline again; review its current version
   and let Flyway apply only pending migrations.
6. Confirm startup completes Hibernate schema validation before routing traffic. Investigate any
   validation or migration error rather than changing `ddl-auto` to `update`.

For a fresh, empty database, Flyway executes V1 and V2 normally. Do not manually execute V1 on
an existing database; the configured baseline is the intended adoption path.
