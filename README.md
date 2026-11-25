# PhishGuard AI

## Abstract

PhishGuard AI is a Java-based cybersecurity application that performs local URL and email
phishing-risk analysis. It combines deterministic structural indicators, explainable risk
categories, Spring Security, JPA persistence, and a Thymeleaf dashboard. It does not fetch
submitted URLs or execute uploaded email content.

## Problem Statement

Users and security analysts need understandable, auditable indicators before trusting a
suspicious website or email. External paid APIs and opaque predictions are unsuitable for
privacy-focused academic and portfolio environments.

## Motivation

The project targets Java 21 and uses Spring Boot, Spring Security, JPA, local rule-based
analysis, database security, PDF/CSV reports, Docker, and automated tests in one
cybersecurity application.

## Objectives

- Analyze URL and email text without outbound URL fetching or attachment execution.
- Keep deterministic rule results, indicators, and any future model outputs clearly distinguished.
- Explain risk categories and recommended defensive actions.
- Authenticate users and protect role-specific operations.
- Persist only necessary scan metadata and SHA-256 input hashes.
- Provide CSV/PDF reports and testable REST APIs.

## Existing and Proposed Systems

Existing solutions often depend on remote reputation APIs or opaque model services. PhishGuard AI
uses a local-first architecture. The current scanner outputs are deterministic rule baselines; real
labelled datasets and trained Tribuo models are required before accuracy claims.

## System Architecture

The application uses layered MVC architecture:

```text
Thymeleaf / REST Controllers
        |
Security + Validation + Exception Handling
        |
Deterministic URL/email analysis + History / Report / Registration Services
        |
Spring Data JPA Repositories
        |
H2 (development) / PostgreSQL (production)
```

URL and email text are analyzed locally without fetching submitted URLs. The authenticated API
returns the rule-based result and stores user-scoped scan metadata; persistence keeps a SHA-256
input hash and a sanitized URL preview or email subject rather than full submitted content.

## Status

The application currently provides tested URL and email deterministic rule baselines:

- URL model version: `url-rule-v1`
- Email model version: `email-rule-v2`

These baselines are **not trained ML models** and have no published accuracy. No model metrics,
screenshots, or security effectiveness claims are fabricated. Tribuo dependencies are included,
but they are not currently used by the deterministic prediction services. Apache OpenNLP is also
present as a dependency; no trained NLP pipeline is active.

## Technology

- Java 21 or later runtime; Java 21 source and bytecode target
- Spring Boot 4.1.3 (Spring Framework 7.0.11)
- Spring MVC, Security, Data JPA
- Thymeleaf
- H2 local database
- PostgreSQL production database
- Oracle Tribuo (included for planned training; not active in current rule baselines)
- Apache OpenNLP (dependency present; no trained NLP pipeline currently active)
- Apache Commons CSV
- OpenPDF
- JUnit 6 and Mockito support

## Requirements

- JDK 21 or later with `JAVA_HOME` configured.
- Internet access on the first Maven Wrapper run so it can download the pinned Maven 3.9.11
  distribution. A separately installed Maven is not required.

## Run Locally

```powershell
.\mvnw.cmd clean test
.\mvnw.cmd spring-boot:run
```

On macOS/Linux, use `sh ./mvnw` with the same Maven goals; this also works if the wrapper's
executable bit is not preserved when the project is first added to Git on Windows.

Open `http://localhost:8080/login`.

The H2 console is enabled only for local development at `/h2-console`.

## Production

For the loopback-only HTTP Compose demo, copy `.env.example` to `.env` only if `.env` does not
already exist. Set a unique local `DB_PASSWORD`; Compose intentionally rejects the blank example
value. Never overwrite an existing `.env` or commit it. Then run:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
notepad .env
docker compose -p phishguard-demo up --build -d
```

The multi-stage Docker build compiles, tests, and packages the application before copying
the JAR into the runtime image.

Compose binds the application only to `127.0.0.1:8080`.
The Compose profile uses PostgreSQL and Flyway; existing schemas are baselined at version 1 and
receive only subsequent migrations. Hibernate validates the schema at startup. Compose defaults
the secure-cookie flag off because this example binds HTTP to loopback only. For production,
terminate TLS at a trusted proxy and explicitly set `SESSION_COOKIE_SECURE=true`.

### Render deployment preparation

The root `render.yaml` is a deployment blueprint for a temporary college demo. It defines a
Docker web service, a private PostgreSQL database, and the health check. The production profile
prefers Render's `PORT` value while retaining `SERVER_PORT` and port 8080 as local fallbacks.
The blueprint requires `TRUSTED_PROXY_INTERNALS` to be supplied during setup; do not use a
wildcard or broad network range. Confirm the trusted proxy source address with the hosting
platform before relying on forwarded HTTPS headers.

The blueprint uses Render's free plans to avoid provisioning charges. Render documents that free
web services spin down when idle and free Postgres databases expire after 30 days, so this setup
is for a short demonstration, not production or durable data retention. No Render service has
been created or deployed from this repository.

## Security

- URLs are analyzed as strings; arbitrary URLs are never fetched.
- Email HTML is stripped to text and is never rendered as a trusted HTML document.
- Links and attachments are never opened or executed.
- Bootstrap CSS is fetched from a version-pinned jsDelivr URL with Subresource Integrity; browsers still contact that CDN.
- Bulk uploads are limited to 10 MB and 1000 URL rows.
- Passwords use BCrypt.
- Five failed login attempts trigger a 15-minute account lockout; successful login resets the counter.
- CSRF, security headers, session limits, login locking, and API rate limiting are configured.

## Main Endpoints

- `POST /api/auth/register`
- `POST /api/scan/url`
- `POST /api/scan/email`
- `POST /api/scan/bulk`
- `POST /api/reports/url/csv`
- `POST /api/reports/url/pdf`
- `GET /api/public/health`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/history`
- `GET /api/history/{id}`
- `GET /api/dashboard`
- `GET /api/analytics`
- `GET|PUT /api/profile`
- `POST /api/profile/password`
- `GET /api/models/status`
- `GET /api/models/performance`
- `GET /api/reports/{id}`
- `GET /api/admin/users`
- `GET /api/admin/audit-logs`

## Testing

```powershell
.\mvnw.cmd clean test
.\mvnw.cmd clean package
```

Browser end-to-end tests use Playwright and start the application with an isolated in-memory H2
database:

```powershell
npm ci
npx playwright install chromium
npm run test:e2e
```

## Final Demonstration Walkthrough

1. Prepare `.env` as described in the Production section, then start the Docker application:
   `docker compose -p phishguard-demo up --build -d`.
2. Confirm PostgreSQL is healthy with `docker compose -p phishguard-demo ps`, then open
   `http://127.0.0.1:8080/login`.
3. Register a throwaway demo account and sign in. Show the dashboard and its scan counts.
4. Analyze `https://example.com` as a low-indicator example, then
   `http://login-secure.example.test/verify?token=demo` as a suspicious-rule example.
5. Analyze a fictional routine meeting email, then a fictional message requesting a password or
   one-time code. Do not use real email content.
6. Open scan history, inspect details, and show that the stored preview excludes URL query data
   and email body/sender content.
7. Open threat analytics, update the profile, and verify the updated details remain visible.
8. Sign out and show that the protected dashboard redirects to login.
9. Optionally restart only the app with `docker compose -p phishguard-demo restart app`; sign in
   again and confirm the account and history remain. Do not stop or remove the database volume.
10. Explain that Compose uses PostgreSQL/Flyway, keeps PostgreSQL on an internal network, and binds
    the app to `127.0.0.1:8080`. Mention the public health endpoint and the model status: analysis
    currently uses deterministic rule baselines, not a trained model.

Use a throwaway demo account and do not enter real credentials or sensitive email contents.

### Suggested 5–7 Minute Presentation

- **0:00–0:45 — Problem and design:** Introduce phishing risks and the goal of a private, user-scoped
  scanner. Briefly describe the Spring Boot API, web UI, PostgreSQL, and Docker architecture.
- **0:45–1:30 — Registration and dashboard:** Create a throwaway account, sign in, and show the
  dashboard.
- **1:30–2:30 — Scanning:** Run the two safe URL examples and the fictional email examples above.
- **2:30–3:30 — History, analytics, and profile:** Show user-scoped persisted history, summary
  counts, and profile management.
- **3:30–4:15 — Security and persistence:** Explain BCrypt, CSRF/session protection, ownership
  checks, loopback-only binding, and PostgreSQL's named volume. Optionally restart only `app`.
- **4:15–5:00 — Testing and limitations:** Report the latest verified 75/75 backend tests and
  8/8 Playwright tests. Clarify that Playwright uses isolated H2 test data; Docker/PostgreSQL
  workflows were separately verified. State that rule-based analysis can produce false
  positives/negatives and has no trained-model accuracy claim.
- **5:00–7:00 — Questions:** Use the remaining time for the evaluator's questions.

**Short spoken script:** “PhishGuard AI is a web application for demonstrating phishing-risk
analysis of submitted URLs and email text. The application uses Spring Boot and Spring Security,
with a browser UI and PostgreSQL persistence in the Docker deployment. A user can register, scan
safe sample inputs, and review their own history and analytics. Submitted URLs are analyzed as
text; the app does not visit them. Passwords are hashed, requests use session and CSRF protections,
and the demo is bound to localhost. The current detector is deterministic and rule-based, not a
trained machine-learning model, so results are illustrative and can include false positives or
false negatives. The backend suite passed 75 tests and the Playwright suite passed 8 tests; the
PostgreSQL deployment path was verified separately.”

**Likely viva questions:**

- **Does it use machine learning?** No. Current scan decisions use deterministic rules; no trained
  model or accuracy claim is included.
- **How is user data protected?** Spring Security controls authenticated routes, CSRF is enabled
  for browser sessions, and history queries are scoped to the current user.
- **Does URL scanning visit submitted sites?** No. It analyzes the URL string without making a
  request to that destination.
- **How does data survive an app restart?** PostgreSQL stores the records in a named Docker
  volume; the app container can restart independently.
- **What are the limitations?** Heuristic rules may misclassify inputs; the app does not perform
  live site inspection or claim trained-model performance.

## Screenshots

No screenshots are currently included. Add genuine captures of the dashboard, scanner results,
history, and analytics after running the application; do not use fabricated results or real user
data.

## Limitations

- Rule baselines can produce false positives and false negatives.
- No real public datasets are bundled or trained here.
- Scan history and dashboard/analytics statistics use persisted records; history stores a sanitized
  URL preview or email subject, not full email content.
- The default development H2 database is in-memory; use the production PostgreSQL profile/volume
  when scan data must persist across application restarts.
- The in-process API rate limiter is per instance; multi-instance deployments should also enforce
  limits at a trusted gateway or shared rate-limiting service.
- Live website inspection and DNS lookups are intentionally omitted; URLs are analyzed as strings
  to avoid visiting arbitrary targets and leaking submitted domains.
- No claimed model accuracy or production metrics are available yet.
- Bulk email processing and real Tribuo training require additional dataset work.

## Future Scope

- Add licensed, reproducible URL and email datasets.
- Train and evaluate Tribuo classifiers using stratified domain/message-aware splits.
- Implement model versioning and calibration.
- Add pagination, retention controls, and richer database-backed analytics.
- If live URL inspection is ever added, require strict SSRF controls and explicit approval first.

## References

- Spring Boot and Spring Security documentation
- Oracle Tribuo documentation
- Apache Commons CSV and Apache OpenNLP documentation
- OWASP Secure Coding Practices
- OWASP SSRF Prevention Cheat Sheet

## Project Documentation

- [Architecture and data flow](docs/architecture.md)
- [API reference](docs/API.md)
- [Database schema and migrations](docs/database.md)
- [Detection methodology and limitations](docs/methodology.md)
- [Dataset methodology](docs/dataset-methodology.md)
- [Deployment and migration guidance](docs/deployment.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License](LICENSE)
