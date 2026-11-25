# Security Policy

## Reporting

Do not publish credentials or private incident details in public issues. If private vulnerability
reporting is enabled for the GitHub repository, use that feature. Otherwise contact the project
maintainer privately; do not include sensitive data in a public issue.

## Security Boundaries

- No arbitrary URL is fetched by the application.
- Email HTML is stripped and not rendered.
- Uploaded files are not executed.
- Embedded email links are not opened.
- Bootstrap CSS is fetched from a version-pinned jsDelivr URL with Subresource Integrity; clients still contact that CDN. Self-host it for offline deployments.
- Registration passwords are BCrypt-hashed.
- REST API and session endpoints use Spring Security.

## Production Requirements

- Set a strong `DB_PASSWORD`.
- Activate `prod` with `SPRING_PROFILES_ACTIVE=prod`.
- Use TLS at a trusted reverse proxy or platform.
- Do not expose PostgreSQL ports publicly.
- Replace the in-memory H2 configuration in production.
- Replace rule baselines with evaluated, licensed datasets before making factual ML claims.
