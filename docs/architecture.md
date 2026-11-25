# Architecture

```text
Thymeleaf / Browser REST client
        |
Spring Security + MVC Controllers + Request Validation
        |
URL / Email Deterministic Analysis + History / Profile / Reports
        |
Spring Data JPA Repositories
        |
H2 (local) / PostgreSQL (production)
```

## Request and Data Flow

1. A user submits URL or email text through the authenticated browser UI or API. Session-based
   requests use CSRF protection.
2. Controllers validate request DTOs and call local feature extractors and deterministic scoring
   services. URL analysis does not resolve DNS or make HTTP requests; email content and links are
   not executed.
3. Scan results are returned with the deterministic rule version, risk category, and indicators.
4. Persistence associates each scan with its authenticated user and stores a SHA-256 input hash,
   a sanitized URL preview or email subject, prediction metadata, and indicator rows. Full email
   body/sender content and URL query strings are not stored.
5. History, dashboard, analytics, profile, and admin queries are protected by Spring Security;
   user scan queries are scoped to the authenticated username.

The package layout follows Spring conventions:

- `controller`: HTTP endpoints
- `service`: business services
- `repository`: JPA repositories
- `entity`: persistence entities
- `dto`: validated request and response records
- `ml`: feature extraction and prediction
- `security`: authentication and request controls
- `exception`: centralized API errors
- `util`: reusable utilities
