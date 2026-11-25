# API Documentation

OpenAPI UI is available at `/swagger-ui/index.html` in the running application.

## Register

`POST /api/auth/register`

```json
{"username":"analyst1","email":"analyst1@example.com","password":"StrongPass!123"}
```

## URL Scan

`POST /api/scan/url`

```json
{"url":"https://example.com/login"}
```

## Email Scan

`POST /api/scan/email`

```json
{"subject":"Verify account","body":"Confirm your password.","sender":"alerts@example.com"}
```

## Bulk Scan

`POST /api/scan/bulk`

Multipart field: `file`

The CSV must contain a `url` column. Maximum size: 10 MB. Maximum records: 1000.

## Reports

- `POST /api/reports/url/csv`
- `POST /api/reports/url/pdf`
- `GET /api/reports/{id}`

## History and Analytics

- `GET /api/history?search=&scanType=URL|EMAIL&riskLevel=LOW|MEDIUM|HIGH&sort=newest|oldest`
- `GET /api/history/{id}`
- `DELETE /api/history/{id}` (only the owning user)
- `GET /api/analytics`
- `GET /api/dashboard`

Analytics includes a 7-day daily activity series, LOW/MEDIUM/HIGH risk distribution, and URL/email
scan totals, all calculated from the authenticated user's stored scans.

History results include the sanitized URL/subject preview and detection indicators. Search, type,
risk, and date-order filters are optional. Older records without a stored preview remain available.

## Models

- `GET /api/models/status`
- `GET /api/models/performance`

Both model endpoints expose rule-baseline status honestly. They do not publish fabricated metrics.

## Authentication

- `POST /api/auth/login`
- `POST /api/auth/logout` (authenticated, CSRF protected)

These session-based endpoints require a CSRF token. Browser clients can read the token and
header name from the `_csrf` and `_csrf_header` meta tags on `/login` or `/register`.

## Profile

- `GET /api/profile`
- `PUT /api/profile` (username and email)
- `POST /api/profile/password` (current password and a complexity-validated new password)

Profile responses contain account metadata only; password hashes are never returned.

## Administration

- `GET /api/admin/users`
- `GET /api/admin/audit-logs`

Admin endpoints require `ROLE_ADMIN`.
