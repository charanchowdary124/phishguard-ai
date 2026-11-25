# Database Schema

## users

- `id`
- unique `username`
- unique `email`
- BCrypt `password_hash`
- role
- enabled flag
- failed login count
- nullable `locked_until` timestamp (added by V2)
- creation timestamp

Flyway V1 creates the baseline tables. For a fresh database Flyway runs V1 and V2; for an
existing matching schema the production profile records baseline version 1 and runs only later
migrations. V2 only adds the nullable lock-expiry column and does not replace existing rows.

## scan_history

- primary key
- foreign key to `users`
- scan type
- SHA-256 input hash
- sanitized display summary (URL without credentials/query/fragment, or email subject only)
- prediction
- risk category and score
- model version
- scan timestamp
- full URL/email content is not stored; existing records without a summary remain valid

## threat_indicators

- primary key
- foreign key to `scan_history`
- indicator description

## model_registry

- unique model version
- model type
- active flag
- registration timestamp

## audit_logs

- username
- action
- details
- occurrence timestamp
