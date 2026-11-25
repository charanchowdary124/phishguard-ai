# Contributing

1. Fork the repository and create a focused branch.
2. Keep URL and email data pipelines separate.
3. Do not add fabricated labels or model metrics.
4. Add JUnit tests for behavior and security changes.
5. Run `.\mvnw.cmd clean test` before opening a pull request.
6. Never commit secrets, private datasets, email samples, credentials, or model training data.

The project targets Java 21. Browser end-to-end tests can be run with `npm ci`,
`npx playwright install chromium`, and `npm run test:e2e`; they use a disposable in-memory H2
database and must not be pointed at production data.
