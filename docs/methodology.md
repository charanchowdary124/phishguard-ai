# Machine Learning and Rule Methodology

## Current Baseline

The current application uses explicit, tested deterministic rule baselines:

- `url-rule-v1`
- `email-rule-v2`

They are not trained machine-learning models and must not be described as having ML accuracy.

## URL Analysis

The URL extractor inspects:

- URL, domain, path, and query lengths
- HTTPS presence
- IP-address use
- subdomains and hyphenated domains
- suspicious keywords
- special characters
- entropy
- URL-shortening domains
- query parameter count
- credentials or misleading text placed before the hostname

The URL score is a documented weighted rule score, capped to a 0.05–0.95 probability range.
It is not calibrated model probability.

URL endpoint categories are LOW (0–34), MEDIUM (35–64), and HIGH (65–100). Localhost,
private/link-local IPs, and known metadata hostnames are rejected. The analyzer does not resolve
DNS, follow redirects, or make HTTP requests; it analyzes URL strings locally to avoid visiting
untrusted targets.

## Email Analysis

The email extractor safely strips HTML and inspects:

- urgent language
- password or credential requests
- one-time or verification-code requests
- account verification requests
- payment requests
- requests for sensitive financial details
- embedded links
- risky attachment names
- sender/domain mismatches
- malformed sender addresses

HTML is removed as text, never rendered, and attachments and links are never executed or opened.

## Unified Risk Policy

The unified service uses the maximum source risk and distinct deterministic indicator count.
It does not average unrelated model probabilities.

Risk thresholds:

- LOW: 0–34
- MEDIUM: 35–64
- HIGH: 65–100

## Dataset Methodology

Website and email datasets remain separate. A real implementation must:

- record provenance and license
- inspect labels and class balance
- remove duplicates
- handle missing values
- use stratified splitting
- prevent domain/message-family leakage
- evaluate precision, recall, F1, ROC-AUC, PR-AUC, confusion matrix, and calibration
- serialize the model and expose only verified version metrics
