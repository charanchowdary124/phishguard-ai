# Dataset Methodology

## Dataset Separation

Website and email datasets must remain separate. A website dataset contains URL observations and a
website label column. An email dataset contains subject/body observations and an email label column.
The application must not share training labels or split records across these datasets.

## Recommended Public Sources

- Legitimate and phishing URL datasets: verified public sources such as LegitPhish or PhiUSIIL.
- Phishing email datasets: verified public sources such as the zefang-liu phishing email dataset.
- Legitimate email examples: Enron, used only with an applicable dataset license.

Every downloaded dataset must have its URL, retrieval date, license, original file name, SHA-256
hash, and known limitations recorded before use. Do not invent labels or provenance.

## Required Preprocessing Checks

The `DatasetPreparationService` inspects CSV files and reports:

- column names and label columns;
- total, valid, and duplicate row counts;
- missing values per column;
- observed label frequencies and class imbalance;
- invalid required-column values.

The service does not automatically assign labels. Training pipelines must separately remove
duplicates, perform deterministic normalization, use a stratified split, and prevent URL-domain or
message-family leakage between train and test partitions.
