package com.phishguard.dto;

import com.phishguard.ml.UrlPredictionResult;

public record BulkUrlResult(
    int row,
    String url,
    String status,
    UrlPredictionResult result
) {
}
