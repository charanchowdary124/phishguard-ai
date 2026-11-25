package com.phishguard.ml;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record EmailPredictionResult(
    String predictedClass,
    double probability,
    int riskScore,
    String riskCategory,
    List<String> suspiciousIndicators,
    Map<String, Double> extractedFeatures,
    String modelVersion,
    Instant predictionTimestamp,
    String explanation
) {
}
