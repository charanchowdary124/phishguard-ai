package com.phishguard.ml;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ThreatAnalysisResult(
    String riskCategory,
    int riskScore,
    String summary,
    List<String> indicators,
    List<String> contributingModels,
    Map<String, Object> modelOutputs,
    List<String> recommendedActions,
    Instant analyzedAt
) {
}
