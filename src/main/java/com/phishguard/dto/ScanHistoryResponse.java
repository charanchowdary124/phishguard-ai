package com.phishguard.dto;

import java.time.Instant;
import java.util.List;

public record ScanHistoryResponse(
    Long id,
    String scanType,
    String inputHash,
    String inputSummary,
    String prediction,
    String riskCategory,
    int riskScore,
    String modelVersion,
    Instant scannedAt,
    List<String> indicators
) {
}
