package com.phishguard.dto;

import java.time.LocalDate;
import java.util.List;

public record AnalyticsResponse(
    long totalScans,
    long urlScans,
    long emailScans,
    long phishingDetections,
    long legitimateDetections,
    long highRiskThreats,
    List<DailyActivity> dailyActivity,
    RiskDistribution riskDistribution,
    ScanTypeComparison scanTypeComparison
) {
    public record DailyActivity(LocalDate date, long totalScans) {
    }

    public record RiskDistribution(long low, long medium, long high) {
    }

    public record ScanTypeComparison(long urlScans, long emailScans) {
    }
}
