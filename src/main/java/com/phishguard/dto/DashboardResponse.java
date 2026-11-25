package com.phishguard.dto;

import java.util.List;

public record DashboardResponse(
    AnalyticsResponse statistics,
    List<ScanHistoryResponse> recentActivity,
    List<ScanHistoryResponse> latestHighRisk
) {
}
