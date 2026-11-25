package com.phishguard.controller;

import com.phishguard.dto.AnalyticsResponse;
import com.phishguard.dto.ApiResponse;
import com.phishguard.dto.DashboardResponse;
import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.service.ScanHistoryService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;

@RestController
public class HistoryController {

    private final ScanHistoryService scanHistoryService;

    public HistoryController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping("/api/history")
    public ApiResponse<List<ScanHistoryResponse>> history(
        @RequestParam(required = false) String search,
        @RequestParam(required = false) String scanType,
        @RequestParam(required = false) String riskLevel,
        @RequestParam(defaultValue = "newest") String sort,
        Principal principal
    ) {
        return ApiResponse.ok(
            "Scan history retrieved",
            scanHistoryService.historyFor(
                principal.getName(), search, scanType, riskLevel, sort
            )
        );
    }

    @GetMapping("/api/history/{id}")
    public ApiResponse<ScanHistoryResponse> historyItem(
        @PathVariable Long id,
        Principal principal
    ) {
        return ApiResponse.ok(
            "Scan history item retrieved",
            scanHistoryService.findFor(principal.getName(), id)
        );
    }

    @DeleteMapping("/api/history/{id}")
    public ApiResponse<Object> deleteHistoryItem(
        @PathVariable Long id,
        Principal principal
    ) {
        scanHistoryService.deleteFor(principal.getName(), id);
        return ApiResponse.ok("Scan history record deleted", null);
    }

    @GetMapping("/api/analytics")
    public ApiResponse<AnalyticsResponse> analytics(Principal principal) {
        return ApiResponse.ok(
            "Analytics retrieved",
            scanHistoryService.analyticsFor(principal.getName())
        );
    }

    @GetMapping("/api/dashboard")
    public ApiResponse<DashboardResponse> dashboard(Principal principal) {
        return ApiResponse.ok(
            "Dashboard data retrieved",
            scanHistoryService.dashboardFor(principal.getName())
        );
    }
}
