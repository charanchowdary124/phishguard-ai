package com.phishguard.service;

import com.phishguard.dto.AnalyticsResponse;
import com.phishguard.dto.DashboardResponse;
import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.entity.ScanHistory;
import com.phishguard.entity.ThreatIndicator;
import com.phishguard.entity.User;
import com.phishguard.repository.ScanHistoryRepository;
import com.phishguard.repository.ThreatIndicatorRepository;
import com.phishguard.repository.UserRepository;
import com.phishguard.util.HashUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
public class ScanHistoryService {

    private final ScanHistoryRepository scanHistoryRepository;
    private final ThreatIndicatorRepository threatIndicatorRepository;
    private final UserRepository userRepository;

    public ScanHistoryService(
        ScanHistoryRepository scanHistoryRepository,
        ThreatIndicatorRepository threatIndicatorRepository,
        UserRepository userRepository
    ) {
        this.scanHistoryRepository = scanHistoryRepository;
        this.threatIndicatorRepository = threatIndicatorRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public ScanHistory record(
        String username,
        String scanType,
        String originalInput,
        String inputSummary,
        String prediction,
        String riskCategory,
        int riskScore,
        String modelVersion,
        List<String> indicators
    ) {
        User user = userRepository.findByUsernameIgnoreCase(username)
            .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));

        ScanHistory scan = new ScanHistory();
        scan.setUser(user);
        scan.setScanType(scanType);
        scan.setInputHash(HashUtils.sha256Hex(originalInput));
        scan.setInputSummary(inputSummary);
        scan.setPrediction(prediction);
        scan.setRiskCategory(riskCategory);
        scan.setRiskScore(riskScore);
        scan.setModelVersion(modelVersion);
        scan = scanHistoryRepository.save(scan);

        for (String description : indicators) {
            ThreatIndicator indicator = new ThreatIndicator();
            indicator.setScan(scan);
            indicator.setDescription(description);
            threatIndicatorRepository.save(indicator);
        }
        return scan;
    }

    @Transactional(readOnly = true)
    public List<ScanHistoryResponse> historyFor(String username) {
        return historyFor(username, null, null, null, "newest");
    }

    @Transactional(readOnly = true)
    public List<ScanHistoryResponse> historyFor(
        String username,
        String search,
        String scanType,
        String riskLevel,
        String sortOrder
    ) {
        String normalizedSearch = normalizeSearch(search);
        String normalizedScanType = normalizeFilter(scanType, Set.of("URL", "EMAIL"), "scan type");
        String normalizedRiskLevel = normalizeFilter(
            riskLevel, Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL"), "risk level"
        );
        Sort sort = switch (normalizeSort(sortOrder)) {
            case "oldest" -> Sort.by(Sort.Order.asc("scannedAt"), Sort.Order.asc("id"));
            default -> Sort.by(Sort.Order.desc("scannedAt"), Sort.Order.desc("id"));
        };

        return scanHistoryRepository.searchMine(
                username,
                normalizedScanType == null ? "" : normalizedScanType,
                normalizedSearch,
                sort
            ).stream()
            .filter(scan -> normalizedRiskLevel == null
                || scan.getRiskCategory().equalsIgnoreCase(normalizedRiskLevel)
                || ("HIGH".equals(normalizedRiskLevel)
                    && "CRITICAL".equalsIgnoreCase(scan.getRiskCategory())))
            .map(this::toResponse)
            .toList();
    }

    @Transactional(readOnly = true)
    public ScanHistoryResponse findFor(String username, Long id) {
        return scanHistoryRepository.findByIdAndUserUsernameIgnoreCase(id, username)
            .map(this::toResponse)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Scan history record not found"
            ));
    }

    @Transactional
    public void deleteFor(String username, Long id) {
        ScanHistory scan = scanHistoryRepository.findByIdAndUserUsernameIgnoreCase(id, username)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "Scan history record not found"
            ));
        scanHistoryRepository.delete(scan);
    }

    @Transactional(readOnly = true)
    public AnalyticsResponse analyticsFor(String username) {
        List<ScanHistory> scans = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc(username);
        return summarize(scans);
    }

    @Transactional(readOnly = true)
    public DashboardResponse dashboardFor(String username) {
        List<ScanHistory> scans = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc(username);
        List<ScanHistoryResponse> recentActivity = scans.stream()
            .limit(5)
            .map(this::toResponse)
            .toList();
        List<ScanHistoryResponse> latestHighRisk = scans.stream()
            .filter(this::isHighRisk)
            .limit(5)
            .map(this::toResponse)
            .toList();
        return new DashboardResponse(summarize(scans), recentActivity, latestHighRisk);
    }

    private AnalyticsResponse summarize(List<ScanHistory> scans) {
        long phishing = scans.stream()
            .filter(scan -> "PHISHING".equalsIgnoreCase(scan.getPrediction()))
            .count();
        long legitimate = scans.stream()
            .filter(scan -> "LEGITIMATE".equalsIgnoreCase(scan.getPrediction()))
            .count();
        long url = scans.stream()
            .filter(scan -> "URL".equalsIgnoreCase(scan.getScanType()))
            .count();
        long email = scans.stream()
            .filter(scan -> "EMAIL".equalsIgnoreCase(scan.getScanType()))
            .count();
        long highRisk = scans.stream()
            .filter(this::isHighRisk)
            .count();
        long lowRisk = scans.stream()
            .filter(scan -> "LOW".equalsIgnoreCase(scan.getRiskCategory()))
            .count();
        long mediumRisk = scans.stream()
            .filter(scan -> "MEDIUM".equalsIgnoreCase(scan.getRiskCategory()))
            .count();
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        Map<LocalDate, Long> dailyCounts = new HashMap<>();
        for (int daysAgo = 6; daysAgo >= 0; daysAgo--) {
            dailyCounts.put(today.minusDays(daysAgo), 0L);
        }
        for (ScanHistory scan : scans) {
            LocalDate scanDate = scan.getScannedAt().atZone(ZoneOffset.UTC).toLocalDate();
            if (dailyCounts.containsKey(scanDate)) {
                dailyCounts.compute(scanDate, (date, count) -> count + 1);
            }
        }
        List<AnalyticsResponse.DailyActivity> dailyActivity = dailyCounts.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(entry -> new AnalyticsResponse.DailyActivity(entry.getKey(), entry.getValue()))
            .toList();
        return new AnalyticsResponse(
            scans.size(),
            url,
            email,
            phishing,
            legitimate,
            highRisk,
            dailyActivity,
            new AnalyticsResponse.RiskDistribution(lowRisk, mediumRisk, highRisk),
            new AnalyticsResponse.ScanTypeComparison(url, email)
        );
    }

    private boolean isHighRisk(ScanHistory scan) {
        return "HIGH".equalsIgnoreCase(scan.getRiskCategory())
            || "CRITICAL".equalsIgnoreCase(scan.getRiskCategory());
    }

    private ScanHistoryResponse toResponse(ScanHistory scan) {
        return new ScanHistoryResponse(
            scan.getId(),
            scan.getScanType(),
            scan.getInputHash(),
            scan.getInputSummary(),
            scan.getPrediction(),
            scan.getRiskCategory(),
            scan.getRiskScore(),
            scan.getModelVersion(),
            scan.getScannedAt(),
            scan.getIndicators().stream()
                .map(indicator -> indicator.getDescription())
                .toList()
        );
    }

    private String normalizeSearch(String search) {
        if (search == null || search.isBlank()) {
            return "";
        }
        String normalized = search.trim();
        if (normalized.length() > 2048) {
            throw new IllegalArgumentException("Search text must not exceed 2048 characters");
        }
        return normalized;
    }

    private String normalizeFilter(String value, Set<String> allowed, String label) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!allowed.contains(normalized)) {
            throw new IllegalArgumentException("Unsupported " + label);
        }
        return normalized;
    }

    private String normalizeSort(String value) {
        String normalized = value == null ? "newest" : value.trim().toLowerCase(Locale.ROOT);
        if (!normalized.equals("newest") && !normalized.equals("oldest")) {
            throw new IllegalArgumentException("Sort order must be newest or oldest");
        }
        return normalized;
    }
}
