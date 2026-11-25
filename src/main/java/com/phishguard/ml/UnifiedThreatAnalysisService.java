package com.phishguard.ml;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class UnifiedThreatAnalysisService {

    public ThreatAnalysisResult analyze(
        UrlPredictionResult urlResult,
        EmailPredictionResult emailResult
    ) {
        List<String> indicators = new ArrayList<>();
        List<String> contributingModels = new ArrayList<>();
        Map<String, Object> modelOutputs = new LinkedHashMap<>();

        int score = 0;
        if (urlResult != null) {
            indicators.addAll(urlResult.suspiciousIndicators());
            if (!urlResult.suspiciousIndicators().isEmpty()) {
                contributingModels.add(urlResult.modelVersion());
            }
            modelOutputs.put("website", urlResult);
            score = Math.max(score, urlResult.riskScore());
        }
        if (emailResult != null) {
            indicators.addAll(emailResult.suspiciousIndicators());
            if (!emailResult.suspiciousIndicators().isEmpty()) {
                contributingModels.add(emailResult.modelVersion());
            }
            modelOutputs.put("email", emailResult);
            score = Math.max(score, emailResult.riskScore());
        }

        long distinctIndicatorCount = indicators.stream().distinct().count();
        if (distinctIndicatorCount >= 5) {
            score = Math.max(score, 85);
        } else if (distinctIndicatorCount >= 3) {
            score = Math.max(score, 65);
        } else if (distinctIndicatorCount >= 1) {
            score = Math.max(score, 35);
        }

        String category;
        if (score >= 65) {
            category = "HIGH";
        } else if (score >= 35) {
            category = "MEDIUM";
        } else {
            category = "LOW";
        }

        List<String> actions = recommendedActions(category);
        String summary = indicators.isEmpty()
            ? "No strong suspicious indicators were detected by the configured deterministic rules."
            : "Suspicious indicators were detected: " + String.join("; ", indicators.stream().distinct().toList()) + ".";

        return new ThreatAnalysisResult(
            category,
            score,
            summary,
            indicators.stream().distinct().toList(),
            List.copyOf(contributingModels),
            Map.copyOf(modelOutputs),
            actions,
            Instant.now()
        );
    }

    private List<String> recommendedActions(String category) {
        return switch (category) {
            case "HIGH" -> List.of(
                "Do not open the link or respond to the message.",
                "Report it to the organization's security team.",
                "Reset credentials only through a trusted, separately typed address."
            );
            case "MEDIUM" -> List.of(
                "Inspect the source carefully before acting.",
                "Avoid submitting personal or payment information.",
                "Use a trusted channel to confirm the request."
            );
            default -> List.of(
                "No immediate action is indicated, but continue normal caution.",
                "Verify unexpected requests independently."
            );
        };
    }
}
