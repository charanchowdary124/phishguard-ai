package com.phishguard.ml;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UnifiedThreatAnalysisServiceTests {

    private final UnifiedThreatAnalysisService service = new UnifiedThreatAnalysisService();

    @Test
    void combinesUrlAndEmailIndicatorsWithDistinctCountRules() {
        UrlPredictionResult url = new UrlPredictionResult(
            "PHISHING", 0.82, 82, "HIGH",
            List.of("No HTTPS scheme", "IP address used instead of domain name", "Suspicious keyword present"),
            java.util.Map.of(), "url-rule-v1", Instant.now(), "Detected indicators"
        );
        EmailPredictionResult email = new EmailPredictionResult(
            "PHISHING", 0.90, 90, "HIGH",
            List.of("Urgent or pressure language", "Password or credential request"),
            java.util.Map.of(), "email-rule-v1", Instant.now(), "Detected indicators"
        );

        ThreatAnalysisResult result = service.analyze(url, email);

        assertEquals("HIGH", result.riskCategory());
        assertEquals(90, result.riskScore());
        assertTrue(result.indicators().size() >= 5);
        assertTrue(result.recommendedActions().size() >= 3);
    }

    @Test
    void lowRiskInputProducesLowCategory() {
        UrlPredictionResult url = new UrlPredictionResult(
            "LEGITIMATE", 0.08, 8, "LOW", List.of(),
            java.util.Map.of(), "url-rule-v1", Instant.now(), "No indicators"
        );

        ThreatAnalysisResult result = service.analyze(url, null);

        assertEquals("LOW", result.riskCategory());
        assertEquals(8, result.riskScore());
        assertTrue(result.indicators().isEmpty());
    }
}
