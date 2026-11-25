package com.phishguard.ml;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class UrlPredictionService {

    private final UrlFeatureExtractor featureExtractor;

    public UrlPredictionService(UrlFeatureExtractor featureExtractor) {
        this.featureExtractor = featureExtractor;
    }

    public UrlPredictionResult predict(String submittedUrl) {
        UrlFeatureVector features = featureExtractor.extract(submittedUrl);
        List<String> indicators = featureExtractor.indicators(submittedUrl, features);

        double score = 0.08;
        if (features.get("hasHttps") == 0.0) score += 0.18;
        if (features.get("ipAddress") == 1.0) score += 0.30;
        score += Math.min(0.20, features.get("suspiciousKeywords") * 0.06);
        score += Math.min(0.14, features.get("subdomainCount") * 0.04);
        score += Math.min(0.12, features.get("specialCharacterCount") * 0.008);
        score += features.get("urlShortener") * 0.12;
        score += features.get("suspiciousDomainStructure") * 0.08;
        score += features.get("userInfo") * 0.20;

        double probability = Math.max(0.05, Math.min(0.95, score));
        int riskScore = (int) Math.round(probability * 100);
        String riskCategory = riskCategory(riskScore);
        String predictedClass = probability >= 0.50 ? "PHISHING" : "LEGITIMATE";
        String explanation = indicators.isEmpty()
            ? "No strong deterministic suspicious indicators were detected."
            : "Detected indicators: " + String.join("; ", indicators) + ".";

        return new UrlPredictionResult(
            predictedClass,
            probability,
            riskScore,
            riskCategory,
            indicators,
            features.asMap(),
            "url-rule-v1",
            Instant.now(),
            explanation
        );
    }

    private String riskCategory(int riskScore) {
        if (riskScore >= 65) return "HIGH";
        if (riskScore >= 35) return "MEDIUM";
        return "LOW";
    }
}
