package com.phishguard.ml;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

@Service
public class EmailPredictionService {

    private final EmailFeatureExtractor featureExtractor;

    public EmailPredictionService(EmailFeatureExtractor featureExtractor) {
        this.featureExtractor = featureExtractor;
    }

    public EmailPredictionResult predict(String subject, String body, String sender) {
        EmailFeatureVector features = featureExtractor.extract(subject, body, sender);
        List<String> indicators = featureExtractor.indicators(subject, body, sender, features);

        double score = 0.05;
        score += features.get("urgentLanguage") * 0.12;
        score += features.get("passwordRequest") * 0.45;
        score += features.get("oneTimeCodeRequest") * 0.45;
        score += features.get("accountVerification") * 0.20;
        score += features.get("paymentRequest") * 0.18;
        score += features.get("financialInformationRequest") * 0.20;
        score += Math.min(0.12, features.get("embeddedLinkCount") * 0.04);
        score += features.get("attachmentIndicator") * 0.15;
        score += features.get("senderMismatch") * 0.20;
        score += features.get("malformedSender") * 0.10;

        double probability = Math.max(0.05, Math.min(0.95, score));
        int riskScore = (int) Math.round(probability * 100);
        String riskCategory = riskCategory(riskScore);
        String predictedClass = probability >= 0.50 ? "PHISHING" : "LEGITIMATE";
        String explanation = indicators.isEmpty()
            ? "No strong deterministic suspicious indicators were detected."
            : "Detected indicators: " + String.join("; ", indicators) + ".";

        return new EmailPredictionResult(
            predictedClass,
            probability,
            riskScore,
            riskCategory,
            indicators,
            features.values(),
            "email-rule-v2",
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
