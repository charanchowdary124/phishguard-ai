package com.phishguard.ml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmailFeatureExtractorTests {

    private final EmailFeatureExtractor extractor = new EmailFeatureExtractor();
    private final EmailPredictionService service = new EmailPredictionService(extractor);

    @Test
    void extractsSuspiciousEmailIndicatorsWithoutRenderingHtml() {
        EmailFeatureVector features = extractor.extract(
            "Urgent: verify account",
            "<p>Please confirm your password immediately</p><a href=\"https://example.com\">link</a>",
            "security@secure.example"
        );

        assertEquals(1.0, features.get("urgentLanguage"));
        assertEquals(1.0, features.get("passwordRequest"));
        assertEquals(1.0, features.get("accountVerification"));
        assertEquals(1.0, features.get("embeddedLinkCount"));
    }

    @Test
    void rejectsEmailWithNoSubjectOrBody() {
        assertThrows(IllegalArgumentException.class,
            () -> extractor.extract(" ", " ", "sender@example.com"));
    }

    @Test
    void marksMultipleStrongIndicatorsAsPhishing() {
        EmailPredictionResult result = service.predict(
            "Final notice - verify account",
            "Send your password immediately and pay by gift card.",
            "alerts@example.net"
        );

        assertEquals("PHISHING", result.predictedClass());
        assertTrue(result.riskScore() >= 65);
        assertTrue(result.suspiciousIndicators().size() >= 3);
    }

    @Test
    void ordinaryMeetingEmailRemainsLowRisk() {
        EmailPredictionResult result = service.predict(
            "Project meeting",
            "The team meeting is scheduled for Tuesday at 10 AM.",
            "colleague@example.com"
        );

        assertEquals("LEGITIMATE", result.predictedClass());
        assertTrue(result.riskScore() < 35);
    }

    @Test
    void detectsOneTimeCodesFinancialRequestsAndWebLinks() {
        EmailFeatureVector features = extractor.extract(
            "Action required: https://example.test/continue",
            "Send your OTP and bank account number to continue.",
            "security@example.test"
        );

        assertEquals(1.0, features.get("oneTimeCodeRequest"));
        assertEquals(1.0, features.get("financialInformationRequest"));
        assertEquals(1.0, features.get("embeddedLinkCount"));
    }

    @Test
    void identifiesMalformedSenderWithoutRejectingTheEmail() {
        EmailPredictionResult result = service.predict(
            "Project update",
            "Please review the attached report.",
            "not-an-email"
        );

        assertTrue(result.suspiciousIndicators().contains("Sender address format is suspicious"));
    }

    @Test
    void explicitPasswordAndOneTimeCodeSolicitationsArePhishingMedium() {
        EmailPredictionResult passwordRequest = service.predict(
            "Account support",
            "Reply with your password to continue.",
            "support@example.test"
        );
        EmailPredictionResult codeRequest = service.predict(
            "Verification",
            "Send your OTP to continue.",
            "support@example.test"
        );
        EmailPredictionResult benignMention = service.predict(
            "Password help",
            "Open settings to change your password.",
            "support@example.test"
        );

        assertEquals("PHISHING", passwordRequest.predictedClass());
        assertEquals("MEDIUM", passwordRequest.riskCategory());
        assertEquals("PHISHING", codeRequest.predictedClass());
        assertEquals("MEDIUM", codeRequest.riskCategory());
        assertEquals("LEGITIMATE", benignMention.predictedClass());
        assertEquals("LOW", benignMention.riskCategory());
    }

    @Test
    void categorizesRuleScoresAsLowMediumOrHigh() {
        assertEquals("LOW", service.predict(
            "Team lunch",
            "The meeting starts at noon.",
            "colleague@example.test"
        ).riskCategory());
        assertEquals("MEDIUM", service.predict(
            "Payroll update",
            "Please send your password.",
            "support@example.test"
        ).riskCategory());
        assertEquals("HIGH", service.predict(
            "Urgent account alert",
            "Send your password and OTP, bank account details, and payment now.",
            "not-an-email"
        ).riskCategory());
    }
}
