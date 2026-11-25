package com.phishguard.ml;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlFeatureExtractorTests {

    private final UrlFeatureExtractor extractor = new UrlFeatureExtractor();
    private final UrlPredictionService service = new UrlPredictionService(extractor);

    @Test
    void extractsHttpsIpAndQueryFeatures() {
        UrlFeatureVector features = extractor.extract("http://8.8.8.8/login?account=1&confirm=1");

        assertEquals(1.0, features.get("ipAddress"));
        assertEquals(0.0, features.get("hasHttps"));
        assertEquals(2.0, features.get("queryParameterCount"));
    }

    @Test
    void rejectsBlankAndOversizedUrls() {
        assertThrows(IllegalArgumentException.class, () -> extractor.extract(" "));
        assertThrows(IllegalArgumentException.class, () -> extractor.extract("https://" + "a".repeat(2048)));
    }

    @Test
    void marksSuspiciousUrlAsNonLegitimateWithIndicators() {
        UrlPredictionResult result = service.predict(
            "http://8.8.8.8/login/verify-account?password=1&confirm=1"
        );

        assertEquals("PHISHING", result.predictedClass());
        assertTrue(result.riskScore() >= 65);
        assertTrue(result.suspiciousIndicators().contains("IP address used instead of domain name"));
    }

    @Test
    void keepsUnusualButLowEvidenceUrlConservative() {
        UrlPredictionResult result = service.predict("https://example.com/products");

        assertEquals("LEGITIMATE", result.predictedClass());
        assertTrue(result.riskScore() < 50);
    }

    @Test
    void rejectsLocalPrivateAndMetadataTargets() {
        assertThrows(IllegalArgumentException.class, () -> extractor.extract("http://localhost/admin"));
        assertThrows(IllegalArgumentException.class, () -> extractor.extract("http://192.168.1.1/login"));
        assertThrows(IllegalArgumentException.class, () -> extractor.extract("http://169.254.169.254/latest"));
        assertThrows(IllegalArgumentException.class, () -> extractor.extract("http://[::1]/admin"));
        assertThrows(IllegalArgumentException.class,
            () -> extractor.extract("http://metadata.google.internal/"));
    }

    @Test
    void rejectsUnsupportedProtocols() {
        assertThrows(IllegalArgumentException.class,
            () -> extractor.extract("ftp://example.com/file"));
    }

    @Test
    void flagsUrlUserInfoAsPotentiallyMisleading() {
        UrlPredictionResult result = service.predict(
            "https://trusted.example@evil.example/login"
        );

        assertTrue(result.suspiciousIndicators().contains(
            "Credentials or misleading text precede the host"));
    }
}
