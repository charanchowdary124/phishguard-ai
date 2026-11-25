package com.phishguard.service;

import com.phishguard.ml.UrlPredictionResult;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportServiceTests {

    private final ReportService service = new ReportService();

    @Test
    void csvAndPdfReportsContainPredictionMetadata() throws Exception {
        UrlPredictionResult result = new UrlPredictionResult(
            "PHISHING",
            0.82,
            82,
            "HIGH",
            List.of("No HTTPS scheme", "Suspicious keyword present"),
            Map.of(),
            "url-rule-v1",
            Instant.now(),
            "Detected indicators"
        );

        String csv = service.toCsv(result);
        byte[] pdf = service.toPdf(result);

        assertTrue(csv.contains("prediction,risk_category"));
        assertTrue(csv.contains("PHISHING"));
        assertTrue(pdf.length > 100);
        assertTrue(pdf[0] == '%' && pdf[1] == 'P'
            && pdf[2] == 'D' && pdf[3] == 'F');
    }
}
