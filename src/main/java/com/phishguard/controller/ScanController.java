package com.phishguard.controller;

import com.phishguard.dto.ApiResponse;
import com.phishguard.dto.EmailScanRequest;
import com.phishguard.dto.UrlScanRequest;
import com.phishguard.ml.EmailPredictionResult;
import com.phishguard.ml.EmailPredictionService;
import com.phishguard.ml.UrlPredictionResult;
import com.phishguard.ml.UrlPredictionService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import com.phishguard.dto.BulkScanResult;
import com.phishguard.dto.BulkUrlResult;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.security.Principal;
import com.phishguard.service.ScanHistoryService;
import com.phishguard.service.ScanInputSanitizer;

@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private final UrlPredictionService urlPredictionService;
    private final EmailPredictionService emailPredictionService;
    private final ScanHistoryService scanHistoryService;

    public ScanController(
        UrlPredictionService urlPredictionService,
        EmailPredictionService emailPredictionService,
        ScanHistoryService scanHistoryService
    ) {
        this.urlPredictionService = urlPredictionService;
        this.emailPredictionService = emailPredictionService;
        this.scanHistoryService = scanHistoryService;
    }

    @PostMapping("/url")
    public ApiResponse<UrlPredictionResult> scanUrl(
        @Valid @RequestBody UrlScanRequest request,
        Principal principal
    ) {
        UrlPredictionResult result = urlPredictionService.predict(request.url());
        scanHistoryService.record(
            principal.getName(),
            "URL",
            request.url(),
            ScanInputSanitizer.urlPreview(request.url()),
            result.predictedClass(),
            result.riskCategory(),
            result.riskScore(),
            result.modelVersion(),
            result.suspiciousIndicators()
        );
        return ApiResponse.ok("URL analysis completed", result);
    }

    @PostMapping("/email")
    public ApiResponse<EmailPredictionResult> scanEmail(
        @Valid @RequestBody EmailScanRequest request,
        Principal principal
    ) {
        EmailPredictionResult result = emailPredictionService.predict(
            request.subject(),
            request.body(),
            request.sender()
        );
        scanHistoryService.record(
            principal.getName(),
            "EMAIL",
            (request.subject() == null ? "" : request.subject()) + "\n" +
                (request.body() == null ? "" : request.body()) + "\n" +
                (request.sender() == null ? "" : request.sender()),
            ScanInputSanitizer.emailSubject(request.subject()),
            result.predictedClass(),
            result.riskCategory(),
            result.riskScore(),
            result.modelVersion(),
            result.suspiciousIndicators()
        );
        return ApiResponse.ok(
            "Email analysis completed",
            result
        );
    }

    @PostMapping("/bulk")
    public ApiResponse<BulkScanResult> bulkScan(
        @RequestParam("file") MultipartFile file,
        Principal principal
    ) throws Exception {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("Bulk scan file must not be empty");
        }
        if (file.getSize() > 10 * 1024 * 1024) {
            throw new IllegalArgumentException("Bulk scan file exceeds 10 MB");
        }
        String name = file.getOriginalFilename();
        if (name == null || !name.toLowerCase().endsWith(".csv")) {
            throw new IllegalArgumentException("Only CSV bulk scan files are accepted");
        }

        List<BulkUrlResult> results = new ArrayList<>();
        int rejected = 0;
        int row = 1;
        try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8));
             CSVParser parser = CSVFormat.DEFAULT.builder()
                 .setHeader()
                 .setSkipHeaderRecord(true)
                 .setIgnoreSurroundingSpaces(true)
                 .setTrim(true)
                 .build()
                 .parse(reader)) {
            if (!parser.getHeaderMap().containsKey("url")) {
                throw new IllegalArgumentException("CSV must contain a url column");
            }
            for (CSVRecord record : parser) {
                row++;
                if (row > 1001) {
                    throw new IllegalArgumentException("Bulk scan record limit is 1000");
                }
                String url = record.isMapped("url") ? record.get("url") : null;
                if (url == null || url.isBlank()) {
                    rejected++;
                    results.add(new BulkUrlResult(row, "", "rejected", null));
                    continue;
                }
                try {
                    com.phishguard.ml.UrlPredictionResult bulkResult =
                        urlPredictionService.predict(url);
                    scanHistoryService.record(
                        principal.getName(),
                        "URL",
                        url,
                        ScanInputSanitizer.urlPreview(url),
                        bulkResult.predictedClass(),
                        bulkResult.riskCategory(),
                        bulkResult.riskScore(),
                        bulkResult.modelVersion(),
                        bulkResult.suspiciousIndicators()
                    );
                    results.add(new BulkUrlResult(
                        row,
                        url,
                        "processed",
                        bulkResult
                    ));
                } catch (IllegalArgumentException ex) {
                    rejected++;
                    results.add(new BulkUrlResult(row, url, "rejected", null));
                }
            }
        }
        return ApiResponse.ok(
            "Bulk scan completed",
            new BulkScanResult(results.size() - rejected, rejected, results)
        );
    }
}
