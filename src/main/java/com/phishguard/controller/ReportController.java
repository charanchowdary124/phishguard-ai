package com.phishguard.controller;

import com.phishguard.dto.UrlScanRequest;
import com.phishguard.ml.UrlPredictionService;
import com.phishguard.service.ReportService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final UrlPredictionService urlPredictionService;
    private final ReportService reportService;

    public ReportController(
        UrlPredictionService urlPredictionService,
        ReportService reportService
    ) {
        this.urlPredictionService = urlPredictionService;
        this.reportService = reportService;
    }

    @PostMapping("/url/csv")
    public ResponseEntity<String> urlCsv(@Valid @RequestBody UrlScanRequest request) {
        String csv = reportService.toCsv(urlPredictionService.predict(request.url()));
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=phishguard-report.csv")
            .contentType(MediaType.parseMediaType("text/csv"))
            .body(csv);
    }

    @PostMapping("/url/pdf")
    public ResponseEntity<byte[]> urlPdf(@Valid @RequestBody UrlScanRequest request) throws Exception {
        byte[] pdf = reportService.toPdf(urlPredictionService.predict(request.url()));
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=phishguard-report.pdf")
            .contentType(MediaType.APPLICATION_PDF)
            .body(pdf);
    }
}
