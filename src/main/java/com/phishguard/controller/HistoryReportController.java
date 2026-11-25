package com.phishguard.controller;

import com.phishguard.dto.ScanHistoryResponse;
import com.phishguard.service.ScanHistoryService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.Principal;

@RestController
public class HistoryReportController {

    private final ScanHistoryService scanHistoryService;

    public HistoryReportController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping("/api/reports/{id}")
    public ResponseEntity<byte[]> report(
        @PathVariable Long id,
        Principal principal
    ) {
        ScanHistoryResponse scan = scanHistoryService.findFor(principal.getName(), id);
        String csv = "scan_id,scan_type,input_hash,prediction,risk_category,risk_score,model_version,scanned_at\n"
            + scan.id() + ","
            + scan.scanType() + ","
            + scan.inputHash() + ","
            + scan.prediction() + ","
            + scan.riskCategory() + ","
            + scan.riskScore() + ","
            + scan.modelVersion() + ","
            + scan.scannedAt();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentDisposition(ContentDisposition.attachment()
            .filename("phishguard-scan-" + id + ".csv")
            .build());
        headers.setContentType(MediaType.parseMediaType("text/csv"));
        return ResponseEntity.ok()
            .headers(headers)
            .body(csv.getBytes(StandardCharsets.UTF_8));
    }
}
