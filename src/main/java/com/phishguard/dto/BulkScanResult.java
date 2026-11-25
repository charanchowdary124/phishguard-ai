package com.phishguard.dto;

import java.util.List;

public record BulkScanResult(
    int processed,
    int rejected,
    List<BulkUrlResult> results
) {
}
