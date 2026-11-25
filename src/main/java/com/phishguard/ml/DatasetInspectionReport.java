package com.phishguard.ml;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record DatasetInspectionReport(
    DatasetType datasetType,
    Path datasetPath,
    List<String> columns,
    long rowCount,
    long validRowCount,
    long duplicateRowCount,
    Map<String, Integer> missingValuesByColumn,
    Map<String, Long> labelCounts
) {
}
