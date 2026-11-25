package com.phishguard.ml;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class DatasetPreparationService {

    public DatasetInspectionReport inspect(
        DatasetType datasetType,
        Path datasetPath,
        String labelColumn,
        List<String> requiredColumns
    ) throws java.io.IOException {
        if (!Files.isRegularFile(datasetPath)) {
            throw new IllegalArgumentException("Dataset file does not exist: " + datasetPath);
        }
        if (labelColumn == null || labelColumn.isBlank()) {
            throw new IllegalArgumentException("Label column is required");
        }

        try (Reader reader = Files.newBufferedReader(datasetPath, StandardCharsets.UTF_8);
             CSVParser parser = CSVFormat.DEFAULT.builder()
                 .setHeader()
                 .setSkipHeaderRecord(true)
                 .setIgnoreSurroundingSpaces(true)
                 .setTrim(true)
                 .build()
                 .parse(reader)) {

            List<String> columns = new ArrayList<>(parser.getHeaderMap().keySet());
            validateColumns(columns, labelColumn, requiredColumns);

            Map<String, Integer> missing = new LinkedHashMap<>();
            columns.forEach(column -> missing.put(column, 0));
            Map<String, Long> labelCounts = new HashMap<>();

            Set<String> seenRows = new HashSet<>();
            long rowCount = 0;
            long validRowCount = 0;
            long duplicateRowCount = 0;

            for (CSVRecord record : parser) {
                rowCount++;
                String normalizedRowKey = normalizeRow(record, columns);
                if (!seenRows.add(normalizedRowKey)) {
                    duplicateRowCount++;
                }

                boolean requiredValuesPresent = true;
                for (String column : requiredColumns) {
                    String value = record.isMapped(column) ? record.get(column) : null;
                    if (value == null || value.isBlank()) {
                        requiredValuesPresent = false;
                    }
                }
                for (String column : columns) {
                    String value = record.isMapped(column) ? record.get(column) : null;
                    if (value == null || value.isBlank()) {
                        missing.put(column, missing.getOrDefault(column, 0) + 1);
                    }
                }

                if (record.isMapped(labelColumn)) {
                    String label = record.get(labelColumn);
                    if (label != null && !label.isBlank()) {
                        labelCounts.put(label.trim(), labelCounts.getOrDefault(label.trim(), 0L) + 1L);
                    }
                }

                if (requiredValuesPresent) {
                    validRowCount++;
                }
            }

            return new DatasetInspectionReport(
                datasetType,
                datasetPath,
                List.copyOf(columns),
                rowCount,
                validRowCount,
                duplicateRowCount,
                Map.copyOf(missing),
                Map.copyOf(labelCounts)
            );
        }
    }

    private void validateColumns(
        List<String> columns,
        String labelColumn,
        List<String> requiredColumns
    ) {
        if (!columns.contains(labelColumn)) {
            throw new IllegalArgumentException("Missing label column: " + labelColumn);
        }
        for (String requiredColumn : requiredColumns) {
            if (!columns.contains(requiredColumn)) {
                throw new IllegalArgumentException("Missing required column: " + requiredColumn);
            }
        }
    }

    private String normalizeRow(CSVRecord record, List<String> columns) {
        StringBuilder key = new StringBuilder();
        for (String column : columns) {
            String value = record.isMapped(column) ? record.get(column) : "";
            key.append(value == null ? "" : value.trim().toLowerCase()).append('\u001F');
        }
        return key.toString();
    }
}
