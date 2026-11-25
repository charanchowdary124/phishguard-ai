package com.phishguard.ml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DatasetPreparationServiceTests {

    @TempDir
    Path tempDir;

    private final DatasetPreparationService service = new DatasetPreparationService();

    @Test
    void inspectsRowsLabelsMissingValuesAndDuplicates() throws Exception {
        Path csv = tempDir.resolve("website.csv");
        Files.writeString(csv, """
            url,label
            https://example.com,legitimate
            https://example.com,legitimate
            http://verify.example,phishing
            ,phishing
            """);

        DatasetInspectionReport report = service.inspect(
            DatasetType.WEBSITE,
            csv,
            "label",
            List.of("url")
        );

        assertEquals(4, report.rowCount());
        assertEquals(3, report.validRowCount());
        assertEquals(1, report.duplicateRowCount());
        assertEquals(1, report.missingValuesByColumn().get("url"));
        assertEquals(2L, report.labelCounts().get("legitimate"));
        assertEquals(2L, report.labelCounts().get("phishing"));
    }

    @Test
    void rejectsDatasetWithoutRequiredLabelColumn() throws Exception {
        Path csv = tempDir.resolve("email.csv");
        Files.writeString(csv, "subject,body\nAlert,Verify now");

        assertThrows(IllegalArgumentException.class, () ->
            service.inspect(
                DatasetType.EMAIL,
                csv,
                "label",
                List.of("subject", "body")
            )
        );
    }
}
