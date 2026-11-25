package com.phishguard.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanInputSanitizerTests {

    @Test
    void urlPreviewRemovesCredentialsQueryAndFragment() {
        assertEquals(
            "https://example.test/account",
            ScanInputSanitizer.urlPreview(
                "https://analyst:secret@example.test/account?token=private#section"
            )
        );
    }

    @Test
    void urlPreviewAddsSchemeWhenOmitted() {
        assertEquals(
            "http://example.test/login",
            ScanInputSanitizer.urlPreview("example.test/login?token=private")
        );
    }

    @Test
    void emailSubjectCollapsesWhitespaceWithoutAddingBodyContent() {
        assertEquals(
            "Verify account",
            ScanInputSanitizer.emailSubject(" Verify\n\taccount ")
        );
    }
}
