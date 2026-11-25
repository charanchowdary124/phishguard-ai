package com.phishguard.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

public final class ScanInputSanitizer {

    private ScanInputSanitizer() {
    }

    public static String urlPreview(String submittedUrl) {
        if (submittedUrl == null || submittedUrl.isBlank()) {
            return "";
        }

        String value = submittedUrl.trim();
        boolean hasHttpScheme = value.regionMatches(true, 0, "http://", 0, 7)
            || value.regionMatches(true, 0, "https://", 0, 8);
        try {
            URI uri = new URI(hasHttpScheme ? value : "http://" + value);
            if (uri.getHost() == null) {
                return "URL preview unavailable";
            }
            return new URI(
                uri.getScheme().toLowerCase(Locale.ROOT),
                null,
                uri.getHost(),
                uri.getPort(),
                uri.getPath(),
                null,
                null
            ).toASCIIString();
        } catch (URISyntaxException ex) {
            return "URL preview unavailable";
        }
    }

    public static String emailSubject(String subject) {
        if (subject == null) {
            return "";
        }
        return subject.replaceAll("\\p{Cntrl}", " ")
            .replaceAll("\\s+", " ")
            .trim();
    }
}
