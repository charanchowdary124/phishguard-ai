package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UrlScanRequest(
    @NotBlank @Size(max = 2048) String url
) {
}
