package com.phishguard.dto;

import jakarta.validation.constraints.Size;

public record EmailScanRequest(
    @Size(max = 998) String subject,
    @Size(max = 20000) String body,
    @Size(max = 254) String sender
) {
}
