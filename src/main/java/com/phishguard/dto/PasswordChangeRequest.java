package com.phishguard.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
    @NotBlank @Size(max = 128) String currentPassword,

    @NotBlank @Size(min = 12, max = 128)
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Password must contain uppercase, lowercase, digit and special character"
    )
    String newPassword,

    @NotBlank @Size(min = 12, max = 128)
    String newPasswordConfirmation
) {
}
