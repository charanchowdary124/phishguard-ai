package com.phishguard.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegistrationRequest(
    @NotBlank @Size(min = 3, max = 100)
    @Pattern(regexp = "^[A-Za-z0-9._-]+$")
    String username,

    @NotBlank @Email @Size(max = 254)
    String email,

    @NotBlank @Size(min = 12, max = 128)
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Password must contain uppercase, lowercase, digit and special character"
    )
    String password
) {
}
