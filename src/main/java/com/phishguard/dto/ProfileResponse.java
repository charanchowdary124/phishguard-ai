package com.phishguard.dto;

import com.phishguard.entity.Role;

import java.time.Instant;

public record ProfileResponse(
    String username,
    String email,
    Role role,
    Instant createdAt
) {
}
