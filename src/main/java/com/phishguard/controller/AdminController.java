package com.phishguard.controller;

import com.phishguard.dto.ApiResponse;
import com.phishguard.entity.AuditLog;
import com.phishguard.repository.AuditLogRepository;
import com.phishguard.repository.UserRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;

    public AdminController(
        UserRepository userRepository,
        AuditLogRepository auditLogRepository
    ) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
    }

    @GetMapping("/users")
    public ApiResponse<List<Map<String, Object>>> users() {
        List<Map<String, Object>> users = userRepository.findAll().stream()
            .map(user -> Map.<String, Object>of(
                "id", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole().name(),
                "enabled", user.isEnabled()
            ))
            .toList();
        return ApiResponse.ok("Users retrieved", users);
    }

    @GetMapping("/audit-logs")
    public ApiResponse<List<AuditLog>> auditLogs() {
        return ApiResponse.ok(
            "Audit logs retrieved",
            auditLogRepository.findTop500ByOrderByOccurredAtDesc()
        );
    }
}
