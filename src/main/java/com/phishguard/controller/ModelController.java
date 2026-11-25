package com.phishguard.controller;

import com.phishguard.dto.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/models")
public class ModelController {

    @GetMapping("/status")
    public ApiResponse<List<Map<String, Object>>> status() {
        return ApiResponse.ok(List.of(
            Map.of(
                "modelVersion", "url-rule-v1",
                "modelType", "DETERMINISTIC_URL_RULES",
                "active", true,
                "trained", false,
                "metricsAvailable", false
            ),
            Map.of(
                "modelVersion", "email-rule-v2",
                "modelType", "DETERMINISTIC_EMAIL_RULES",
                "active", true,
                "trained", false,
                "metricsAvailable", false
            )
        ));
    }

    @GetMapping("/performance")
    public ApiResponse<Map<String, Object>> performance() {
        return ApiResponse.ok(Map.of(
            "metricsAvailable", false,
            "message", "No fabricated model metrics are available until real labelled datasets are evaluated."
        ));
    }
}
