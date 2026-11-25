package com.phishguard;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("default")
@AutoConfigureMockMvc
class PhishGuardApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Context loads successfully with default H2 in-memory profile")
    void contextLoads() {
        assertTrue(true, "Spring application context initialized successfully");
    }

    @Test
    @DisplayName("Public health endpoint is accessible")
    void publicHealthEndpointIsAccessible() throws Exception {
        mockMvc.perform(get("/api/public/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP"))
            .andExpect(jsonPath("$.system").value("PhishGuard AI"))
            .andExpect(jsonPath("$.nlpEngine")
                .value("Apache OpenNLP 2.5.13 (dependency present; no trained pipeline active)"))
            .andExpect(result -> {
                String policy = result.getResponse().getHeader("Content-Security-Policy");
                assertTrue(policy != null && policy.contains("default-src 'self'"));
            });
    }

    @Test
    @DisplayName("Swagger and OpenAPI remain available in the default development profile")
    void apiDocumentationRemainsAvailableInDevelopment() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
            .andExpect(status().isOk());

        mockMvc.perform(get("/swagger-ui/index.html"))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Protected dashboard requires authentication")
    void protectedDashboardRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "page-user", roles = "USER")
    @DisplayName("Authenticated application pages render")
    void applicationPagesRender() throws Exception {
        for (String path : List.of(
            "/dashboard",
            "/scan/url",
            "/scan/email",
            "/history",
            "/analytics",
            "/profile"
        )) {
            mockMvc.perform(get(path))
                .andExpect(status().isOk());
        }
    }
}
