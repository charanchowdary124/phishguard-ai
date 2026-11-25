package com.phishguard.controller;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import com.phishguard.repository.ScanHistoryRepository;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("default")
@AutoConfigureMockMvc
class ApiAuthorizationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ScanHistoryRepository scanHistoryRepository;

    @Test
    void unauthenticatedUserCannotReadHistory() throws Exception {
        mockMvc.perform(get("/api/history"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void userCanAnalyzeUrlAndResponseIsConsistent() throws Exception {
        ensureUserExists();
        mockMvc.perform(post("/api/scan/url")
                .with(csrf())
                .contentType("application/json")
                .content("{\"url\":\"http://8.8.8.8/login?password=1\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.predictedClass").exists())
            .andExpect(jsonPath("$.data.riskCategory").exists());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void urlScanPersistsOnlySanitizedPreviewAndHash() throws Exception {
        ensureUserExists();
        String submittedUrl = "https://analyst:secret@example.test/private?token=secret#section";

        mockMvc.perform(post("/api/scan/url")
                .with(csrf())
                .contentType("application/json")
                .content("{\"url\":\"" + submittedUrl + "\"}"))
            .andExpect(status().isOk());

        var savedScan = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc("user1").get(0);
        assertEquals("https://example.test/private", savedScan.getInputSummary());
        assertFalse(savedScan.getInputHash().equals(submittedUrl));
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void emailScanPersistsSubjectWithoutBodyOrSender() throws Exception {
        ensureUserExists();

        mockMvc.perform(post("/api/scan/email")
                .with(csrf())
                .contentType("application/json")
                .content("""
                    {"subject":" Verify account ","body":"private message body","sender":"sender@example.test"}
                    """))
            .andExpect(status().isOk());

        var savedScan = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc("user1").get(0);
        assertEquals("Verify account", savedScan.getInputSummary());
        assertFalse(savedScan.getInputSummary().contains("private message body"));
        assertFalse(savedScan.getInputSummary().contains("sender@example.test"));
    }

    @Test
    @WithMockUser(username = "admin1", roles = "ADMIN")
    void adminCanReadAdminUsers() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void userCannotReadAdminUsers() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void bulkUploadRejectsOversizedFile() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "urls.csv",
            "text/csv",
            new byte[10 * 1024 * 1024 + 1]
        );
        mockMvc.perform(multipart("/api/scan/bulk")
                .file(file)
                .with(csrf()))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void bulkUploadRequiresCsvExtension() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "urls.txt",
            "text/plain",
            "url\nhttps://example.com\n".getBytes()
        );
        mockMvc.perform(multipart("/api/scan/bulk")
                .file(file)
                .with(csrf()))
            .andExpect(status().isBadRequest());
    }

    @Test
    void publicEndpointsReceiveBrowserSecurityHeaders() throws Exception {
        mockMvc.perform(get("/api/public/health"))
            .andExpect(status().isOk())
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().string("X-Frame-Options", "SAMEORIGIN"))
            .andExpect(header().string("Referrer-Policy",
                "strict-origin-when-cross-origin"))
            .andExpect(header().string("Content-Security-Policy",
                org.hamcrest.Matchers.containsString("object-src 'none'")))
            .andExpect(header().string("Permissions-Policy",
                org.hamcrest.Matchers.containsString("camera=()")));
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void xssPayloadInEmailSubjectIsStoredWithoutMarkupInterpretation() throws Exception {
        ensureUserExists();
        String payload = "<script>alert('xss')</script>";

        mockMvc.perform(post("/api/scan/email")
                .with(csrf())
                .contentType("application/json")
                .content("{\"subject\":\"" + payload + "\",\"body\":\"private body\",\"sender\":\"<img src=x onerror=alert(1)>\"}"))
            .andExpect(status().isOk());

        var savedScan = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc("user1").get(0);
        assertEquals(payload, savedScan.getInputSummary());
        assertFalse(savedScan.getInputSummary().contains("private body"));
        assertFalse(savedScan.getInputSummary().contains("onerror"));
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void historySearchTreatsSqlInjectionTextAsData() throws Exception {
        mockMvc.perform(get("/api/history")
                .param("search", "' OR 1=1 --"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data").isArray());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void privateUrlScanIsRejectedWithoutPersistence() throws Exception {
        ensureUserExists();
        long priorCount = scanHistoryRepository.count();

        mockMvc.perform(post("/api/scan/url")
                .with(csrf())
                .contentType("application/json")
                .content("{\"url\":\"http://127.0.0.1/admin\"}"))
            .andExpect(status().isBadRequest());

        assertEquals(priorCount, scanHistoryRepository.count());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void historyFiltersDetailsAndDeletesOnlyTheOwnersRecord() throws Exception {
        ensureUserExists();
        mockMvc.perform(post("/api/scan/url")
                .with(csrf())
                .contentType("application/json")
                .content("{\"url\":\"https://example.test/products\"}"))
            .andExpect(status().isOk());

        mockMvc.perform(get("/api/history"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.length()").value(1));

        var historyResult = mockMvc.perform(get("/api/history")
                .param("search", "Example.Test")
                .param("scanType", "url")
                .param("riskLevel", "low")
                .param("sort", "oldest"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data[0].inputSummary").value("https://example.test/products"))
            .andReturn();
        JsonNode rows = objectMapper.readTree(historyResult.getResponse().getContentAsString()).path("data");
        long scanId = rows.get(0).path("id").asLong();

        mockMvc.perform(get("/api/history/{id}", scanId)
                .with(user("another-user").roles("USER")))
            .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/history/{id}", scanId))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.indicators").isArray());

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .delete("/api/history/{id}", scanId)
                .with(csrf()))
            .andExpect(status().isOk());
        assertFalse(scanHistoryRepository.findById(scanId).isPresent());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void dashboardStatisticsAndThreatListsReflectPersistedScans() throws Exception {
        ensureUserExists();
        mockMvc.perform(post("/api/scan/url")
                .with(csrf())
                .contentType("application/json")
                .content("{\"url\":\"http://8.8.8.8/login/verify-account?password=1\"}"))
            .andExpect(status().isOk());

        long storedScans = scanHistoryRepository
            .findByUserUsernameOrderByScannedAtDesc("user1").size();
        var dashboardResult = mockMvc.perform(get("/api/dashboard"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.statistics.totalScans").value(storedScans))
            .andExpect(jsonPath("$.data.recentActivity[0].id").exists())
            .andExpect(jsonPath("$.data.latestHighRisk[0].id").exists())
            .andReturn();
        JsonNode dashboard = objectMapper
            .readTree(dashboardResult.getResponse().getContentAsString()).path("data");
        JsonNode analytics = objectMapper.readTree(mockMvc.perform(get("/api/analytics"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString())
            .path("data");

        assertEquals(dashboard.path("statistics"), analytics);
        assertEquals(7, analytics.path("dailyActivity").size());
        assertEquals(storedScans, analytics.path("riskDistribution").path("low").asLong()
            + analytics.path("riskDistribution").path("medium").asLong()
            + analytics.path("riskDistribution").path("high").asLong());
        assertEquals(storedScans, analytics.path("scanTypeComparison").path("urlScans").asLong()
            + analytics.path("scanTypeComparison").path("emailScans").asLong());
    }

    @Test
    void unauthenticatedModelPerformanceRequestIsProtected() throws Exception {
        mockMvc.perform(get("/api/models/performance"))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    void apiLogoutRequiresAuthentication() throws Exception {
        mockMvc.perform(post("/api/auth/logout").with(csrf()))
            .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void apiLogoutInvalidatesTheSession() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/api/auth/logout")
                .session(session)
                .with(csrf()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true));

        assertThrows(IllegalStateException.class, () -> session.getAttribute("test"));
    }

    @Test
    @WithMockUser(username = "user1", roles = "USER")
    void formLogoutRedirectsToConfirmation() throws Exception {
        mockMvc.perform(post("/logout").with(csrf()))
            .andExpect(status().is3xxRedirection())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                .redirectedUrl("/login?logout=true"));
    }

    private void ensureUserExists() {
        if (!userRepository.existsByUsernameIgnoreCase("user1")) {
            User user = new User();
            user.setUsername("user1");
            user.setEmail("user1@example.test");
            user.setPasswordHash("test-only");
            user.setRole(Role.USER);
            userRepository.save(user);
        }
    }
}
