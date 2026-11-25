package com.phishguard.controller;

import tools.jackson.databind.ObjectMapper;
import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.core.env.Environment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("default")
@AutoConfigureMockMvc
@Transactional
class AuthControllerTests {

    private static final String EXISTING_PASSWORD = "ExistingPass123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private Environment environment;

    @Test
    void apiLoginAcceptsExistingPasswordWithoutRegistrationComplexity() throws Exception {
        String username = createExistingUser();

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username.toUpperCase(Locale.ROOT),
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.username").value(username));
    }

    @Test
    void formLoginAcceptsExistingPasswordWithoutRegistrationComplexity() throws Exception {
        String username = createExistingUser();
        User user = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        user.setFailedLoginAttempts(2);

        mockMvc.perform(post("/login")
                .with(csrf())
                .param("username", username)
                .param("password", EXISTING_PASSWORD))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/dashboard"));

        assertEquals(0, userRepository.findByUsernameIgnoreCase(username)
            .orElseThrow().getFailedLoginAttempts());
    }

    @Test
    void apiLoginRejectsIncorrectPassword() throws Exception {
        String username = createExistingUser();

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "password", "IncorrectPass123"
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("Authentication required or invalid credentials"));
    }

    @Test
    void apiLoginRejectsUnknownUsername() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", "missing-" + UUID.randomUUID(),
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("Authentication required or invalid credentials"));
    }

    @Test
    void sessionCookieSecurityPropertiesAreEnabled() {
        assertEquals("true",
            environment.getProperty("server.servlet.session.cookie.http-only"));
        assertEquals("strict",
            environment.getProperty("server.servlet.session.cookie.same-site"));
    }

    @Test
    void duplicateRegistrationDoesNotDiscloseWhetherUsernameOrEmailExists() throws Exception {
        String username = createExistingUser();

        mockMvc.perform(post("/api/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "email", UUID.randomUUID() + "@example.test",
                    "password", "StrongPass!123"
                ))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Registration details are already in use"));
    }

    @Test
    void apiLoginTemporarilyLocksAfterRepeatedFailuresWithoutRevealingAccountState() throws Exception {
        String username = createExistingUser();
        String genericMessage = "Authentication required or invalid credentials";

        for (int attempt = 0; attempt < 5; attempt++) {
            mockMvc.perform(post("/api/auth/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(json(Map.of(
                        "username", username,
                        "password", "IncorrectPass123"
                    ))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(genericMessage));
        }

        User lockedUser = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        assertEquals(5, lockedUser.getFailedLoginAttempts());
        assertTrue(lockedUser.getLockedUntil().isAfter(java.time.Instant.now()));

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value(genericMessage));
    }

    @Test
    void apiLoginResetsFailureCounterAfterSuccessfulAuthentication() throws Exception {
        String username = createExistingUser();
        User user = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        user.setFailedLoginAttempts(3);

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isOk());

        assertEquals(0, userRepository.findByUsernameIgnoreCase(username)
            .orElseThrow().getFailedLoginAttempts());
    }

    @Test
    void registrationStillRequiresPasswordComplexity() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", "new-" + UUID.randomUUID(),
                    "email", UUID.randomUUID() + "@example.test",
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value(
                org.hamcrest.Matchers.containsString("Password must contain uppercase, lowercase, digit and special character")
            ));
    }

    @Test
    void registrationStoresBcryptHash() throws Exception {
        String username = "new-" + UUID.randomUUID();
        String password = "StrongPass!123";

        mockMvc.perform(post("/api/auth/register")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "email", UUID.randomUUID() + "@example.test",
                    "password", password
                ))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.success").value(true));

        User user = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        assertNotEquals(password, user.getPasswordHash());
        assertTrue(passwordEncoder.matches(password, user.getPasswordHash()));
    }

    @Test
    void apiAuthenticationRequiresCsrfToken() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", "missing-" + UUID.randomUUID(),
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isForbidden());
    }

    @Test
    void apiLoginRotatesExistingSessionId() throws Exception {
        String username = createExistingUser();
        MockHttpSession session = new MockHttpSession();
        String originalSessionId = session.getId();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .session(session)
                .with(request -> {
                    request.setRequestedSessionId(originalSessionId);
                    request.setRequestedSessionIdValid(true);
                    return request;
                })
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", username,
                    "password", EXISTING_PASSWORD
                ))))
            .andExpect(status().isOk())
            .andReturn();

        assertNotEquals(originalSessionId, result.getRequest().getSession(false).getId());
    }

    @Test
    void apiLoginRejectsEmptyCredentials() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of("username", "", "password", ""))))
            .andExpect(status().isBadRequest());
    }

    private String createExistingUser() {
        String username = "existing-" + UUID.randomUUID();
        User user = new User();
        user.setUsername(username);
        user.setEmail(username + "@example.test");
        user.setPasswordHash(passwordEncoder.encode(EXISTING_PASSWORD));
        user.setRole(Role.USER);
        userRepository.saveAndFlush(user);
        return username;
    }

    private String json(Map<String, String> body) throws Exception {
        return objectMapper.writeValueAsString(body);
    }
}
