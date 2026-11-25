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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("default")
@AutoConfigureMockMvc
@Transactional
class ProfileControllerTests {

    private static final String USERNAME = "profile-user";
    private static final String CURRENT_PASSWORD = "ExistingPassword123";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @WithMockUser(username = USERNAME, roles = "USER")
    void profileViewReturnsAccountDetailsButNeverPasswordData() throws Exception {
        createUser(USERNAME, "profile@example.test");

        mockMvc.perform(get("/api/profile"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.username").value(USERNAME))
            .andExpect(jsonPath("$.data.email").value("profile@example.test"))
            .andExpect(jsonPath("$.data.createdAt").exists())
            .andExpect(jsonPath("$.data.password").doesNotExist())
            .andExpect(jsonPath("$.data.passwordHash").doesNotExist());
    }

    @Test
    @WithMockUser(username = USERNAME, roles = "USER")
    void profileUpdateValidatesAndRejectsDuplicateAccounts() throws Exception {
        createUser(USERNAME, "profile@example.test");
        createUser("taken-user", "taken@example.test");

        mockMvc.perform(put("/api/profile")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", "updated-user",
                    "email", "updated@example.test"
                ))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.username").value("updated-user"))
            .andExpect(jsonPath("$.data.email").value("updated@example.test"));

        assertTrue(userRepository.existsByUsernameIgnoreCase("updated-user"));
        assertTrue(userRepository.existsByEmailIgnoreCase("updated@example.test"));

        mockMvc.perform(put("/api/profile")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "username", "taken-user",
                    "email", "different@example.test"
                ))))
            .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = USERNAME, roles = "USER")
    void passwordChangeVerifiesCurrentPasswordAndRequiresComplexity() throws Exception {
        createUser(USERNAME, "profile@example.test");

        mockMvc.perform(post("/api/profile/password")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "currentPassword", CURRENT_PASSWORD,
                    "newPassword", "WeakPassword123",
                    "newPasswordConfirmation", "WeakPassword123"
                ))))
            .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/profile/password")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "currentPassword", "WrongPassword!123",
                    "newPassword", "NewPassword!123",
                    "newPasswordConfirmation", "NewPassword!123"
                ))))
            .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/profile/password")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(json(Map.of(
                    "currentPassword", CURRENT_PASSWORD,
                    "newPassword", "NewPassword!123",
                    "newPasswordConfirmation", "NewPassword!123"
                ))))
            .andExpect(status().isOk());

        User user = userRepository.findByUsernameIgnoreCase(USERNAME).orElseThrow();
        assertTrue(passwordEncoder.matches("NewPassword!123", user.getPasswordHash()));
        assertFalse(passwordEncoder.matches(CURRENT_PASSWORD, user.getPasswordHash()));
    }

    private void createUser(String username, String email) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(CURRENT_PASSWORD));
        user.setRole(Role.USER);
        userRepository.saveAndFlush(user);
    }

    private String json(Map<String, String> body) throws Exception {
        return objectMapper.writeValueAsString(body);
    }
}
