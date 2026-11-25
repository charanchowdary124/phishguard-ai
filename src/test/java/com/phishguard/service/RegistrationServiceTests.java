package com.phishguard.service;

import com.phishguard.dto.RegistrationRequest;
import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest
@Import({RegistrationService.class, RegistrationServiceTests.PasswordEncoderConfig.class})
class RegistrationServiceTests {

    @TestConfiguration(proxyBeanMethods = false)
    static class PasswordEncoderConfig {
        @Bean
        PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(12);
        }
    }

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserRepository userRepository;

    @Test
    void registersUserWithBcryptHashAndDefaultRole() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        RegistrationRequest request = new RegistrationRequest(
            "analyst1",
            "analyst1@example.com",
            "StrongPass!123"
        );

        User user = registrationService.register(request);

        assertEquals("analyst1", user.getUsername());
        assertEquals(Role.USER, user.getRole());
        assertNotEquals("StrongPass!123", user.getPasswordHash());
        assertTrue(encoder.matches("StrongPass!123", user.getPasswordHash()));
        assertEquals(1, userRepository.count());
    }

    @Test
    void rejectsDuplicateUsernameAndEmail() {
        RegistrationRequest request = new RegistrationRequest(
            "duplicate",
            "unique@example.com",
            "StrongPass!123"
        );
        registrationService.register(request);

        assertThrows(IllegalArgumentException.class, () ->
            registrationService.register(new RegistrationRequest(
                "duplicate",
                "other@example.com",
                "StrongPass!123"
            ))
        );
        assertThrows(IllegalArgumentException.class, () ->
            registrationService.register(new RegistrationRequest(
                "other",
                "unique@example.com",
                "StrongPass!123"
            ))
        );
    }
}
