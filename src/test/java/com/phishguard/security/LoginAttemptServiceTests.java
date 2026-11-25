package com.phishguard.security;

import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class LoginAttemptServiceTests {

    private static final String USERNAME = "login-test";
    private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    private UserRepository userRepository;
    private User user;
    private MutableClock clock;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        user = new User();
        user.setUsername(USERNAME);
        clock = new MutableClock(START);
        service = new LoginAttemptService(userRepository, clock);
        when(userRepository.findByUsernameIgnoreCaseForUpdate(USERNAME))
            .thenReturn(Optional.of(user));
    }

    @Test
    void locksAfterFiveFailuresAndDoesNotExtendAnActiveLock() {
        for (int attempt = 0; attempt < 4; attempt++) {
            service.registerFailure(USERNAME);
        }

        assertEquals(4, user.getFailedLoginAttempts());
        assertFalse(service.isLocked(user));

        service.registerFailure(USERNAME);
        Instant lockedUntil = user.getLockedUntil();

        assertEquals(5, user.getFailedLoginAttempts());
        assertNotNull(lockedUntil);
        assertTrue(service.isLocked(user));

        clock.advanceSeconds(60);
        service.registerFailure(USERNAME);

        assertEquals(5, user.getFailedLoginAttempts());
        assertEquals(lockedUntil, user.getLockedUntil());
    }

    @Test
    void expiredLockAllowsAuthenticationAndStartsANewFailureCount() {
        for (int attempt = 0; attempt < 5; attempt++) {
            service.registerFailure(USERNAME);
        }
        clock.setInstant(user.getLockedUntil().plusMillis(1));

        assertFalse(service.isLocked(user));
        service.registerFailure(USERNAME);

        assertEquals(1, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
    }

    @Test
    void successfulAuthenticationClearsFailuresAndLockout() {
        for (int attempt = 0; attempt < 5; attempt++) {
            service.registerFailure(USERNAME);
        }

        service.registerSuccess(USERNAME);

        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        assertFalse(service.isLocked(user));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant);
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void setInstant(Instant instant) {
            this.instant = instant;
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }
    }
}
