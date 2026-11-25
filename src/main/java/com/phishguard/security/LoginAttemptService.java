package com.phishguard.security;

import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@Service
public class LoginAttemptService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    private final UserRepository userRepository;
    private final Clock clock;

    public LoginAttemptService(UserRepository userRepository, Clock clock) {
        this.userRepository = userRepository;
        this.clock = clock;
    }

    @Transactional
    public void registerFailure(String username) {
        userRepository.findByUsernameIgnoreCaseForUpdate(username).ifPresent(user -> {
            Instant now = clock.instant();
            if (isLocked(user)) {
                return;
            }
            if (user.getLockedUntil() != null) {
                user.setFailedLoginAttempts(0);
                user.setLockedUntil(null);
            }

            int failedAttempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(Math.min(MAX_FAILED_ATTEMPTS, failedAttempts));
            if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(now.plus(LOCKOUT_DURATION));
            }
        });
    }

    @Transactional
    public void registerSuccess(String username) {
        userRepository.findByUsernameIgnoreCaseForUpdate(username).ifPresent(user -> {
            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
        });
    }

    public boolean isLocked(User user) {
        return user.getLockedUntil() != null
            && user.getLockedUntil().isAfter(clock.instant());
    }
}
