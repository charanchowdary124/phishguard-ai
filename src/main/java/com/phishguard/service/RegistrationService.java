package com.phishguard.service;

import com.phishguard.dto.RegistrationRequest;
import com.phishguard.entity.Role;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationService(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User register(RegistrationRequest request) {
        if (userRepository.existsByUsernameIgnoreCase(request.username().trim())) {
            throw new IllegalArgumentException("Registration details are already in use");
        }
        if (userRepository.existsByEmailIgnoreCase(request.email().trim())) {
            throw new IllegalArgumentException("Registration details are already in use");
        }

        User user = new User();
        user.setUsername(request.username().trim());
        user.setEmail(request.email().trim());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(Role.USER);
        user.setEnabled(true);
        return userRepository.save(user);
    }
}
