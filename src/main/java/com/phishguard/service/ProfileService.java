package com.phishguard.service;

import com.phishguard.dto.PasswordChangeRequest;
import com.phishguard.dto.ProfileResponse;
import com.phishguard.dto.ProfileUpdateRequest;
import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public ProfileService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public ProfileResponse getProfile(String username) {
        return toResponse(findUser(username));
    }

    @Transactional
    public ProfileResponse updateProfile(String currentUsername, ProfileUpdateRequest request) {
        User user = findUser(currentUsername);
        String username = request.username().trim();
        String email = request.email().trim();
        if (userRepository.existsByUsernameIgnoreCaseAndIdNot(username, user.getId())) {
            throw new IllegalArgumentException("Profile details are already in use");
        }
        if (userRepository.existsByEmailIgnoreCaseAndIdNot(email, user.getId())) {
            throw new IllegalArgumentException("Profile details are already in use");
        }
        user.setUsername(username);
        user.setEmail(email);
        return toResponse(user);
    }

    @Transactional
    public void changePassword(String username, PasswordChangeRequest request) {
        User user = findUser(username);
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        if (!request.newPassword().equals(request.newPasswordConfirmation())) {
            throw new IllegalArgumentException("New password confirmation does not match");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
    }

    private User findUser(String username) {
        return userRepository.findByUsernameIgnoreCase(username)
            .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }

    private ProfileResponse toResponse(User user) {
        return new ProfileResponse(
            user.getUsername(),
            user.getEmail(),
            user.getRole(),
            user.getCreatedAt()
        );
    }
}
