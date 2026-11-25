package com.phishguard.security;

import com.phishguard.entity.User;
import com.phishguard.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final LoginAttemptService loginAttemptService;

    public DatabaseUserDetailsService(
        UserRepository userRepository,
        LoginAttemptService loginAttemptService
    ) {
        this.userRepository = userRepository;
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameIgnoreCase(username)
            .orElseThrow(() -> new UsernameNotFoundException("Unknown account"));
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPasswordHash())
            .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())))
            .disabled(!user.isEnabled())
            .accountLocked(loginAttemptService.isLocked(user))
            .build();
    }
}
