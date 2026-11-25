package com.phishguard.controller;

import com.phishguard.dto.ApiResponse;
import com.phishguard.dto.RegistrationRequest;
import com.phishguard.entity.User;
import com.phishguard.service.RegistrationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.phishguard.dto.LoginRequest;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final AuthenticationManager authenticationManager;
    private final com.phishguard.security.LoginAttemptService loginAttemptService;
    private final SessionAuthenticationStrategy apiSessionAuthenticationStrategy;

    public AuthController(
        RegistrationService registrationService,
        AuthenticationManager authenticationManager,
        com.phishguard.security.LoginAttemptService loginAttemptService,
        SessionAuthenticationStrategy apiSessionAuthenticationStrategy
    ) {
        this.registrationService = registrationService;
        this.authenticationManager = authenticationManager;
        this.loginAttemptService = loginAttemptService;
        this.apiSessionAuthenticationStrategy = apiSessionAuthenticationStrategy;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, Object>>> register(
        @Valid @RequestBody RegistrationRequest request
    ) {
        User user = registrationService.register(request);
        Map<String, Object> safeUser = Map.of(
            "id", user.getId(),
            "username", user.getUsername(),
            "role", user.getRole().name()
        );
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(ApiResponse.ok("Registration successful", safeUser));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Map<String, Object>>> login(
        @Valid @RequestBody LoginRequest request,
        HttpServletRequest servletRequest,
        HttpServletResponse servletResponse
    ) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                    request.username(),
                    request.password()
                )
            );
        } catch (org.springframework.security.core.AuthenticationException ex) {
            loginAttemptService.registerFailure(request.username());
            throw new org.springframework.security.authentication.BadCredentialsException(
                "Invalid username or password"
            );
        }

        servletRequest.getSession(true);
        apiSessionAuthenticationStrategy.onAuthentication(
            authentication,
            servletRequest,
            servletResponse
        );
        loginAttemptService.registerSuccess(authentication.getName());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        servletRequest.getSession(false).setAttribute(
            HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
            SecurityContextHolder.getContext()
        );

        Map<String, Object> user = Map.of(
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .toList()
        );
        return ResponseEntity.ok(ApiResponse.ok("Login successful", user));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Object>> logout(
        HttpServletRequest request,
        HttpServletResponse response
    ) throws Exception {
        request.logout();
        request.getSession(false);
        if (request.getSession(false) != null) {
            request.getSession(false).invalidate();
        }
        response.setStatus(HttpServletResponse.SC_OK);
        return ResponseEntity.ok(ApiResponse.ok("Logout successful", null));
    }
}
