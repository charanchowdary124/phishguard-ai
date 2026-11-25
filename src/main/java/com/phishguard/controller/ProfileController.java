package com.phishguard.controller;

import com.phishguard.dto.ApiResponse;
import com.phishguard.dto.PasswordChangeRequest;
import com.phishguard.dto.ProfileResponse;
import com.phishguard.dto.ProfileUpdateRequest;
import com.phishguard.service.ProfileService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @GetMapping
    public ApiResponse<ProfileResponse> profile(Principal principal) {
        return ApiResponse.ok("Profile retrieved", profileService.getProfile(principal.getName()));
    }

    @PutMapping
    public ApiResponse<ProfileResponse> updateProfile(
        @Valid @RequestBody ProfileUpdateRequest request,
        Principal principal,
        HttpServletRequest servletRequest
    ) {
        ProfileResponse profile = profileService.updateProfile(principal.getName(), request);
        if (!profile.username().equals(principal.getName())) {
            Authentication current = SecurityContextHolder.getContext().getAuthentication();
            Authentication updated = new UsernamePasswordAuthenticationToken(
                profile.username(), null, current.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(updated);
            if (servletRequest.getSession(false) != null) {
                servletRequest.getSession(false).setAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                    SecurityContextHolder.getContext()
                );
            }
        }
        return ApiResponse.ok("Profile updated", profile);
    }

    @PostMapping("/password")
    public ResponseEntity<ApiResponse<Object>> changePassword(
        @Valid @RequestBody PasswordChangeRequest request,
        Principal principal
    ) {
        profileService.changePassword(principal.getName(), request);
        return ResponseEntity.status(HttpStatus.OK)
            .body(ApiResponse.ok("Password changed successfully", null));
    }
}
