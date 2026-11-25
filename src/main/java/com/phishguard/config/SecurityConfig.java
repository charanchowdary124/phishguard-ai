package com.phishguard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import com.phishguard.security.AuthenticationHandlers;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

import java.util.List;

/**
 * Core Security Configuration for PhishGuard AI.
 * Enforces Role-Based Access Control, Secure Headers, and Session Protections.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final AuthenticationHandlers authenticationHandlers;

    public SecurityConfig(AuthenticationHandlers authenticationHandlers) {
        this.authenticationHandlers = authenticationHandlers;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(
        AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public SessionAuthenticationStrategy apiSessionAuthenticationStrategy(
        SessionRegistry sessionRegistry
    ) {
        ConcurrentSessionControlAuthenticationStrategy concurrency =
            new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
        concurrency.setMaximumSessions(1);

        return new CompositeSessionAuthenticationStrategy(List.of(
            concurrency,
            new ChangeSessionIdAuthenticationStrategy(),
            new RegisterSessionAuthenticationStrategy(sessionRegistry)
        ));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/",
                    "/login",
                    "/register",
                    "/css/**",
                    "/js/**",
                    "/images/**",
                    "/swagger-ui/**",
                    "/v3/api-docs/**"
                ).permitAll()
                    .requestMatchers("/api/auth/logout").authenticated()
                    .requestMatchers(
                    "/api/auth/**",
                    "/api/public/**"
                ).permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/models/**").hasAnyRole("ADMIN", "ANALYST")
                .anyRequest().authenticated()
            )
            .formLogin(login -> login
                .loginPage("/login")
                .successHandler(authenticationHandlers)
                .failureHandler(authenticationHandlers)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .sessionManagement(session -> session
                .maximumSessions(1)
                .sessionRegistry(sessionRegistry())
                .expiredUrl("/login?expired=true")
            )
            .headers(headers -> headers
                .frameOptions(frame -> frame.sameOrigin())
                .contentTypeOptions(content -> {})
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)
                    .preload(true)
                )
                .crossOriginOpenerPolicy(coop ->
                    coop.policy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN)
                )
                .crossOriginResourcePolicy(corp ->
                    corp.policy(CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN)
                )
                .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                .addHeaderWriter(new StaticHeadersWriter(
                    "Content-Security-Policy",
                    "default-src 'self'; base-uri 'none'; frame-ancestors 'self'; object-src 'none'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:"
                ))
                .addHeaderWriter(new StaticHeadersWriter("X-XSS-Protection", "0"))
                .addHeaderWriter(new StaticHeadersWriter(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=()"
                ))
            );

        return http.build();
    }
}
