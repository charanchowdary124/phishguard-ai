package com.phishguard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.event.EventListener;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.time.Clock;

/**
 * PhishGuard AI - Rule-Based Phishing Risk Analysis for URLs and Email
 * Primary Application Entrypoint.
 */
@SpringBootApplication
public class PhishGuardApplication {

    private static final Logger log = LoggerFactory.getLogger(PhishGuardApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(PhishGuardApplication.class, args);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(ApplicationReadyEvent event) {
        log.info("====================================================================");
        log.info("  PhishGuard AI System Started Successfully");
        log.info("  Detection: Deterministic URL and email rule baselines");
        log.info("  Security Mode: Strict SSRF Isolation & Role-Based Access Control");
        if (event.getApplicationContext() instanceof WebServerApplicationContext context) {
            String contextPath = context.getEnvironment()
                .getProperty("server.servlet.context-path", "");
            if (contextPath.endsWith("/")) {
                contextPath = contextPath.substring(0, contextPath.length() - 1);
            }
            log.info("  Local URL: http://localhost:{}{}/login", context.getWebServer().getPort(), contextPath);
        }
        log.info("====================================================================");
    }
}
