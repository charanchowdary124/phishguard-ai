package com.phishguard.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

/**
 * Initial Root and Health Controller.
 */
@Controller
public class HomeController {

    private static final String OPENNLP_VERSION = "2.5.13";

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/dashboard")
    public String dashboard() {
        return "dashboard";
    }

    @GetMapping("/scan/url")
    public String urlScanner() {
        return "url-scanner";
    }

    @GetMapping("/scan/email")
    public String emailScanner() {
        return "email-scanner";
    }

    @GetMapping("/history")
    public String history() {
        return "history";
    }

    @GetMapping("/analytics")
    public String analytics() {
        return "analytics";
    }

    @GetMapping("/profile")
    public String profile() {
        return "profile";
    }

    @GetMapping("/api/public/health")
    @ResponseBody
    public Map<String, Object> health() {
        return Map.of(
            "status", "UP",
            "system", "PhishGuard AI",
            "version", "1.0.0",
            "mlFramework", "Oracle Tribuo 4.3.1 (dependency present; no trained model active)",
            "nlpEngine", "Apache OpenNLP " + OPENNLP_VERSION
                + " (dependency present; no trained pipeline active)"
        );
    }
}
