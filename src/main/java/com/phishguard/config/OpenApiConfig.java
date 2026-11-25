package com.phishguard.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI 3 / Swagger Documentation Configuration.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("PhishGuard AI — API Documentation")
                .version("1.0.0")
                .description("Advanced ML & NLP powered Phishing Detection REST APIs for Websites and Emails.")
                .contact(new Contact()
                    .name("PhishGuard AI Engineering Team")
                    .email("security@phishguard.local"))
                .license(new License()
                    .name("MIT")
                    .url("https://opensource.org/licenses/MIT")));
    }
}
