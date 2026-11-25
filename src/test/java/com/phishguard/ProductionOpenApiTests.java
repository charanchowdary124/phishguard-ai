package com.phishguard;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.env.Environment;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "PORT=0",
    "SERVER_PORT=8081",
    "spring.datasource.url=jdbc:h2:mem:production-openapi;DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.flyway.enabled=false"
})
@ActiveProfiles("prod")
@AutoConfigureMockMvc
class ProductionOpenApiTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private Environment environment;

    @Test
    void swaggerAndOpenApiEndpointsAreDisabledInProduction() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
            .andExpect(status().isNotFound());

        mockMvc.perform(get("/swagger-ui/index.html"))
            .andExpect(status().isNotFound());
    }

    @Test
    void h2ConsoleIsNotAvailableInProduction() throws Exception {
        mockMvc.perform(get("/h2-console")
                .with(SecurityMockMvcRequestPostProcessors.user("demo")))
            .andExpect(status().isNotFound());
    }

    @Test
    void productionUsesSecureCookiesAndRestrictsForwardedHeadersToConfiguredProxy() {
        assertEquals("true",
            environment.getProperty("server.servlet.session.cookie.secure"));
        assertEquals("native",
            environment.getProperty("server.forward-headers-strategy"));
        assertEquals("127[.]0[.]0[.]1|::1",
            environment.getProperty("server.tomcat.remoteip.internal-proxies"));
    }

    @Test
    void productionPrefersTheHostingPlatformPort() {
        assertEquals("0", environment.getProperty("server.port"));
    }

    @Test
    void publicHealthRemainsAvailableAndDashboardStillRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/public/health"))
            .andExpect(status().isOk());

        mockMvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection());
    }
}
