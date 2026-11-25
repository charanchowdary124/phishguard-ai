package com.phishguard.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RateLimitFilterTests {

    @Test
    void rateLimitsAClientWithinTheWindow() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(2, Clock.systemUTC(), 10);
        AtomicInteger passedRequests = new AtomicInteger();
        FilterChain chain = (request, response) -> passedRequests.incrementAndGet();

        MockHttpServletResponse first = send(filter, "192.0.2.1", chain);
        MockHttpServletResponse second = send(filter, "192.0.2.1", chain);
        MockHttpServletResponse third = send(filter, "192.0.2.1", chain);

        assertEquals(200, first.getStatus());
        assertEquals(200, second.getStatus());
        assertEquals(429, third.getStatus());
        assertEquals(2, passedRequests.get());
    }

    @Test
    void boundsTrackedClientsAndReclaimsExpiredBuckets() throws Exception {
        TestClock clock = new TestClock();
        RateLimitFilter filter = new RateLimitFilter(10, clock, 1);
        AtomicInteger passedRequests = new AtomicInteger();
        FilterChain chain = (request, response) -> passedRequests.incrementAndGet();

        assertEquals(200, send(filter, "192.0.2.1", chain).getStatus());
        assertEquals(429, send(filter, "192.0.2.2", chain).getStatus());

        clock.advanceMillis(60_001);

        assertEquals(200, send(filter, "192.0.2.2", chain).getStatus());
        assertEquals(2, passedRequests.get());
    }

    private MockHttpServletResponse send(
        RateLimitFilter filter,
        String remoteAddress,
        FilterChain chain
    ) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/test");
        request.setRemoteAddr(remoteAddress);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        return response;
    }

    private static final class TestClock extends Clock {
        private Instant current = Instant.parse("2026-01-01T00:00:00Z");

        @Override
        public synchronized Instant instant() {
            return current;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        synchronized void advanceMillis(long millis) {
            current = current.plusMillis(millis);
        }
    }
}
