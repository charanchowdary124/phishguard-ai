package com.phishguard.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MILLIS = 60_000L;
    private static final int MAX_TRACKED_CLIENTS = 10_000;

    private final int requestsPerMinute;
    private final int maxTrackedClients;
    private final Clock clock;
    private final Map<String, Deque<Long>> requestTimes = new ConcurrentHashMap<>();
    private final AtomicLong lastCleanupMillis = new AtomicLong();

    @Autowired
    public RateLimitFilter(
        @Value("${phishguard.security.rate-limit.requests-per-minute:60}") int requestsPerMinute,
        Clock clock
    ) {
        this(requestsPerMinute, clock, MAX_TRACKED_CLIENTS);
    }

    RateLimitFilter(int requestsPerMinute, Clock clock, int maxTrackedClients) {
        this.requestsPerMinute = requestsPerMinute;
        this.clock = Objects.requireNonNull(clock);
        if (maxTrackedClients < 1) {
            throw new IllegalArgumentException("Maximum tracked clients must be positive");
        }
        this.maxTrackedClients = maxTrackedClients;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        if (!request.getRequestURI().startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String client = request.getRemoteAddr();
        long now = clock.millis();
        Deque<Long> timestamps = bucketFor(client, now);
        if (timestamps == null) {
            reject(response);
            return;
        }
        synchronized (timestamps) {
            discardExpired(timestamps, now);
            if (timestamps.size() >= requestsPerMinute) {
                reject(response);
                return;
            }
            timestamps.addLast(now);
        }

        filterChain.doFilter(request, response);
    }

    private Deque<Long> bucketFor(String client, long now) {
        cleanupExpired(now);
        Deque<Long> timestamps = requestTimes.get(client);
        if (timestamps != null) {
            return timestamps;
        }
        synchronized (requestTimes) {
            timestamps = requestTimes.get(client);
            if (timestamps != null) {
                return timestamps;
            }
            if (requestTimes.size() >= maxTrackedClients) {
                return null;
            }
            timestamps = new ArrayDeque<>();
            requestTimes.put(client, timestamps);
            return timestamps;
        }
    }

    private void cleanupExpired(long now) {
        long lastCleanup = lastCleanupMillis.get();
        if (now - lastCleanup < WINDOW_MILLIS
            || !lastCleanupMillis.compareAndSet(lastCleanup, now)) {
            return;
        }
        requestTimes.forEach((client, timestamps) -> {
            synchronized (timestamps) {
                discardExpired(timestamps, now);
                if (timestamps.isEmpty()) {
                    requestTimes.remove(client, timestamps);
                }
            }
        });
    }

    private void discardExpired(Deque<Long> timestamps, long now) {
        while (!timestamps.isEmpty() && timestamps.peekFirst() < now - WINDOW_MILLIS) {
            timestamps.pollFirst();
        }
    }

    private void reject(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.getWriter().write("{\"success\":false,\"message\":\"Too many requests\"}");
    }
}
