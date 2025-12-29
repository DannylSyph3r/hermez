package dev.slethware.hermez.ratelimit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Service
public class RateLimitService {

    private final Cache<String, AtomicInteger> requestCache;
    private static final int MAX_REQUESTS_PER_MINUTE = 5;

    public RateLimitService() {
        this.requestCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(10_000)
                .build();

        log.info("Rate limit service initialized with {} requests per minute", MAX_REQUESTS_PER_MINUTE);
    }

    public boolean isAllowed(String identifier) {
        AtomicInteger counter = requestCache.get(identifier, key -> new AtomicInteger(0));

        if (counter == null) {
            counter = new AtomicInteger(0);
            requestCache.put(identifier, counter);
        }

        int currentCount = counter.incrementAndGet();

        if (currentCount > MAX_REQUESTS_PER_MINUTE) {
            log.warn("Rate limit exceeded for identifier: {} (count: {})", identifier, currentCount);
            return false;
        }

        log.debug("Rate limit check passed for identifier: {} (count: {}/{})",
                identifier, currentCount, MAX_REQUESTS_PER_MINUTE);
        return true;
    }
}