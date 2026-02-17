package dev.slethware.hermez.proxy;

import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.config.RedisScriptLoader;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimiter {

    private static final int WINDOW_SECONDS = 60;

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScriptLoader scriptLoader;
    private final HermezConfigProperties config;

    public record RateLimitResult(boolean allowed, long count, int limit, int retryAfterSeconds) {}

    public Mono<RateLimitResult> checkLimit(String subdomain) {
        int limit = config.getRateLimit().getFreeTier();
        long windowEpoch = Instant.now().getEpochSecond() / WINDOW_SECONDS;
        String key = "ratelimit:" + subdomain + ":" + windowEpoch;

        return redisTemplate.execute(
                        scriptLoader.getRateLimitScript(),
                        List.of(key),
                        List.of(String.valueOf(WINDOW_SECONDS))
                )
                .next()
                .map(count -> {
                    boolean allowed = count <= limit;
                    int retryAfter = allowed ? 0
                            : (int) (WINDOW_SECONDS - (Instant.now().getEpochSecond() % WINDOW_SECONDS));
                    return new RateLimitResult(allowed, count, limit, retryAfter);
                })
                .doOnError(e -> log.warn("Redis unavailable for rate limit check on subdomain={}, failing open: {}", subdomain, e.getMessage()))
                .onErrorReturn(new RateLimitResult(true, 0, limit, 0));
    }
}