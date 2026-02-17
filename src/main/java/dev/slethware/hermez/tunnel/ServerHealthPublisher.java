package dev.slethware.hermez.tunnel;

import dev.slethware.hermez.config.HermezConfigProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Slf4j
@Component
@RequiredArgsConstructor
public class ServerHealthPublisher {

    private static final Duration HEALTH_TTL = Duration.ofSeconds(10);

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final HermezConfigProperties configProperties;

    @Scheduled(fixedRate = 5000)
    public void publishHealth() {
        String serverId = configProperties.getServer().getId();
        String key      = "server:" + serverId + ":health";

        redisTemplate.opsForValue()
                .set(key, Instant.now().toString(), HEALTH_TTL)
                .doOnSuccess(ok -> log.debug("Published health for server: {}", serverId))
                .doOnError(e  -> log.error("Failed to publish health for server {}: {}", serverId, e.getMessage()))
                .subscribe();
    }
}