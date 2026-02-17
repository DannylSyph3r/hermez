package dev.slethware.hermez.tunnel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.config.RedisScriptLoader;
import dev.slethware.hermez.exception.ConflictException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@RequiredArgsConstructor
public class TunnelRegistryImpl implements TunnelRegistry {

    private static final int    TUNNEL_TTL_SECONDS = 20;
    private static final String TUNNEL_KEY_PREFIX  = "tunnel:";

    private final ConcurrentHashMap<String, TunnelConnection> localTunnels = new ConcurrentHashMap<>();

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScriptLoader scriptLoader;
    private final ObjectMapper objectMapper;
    private final HermezConfigProperties configProperties;

    @Override
    public Mono<Void> register(String subdomain, TunnelConnection connection, TunnelInfo info, UUID userId) {
        registerLocal(subdomain, connection);
        return registerRedis(subdomain, info, userId)
                .doOnError(e -> unregisterLocal(subdomain)); // rollback local on Redis failure
    }

    @Override
    public Mono<Void> unregister(String subdomain) {
        unregisterLocal(subdomain);
        return redisTemplate.delete(TUNNEL_KEY_PREFIX + subdomain)
                .doOnSuccess(count -> log.info("Unregistered tunnel from Redis: {} (deleted={})", subdomain, count))
                .then();
    }

    @Override
    public Mono<TunnelLookupResult> lookup(String subdomain) {
        TunnelConnection local = localTunnels.get(subdomain);
        if (local != null) {
            return Mono.just(new TunnelLookupResult.Local(local));
        }
        return lookupRedis(subdomain);
    }

    @Override
    public Mono<Void> refreshTtl(String subdomain) {
        return redisTemplate.expire(TUNNEL_KEY_PREFIX + subdomain, Duration.ofSeconds(TUNNEL_TTL_SECONDS))
                .doOnSuccess(extended -> {
                    if (Boolean.FALSE.equals(extended)) {
                        log.warn("refreshTtl: tunnel key not found in Redis for subdomain: {}", subdomain);
                    }
                })
                .then();
    }

    // Private Methods

    private void registerLocal(String subdomain, TunnelConnection connection) {
        localTunnels.put(subdomain, connection);
        log.info("Tunnel registered locally: {}", subdomain);
    }

    private void unregisterLocal(String subdomain) {
        localTunnels.remove(subdomain);
        log.info("Tunnel unregistered locally: {}", subdomain);
    }

    private Mono<Void> registerRedis(String subdomain, TunnelInfo info, UUID userId) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(info))
                .flatMap(json -> redisTemplate.execute(
                        scriptLoader.getTunnelRegisterScript(),
                        List.of(TUNNEL_KEY_PREFIX + subdomain),
                        List.of(json, String.valueOf(TUNNEL_TTL_SECONDS), userId.toString())
                ).next())
                .switchIfEmpty(Mono.error(new IllegalStateException(
                        "tunnel_register.lua returned no result for subdomain: " + subdomain)))
                .flatMap(result -> parseRegisterResult(result, subdomain))
                .then();
    }

    private Mono<Void> parseRegisterResult(String result, String subdomain) {
        try {
            JsonNode node   = objectMapper.readTree(result);
            String   status = node.get("status").asText();
            return switch (status) {
                case "created", "takeover" -> {
                    log.info("Tunnel registered in Redis: {} (status={})", subdomain, status);
                    yield Mono.empty();
                }
                case "conflict" -> {
                    log.warn("Tunnel registration conflict for subdomain: {}", subdomain);
                    yield Mono.error(new ConflictException("Subdomain is already in use by another active tunnel"));
                }
                default -> Mono.error(new IllegalStateException(
                        "Unexpected status from tunnel_register.lua: " + status));
            };
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to parse tunnel_register.lua result", e));
        }
    }

    private Mono<TunnelLookupResult> lookupRedis(String subdomain) {
        return redisTemplate.execute(
                        scriptLoader.getTunnelRouteScript(),
                        List.of(TUNNEL_KEY_PREFIX + subdomain)
                ).next()
                .flatMap(result -> parseLookupResult(result, subdomain))
                .defaultIfEmpty(new TunnelLookupResult.NotFound());
    }

    private Mono<TunnelLookupResult> parseLookupResult(String result, String subdomain) {
        try {
            JsonNode node   = objectMapper.readTree(result);
            String   status = node.get("status").asText();
            return switch (status) {
                case "ok" -> {
                    JsonNode tunnelNode   = objectMapper.readTree(node.get("tunnel").asText());
                    String   tunnelServer = tunnelNode.get("server_id").asText();
                    String   serverAddr   = tunnelNode.get("server_address").asText();

                    // Redis says it's on this server but we don't have it locally — stale entry
                    if (tunnelServer.equals(configProperties.getServer().getId())) {
                        log.warn("Stale Redis registration for subdomain: {} — no local connection found", subdomain);
                        yield Mono.just((TunnelLookupResult) new TunnelLookupResult.NotFound());
                    }
                    yield Mono.just((TunnelLookupResult) new TunnelLookupResult.Remote(serverAddr));
                }
                case "not_found"  -> Mono.just(new TunnelLookupResult.NotFound());
                case "server_dead" -> {
                    log.warn("Dead server detected for subdomain: {}", subdomain);
                    yield Mono.just((TunnelLookupResult) new TunnelLookupResult.ServerDead(subdomain));
                }
                default -> Mono.error(new IllegalStateException(
                        "Unexpected status from tunnel_route.lua: " + status));
            };
        } catch (Exception e) {
            return Mono.error(new IllegalStateException("Failed to parse tunnel_route.lua result", e));
        }
    }
}