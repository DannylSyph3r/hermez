package dev.slethware.hermez.tunnel;

import dev.slethware.hermez.auth.TokenService;
import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.subdomain.SubdomainGenerator;
import dev.slethware.hermez.subdomain.validation.SubdomainValidator;
import dev.slethware.hermez.subdomain.validation.ValidationResult;
import dev.slethware.hermez.tunnel.protocol.MessageDecoder;
import dev.slethware.hermez.tunnel.protocol.ProtocolMessage;
import dev.slethware.hermez.user.SubscriptionTier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.CloseStatus;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketMessage;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class TunnelWebSocketHandler implements WebSocketHandler {

    private static final String HEADER_SUBDOMAIN   = "X-Hermez-Subdomain";
    private static final String HEADER_LOCAL_PORT  = "X-Hermez-Local-Port";
    private static final String BEARER_PREFIX      = "Bearer ";

    private final TokenService tokenService;
    private final SubdomainValidator subdomainValidator;
    private final SubdomainGenerator subdomainGenerator;
    private final TunnelRegistry tunnelRegistry;
    private final HeartbeatManager heartbeatManager;
    private final HermezConfigProperties configProperties;

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        HttpHeaders headers    = session.getHandshakeInfo().getHeaders();
        String authHeader      = headers.getFirst(HttpHeaders.AUTHORIZATION);
        String subdomainHeader = headers.getFirst(HEADER_SUBDOMAIN);
        String localPortHeader = headers.getFirst(HEADER_LOCAL_PORT);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.warn("WebSocket connection rejected: missing or malformed Authorization header. sessionId={}", session.getId());
            return session.close(CloseStatus.POLICY_VIOLATION.withReason("Missing authorization"));
        }

        int    localPort          = parseLocalPort(localPortHeader);
        String token              = authHeader.substring(BEARER_PREFIX.length());
        // null means no subdomain requested — server will assign one randomly
        String requestedSubdomain = (subdomainHeader != null && !subdomainHeader.isBlank())
                ? subdomainHeader.toLowerCase().trim()
                : null;

        return tokenService.validateAccessToken(token)
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("WebSocket connection rejected: invalid token. sessionId={}", session.getId());
                    return session.close(CloseStatus.POLICY_VIOLATION.withReason("Invalid or expired token"))
                            .then(Mono.empty());
                }))
                .flatMap(userId -> tokenService.resolveTier(token)
                        .defaultIfEmpty("chelys")
                        .flatMap(tier -> checkTunnelLimit(session, userId, tier))
                )
                .flatMap(userId -> resolveSubdomain(session, userId, requestedSubdomain, localPort)
                        .flatMap(resolution -> {
                            TunnelInfo info = buildTunnelInfo(userId, resolution.subdomain(), localPort);
                            TunnelConnection connection = new TunnelConnection(session, info, resolution.random());

                            return tunnelRegistry.register(resolution.subdomain(), connection, info, userId)
                                    .doOnSuccess(v -> {
                                        connection.sendTunnelConnected(buildPublicUrl(resolution.subdomain()));
                                        heartbeatManager.start(resolution.subdomain(), connection, tunnelRegistry);
                                        log.info("Tunnel established: subdomain={} userId={} localPort={} random={}",
                                                resolution.subdomain(), userId, localPort, resolution.random());
                                    })
                                    .then(runSession(session, connection))
                                    .doFinally(signal -> cleanup(resolution.subdomain(), connection, signal.toString()));
                        })
                );
    }

    private Mono<Void> runSession(WebSocketSession session, TunnelConnection connection) {

        // Receive: session messages → decode → dispatch to connection
        Mono<Void> receive = session.receive()
                .filter(msg -> msg.getType() == WebSocketMessage.Type.BINARY)
                .doOnNext(msg -> {
                    byte[] payload = new byte[msg.getPayload().readableByteCount()];
                    msg.getPayload().read(payload);
                    try {
                        ProtocolMessage decoded = MessageDecoder.decode(payload);
                        connection.handleMessage(decoded);
                    } catch (Exception e) {
                        log.warn("Failed to decode message for tunnel {}: {}", connection.getSubdomain(), e.getMessage());
                    }
                })
                .then();

        // Send: connection outbound sink → encode as binary frames → session send
        Mono<Void> send = session.send(
                connection.outbound()
                        .map(bytes -> session.binaryMessage(factory -> factory.wrap(bytes)))
        );

        return Mono.when(receive, send);
    }

    private record SubdomainResolution(String subdomain, boolean random) {}

    private Mono<SubdomainResolution> resolveSubdomain(
            WebSocketSession session, UUID userId, String requestedSubdomain, int localPort) {

        if (requestedSubdomain != null) {
            // User explicitly requested a subdomain — validate ownership and availability
            return validateSubdomain(session, requestedSubdomain, userId)
                    .map(ignored -> new SubdomainResolution(requestedSubdomain, false));
        }

        // No subdomain provided — check grace period first, then generate fresh
        return tunnelRegistry.checkGrace(userId, localPort)
                .flatMap(gracedSubdomain ->
                        tunnelRegistry.lookup(gracedSubdomain)
                                .flatMap(result -> {
                                    boolean available = result instanceof TunnelLookupResult.NotFound
                                            || result instanceof TunnelLookupResult.ServerDead;
                                    if (available) {
                                        log.info("Reclaiming grace subdomain: {} userId={}", gracedSubdomain, userId);
                                        return Mono.just(new SubdomainResolution(gracedSubdomain, true));
                                    }
                                    return tryGenerate(0);
                                })
                )
                .switchIfEmpty(Mono.defer(() -> tryGenerate(0)));
    }

    private Mono<SubdomainResolution> tryGenerate(int attempt) {
        if (attempt >= 10) {
            return Mono.error(new IllegalStateException(
                    "Could not generate a unique subdomain after 10 attempts"));
        }
        String candidate = subdomainGenerator.generate();
        return tunnelRegistry.lookup(candidate)
                .flatMap(result -> {
                    boolean taken = result instanceof TunnelLookupResult.Local
                            || result instanceof TunnelLookupResult.Remote;
                    if (taken) {
                        return tryGenerate(attempt + 1);
                    }
                    return Mono.just(new SubdomainResolution(candidate, true));
                });
    }

    private String buildPublicUrl(String subdomain) {
        return String.format("https://%s.%s",
                subdomain, configProperties.getSubdomain().getBaseDomain());
    }

    private Mono<UUID> validateSubdomain(WebSocketSession session, String subdomain, UUID userId) {
        return subdomainValidator.validate(subdomain, userId)
                .flatMap(result -> switch (result) {
                    case ValidationResult.Valid ignored           -> Mono.just(userId);
                    case ValidationResult.Reserved(String ignored, UUID ownerId) -> {
                        if (ownerId.equals(userId)) {
                            // User is connecting to their own reserved subdomain — allowed
                            yield Mono.just(userId);
                        }
                        log.warn("Subdomain {} is reserved by another user, rejecting sessionId={}", subdomain, session.getId());
                        yield session.close(CloseStatus.POLICY_VIOLATION.withReason("Subdomain reserved by another user"))
                                .then(Mono.empty());
                    }
                    case ValidationResult.InUse(String ignored, UUID ownerId) -> {
                        if (ownerId.equals(userId)) {
                            // Same user reconnecting — takeover allowed
                            yield Mono.just(userId);
                        }
                        log.warn("Subdomain {} is in use by another user, rejecting sessionId={}", subdomain, session.getId());
                        yield session.close(CloseStatus.POLICY_VIOLATION.withReason("Subdomain in use"))
                                .then(Mono.empty());
                    }
                    case ValidationResult.InvalidFormat(String ignored, String reason) -> {
                        log.warn("Invalid subdomain format: {} reason={}", subdomain, reason);
                        yield session.close(CloseStatus.POLICY_VIOLATION.withReason("Invalid subdomain"))
                                .then(Mono.empty());
                    }
                    case ValidationResult.Blocked ignored -> {
                        log.warn("Blocked subdomain attempted: {}", subdomain);
                        yield session.close(CloseStatus.POLICY_VIOLATION.withReason("Subdomain not allowed"))
                                .then(Mono.empty());
                    }
                });
    }

    private Mono<UUID> checkTunnelLimit(WebSocketSession session, UUID userId, String tier) {
        SubscriptionTier subscriptionTier = SubscriptionTier.fromValue(tier);

        if (subscriptionTier.isUnlimitedTunnels()) {
            return Mono.just(userId);
        }

        return tunnelRegistry.listByUser(userId)
                .count()
                .flatMap(count -> {
                    if (count >= subscriptionTier.getMaxTunnels()) {
                        log.warn("Tunnel limit reached: userId={} tier={} active={} max={}",
                                userId, tier, count, subscriptionTier.getMaxTunnels());
                        return session.close(CloseStatus.POLICY_VIOLATION.withReason("Tunnel limit reached"))
                                .then(Mono.<UUID>empty());
                    }
                    return Mono.just(userId);
                });
    }

    private TunnelInfo buildTunnelInfo(UUID userId, String subdomain, int localPort) {
        return new TunnelInfo(
                UUID.randomUUID(),
                configProperties.getServer().getId(),
                configProperties.getServer().getAddress(),
                userId,
                subdomain,
                localPort,
                Instant.now()
        );
    }

    private void cleanup(String subdomain, TunnelConnection connection, String signal) {
        log.info("Tunnel disconnected: subdomain={} signal={}", subdomain, signal);
        heartbeatManager.stop(subdomain);
        tunnelRegistry.unregister(subdomain)
                .doOnError(e -> log.error("Error unregistering tunnel {}: {}", subdomain, e.getMessage()))
                .subscribe();
        connection.close().subscribe();
    }

    private int parseLocalPort(String value) {
        if (value == null) return 0;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}