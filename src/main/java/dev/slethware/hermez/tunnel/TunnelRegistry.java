package dev.slethware.hermez.tunnel;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface TunnelRegistry {

    Mono<Void> register(String subdomain, TunnelConnection connection, TunnelInfo info, UUID userId);
    Mono<Void> unregister(String subdomain);
    Mono<TunnelLookupResult> lookup(String subdomain);
    Mono<Void> refreshTtl(String subdomain);
    Flux<TunnelConnection> listByUser(UUID userId);
    Mono<String> checkGrace(UUID userId, int localPort);
}