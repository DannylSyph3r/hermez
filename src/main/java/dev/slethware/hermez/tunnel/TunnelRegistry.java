package dev.slethware.hermez.tunnel;

import reactor.core.publisher.Mono;

import java.util.UUID;

public interface TunnelRegistry {

    Mono<Void> register(String subdomain, TunnelConnection connection, TunnelInfo info, UUID userId);
    Mono<Void> unregister(String subdomain);
    Mono<TunnelLookupResult> lookup(String subdomain);
    Mono<Void> refreshTtl(String subdomain);
}