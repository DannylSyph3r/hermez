package dev.slethware.hermez.tunnel;

import dev.slethware.hermez.tunnel.api.TunnelListResponse;
import reactor.core.publisher.Mono;

import java.util.UUID;

public interface TunnelService {
    Mono<TunnelListResponse> listTunnels(UUID userId);
    Mono<Void> closeTunnel(UUID tunnelId, UUID requestingUserId);
}