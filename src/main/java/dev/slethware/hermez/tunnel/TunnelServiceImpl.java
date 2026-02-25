package dev.slethware.hermez.tunnel;

import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.exception.ResourceNotFoundException;
import dev.slethware.hermez.tunnel.api.TunnelListResponse;
import dev.slethware.hermez.tunnel.api.TunnelResponse;
import dev.slethware.hermez.user.SubscriptionTier;
import dev.slethware.hermez.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TunnelServiceImpl implements TunnelService {

    private final TunnelRegistry tunnelRegistry;
    private final UserRepository userRepository;
    private final HermezConfigProperties configProperties;

    @Override
    public Mono<TunnelListResponse> listTunnels(UUID userId) {
        return userRepository.findById(userId)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("User not found")))
                .flatMap(user -> {
                    SubscriptionTier tier = SubscriptionTier.fromValue(user.getTier());

                    return tunnelRegistry.listByUser(userId)
                            .map(this::toResponse)
                            .collectList()
                            .map(tunnels -> new TunnelListResponse(
                                    tunnels,
                                    tunnels.size(),
                                    new TunnelListResponse.LimitsInfo(
                                            tier.getMaxTunnels(),
                                            tunnels.size()
                                    )
                            ));
                });
    }

    @Override
    public Mono<Void> closeTunnel(UUID tunnelId, UUID requestingUserId) {
        return tunnelRegistry.listByUser(requestingUserId)
                .filter(conn -> tunnelId.equals(conn.getTunnelInfo().tunnelId()))
                .next()
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Tunnel not found")))
                .flatMap(conn -> {
                    log.info("Force closing tunnel: tunnelId={} subdomain={} userId={}",
                            tunnelId, conn.getSubdomain(), requestingUserId);
                    conn.sendTunnelClose("Tunnel closed from the dashboard", "dashboard_close");
                    return conn.close();
                });
    }

    private TunnelResponse toResponse(TunnelConnection conn) {
        TunnelInfo info = conn.getTunnelInfo();
        String publicUrl = String.format("https://%s.%s",
                info.subdomain(), configProperties.getSubdomain().getBaseDomain());
        return new TunnelResponse(
                info.tunnelId(),
                info.subdomain(),
                publicUrl,
                info.localPort(),
                "active",
                info.createdAt(),
                conn.getRequestCount()
        );
    }
}