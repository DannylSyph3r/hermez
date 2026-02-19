package dev.slethware.hermez.tunnel.api;

import java.time.Instant;
import java.util.UUID;

public record TunnelResponse(
        UUID tunnelId,
        String subdomain,
        String publicUrl,
        int localPort,
        String status,
        Instant createdAt,
        long requestCount
) {}