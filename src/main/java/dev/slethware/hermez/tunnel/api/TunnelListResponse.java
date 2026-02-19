package dev.slethware.hermez.tunnel.api;

import java.util.List;

public record TunnelListResponse(
        List<TunnelResponse> tunnels,
        int total,
        LimitsInfo limits
) {
    public record LimitsInfo(int maxTunnels, int usedTunnels) {}
}