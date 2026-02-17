package dev.slethware.hermez.tunnel;

public sealed interface TunnelLookupResult
        permits TunnelLookupResult.Local,
        TunnelLookupResult.Remote,
        TunnelLookupResult.NotFound,
        TunnelLookupResult.ServerDead {

    // Tunnel is on this server instance
    record Local(TunnelConnection connection) implements TunnelLookupResult {}

    // Tunnel is on a different server instance, proxy to that address
    record Remote(String serverAddress) implements TunnelLookupResult {}

    // No active tunnel found for this subdomain
    record NotFound() implements TunnelLookupResult {}

    // Tunnel entry exists in Redis but the attached server is unhealthy
    record ServerDead(String subdomain) implements TunnelLookupResult {}
}