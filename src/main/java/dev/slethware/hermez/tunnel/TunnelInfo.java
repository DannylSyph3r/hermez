package dev.slethware.hermez.tunnel;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.UUID;

public record TunnelInfo(
        @JsonProperty("server_id")      String serverId,
        @JsonProperty("server_address") String serverAddress,
        @JsonProperty("user_id")        UUID userId,
        String subdomain,
        @JsonProperty("local_port")     int localPort,
        @JsonProperty("created_at")     Instant createdAt
) {}