package dev.slethware.hermez.tunnel.protocol;

import java.util.Map;
import java.util.UUID;

public record HttpRequestMessage(
        UUID requestId,
        String method,
        String path,
        Map<String, String> headers,
        byte[] body
) {}