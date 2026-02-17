package dev.slethware.hermez.tunnel.protocol;

import java.util.Map;
import java.util.UUID;

public record HttpResponseMessage(
        UUID requestId,
        int statusCode,
        Map<String, String> headers,
        byte[] body
) {}