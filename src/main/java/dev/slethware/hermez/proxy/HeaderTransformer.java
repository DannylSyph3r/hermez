package dev.slethware.hermez.proxy;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import java.net.InetSocketAddress;
import java.util.Set;

@Component
public class HeaderTransformer {

    private static final Set<String> HEADERS_TO_STRIP = Set.of(
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-real-ip"
    );

    public HttpHeaders transform(HttpHeaders original, InetSocketAddress clientAddress, int localPort, String requestId) {
        HttpHeaders transformed = new HttpHeaders();

        original.forEach((name, values) -> {
            if (!HEADERS_TO_STRIP.contains(name.toLowerCase())) {
                transformed.addAll(name, values);
            }
        });

        // Rewrite Host
        transformed.set(HttpHeaders.HOST, "localhost:" + localPort);

        // Forwarding headers
        if (clientAddress != null && clientAddress.getAddress() != null) {
            transformed.set("X-Forwarded-For", clientAddress.getAddress().getHostAddress());
        }
        transformed.set("X-Forwarded-Proto", "https");
        transformed.set("X-Forwarded-Host", original.getFirst(HttpHeaders.HOST));
        transformed.set("X-Forwarded-Port", "443");

        // Correlation ID
        transformed.set("X-Request-Id", requestId);

        return transformed;
    }
}