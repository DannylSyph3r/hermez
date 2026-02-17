package dev.slethware.hermez.proxy;

import dev.slethware.hermez.config.HermezConfigProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SubdomainExtractor {

    private final HermezConfigProperties config;

    // Extracts the tunnel subdomain from the Host header.
    public String extract(ServerHttpRequest request) {
        String host = request.getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) return null;

        // Strip port if present
        int colonIdx = host.indexOf(':');
        if (colonIdx != -1) {
            host = host.substring(0, colonIdx);
        }

        String suffix = "." + config.getSubdomain().getBaseDomain();
        if (!host.endsWith(suffix)) return null;

        String subdomain = host.substring(0, host.length() - suffix.length());

        // Must be a single label — no dots, non-empty
        if (subdomain.isEmpty() || subdomain.contains(".")) return null;

        return subdomain.toLowerCase();
    }
}