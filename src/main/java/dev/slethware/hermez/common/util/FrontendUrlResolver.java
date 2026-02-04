package dev.slethware.hermez.common.util;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class FrontendUrlResolver {

    public String getFrontendUrl(ServerHttpRequest request) {
        String host = request.getHeaders().getHost().getHostString();

        return switch (host) {
            case "localhost", "127.0.0.1" -> "http://localhost:3000";
            case "api.staging.hermez.one" -> "https://staging.hermez.one";
            case "api.hermez.one" -> "https://hermez.one";
            default -> "https://hermez.one";
        };
    }

    public String getLoginUrl(ServerHttpRequest request) {
        return getFrontendUrl(request) + "/login";
    }
}