package dev.slethware.hermez.proxy;

import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.domain.CustomDomainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(-200)
@RequiredArgsConstructor
public class RequestRouter implements WebFilter {

    public static final String HERMEZ_RESOLVED_SUBDOMAIN = "HERMEZ_RESOLVED_SUBDOMAIN";

    private final ProxyService proxyService;
    private final CustomDomainService customDomainService;
    private final HermezConfigProperties config;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Always pass WebSocket upgrade requests through — covers CLI connections to /connect
        String upgrade = exchange.getRequest().getHeaders().getFirst(HttpHeaders.UPGRADE);
        if ("websocket".equalsIgnoreCase(upgrade)) {
            return chain.filter(exchange);
        }

        String host = exchange.getRequest().getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) {
            return chain.filter(exchange);
        }

        // Strip port if present
        String hostWithoutPort = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        String baseDomain = config.getSubdomain().getBaseDomain();

        // api.hermez.one and bare hermez.one → normal Spring controller routing
        if (hostWithoutPort.equals("api." + baseDomain) || hostWithoutPort.equals(baseDomain)) {
            return chain.filter(exchange);
        }

        // *.hermez.one → tunnel traffic, short-circuit to proxy
        if (hostWithoutPort.endsWith("." + baseDomain)) {
            return proxyService.handle(exchange);
        }

        // Custom domain — resolve against registered domains, route to proxy if found
        return customDomainService.resolveSubdomain(hostWithoutPort)
                .flatMap(resolvedSubdomain -> {
                    exchange.getAttributes().put(HERMEZ_RESOLVED_SUBDOMAIN, resolvedSubdomain);
                    return proxyService.handle(exchange);
                })
                .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)));
    }
}