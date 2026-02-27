package dev.slethware.hermez.proxy;

import dev.slethware.hermez.config.HermezConfigProperties;
import dev.slethware.hermez.requestinspection.LogStatus;
import dev.slethware.hermez.requestinspection.RequestInspectionService;
import dev.slethware.hermez.tunnel.TunnelLookupResult;
import dev.slethware.hermez.tunnel.TunnelRegistry;
import dev.slethware.hermez.tunnel.protocol.HttpRequestMessage;
import dev.slethware.hermez.tunnel.protocol.HttpResponseMessage;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeoutException;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProxyService {

    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
            "transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "upgrade"
    );

    private final TunnelRegistry tunnelRegistry;
    private final SubdomainExtractor subdomainExtractor;
    private final HeaderTransformer headerTransformer;
    private final RateLimiter rateLimiter;
    private final HermezConfigProperties config;
    private final RequestInspectionService requestInspectionService;

    private String page404;
    private String page503;
    private String page429;
    private String page502;

    @PostConstruct
    public void loadErrorPages() {
        page404 = loadResource("error-pages/404.html");
        page503 = loadResource("error-pages/503.html");
        page429 = loadResource("error-pages/429.html");
        page502 = loadResource("error-pages/502.html");
        log.info("Proxy error pages loaded");
    }

    public Mono<Void> handle(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        // Custom domain traffic arrives with a pre-resolved subdomain attribute set by RequestRouter
        String resolvedSubdomain = exchange.getAttribute(RequestRouter.HERMEZ_RESOLVED_SUBDOMAIN);
        String subdomain = resolvedSubdomain != null
                ? resolvedSubdomain
                : subdomainExtractor.extract(request);

        if (subdomain == null) {
            return writeErrorPage(response, HttpStatus.NOT_FOUND, page404, "unknown");
        }

        // For custom domain traffic, error pages show the original host the user typed
        String displayHost = resolvedSubdomain != null
                ? extractHostWithoutPort(request)
                : subdomain;

        return rateLimiter.checkLimit(subdomain)
                .flatMap(rateLimit -> {
                    response.getHeaders().set("X-RateLimit-Limit", String.valueOf(rateLimit.limit()));

                    if (!rateLimit.allowed()) {
                        log.info("Rate limit exceeded: subdomain={} count={}/{}", subdomain, rateLimit.count(), rateLimit.limit());
                        response.getHeaders().set("Retry-After", String.valueOf(rateLimit.retryAfterSeconds()));
                        response.getHeaders().set("X-RateLimit-Remaining", "0");
                        return writeErrorPage(response, HttpStatus.TOO_MANY_REQUESTS, page429, displayHost);
                    }

                    response.getHeaders().set("X-RateLimit-Remaining",
                            String.valueOf(Math.max(0, rateLimit.limit() - rateLimit.count())));

                    return tunnelRegistry.lookup(subdomain)
                            .flatMap(result -> switch (result) {
                                case TunnelLookupResult.Local local ->
                                        forwardToTunnel(local, request, response, subdomain, displayHost);

                                case TunnelLookupResult.ServerDead ignored -> {
                                    log.warn("Dead server for subdomain={}", subdomain);
                                    yield writeErrorPage(response, HttpStatus.SERVICE_UNAVAILABLE, page503, displayHost);
                                }

                                case TunnelLookupResult.Remote ignored -> {
                                    // Single-server MVP — cross-server forwarding not implemented
                                    log.warn("Remote tunnel lookup for subdomain={} not supported in MVP", subdomain);
                                    yield writeErrorPage(response, HttpStatus.SERVICE_UNAVAILABLE, page503, displayHost);
                                }

                                case TunnelLookupResult.NotFound ignored -> {
                                    log.debug("Tunnel not found: subdomain={}", subdomain);
                                    yield writeErrorPage(response, HttpStatus.NOT_FOUND, page404, displayHost);
                                }
                            });
                });
    }

    private Mono<Void> forwardToTunnel(
            TunnelLookupResult.Local local,
            ServerHttpRequest request,
            ServerHttpResponse response,
            String subdomain,
            String displayHost) {

        Instant startedAt = Instant.now();
        int localPort = local.connection().getTunnelInfo().localPort();
        UUID userId = local.connection().getTunnelInfo().userId();
        InetSocketAddress clientAddress = request.getRemoteAddress();
        String clientIp = clientAddress != null ? clientAddress.getAddress().getHostAddress() : null;
        String requestId = UUID.randomUUID().toString();

        HttpHeaders transformedHeaders = headerTransformer.transform(
                request.getHeaders(), clientAddress, localPort, requestId
        );

        return DataBufferUtils.join(request.getBody())
                .defaultIfEmpty(response.bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> {
                    byte[] bodyBytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bodyBytes);
                    DataBufferUtils.release(dataBuffer);

                    Map<String, String> headersMap = new HashMap<>();
                    transformedHeaders.forEach((name, values) -> {
                        if (!values.isEmpty()) headersMap.put(name, values.getFirst());
                    });

                    String rawPath  = request.getURI().getRawPath();
                    String rawQuery = request.getURI().getRawQuery();
                    String fullPath = rawQuery != null ? rawPath + "?" + rawQuery : rawPath;

                    HttpRequestMessage message = new HttpRequestMessage(
                            UUID.randomUUID(),
                            request.getMethod().name(),
                            fullPath,
                            headersMap,
                            bodyBytes
                    );

                    log.debug("Forwarding: subdomain={} method={} path={}", subdomain, message.method(), message.path());

                    return requestInspectionService.captureRequest(
                                    subdomain, userId, requestId,
                                    request.getMethod().name(), rawPath, rawQuery, clientIp,
                                    headersMap, bodyBytes, startedAt)
                            .map(Optional::of)
                            .onErrorResume(e -> {
                                log.warn("Inspection capture failed, proceeding without capture: {}", e.getMessage());
                                return Mono.just(Optional.empty());
                            })
                            .flatMap(optLogId ->
                                    local.connection().sendRequest(message)
                                            .timeout(config.getTunnel().getRequestTimeout())
                                            .flatMap(tunnelResponse -> {
                                                optLogId.ifPresent(logId ->
                                                        requestInspectionService.completeCapture(logId, tunnelResponse, Instant.now())
                                                                .onErrorResume(err -> {
                                                                    log.warn("Failed to complete inspection log {}: {}", logId, err.getMessage());
                                                                    return Mono.empty();
                                                                })
                                                                .subscribeOn(Schedulers.boundedElastic())
                                                                .subscribe()
                                                );
                                                return writeProxyResponse(response, tunnelResponse);
                                            })
                                            .onErrorResume(TimeoutException.class, e -> {
                                                log.warn("Tunnel request timed out: subdomain={}", subdomain);
                                                optLogId.ifPresent(logId ->
                                                        requestInspectionService.failCapture(logId, "Request timed out", LogStatus.TIMEOUT, Instant.now())
                                                                .onErrorResume(err -> {
                                                                    log.warn("Failed to fail inspection log {}: {}", logId, err.getMessage());
                                                                    return Mono.empty();
                                                                })
                                                                .subscribeOn(Schedulers.boundedElastic())
                                                                .subscribe()
                                                );
                                                return writeErrorPage(response, HttpStatus.GATEWAY_TIMEOUT, page502, displayHost);
                                            })
                                            .onErrorResume(e -> {
                                                log.error("Tunnel forwarding error: subdomain={} error={}", subdomain, e.getMessage());
                                                optLogId.ifPresent(logId ->
                                                        requestInspectionService.failCapture(logId, e.getMessage(), LogStatus.ERROR, Instant.now())
                                                                .onErrorResume(err -> {
                                                                    log.warn("Failed to fail inspection log {}: {}", logId, err.getMessage());
                                                                    return Mono.empty();
                                                                })
                                                                .subscribeOn(Schedulers.boundedElastic())
                                                                .subscribe()
                                                );
                                                return writeErrorPage(response, HttpStatus.BAD_GATEWAY, page502, displayHost);
                                            })
                            );
                });
    }

    private String extractHostWithoutPort(ServerHttpRequest request) {
        String host = request.getHeaders().getFirst(HttpHeaders.HOST);
        if (host == null) return "unknown";
        int colonIdx = host.indexOf(':');
        return colonIdx != -1 ? host.substring(0, colonIdx) : host;
    }

    private Mono<Void> writeProxyResponse(ServerHttpResponse response, HttpResponseMessage tunnelResponse) {
        response.setStatusCode(HttpStatus.valueOf(tunnelResponse.statusCode()));

        tunnelResponse.headers().forEach((name, value) -> {
            if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                response.getHeaders().set(name, value);
            }
        });

        if (tunnelResponse.body() != null && tunnelResponse.body().length > 0) {
            DataBuffer buffer = response.bufferFactory().wrap(tunnelResponse.body());
            return response.writeWith(Mono.just(buffer));
        }

        return response.setComplete();
    }

    private Mono<Void> writeErrorPage(ServerHttpResponse response, HttpStatus status, String template, String subdomain) {
        if (response.isCommitted()) {
            return Mono.empty();
        }
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.TEXT_HTML);
        String html = template.replace("{{subdomain}}", subdomain);
        DataBuffer buffer = response.bufferFactory().wrap(html.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private String loadResource(String path) {
        try {
            ClassPathResource resource = new ClassPathResource(path);
            try (InputStream is = resource.getInputStream()) {
                return StreamUtils.copyToString(is, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            log.error("Failed to load error page: {}", path, e);
            return "<html><body><h1>Error</h1></body></html>";
        }
    }
}