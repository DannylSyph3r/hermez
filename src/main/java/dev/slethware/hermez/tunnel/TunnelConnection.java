package dev.slethware.hermez.tunnel;

import dev.slethware.hermez.tunnel.protocol.HttpRequestMessage;
import dev.slethware.hermez.tunnel.protocol.HttpResponseMessage;
import dev.slethware.hermez.tunnel.protocol.MessageEncoder;
import dev.slethware.hermez.tunnel.protocol.ProtocolMessage;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.publisher.MonoSink;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class TunnelConnection {

    @Getter
    private final String subdomain;

    private final WebSocketSession session;
    private final Sinks.Many<byte[]> outboundSink;
    private final ConcurrentHashMap<UUID, MonoSink<HttpResponseMessage>> pendingRequests;
    private final ConcurrentHashMap<UUID, ChunkedResponseAccumulator> pendingChunks;
    private final AtomicLong lastPongTime;

    public TunnelConnection(WebSocketSession session, String subdomain) {
        this.session        = session;
        this.subdomain      = subdomain;
        this.outboundSink   = Sinks.many().unicast().onBackpressureBuffer();
        this.pendingRequests = new ConcurrentHashMap<>();
        this.pendingChunks   = new ConcurrentHashMap<>();
        this.lastPongTime    = new AtomicLong(System.currentTimeMillis());
    }

    public Mono<HttpResponseMessage> sendRequest(HttpRequestMessage request) {
        // Return a Mono that completes when the CLI sends back the corresponding response.
        return Mono.<HttpResponseMessage>create(sink -> {
            pendingRequests.put(request.requestId(), sink);
            MessageEncoder.encodeRequest(request).forEach(frame -> {
                Sinks.EmitResult result = outboundSink.tryEmitNext(frame);
                if (result.isFailure()) {
                    log.warn("Failed to emit request frame for requestId={}: {}", request.requestId(), result);
                }
            });

            // Clean up on timeouts to prevent stale entries and memory leaks
            sink.onDispose(() -> pendingRequests.remove(request.requestId()));
        });
    }

    // Route an inbound protocol message to the appropriate handler.
    public void handleMessage(ProtocolMessage message) {
        switch (message) {
            case ProtocolMessage.Pong() -> {
                lastPongTime.set(System.currentTimeMillis());
                log.debug("Pong received for tunnel: {}", subdomain);
            }
            case ProtocolMessage.HttpResponse(HttpResponseMessage response) ->
                    completeRequest(response);

            case ProtocolMessage.HttpResponseStart(UUID requestId, int statusCode, Map<String, String> headers) ->
                    pendingChunks.put(requestId, new ChunkedResponseAccumulator(requestId, statusCode, headers));

            case ProtocolMessage.HttpResponseChunk(UUID requestId, byte[] data) -> {
                ChunkedResponseAccumulator acc = pendingChunks.get(requestId);
                if (acc != null) {
                    acc.addChunk(data);
                } else {
                    log.warn("Received chunk for unknown requestId={}", requestId);
                }
            }

            case ProtocolMessage.HttpResponseEnd(UUID requestId) -> {
                ChunkedResponseAccumulator acc = pendingChunks.remove(requestId);
                if (acc != null) {
                    completeRequest(acc.build());
                } else {
                    log.warn("Received response end for unknown requestId={}", requestId);
                }
            }
        }
    }

    public void sendPing() {
        Sinks.EmitResult result = outboundSink.tryEmitNext(MessageEncoder.encodePing());
        if (result.isFailure()) {
            log.warn("Failed to emit PING for tunnel: {}", subdomain);
        }
    }

    public long getLastPongTime() {
        return lastPongTime.get();
    }

    public Flux<byte[]> outbound() {
        return outboundSink.asFlux();
    }

    public Mono<Void> close() {
        outboundSink.tryEmitComplete();

        pendingChunks.clear();

        pendingRequests.forEach((id, sink) ->
                sink.error(new IllegalStateException("Tunnel connection closed for subdomain: " + subdomain)));
        pendingRequests.clear();

        return session.close()
                .doOnSuccess(v -> log.info("WebSocket session closed for tunnel: {}", subdomain))
                .onErrorResume(e -> {
                    log.warn("Error closing session for tunnel {}: {}", subdomain, e.getMessage());
                    return Mono.empty();
                });
    }

    private void completeRequest(HttpResponseMessage response) {
        MonoSink<HttpResponseMessage> sink = pendingRequests.remove(response.requestId());
        if (sink == null) {
            // Already timed out — onDispose cleaned the map, discard silently
            log.debug("Response arrived for expired/unknown requestId={}, discarding", response.requestId());
            return;
        }
        sink.success(response);
    }

    private static class ChunkedResponseAccumulator {

        private final UUID requestId;
        private final int statusCode;
        private final Map<String, String> headers;
        private final ByteArrayOutputStream body;

        ChunkedResponseAccumulator(UUID requestId, int statusCode, Map<String, String> headers) {
            this.requestId  = requestId;
            this.statusCode = statusCode;
            this.headers    = headers;
            this.body       = new ByteArrayOutputStream();
        }

        void addChunk(byte[] data) {
            try {
                body.write(data);
            } catch (IOException e) {
                log.error("Unexpected error writing chunk for requestId={}", requestId, e);
            }
        }

        HttpResponseMessage build() {
            return new HttpResponseMessage(requestId, statusCode, headers, body.toByteArray());
        }
    }
}