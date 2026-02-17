package dev.slethware.hermez.tunnel.protocol;

import java.util.Map;
import java.util.UUID;

public sealed interface ProtocolMessage
        permits ProtocolMessage.Pong,
        ProtocolMessage.HttpResponse,
        ProtocolMessage.HttpResponseStart,
        ProtocolMessage.HttpResponseChunk,
        ProtocolMessage.HttpResponseEnd {

    record Pong() implements ProtocolMessage {}
    record HttpResponse(HttpResponseMessage message) implements ProtocolMessage {}
    record HttpResponseStart(UUID requestId, int statusCode, Map<String, String> headers) implements ProtocolMessage {}
    record HttpResponseChunk(UUID requestId, byte[] data) implements ProtocolMessage {}
    record HttpResponseEnd(UUID requestId) implements ProtocolMessage {}
}