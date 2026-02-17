package dev.slethware.hermez.tunnel.protocol;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class MessageDecoder {

    private MessageDecoder() {}

    public static ProtocolMessage decode(byte[] frame) {
        if (frame.length < 5) {
            throw new IllegalArgumentException("Frame too short: " + frame.length + " bytes");
        }

        ByteBuffer buf = ByteBuffer.wrap(frame);
        int length = buf.getInt();

        if (frame.length < 4 + length) {
            throw new IllegalArgumentException(
                    "Incomplete frame: expected " + (4 + length) + " bytes, got " + frame.length);
        }

        MessageType type = MessageType.fromByte(buf.get());

        return switch (type) {
            case PONG              -> new ProtocolMessage.Pong();
            case HTTP_RESPONSE     -> decodeHttpResponse(buf);
            case HTTP_RESPONSE_START -> decodeHttpResponseStart(buf);
            case HTTP_RESPONSE_CHUNK -> decodeHttpResponseChunk(buf);
            case HTTP_RESPONSE_END   -> decodeHttpResponseEnd(buf);
            default -> throw new IllegalArgumentException("Unexpected message type from client: " + type);
        };
    }

    private static ProtocolMessage.HttpResponse decodeHttpResponse(ByteBuffer buf) {
        UUID requestId = readRequestId(buf);
        int statusCode = buf.getShort() & 0xFFFF;
        Map<String, String> headers = readHeaders(buf);
        int bodyLen = buf.getInt();
        byte[] body = new byte[bodyLen];
        buf.get(body);
        return new ProtocolMessage.HttpResponse(
                new HttpResponseMessage(requestId, statusCode, headers, body));
    }

    private static ProtocolMessage.HttpResponseStart decodeHttpResponseStart(ByteBuffer buf) {
        UUID requestId = readRequestId(buf);
        int statusCode = buf.getShort() & 0xFFFF;
        Map<String, String> headers = readHeaders(buf);
        return new ProtocolMessage.HttpResponseStart(requestId, statusCode, headers);
    }

    private static ProtocolMessage.HttpResponseChunk decodeHttpResponseChunk(ByteBuffer buf) {
        UUID requestId = readRequestId(buf);
        int len = buf.getInt();
        byte[] data = new byte[len];
        buf.get(data);
        return new ProtocolMessage.HttpResponseChunk(requestId, data);
    }

    private static ProtocolMessage.HttpResponseEnd decodeHttpResponseEnd(ByteBuffer buf) {
        return new ProtocolMessage.HttpResponseEnd(readRequestId(buf));
    }

    private static UUID readRequestId(ByteBuffer buf) {
        byte[] idBytes = new byte[32];
        buf.get(idBytes);
        String hex = new String(idBytes, StandardCharsets.UTF_8);
        // Reinsert hyphens: 8-4-4-4-12
        return UUID.fromString(
                hex.substring(0, 8) + "-" +
                        hex.substring(8, 12) + "-" +
                        hex.substring(12, 16) + "-" +
                        hex.substring(16, 20) + "-" +
                        hex.substring(20)
        );
    }

    private static Map<String, String> readHeaders(ByteBuffer buf) {
        int count = buf.getShort() & 0xFFFF;
        Map<String, String> headers = new HashMap<>(count);
        for (int i = 0; i < count; i++) {
            int nameLen = buf.getShort() & 0xFFFF;
            byte[] nameBytes = new byte[nameLen];
            buf.get(nameBytes);
            int valueLen = buf.getShort() & 0xFFFF;
            byte[] valueBytes = new byte[valueLen];
            buf.get(valueBytes);
            headers.put(
                    new String(nameBytes, StandardCharsets.UTF_8),
                    new String(valueBytes, StandardCharsets.UTF_8)
            );
        }
        return headers;
    }
}