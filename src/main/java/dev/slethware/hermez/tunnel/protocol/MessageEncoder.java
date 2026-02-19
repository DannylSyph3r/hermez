package dev.slethware.hermez.tunnel.protocol;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class MessageEncoder {

    private static final int CHUNK_THRESHOLD = 64 * 1024;
    private static final int CHUNK_SIZE = 32 * 1024;

    private MessageEncoder() {}

    public static byte[] encodePing() {
        // length=1 (just the type byte), type=PING, no payload
        ByteBuffer buf = ByteBuffer.allocate(5);
        buf.putInt(1);
        buf.put(MessageType.PING.getValue());
        return buf.array();
    }

    public static byte[] encodeTunnelClose(String reason, String code) {
        byte[] payload = String.format("{\"reason\":\"%s\",\"code\":\"%s\"}", reason, code)
                .getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + 1 + payload.length);
        buf.putInt(1 + payload.length);
        buf.put(MessageType.TUNNEL_CLOSE.getValue());
        buf.put(payload);
        return buf.array();
    }

    public static List<byte[]> encodeRequest(HttpRequestMessage message) {
        byte[] body = message.body() != null ? message.body() : new byte[0];
        if (body.length < CHUNK_THRESHOLD) {
            return List.of(encodeSingleRequest(message, body));
        }
        return encodeChunkedRequest(message, body);
    }

    private static byte[] encodeSingleRequest(HttpRequestMessage message, byte[] body) {
        byte[] idBytes    = uuidToBytes(message.requestId());
        byte[] methodBytes = message.method().getBytes(StandardCharsets.UTF_8);
        byte[] pathBytes   = message.path().getBytes(StandardCharsets.UTF_8);
        byte[] headerBytes = encodeHeaders(message.headers());

        int payloadSize = 32 + 1 + methodBytes.length
                + 2 + pathBytes.length
                + headerBytes.length
                + 4 + body.length;

        ByteBuffer buf = ByteBuffer.allocate(4 + 1 + payloadSize);
        buf.putInt(1 + payloadSize);
        buf.put(MessageType.HTTP_REQUEST.getValue());
        buf.put(idBytes);
        buf.put((byte) methodBytes.length);
        buf.put(methodBytes);
        buf.putShort((short) pathBytes.length);
        buf.put(pathBytes);
        buf.put(headerBytes);
        buf.putInt(body.length);
        buf.put(body);
        return buf.array();
    }

    private static List<byte[]> encodeChunkedRequest(HttpRequestMessage message, byte[] body) {
        List<byte[]> frames = new ArrayList<>();
        byte[] idBytes     = uuidToBytes(message.requestId());
        byte[] methodBytes = message.method().getBytes(StandardCharsets.UTF_8);
        byte[] pathBytes   = message.path().getBytes(StandardCharsets.UTF_8);
        byte[] headerBytes = encodeHeaders(message.headers());

        // START: metadata only
        int startPayload = 32 + 1 + methodBytes.length + 2 + pathBytes.length + headerBytes.length;
        ByteBuffer start = ByteBuffer.allocate(4 + 1 + startPayload);
        start.putInt(1 + startPayload);
        start.put(MessageType.HTTP_REQUEST_START.getValue());
        start.put(idBytes);
        start.put((byte) methodBytes.length);
        start.put(methodBytes);
        start.putShort((short) pathBytes.length);
        start.put(pathBytes);
        start.put(headerBytes);
        frames.add(start.array());

        // CHUNKS
        int offset = 0;
        while (offset < body.length) {
            int len = Math.min(CHUNK_SIZE, body.length - offset);
            ByteBuffer chunk = ByteBuffer.allocate(4 + 1 + 32 + 4 + len);
            chunk.putInt(1 + 32 + 4 + len);
            chunk.put(MessageType.HTTP_REQUEST_CHUNK.getValue());
            chunk.put(idBytes);
            chunk.putInt(len);
            chunk.put(body, offset, len);
            frames.add(chunk.array());
            offset += len;
        }

        // END
        ByteBuffer end = ByteBuffer.allocate(4 + 1 + 32);
        end.putInt(1 + 32);
        end.put(MessageType.HTTP_REQUEST_END.getValue());
        end.put(idBytes);
        frames.add(end.array());

        return frames;
    }

    private static byte[] encodeHeaders(Map<String, String> headers) {
        List<byte[]> names  = new ArrayList<>(headers.size());
        List<byte[]> values = new ArrayList<>(headers.size());
        int total = 2; // header count field

        for (Map.Entry<String, String> entry : headers.entrySet()) {
            byte[] name  = entry.getKey().getBytes(StandardCharsets.UTF_8);
            byte[] value = entry.getValue().getBytes(StandardCharsets.UTF_8);
            names.add(name);
            values.add(value);
            total += 2 + name.length + 2 + value.length;
        }

        ByteBuffer buf = ByteBuffer.allocate(total);
        buf.putShort((short) headers.size());
        for (int i = 0; i < names.size(); i++) {
            buf.putShort((short) names.get(i).length);
            buf.put(names.get(i));
            buf.putShort((short) values.get(i).length);
            buf.put(values.get(i));
        }
        return buf.array();
    }

    static byte[] uuidToBytes(UUID uuid) {
        String hex = uuid.toString().replace("-", ""); // 32 chars
        return hex.getBytes(StandardCharsets.UTF_8);
    }
}