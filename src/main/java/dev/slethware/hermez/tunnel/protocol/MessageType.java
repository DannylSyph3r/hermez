package dev.slethware.hermez.tunnel.protocol;

public enum MessageType {

    PING(0x01),
    PONG(0x02),
    HTTP_REQUEST(0x10),
    HTTP_RESPONSE(0x11),
    HTTP_REQUEST_START(0x12),
    HTTP_REQUEST_CHUNK(0x13),
    HTTP_REQUEST_END(0x14),
    HTTP_RESPONSE_START(0x15),
    HTTP_RESPONSE_CHUNK(0x16),
    HTTP_RESPONSE_END(0x17),
    TUNNEL_CLOSE(0x20),
    ERROR(0xFF);

    private final int value;

    MessageType(int value) {
        this.value = value;
    }

    public byte getValue() {
        return (byte) value;
    }

    public static MessageType fromByte(byte b) {
        int unsigned = b & 0xFF;
        for (MessageType type : values()) {
            if (type.value == unsigned) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown message type: 0x" + Integer.toHexString(unsigned));
    }
}