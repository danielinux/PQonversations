// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

// Wire envelope for one CPace/pairing IQ payload.  Mirrors PairingMsg from pairing.go.
// Wire layout: uint8(type) | uint32(len) | <payload>
public final class PairingMsg {

    // Message type constants mirror PairingMsgType consts in pairing.go.
    public static final int TYPE_PAKE1   = 1;
    public static final int TYPE_PAKE2   = 2;
    public static final int TYPE_CONFIRM = 3;
    public static final int TYPE_PAYLOAD = 4;
    public static final int TYPE_ACK     = 5;

    private final int    type;
    private final byte[] payload;

    public PairingMsg(int type, byte[] payload) {
        this.type    = type;
        this.payload = payload != null ? Arrays.copyOf(payload, payload.length) : new byte[0];
    }

    public int    getType()    { return type; }
    public byte[] getPayload() { return Arrays.copyOf(payload, payload.length); }

    // Serialises to: uint8(type) | uint32(payloadLen) | payload
    public byte[] marshal() {
        ByteBuffer buf = ByteBuffer.allocate(1 + 4 + payload.length).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) (type & 0xff));
        buf.putInt(payload.length);
        buf.put(payload);
        return buf.array();
    }

    public static PairingMsg unmarshal(byte[] raw) {
        if (raw == null || raw.length < 5) {
            throw new IllegalArgumentException("pairing: protocol violation");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        int type = buf.get() & 0xff;
        long len = buf.getInt() & 0xffffffffL;
        if (buf.remaining() < len) {
            throw new IllegalArgumentException("pairing: protocol violation");
        }
        byte[] payload = new byte[(int) len];
        buf.get(payload);
        return new PairingMsg(type, payload);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PairingMsg)) return false;
        PairingMsg other = (PairingMsg) o;
        return type == other.type && Arrays.equals(payload, other.payload);
    }

    @Override
    public int hashCode() {
        return 31 * type + Arrays.hashCode(payload);
    }
}
