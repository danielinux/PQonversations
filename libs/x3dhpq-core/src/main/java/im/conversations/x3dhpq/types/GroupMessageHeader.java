// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// Fixed 14-byte wire: uint16(version=1) | uint32(epoch) | uint32(senderDeviceId) | uint32(chainIndex).
public final class GroupMessageHeader {

    public static final int WIRE_SIZE = 14;

    public final int version;       // always 1
    public final long epoch;        // uint32, stored as long to avoid sign issues
    public final long senderDeviceId;
    public final long chainIndex;

    public GroupMessageHeader(long epoch, long senderDeviceId, long chainIndex) {
        this.version = 1;
        this.epoch = epoch;
        this.senderDeviceId = senderDeviceId;
        this.chainIndex = chainIndex;
    }

    public byte[] marshal() {
        ByteBuffer buf = ByteBuffer.allocate(WIRE_SIZE).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) version);
        buf.putInt((int) epoch);
        buf.putInt((int) senderDeviceId);
        buf.putInt((int) chainIndex);
        return buf.array();
    }

    public static GroupMessageHeader unmarshal(byte[] b) {
        if (b == null || b.length < WIRE_SIZE) {
            throw new IllegalArgumentException("GroupMessageHeader: truncated wire encoding");
        }
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        int ver = buf.getShort() & 0xffff;
        if (ver != 1) {
            throw new IllegalArgumentException("GroupMessageHeader: unsupported version " + ver);
        }
        long epoch         = buf.getInt() & 0xFFFFFFFFL;
        long senderDevId   = buf.getInt() & 0xFFFFFFFFL;
        long chainIndex    = buf.getInt() & 0xFFFFFFFFL;
        return new GroupMessageHeader(epoch, senderDevId, chainIndex);
    }

    // 12-byte AEAD nonce: "GMSG"(4) || epoch(4 BE) || chainIndex(4 BE).
    public static byte[] aeadNonce(long epoch, long chainIndex) {
        ByteBuffer buf = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 'G');
        buf.put((byte) 'M');
        buf.put((byte) 'S');
        buf.put((byte) 'G');
        buf.putInt((int) epoch);
        buf.putInt((int) chainIndex);
        return buf.array();
    }

    // AEAD AAD per spec §13.3: marshal() || roomJID.getBytes(UTF_8).
    public byte[] aad(String roomJID) {
        byte[] header = marshal();
        byte[] room   = roomJID.getBytes(StandardCharsets.UTF_8);
        byte[] out    = new byte[header.length + room.length];
        System.arraycopy(header, 0, out, 0, header.length);
        System.arraycopy(room,   0, out, header.length, room.length);
        return out;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof GroupMessageHeader)) return false;
        GroupMessageHeader o = (GroupMessageHeader) obj;
        return version == o.version
            && epoch == o.epoch
            && senderDeviceId == o.senderDeviceId
            && chainIndex == o.chainIndex;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(epoch ^ (senderDeviceId << 16) ^ chainIndex);
    }
}
