// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// Wire layout (from groupshare.go):
//   uint16(version=1)
//   | uint16(aikLen) | <AccountIdentityPub.marshal()>
//   | uint32(senderDeviceId)
//   | uint16(roomJidLen) | <roomJID UTF-8>
//   | uint32(epoch)
//   | uint32(chainKeyLen=32) | <chainKey 32 bytes>
//   | uint32(nextIndex)
public final class SenderChainAnnouncement {

    public final AccountIdentityPub senderAIKPub;
    public final long senderDeviceId;   // uint32 stored as long
    public final String roomJID;
    public final long epoch;            // uint32 stored as long
    public final byte[] chainKey;       // always 32 bytes
    public final long nextIndex;        // uint32 stored as long

    public SenderChainAnnouncement(AccountIdentityPub senderAIKPub,
                                   long senderDeviceId,
                                   String roomJID,
                                   long epoch,
                                   byte[] chainKey,
                                   long nextIndex) {
        if (chainKey == null || chainKey.length != 32) {
            throw new IllegalArgumentException("SenderChainAnnouncement: chainKey must be 32 bytes");
        }
        this.senderAIKPub   = senderAIKPub;
        this.senderDeviceId = senderDeviceId;
        this.roomJID        = roomJID;
        this.epoch          = epoch;
        this.chainKey       = Arrays.copyOf(chainKey, 32);
        this.nextIndex      = nextIndex;
    }

    public byte[] marshal() {
        byte[] aikBytes  = senderAIKPub.marshal();
        byte[] roomBytes = roomJID.getBytes(StandardCharsets.UTF_8);

        int size = 2 + 2 + aikBytes.length + 4 + 2 + roomBytes.length + 4 + 4 + 32 + 4;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) 1);                        // version
        buf.putShort((short) aikBytes.length);          // aikLen
        buf.put(aikBytes);
        buf.putInt((int) senderDeviceId);               // senderDeviceId
        buf.putShort((short) roomBytes.length);         // roomJidLen
        buf.put(roomBytes);
        buf.putInt((int) epoch);                        // epoch
        buf.putInt(32);                                 // chainKeyLen
        buf.put(chainKey);
        buf.putInt((int) nextIndex);                    // nextIndex
        return buf.array();
    }

    public static SenderChainAnnouncement unmarshal(byte[] b) {
        if (b == null || b.length < 2) {
            throw new IllegalArgumentException("SenderChainAnnouncement: truncated input");
        }
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);

        int ver = buf.getShort() & 0xffff;
        if (ver != 1) {
            throw new IllegalArgumentException("SenderChainAnnouncement: unsupported version " + ver);
        }

        if (buf.remaining() < 2) throw new IllegalArgumentException("SenderChainAnnouncement: truncated aikLen");
        int aikLen = buf.getShort() & 0xffff;
        if (buf.remaining() < aikLen) throw new IllegalArgumentException("SenderChainAnnouncement: truncated AIK");
        byte[] aikBytes = new byte[aikLen];
        buf.get(aikBytes);
        AccountIdentityPub aik = AccountIdentityPub.unmarshal(aikBytes);

        if (buf.remaining() < 4) throw new IllegalArgumentException("SenderChainAnnouncement: truncated senderDeviceId");
        long senderDeviceId = buf.getInt() & 0xFFFFFFFFL;

        if (buf.remaining() < 2) throw new IllegalArgumentException("SenderChainAnnouncement: truncated roomJidLen");
        int roomLen = buf.getShort() & 0xffff;
        if (buf.remaining() < roomLen) throw new IllegalArgumentException("SenderChainAnnouncement: truncated roomJID");
        byte[] roomBytes = new byte[roomLen];
        buf.get(roomBytes);
        String roomJID = new String(roomBytes, StandardCharsets.UTF_8);

        if (buf.remaining() < 4 + 4 + 32 + 4) throw new IllegalArgumentException("SenderChainAnnouncement: truncated tail");
        long epoch      = buf.getInt() & 0xFFFFFFFFL;
        int ckLen       = buf.getInt();
        if (ckLen != 32) throw new IllegalArgumentException("SenderChainAnnouncement: unexpected chainKeyLen " + ckLen);
        byte[] ck = new byte[32];
        buf.get(ck);
        long nextIndex  = buf.getInt() & 0xFFFFFFFFL;

        return new SenderChainAnnouncement(aik, senderDeviceId, roomJID, epoch, ck, nextIndex);
    }
}
