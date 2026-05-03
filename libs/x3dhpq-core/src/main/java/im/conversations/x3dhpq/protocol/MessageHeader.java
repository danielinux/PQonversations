// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

// Wire-form per-message ratchet header. Mirrors MessageHeader in
// xmppqr/internal/x3dhpqcrypto/header.go exactly (TLV, 4-byte big-endian length prefixes).
//
// Layout (each field prefixed with uint32be length):
//   dhPub        (32 bytes)
//   prevChainLen (uint32, encoded as 4-byte field)
//   n            (uint32, message number in current chain)
//   kemCiphertext (0 or 1088 bytes; non-empty on KEM-checkpoint messages)
//   kemPubForReply (0 or 1184 bytes; non-null when sender advertises its KEM recv pub)
public final class MessageHeader {

    // Sender's current ephemeral X25519 pub (32 bytes).
    public final byte[] dhPub;
    // Length of sender's previous chain (PrevSendCount in Go State).
    public final long prevChainLen;
    // Position of this message in the current chain (SendCount at time of encrypt).
    public final long n;
    // KEM ciphertext encapsulated to the receiver's kemRecvPub; non-null on checkpoint.
    public final byte[] kemCiphertext;
    // Receiver's next KEM pub to encapsulate to; may be null.
    public final byte[] kemPubForReply;

    public MessageHeader(byte[] dhPub, long prevChainLen, long n,
                         byte[] kemCiphertext, byte[] kemPubForReply) {
        this.dhPub         = dhPub         != null ? Arrays.copyOf(dhPub, dhPub.length) : new byte[0];
        this.prevChainLen  = prevChainLen;
        this.n             = n;
        this.kemCiphertext = kemCiphertext != null ? Arrays.copyOf(kemCiphertext, kemCiphertext.length) : new byte[0];
        this.kemPubForReply= kemPubForReply != null ? Arrays.copyOf(kemPubForReply, kemPubForReply.length) : new byte[0];
    }

    // Serialise to bytes matching Go's MessageHeader.Marshal().
    // Each field: uint32be(len) || bytes.  uint32 fields encoded as len=4 field.
    public byte[] marshal() {
        byte[] prevBytes = uint32Bytes((int) prevChainLen);
        byte[] nBytes    = uint32Bytes((int) n);
        int total = 4 + dhPub.length
                  + 4 + 4           // prevChainLen: length-prefix(4) + value(4)
                  + 4 + 4           // n: length-prefix(4) + value(4)
                  + 4 + kemCiphertext.length
                  + 4 + kemPubForReply.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        putField(buf, dhPub);
        putU32Field(buf, (int) prevChainLen);
        putU32Field(buf, (int) n);
        putField(buf, kemCiphertext);
        putField(buf, kemPubForReply);
        return buf.array();
    }

    // Deserialise from bytes matching Go's UnmarshalHeader().
    public static MessageHeader unmarshal(byte[] data) {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        byte[] dhPub         = readField(buf);
        long   prevChainLen  = readU32Field(buf);
        long   n             = readU32Field(buf);
        byte[] kemCiphertext = readField(buf);
        byte[] kemPubForReply= readField(buf);
        return new MessageHeader(dhPub, prevChainLen, n, kemCiphertext, kemPubForReply);
    }

    // Whether this header carries a KEM checkpoint ciphertext.
    public boolean hasKemCheckpoint() {
        return kemCiphertext != null && kemCiphertext.length > 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MessageHeader)) return false;
        MessageHeader h = (MessageHeader) o;
        return prevChainLen == h.prevChainLen && n == h.n
            && Arrays.equals(dhPub, h.dhPub)
            && Arrays.equals(kemCiphertext, h.kemCiphertext)
            && Arrays.equals(kemPubForReply, h.kemPubForReply);
    }

    @Override
    public int hashCode() {
        int r = Arrays.hashCode(dhPub);
        r = 31 * r + (int) prevChainLen;
        r = 31 * r + (int) n;
        r = 31 * r + Arrays.hashCode(kemCiphertext);
        r = 31 * r + Arrays.hashCode(kemPubForReply);
        return r;
    }

    // -------------------------------------------------------------------------
    // Private helpers matching Go's marshalField / marshalU32 / unmarshalField.
    // -------------------------------------------------------------------------

    private static void putField(ByteBuffer buf, byte[] data) {
        buf.putInt(data.length);
        buf.put(data);
    }

    private static void putU32Field(ByteBuffer buf, int value) {
        buf.putInt(4);          // length = 4
        buf.putInt(value);
    }

    // Hard upper bound on any single field. The biggest legitimate field is the
    // ML-KEM-768 public key at 1184 bytes; 64 KiB is comfortably above that and
    // far below Android's heap limits, so a length above this signals corrupt or
    // attacker-controlled input. Without this guard, a 4-byte garbage length
    // (e.g. from a foreign client emitting a different header format) causes
    // an OOM allocation that crashes the entire Conversations process.
    private static final int MAX_FIELD_LEN = 65536;

    private static byte[] readField(ByteBuffer buf) {
        if (buf.remaining() < 4) {
            throw new IllegalArgumentException("header truncated reading length");
        }
        int len = buf.getInt();
        if (len < 0 || len > MAX_FIELD_LEN) {
            throw new IllegalArgumentException("header field length out of range: " + len);
        }
        if (len > buf.remaining()) {
            throw new IllegalArgumentException(
                    "header truncated: declared field length " + len
                            + " exceeds remaining " + buf.remaining());
        }
        if (len == 0) return new byte[0];
        byte[] out = new byte[len];
        buf.get(out);
        return out;
    }

    private static long readU32Field(ByteBuffer buf) {
        if (buf.remaining() < 4) {
            throw new IllegalArgumentException("header truncated reading u32 length");
        }
        int len = buf.getInt();  // should be 4
        if (len != 4) throw new IllegalArgumentException("expected 4-byte u32 field, got " + len);
        if (buf.remaining() < 4) {
            throw new IllegalArgumentException("header truncated reading u32 value");
        }
        return Integer.toUnsignedLong(buf.getInt());
    }

    private static byte[] uint32Bytes(int v) {
        ByteBuffer b = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        b.putInt(v);
        return b.array();
    }
}
