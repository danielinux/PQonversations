// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.types.GroupMessageHeader;
import java.util.Arrays;

/**
 * Pure-Java helpers for marshalling / unmarshalling a group message envelope.
 *
 * The envelope is NOT XML-aware; it works on raw byte arrays.  XML wrapping
 * lives in {@code model/x3dhpq/envelope/EnvelopeGroup.java}.
 *
 * In-memory representation:
 *   header   – 14-byte GroupMessageHeader wire encoding
 *   ct       – AES-256-GCM ciphertext (plaintext.length + 16 bytes tag)
 *
 * Nothing is framed in this class; callers pass the two fields separately
 * to/from the XML model, which base64-encodes them.
 */
public final class GroupEnvelope {

    private static final int MAX_CT_LEN = 65536; // §MAX_FIELD_LEN precedent

    public final GroupMessageHeader header;
    public final byte[] ciphertext;

    public GroupEnvelope(GroupMessageHeader header, byte[] ciphertext) {
        if (header == null) throw new IllegalArgumentException("header is null");
        if (ciphertext == null) throw new IllegalArgumentException("ciphertext is null");
        if (ciphertext.length > MAX_CT_LEN) {
            throw new IllegalArgumentException("ciphertext exceeds MAX_CT_LEN: " + ciphertext.length);
        }
        this.header     = header;
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    }

    /**
     * Returns the 14-byte marshalled header.
     * Callers base64-encode this as the {@code <hdr>} child.
     */
    public byte[] marshalHeader() {
        return header.marshal();
    }

    /**
     * Returns a copy of the ciphertext.
     * Callers base64-encode this as the {@code <ct>} child.
     */
    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    /**
     * Reconstruct a GroupEnvelope from the two base64-decoded children.
     *
     * @param headerBytes 14 bytes from the {@code <hdr>} child
     * @param ct          bytes from the {@code <ct>} child
     */
    public static GroupEnvelope unmarshal(byte[] headerBytes, byte[] ct) {
        if (headerBytes == null || headerBytes.length < GroupMessageHeader.WIRE_SIZE) {
            throw new IllegalArgumentException("GroupEnvelope: header too short");
        }
        if (ct == null || ct.length < 16) {
            throw new IllegalArgumentException("GroupEnvelope: ciphertext too short (need at least GCM tag)");
        }
        if (ct.length > MAX_CT_LEN) {
            throw new IllegalArgumentException("GroupEnvelope: ciphertext exceeds MAX_CT_LEN");
        }
        GroupMessageHeader hdr = GroupMessageHeader.unmarshal(headerBytes);
        return new GroupEnvelope(hdr, ct);
    }
}
