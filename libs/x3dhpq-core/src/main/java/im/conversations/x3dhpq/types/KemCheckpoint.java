// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// Static helper that mirrors kemCheckpointMix() from ratchet.go.
//
// Algorithm (exact info strings from x3dh.go / ratchet.go):
//
//   transcript_hash = SHA-512("X3DHPQ-Checkpoint-Transcript-v1\0" || uint32be(epoch)
//                              || senderDH || kemCT)
//   prk             = HKDF-SHA-512-Extract(salt=senderCK, ikm=kemSS || transcript_hash)
//   newCKs          = HKDF-SHA-512-Expand(prk, "X3DHPQ-ChainSend-v1", 32)
//   newCKr          = HKDF-SHA-512-Expand(prk, "X3DHPQ-ChainRecv-v1", 32)
//   newHistory      = SHA-512("X3DHPQ-KEMHistory-v1\0" || prevHistory || kemSS
//                             || transcript_hash)[:32]
//
// Note: the Go reference uses HKDF-SHA-512 (wolfcrypt WC_SHA512) — not SHA-256.
// HkdfSha512 and Sha512 interfaces are injected so tests can use BouncyCastle and
// production can use the same facade.
public final class KemCheckpoint {

    private KemCheckpoint() {}

    public record Result(byte[] newCKs, byte[] newCKr, byte[] newHistory) {}

    // Null-terminated labels match the Go const literals exactly.
    private static final byte[] TRANSCRIPT_LABEL = withNul("X3DHPQ-Checkpoint-Transcript-v1");
    private static final byte[] HISTORY_LABEL    = withNul("X3DHPQ-KEMHistory-v1");
    private static final byte[] INFO_CHAIN_SEND  = "X3DHPQ-ChainSend-v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_CHAIN_RECV  = "X3DHPQ-ChainRecv-v1".getBytes(StandardCharsets.UTF_8);

    private static byte[] withNul(String s) {
        byte[] raw = s.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[raw.length + 1];
        System.arraycopy(raw, 0, out, 0, raw.length);
        out[raw.length] = 0x00;
        return out;
    }

    public static Result mix(byte[] senderCK, byte[] kemSS, byte[] senderDH,
                             byte[] kemCT, long epoch, byte[] prevHistory,
                             HkdfSha512 hkdf, Sha512 sha) {

        // 1. Transcript hash: SHA-512(label\0 || uint32be(epoch) || senderDH || kemCT)
        byte[] epochBuf = new byte[4];
        ByteBuffer.wrap(epochBuf).order(ByteOrder.BIG_ENDIAN).putInt((int) epoch);
        byte[] transcriptInput = concat(TRANSCRIPT_LABEL, epochBuf, senderDH, kemCT);
        byte[] th = sha.hash(transcriptInput);   // 64 bytes

        // 2. HKDF-SHA-512-Extract(salt=senderCK, ikm=kemSS||th), then Expand per info string.
        //    Calling derive twice recomputes Extract each time; output is identical since
        //    Extract is deterministic and the interface wraps Extract+Expand together.
        byte[] ikm = concat(kemSS, th);
        byte[] newCKs = hkdf.derive(senderCK, ikm, INFO_CHAIN_SEND, 32);
        byte[] newCKr = hkdf.derive(senderCK, ikm, INFO_CHAIN_RECV, 32);

        // 3. History digest: SHA-512(label\0 || prevHistory || kemSS || th), take [:32].
        byte[] histInput  = concat(HISTORY_LABEL, prevHistory, kemSS, th);
        byte[] histDigest = sha.hash(histInput);
        byte[] newHistory = Arrays.copyOf(histDigest, 32);

        return new Result(newCKs, newCKr, newHistory);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
