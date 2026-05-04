// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.GroupMessageHeader;
import im.conversations.x3dhpq.types.HmacSha256;
import im.conversations.x3dhpq.types.SenderChain;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Round-trip test for GroupEnvelope: marshal header → base64 round-trip → unmarshal.
 * Also verifies the full encrypt/decrypt cycle that GroupCryptoService will use.
 *
 * The known-good vector is derived from the Go reference:
 *   groupmsg_test.go TestGroupHeaderMarshalRoundTrip with epoch=42, senderDeviceId=7, chainIndex=99.
 * Go marshal output (14 bytes, big-endian):
 *   00 01  00 00 00 2A  00 00 00 07  00 00 00 63
 *   (version=1, epoch=42, senderDeviceId=7, chainIndex=99)
 */
class GroupEnvelopeRoundTripTest {

    private static HmacSha256 MAC;

    @BeforeAll
    static void setUp() {
        BouncyCastleInstaller.ensureRegistered();
        MAC = (key, message) -> {
            try {
                Mac m = Mac.getInstance("HmacSHA256");
                m.init(new SecretKeySpec(key, "HmacSHA256"));
                return m.doFinal(message);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    // -------------------------------------------------------------------------
    // Wire-format vector matching Go groupmsg_test.go
    // -------------------------------------------------------------------------

    /** Matches Go test: epoch=42, senderDeviceId=7, chainIndex=99. */
    @Test
    void knownGoodHeaderVector() {
        GroupMessageHeader hdr = new GroupMessageHeader(42L, 7L, 99L);
        byte[] wire = hdr.marshal();

        // Expected 14-byte big-endian wire encoding
        byte[] expected = {
            0x00, 0x01,                         // version = 1
            0x00, 0x00, 0x00, 0x2A,             // epoch = 42
            0x00, 0x00, 0x00, 0x07,             // senderDeviceId = 7
            0x00, 0x00, 0x00, 0x63              // chainIndex = 99
        };
        Assertions.assertArrayEquals(expected, wire,
                "header marshal must match Go reference vector");

        // Unmarshal and verify field-by-field
        GroupMessageHeader hdr2 = GroupMessageHeader.unmarshal(wire);
        Assertions.assertEquals(1L,  hdr2.version,         "version must be 1");
        Assertions.assertEquals(42L, hdr2.epoch,           "epoch mismatch");
        Assertions.assertEquals(7L,  hdr2.senderDeviceId,  "senderDeviceId mismatch");
        Assertions.assertEquals(99L, hdr2.chainIndex,      "chainIndex mismatch");
    }

    // -------------------------------------------------------------------------
    // GroupEnvelope round-trip: marshal → unmarshal → re-marshal byte-identical
    // -------------------------------------------------------------------------

    @Test
    void groupEnvelopeRoundTrip_marshalUnmarshalReIdentical() {
        GroupMessageHeader hdr = new GroupMessageHeader(1L, 100L, 7L);
        byte[] fakeCtTag = new byte[32]; // 16 ct + 16 GCM tag minimum
        Arrays.fill(fakeCtTag, (byte) 0xAB);

        GroupEnvelope env = new GroupEnvelope(hdr, fakeCtTag);
        byte[] hdrBytes = env.marshalHeader();
        byte[] ct       = env.getCiphertext();

        // Round-trip
        GroupEnvelope env2 = GroupEnvelope.unmarshal(hdrBytes, ct);
        byte[] hdrBytes2 = env2.marshalHeader();
        byte[] ct2       = env2.getCiphertext();

        Assertions.assertArrayEquals(hdrBytes, hdrBytes2, "header must be byte-identical after round-trip");
        Assertions.assertArrayEquals(ct,       ct2,       "ciphertext must be byte-identical after round-trip");
    }

    // -------------------------------------------------------------------------
    // Full encrypt / decrypt cycle with HMAC-SHA-256 sender chain
    // -------------------------------------------------------------------------

    @Test
    void encryptDecryptGroupMessage_roundTrip() {
        final String roomJid = "testroom@conference.example.org";
        final long epoch = 0L;
        final long senderDeviceId = 42L;

        // Build a fresh sender chain with deterministic key
        byte[] chainKey = new byte[32];
        Arrays.fill(chainKey, (byte) 0x55);
        SenderChain sc = new SenderChain(0, chainKey);

        // Step the chain to get mk and current index
        int indexBefore = sc.nextIndex;
        byte[] mk = sc.step(MAC);
        int chainIndex = indexBefore;

        // Derive header
        GroupMessageHeader hdr = new GroupMessageHeader(epoch, senderDeviceId, chainIndex);
        byte[] aad   = hdr.aad(roomJid);
        byte[] nonce = GroupMessageHeader.aeadNonce(epoch, chainIndex);

        // Encrypt plaintext
        byte[] plaintext = "hello group".getBytes(StandardCharsets.UTF_8);
        byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(mk, nonce, plaintext, aad);

        // Build envelope and simulate XML transport (marshal header, carry ct)
        GroupEnvelope env = new GroupEnvelope(hdr, ct);
        byte[] wireHdr = env.marshalHeader();
        byte[] wireCt  = env.getCiphertext();

        // Receiver side: reconstruct from wire
        GroupEnvelope received = GroupEnvelope.unmarshal(wireHdr, wireCt);
        GroupMessageHeader rxHdr = received.header;

        // Reconstruct recv chain from announced state (same chainKey, nextIndex=0)
        byte[] ckCopy = Arrays.copyOf(chainKey, 32);
        SenderChain rxChain = new SenderChain(0, ckCopy);
        // Step to chainIndex 0
        byte[] rxMk = rxChain.step(MAC);

        Assertions.assertEquals(chainIndex, (int) rxHdr.chainIndex, "chain index mismatch");

        // Decrypt
        byte[] rxNonce   = GroupMessageHeader.aeadNonce(rxHdr.epoch, rxHdr.chainIndex);
        byte[] rxAad     = rxHdr.aad(roomJid);
        byte[] decrypted = X3dhpqCrypto.aes256gcmDecrypt(rxMk, rxNonce, received.ciphertext, rxAad);
        Assertions.assertArrayEquals(plaintext, decrypted, "decrypt must recover original plaintext");
    }

    // -------------------------------------------------------------------------
    // AEAD nonce format: "GMSG" || epoch(4 BE) || chainIndex(4 BE)
    // -------------------------------------------------------------------------

    @Test
    void aeadNonceFormat() {
        byte[] nonce = GroupMessageHeader.aeadNonce(0x0A0B0C0DL, 0x01020304L);
        Assertions.assertEquals(12, nonce.length, "nonce must be 12 bytes");
        Assertions.assertEquals((byte) 'G', nonce[0]);
        Assertions.assertEquals((byte) 'M', nonce[1]);
        Assertions.assertEquals((byte) 'S', nonce[2]);
        Assertions.assertEquals((byte) 'G', nonce[3]);
        // Epoch big-endian
        Assertions.assertEquals((byte) 0x0A, nonce[4]);
        Assertions.assertEquals((byte) 0x0B, nonce[5]);
        Assertions.assertEquals((byte) 0x0C, nonce[6]);
        Assertions.assertEquals((byte) 0x0D, nonce[7]);
        // ChainIndex big-endian
        Assertions.assertEquals((byte) 0x01, nonce[8]);
        Assertions.assertEquals((byte) 0x02, nonce[9]);
        Assertions.assertEquals((byte) 0x03, nonce[10]);
        Assertions.assertEquals((byte) 0x04, nonce[11]);
    }

    // -------------------------------------------------------------------------
    // Reject truncated / invalid inputs
    // -------------------------------------------------------------------------

    @Test
    void unmarshal_rejectsTruncatedHeader() {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> GroupEnvelope.unmarshal(new byte[13], new byte[32]));
    }

    @Test
    void unmarshal_rejectsTooShortCiphertext() {
        byte[] hdr = new GroupMessageHeader(1L, 1L, 0L).marshal();
        // Only 15 bytes: less than the 16-byte GCM tag minimum
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> GroupEnvelope.unmarshal(hdr, new byte[15]));
    }
}
