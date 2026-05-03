// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;

class SenderChainTest {

    private static final HmacSha256 MAC = new BcHmacSha256();

    // A.3 vector: CK = 0xAA x32.
    @Test
    void vectorA3SenderChainStep() {
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0xAA);
        SenderChain chain = new SenderChain(0, ck);
        byte[] mk = chain.step(MAC);
        Assertions.assertEquals(
                "790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e",
                hex(mk), "A.3 message key must match vector");
        Assertions.assertEquals(
                "e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e",
                hex(chain.chainKey), "A.3 next chain key must match vector");
        Assertions.assertEquals(1, chain.nextIndex, "nextIndex must be 1 after one step");
    }

    @Test
    void stepAdvancesNextIndex() {
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0x42);
        SenderChain chain = new SenderChain(3, ck);
        chain.step(MAC);
        Assertions.assertEquals(1, chain.nextIndex);
        chain.step(MAC);
        Assertions.assertEquals(2, chain.nextIndex);
    }

    @Test
    void skippedKeyRoundtrip() {
        SenderChain chain = new SenderChain(0, new byte[32]);
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x7E);
        chain.putSkipped(5, key);
        byte[] got = chain.consumeSkipped(5);
        Assertions.assertArrayEquals(key, got, "consumeSkipped must return stored key");
        Assertions.assertNull(chain.consumeSkipped(5), "second consume must return null");
    }

    @Test
    void skippedKeyTableCapEnforced() {
        SenderChain chain = new SenderChain(0, new byte[32]);
        for (int i = 0; i < SenderChain.DEFAULT_MAX_SKIPPED; i++) {
            chain.putSkipped(i, new byte[32]);
        }
        Assertions.assertThrows(IllegalStateException.class,
                () -> chain.putSkipped(SenderChain.DEFAULT_MAX_SKIPPED, new byte[32]),
                "inserting a 257th skipped key must throw");
    }

    @Test
    void chainStepStaticHelperMatchesInstance() {
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0xBB);
        byte[][] out = SenderChain.chainStep(ck, MAC);
        SenderChain chain = new SenderChain(0, ck);
        byte[] mk = chain.step(MAC);
        Assertions.assertArrayEquals(out[0], mk, "static chainStep MK must match instance step");
        Assertions.assertArrayEquals(out[1], chain.chainKey, "static chainStep nextCK must match instance step");
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
