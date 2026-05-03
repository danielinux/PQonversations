// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;

class KemCheckpointTest {

    private static final HkdfSha512 HKDF = new BcHkdfSha512();
    private static final Sha512     SHA  = new BcSha512();

    // A.5 vector
    @Test
    void vectorA5KemCheckpointMix() {
        byte[] senderCK = new byte[32];
        Arrays.fill(senderCK, (byte) 0xBB);

        byte[] kemSS = new byte[32];
        Arrays.fill(kemSS, (byte) 0xCC);

        byte[] senderDH = new byte[32];
        for (int i = 0; i < 32; i++) senderDH[i] = (byte) (0x01 + i);

        byte[] kemCT = new byte[16];
        Arrays.fill(kemCT, (byte) 0xDD);

        byte[] prevHistory = new byte[32]; // all zeros

        KemCheckpoint.Result r = KemCheckpoint.mix(
                senderCK, kemSS, senderDH, kemCT, 42L, prevHistory, HKDF, SHA);

        Assertions.assertEquals(
                "a69de60e57332f72590af362634ee57f3002644a7d4a6fd86b2146dcaf3d24a7",
                hex(r.newCKs()), "A.5 newCKs must match vector");
        Assertions.assertEquals(
                "fdb1f3d1eb083c9049170245004401f1649eae82d7d14620bdd64d717c39dce2",
                hex(r.newCKr()), "A.5 newCKr must match vector");
        Assertions.assertEquals(
                "3cd70ff3b328c19fb5cb767d31e3e11e8c01e2860393fadd5bb7d3e689c1e10e",
                hex(r.newHistory()), "A.5 newHistory must match vector");
    }

    @Test
    void resultFieldsAre32Bytes() {
        byte[] senderCK  = new byte[32];
        byte[] kemSS     = new byte[32];
        byte[] senderDH  = new byte[32];
        byte[] kemCT     = new byte[16];
        byte[] prevHist  = new byte[32];
        KemCheckpoint.Result r = KemCheckpoint.mix(
                senderCK, kemSS, senderDH, kemCT, 0L, prevHist, HKDF, SHA);
        Assertions.assertEquals(32, r.newCKs().length);
        Assertions.assertEquals(32, r.newCKr().length);
        Assertions.assertEquals(32, r.newHistory().length);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
