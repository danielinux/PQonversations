// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;

class SenderChainAnnouncementTest {

    private static AccountIdentityPub buildAik() {
        byte[] pubEd = new byte[32];
        for (int i = 0; i < 32; i++) pubEd[i] = (byte) (0x01 + i);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) 0xA5);
        return new AccountIdentityPub(pubEd, pubMLDSA);
    }

    @Test
    void marshalUnmarshalRoundtrip() {
        AccountIdentityPub aik = buildAik();
        // aikBytes = 1987 bytes; confirm AIK marshal size matches
        Assertions.assertEquals(1987, aik.marshal().length, "AIK marshal must be 1987 bytes");

        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0x5A);
        SenderChainAnnouncement original = new SenderChainAnnouncement(
                aik, 0xDEADBEEFL, "room@conference.example", 7L, ck, 3L);

        byte[] wire = original.marshal();
        SenderChainAnnouncement recovered = SenderChainAnnouncement.unmarshal(wire);

        Assertions.assertTrue(original.senderAIKPub.equals(recovered.senderAIKPub));
        Assertions.assertEquals(original.senderDeviceId, recovered.senderDeviceId);
        Assertions.assertEquals(original.roomJID, recovered.roomJID);
        Assertions.assertEquals(original.epoch, recovered.epoch);
        Assertions.assertArrayEquals(original.chainKey, recovered.chainKey);
        Assertions.assertEquals(original.nextIndex, recovered.nextIndex);
    }

    @Test
    void wireLengthMatchesFormula() {
        // size = 2 + 2 + aikLen + 4 + 2 + roomLen + 4 + 4 + 32 + 4
        AccountIdentityPub aik = buildAik();
        byte[] ck = new byte[32];
        String room = "r@c.example";
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                aik, 1L, room, 0L, ck, 0L);
        int expected = 2 + 2 + 1987 + 4 + 2 + room.length() + 4 + 4 + 32 + 4;
        Assertions.assertEquals(expected, ann.marshal().length, "wire length must match formula");
    }

    @Test
    void unmarshalRejectsWrongVersion() {
        byte[] buf = new byte[100];
        buf[1] = 0x02; // version = 2
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> SenderChainAnnouncement.unmarshal(buf));
    }

    @Test
    void unmarshalRejectsBadChainKeyLen() {
        AccountIdentityPub aik = buildAik();
        byte[] ck = new byte[32];
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                aik, 1L, "r@c", 0L, ck, 0L);
        byte[] wire = ann.marshal();
        // Corrupt the chainKeyLen field: find its offset.
        // offset = 2 + 2 + 1987 + 4 + 2 + 3 ("r@c" = 3 bytes) + 4 = 2004
        int ckLenOff = 2 + 2 + 1987 + 4 + 2 + 3 + 4;
        wire[ckLenOff + 3] = 16; // set chainKeyLen = 16 instead of 32
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> SenderChainAnnouncement.unmarshal(wire));
    }
}
