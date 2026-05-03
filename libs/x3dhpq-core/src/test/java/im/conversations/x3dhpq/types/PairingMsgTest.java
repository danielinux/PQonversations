// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class PairingMsgTest {

    @Test
    void testMarshalLayout() {
        // Layout: uint8(type) | uint32(len) | payload
        byte[] payload = new byte[]{0x0a, 0x0b, 0x0c};
        PairingMsg msg = new PairingMsg(PairingMsg.TYPE_PAKE1, payload);
        byte[] wire = msg.marshal();

        assertEquals(1 + 4 + 3, wire.length);
        assertEquals(PairingMsg.TYPE_PAKE1, wire[0] & 0xff);
        // uint32 big-endian length = 3
        assertEquals(0, wire[1]);
        assertEquals(0, wire[2]);
        assertEquals(0, wire[3]);
        assertEquals(3, wire[4]);
        assertArrayEquals(payload, Arrays.copyOfRange(wire, 5, 8));
    }

    @Test
    void testMarshalUnmarshalRoundTrip() {
        byte[] payload = new byte[32];
        Arrays.fill(payload, (byte) 0xAB);
        PairingMsg original = new PairingMsg(PairingMsg.TYPE_CONFIRM, payload);
        PairingMsg recovered = PairingMsg.unmarshal(original.marshal());
        assertEquals(original, recovered);
    }

    @Test
    void testEmptyPayload() {
        PairingMsg msg = new PairingMsg(PairingMsg.TYPE_ACK, new byte[0]);
        byte[] wire = msg.marshal();
        assertEquals(5, wire.length);
        PairingMsg recovered = PairingMsg.unmarshal(wire);
        assertEquals(PairingMsg.TYPE_ACK, recovered.getType());
        assertEquals(0, recovered.getPayload().length);
    }

    @Test
    void testAllTypeConstants() {
        assertEquals(1, PairingMsg.TYPE_PAKE1);
        assertEquals(2, PairingMsg.TYPE_PAKE2);
        assertEquals(3, PairingMsg.TYPE_CONFIRM);
        assertEquals(4, PairingMsg.TYPE_PAYLOAD);
        assertEquals(5, PairingMsg.TYPE_ACK);
    }

    @Test
    void testUnmarshalTooShortThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingMsg.unmarshal(new byte[4]));
    }

    @Test
    void testUnmarshalTruncatedPayloadThrows() {
        // type(1) + length=10 but only 3 bytes of payload follow
        byte[] bad = new byte[]{0x01, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03};
        assertThrows(IllegalArgumentException.class, () -> PairingMsg.unmarshal(bad));
    }

    @Test
    void testGetPayloadIsDefensiveCopy() {
        byte[] payload = new byte[]{1, 2, 3};
        PairingMsg msg = new PairingMsg(PairingMsg.TYPE_PAKE2, payload);
        byte[] got = msg.getPayload();
        got[0] = (byte) 0xFF;
        assertEquals(1, msg.getPayload()[0] & 0xff);
    }
}
