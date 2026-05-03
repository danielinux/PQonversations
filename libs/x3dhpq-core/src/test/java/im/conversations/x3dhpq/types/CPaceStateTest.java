// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class CPaceStateTest {

    @Test
    void testConstructorAndAccessors() {
        byte[] sid        = new byte[]{1, 2, 3, 4};
        byte[] transcript = new byte[]{5, 6, 7};
        byte[] g          = new byte[32]; // dummy generator point

        CPaceState st = new CPaceState(CPaceRole.INITIATOR, sid, transcript, g);

        assertEquals(CPaceRole.INITIATOR, st.getRole());
        assertArrayEquals(sid,        st.getSid());
        assertArrayEquals(transcript, st.getTranscript());
        assertArrayEquals(g,          st.getG());
        // ephemeral fields are null until setEphemeral is called
        assertNull(st.getYScalar());
        assertNull(st.getMyMsg());
    }

    @Test
    void testSetEphemeral() {
        byte[] yScalar = new byte[32];
        byte[] myMsg   = new byte[32];
        Arrays.fill(yScalar, (byte) 0xAA);
        Arrays.fill(myMsg,   (byte) 0xBB);

        CPaceState st = new CPaceState(CPaceRole.RESPONDER,
                new byte[4], new byte[3], new byte[32]);
        st.setEphemeral(yScalar, myMsg);

        assertArrayEquals(yScalar, st.getYScalar());
        assertArrayEquals(myMsg,   st.getMyMsg());
    }

    @Test
    void testGettersReturnDefensiveCopies() {
        byte[] sid = new byte[]{0x01, 0x02};
        CPaceState st = new CPaceState(CPaceRole.INITIATOR, sid, new byte[0], new byte[0]);
        byte[] retrieved = st.getSid();
        retrieved[0] = (byte) 0xFF;
        // mutation of retrieved copy must not affect stored value
        assertEquals(0x01, st.getSid()[0] & 0xff);
    }

    @Test
    void testNullInputsTreatedAsEmpty() {
        CPaceState st = new CPaceState(CPaceRole.INITIATOR, null, null, null);
        assertNotNull(st.getSid());
        assertEquals(0, st.getSid().length);
        assertNotNull(st.getTranscript());
        assertNotNull(st.getG());
    }

    @Test
    void testBothRolesCreatable() {
        CPaceState i = new CPaceState(CPaceRole.INITIATOR,  new byte[4], new byte[0], new byte[0]);
        CPaceState r = new CPaceState(CPaceRole.RESPONDER,  new byte[4], new byte[0], new byte[0]);
        assertEquals(CPaceRole.INITIATOR, i.getRole());
        assertEquals(CPaceRole.RESPONDER, r.getRole());
    }
}
