// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class GroupMessageHeaderTest {

    @Test
    void marshalIsExactly14Bytes() {
        GroupMessageHeader h = new GroupMessageHeader(1, 0xDEADBEEFL, 7);
        byte[] wire = h.marshal();
        Assertions.assertEquals(14, wire.length, "marshal() must produce exactly 14 bytes");
    }

    @Test
    void marshalUnmarshalRoundtrip() {
        GroupMessageHeader original = new GroupMessageHeader(99L, 0xCAFEBABEL, 42L);
        byte[] wire = original.marshal();
        GroupMessageHeader recovered = GroupMessageHeader.unmarshal(wire);
        Assertions.assertEquals(original, recovered, "unmarshal(marshal(x)) must equal x");
    }

    @Test
    void wireByteOrder() {
        // epoch=1, senderDeviceId=2, chainIndex=3
        GroupMessageHeader h = new GroupMessageHeader(1, 2, 3);
        byte[] wire = h.marshal();
        // version (2 bytes big-endian) = 0x0001
        Assertions.assertEquals(0x00, wire[0] & 0xff);
        Assertions.assertEquals(0x01, wire[1] & 0xff);
        // epoch (4 bytes big-endian) = 0x00000001
        Assertions.assertEquals(0x00, wire[2] & 0xff);
        Assertions.assertEquals(0x00, wire[3] & 0xff);
        Assertions.assertEquals(0x00, wire[4] & 0xff);
        Assertions.assertEquals(0x01, wire[5] & 0xff);
        // senderDeviceId (4 bytes big-endian) = 0x00000002
        Assertions.assertEquals(0x00, wire[6] & 0xff);
        Assertions.assertEquals(0x02, wire[9] & 0xff);
        // chainIndex (4 bytes big-endian) = 0x00000003
        Assertions.assertEquals(0x00, wire[10] & 0xff);
        Assertions.assertEquals(0x03, wire[13] & 0xff);
    }

    @Test
    void aeadNonceIs12BytesWithGmsgPrefix() {
        byte[] nonce = GroupMessageHeader.aeadNonce(5L, 10L);
        Assertions.assertEquals(12, nonce.length, "AEAD nonce must be 12 bytes");
        // prefix "GMSG"
        Assertions.assertEquals('G', nonce[0] & 0xff);
        Assertions.assertEquals('M', nonce[1] & 0xff);
        Assertions.assertEquals('S', nonce[2] & 0xff);
        Assertions.assertEquals('G', nonce[3] & 0xff);
        // epoch = 5
        Assertions.assertEquals(0x00, nonce[4] & 0xff);
        Assertions.assertEquals(0x00, nonce[5] & 0xff);
        Assertions.assertEquals(0x00, nonce[6] & 0xff);
        Assertions.assertEquals(0x05, nonce[7] & 0xff);
        // chainIndex = 10
        Assertions.assertEquals(0x00, nonce[8]  & 0xff);
        Assertions.assertEquals(0x00, nonce[9]  & 0xff);
        Assertions.assertEquals(0x00, nonce[10] & 0xff);
        Assertions.assertEquals(0x0a, nonce[11] & 0xff);
    }

    @Test
    void aadIsHeaderPlusRoomJid() {
        GroupMessageHeader h = new GroupMessageHeader(0, 1, 0);
        String room = "test@conference.example";
        byte[] aad = h.aad(room);
        Assertions.assertEquals(14 + room.length(), aad.length,
                "AAD must be 14-byte header + roomJID bytes");
    }

    @Test
    void unmarshalRejectsWrongVersion() {
        byte[] buf = new byte[14];
        buf[1] = 0x02; // version = 2
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> GroupMessageHeader.unmarshal(buf));
    }

    @Test
    void unmarshalRejectsTruncated() {
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> GroupMessageHeader.unmarshal(new byte[13]));
    }
}
