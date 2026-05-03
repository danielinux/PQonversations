// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class DeviceIdentityKeyTest {

    // Build a fully populated DeviceIdentityKey with deterministic bytes.
    private static DeviceIdentityKey makeKey() {
        byte[] privEd = new byte[DeviceIdentityKey.ED25519_PRIV_SIZE];
        Arrays.fill(privEd, (byte) 0x01);
        byte[] pubEd = new byte[DeviceIdentityKey.ED25519_PUB_SIZE];
        Arrays.fill(pubEd, (byte) 0x02);
        byte[] privX = new byte[DeviceIdentityKey.X25519_PRIV_SIZE];
        Arrays.fill(privX, (byte) 0x03);
        byte[] pubX = new byte[DeviceIdentityKey.X25519_PUB_SIZE];
        Arrays.fill(pubX, (byte) 0x04);
        byte[] privMldsa = new byte[DeviceIdentityKey.MLDSA65_PRIV_SIZE];
        Arrays.fill(privMldsa, (byte) 0x05);
        byte[] pubMldsa = new byte[DeviceIdentityKey.MLDSA65_PUB_SIZE];
        Arrays.fill(pubMldsa, (byte) 0x06);
        return new DeviceIdentityKey(privEd, pubEd, privX, pubX, privMldsa, pubMldsa);
    }

    @Test
    void marshalLengthIsCorrect() {
        // 32+32+32+32+4032+1952 = 6112 bytes.
        byte[] blob = makeKey().marshal();
        Assertions.assertEquals(DeviceIdentityKey.MARSHAL_SIZE, blob.length);
        Assertions.assertEquals(6112, blob.length);
    }

    @Test
    void marshalUnmarshalRoundtrip() {
        DeviceIdentityKey original = makeKey();
        byte[] blob = original.marshal();
        DeviceIdentityKey recovered = DeviceIdentityKey.unmarshal(blob);

        Assertions.assertArrayEquals(original.getPrivEd25519(), recovered.getPrivEd25519());
        Assertions.assertArrayEquals(original.getPubEd25519(), recovered.getPubEd25519());
        Assertions.assertArrayEquals(original.getPrivX25519(), recovered.getPrivX25519());
        Assertions.assertArrayEquals(original.getPubX25519(), recovered.getPubX25519());
        Assertions.assertArrayEquals(original.getPrivMLDSA(), recovered.getPrivMLDSA());
        Assertions.assertArrayEquals(original.getPubMLDSA(), recovered.getPubMLDSA());
    }

    @Test
    void unmarshalWrongLengthThrows() {
        // Wrong-length blobs must throw, not silently corrupt.
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> DeviceIdentityKey.unmarshal(new byte[100]));
    }
}
