// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class AccountIdentityKeyTest {

    // Build a fully populated AccountIdentityKey with deterministic bytes.
    private static AccountIdentityKey makeKey() {
        byte[] privEd = new byte[AccountIdentityKey.ED25519_PRIV_SIZE];
        Arrays.fill(privEd, (byte) 0x11);

        byte[] privMldsa = new byte[AccountIdentityKey.MLDSA65_PRIV_SIZE];
        Arrays.fill(privMldsa, (byte) 0x22);

        byte[] pubEd = new byte[AccountIdentityPub.ED25519_PUB_SIZE];
        Arrays.fill(pubEd, (byte) 0x33);

        byte[] pubMldsa = new byte[AccountIdentityPub.MLDSA65_PUB_SIZE];
        Arrays.fill(pubMldsa, (byte) 0x44);

        AccountIdentityPub pub = new AccountIdentityPub(pubEd, pubMldsa);
        return new AccountIdentityKey(privEd, privMldsa, pub);
    }

    @Test
    void marshalLengthIsCorrect() {
        // marshal() must produce exactly MARSHAL_SIZE bytes.
        byte[] blob = makeKey().marshal();
        Assertions.assertEquals(AccountIdentityKey.MARSHAL_SIZE, blob.length);
    }

    @Test
    void marshalUnmarshalRoundtrip() {
        AccountIdentityKey original = makeKey();
        byte[] blob = original.marshal();
        AccountIdentityKey recovered = AccountIdentityKey.unmarshal(blob);

        // Private keys must survive the round-trip.
        Assertions.assertArrayEquals(original.getPrivEd25519(), recovered.getPrivEd25519());
        Assertions.assertArrayEquals(original.getPrivMLDSA(), recovered.getPrivMLDSA());
        Assertions.assertTrue(original.getPublic().equals(recovered.getPublic()));
    }

    @Test
    void unmarshalTooShortThrows() {
        // Passing a too-short blob must throw, not silently corrupt.
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> AccountIdentityKey.unmarshal(new byte[10]));
    }
}
