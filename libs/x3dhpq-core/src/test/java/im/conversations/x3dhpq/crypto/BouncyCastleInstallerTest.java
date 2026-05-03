// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.Security;

class BouncyCastleInstallerTest {

    @BeforeAll
    static void install() {
        BouncyCastleInstaller.ensureRegistered();
    }

    @Test
    void providerIsBouncyCastleAtPriorityOne() {
        java.security.Provider p = Security.getProviders()[0];
        Assertions.assertInstanceOf(BouncyCastleProvider.class, p,
                "Priority-1 provider must be BouncyCastleProvider");
    }

    @Test
    void ensureRegisteredIsIdempotent() {
        // Calling twice must not install a duplicate.
        BouncyCastleInstaller.ensureRegistered();
        BouncyCastleInstaller.ensureRegistered();

        long bcCount = java.util.Arrays.stream(Security.getProviders())
                .filter(p -> BouncyCastleInstaller.PROVIDER_NAME.equals(p.getName()))
                .count();
        Assertions.assertEquals(1, bcCount, "Exactly one BC provider must be registered");
    }

    @Test
    void aesGcmCipherAvailableAfterRegistration() throws Exception {
        // Verifies that the BC AES/GCM cipher is reachable after installation.
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleInstaller.PROVIDER_NAME);
        Assertions.assertNotNull(c);
    }
}
