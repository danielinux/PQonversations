// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

// Registers the full BouncyCastle provider; Android ships a stripped "BC" that lacks PQC.
public final class BouncyCastleInstaller {

    // Provider name used in every Cipher/Signature/etc. getInstance call.
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME; // "BC"

    private BouncyCastleInstaller() {}

    // Idempotent: inserts BouncyCastleProvider at priority 1 if not already present.
    public static synchronized void ensureRegistered() {
        if (Security.getProvider(PROVIDER_NAME) instanceof BouncyCastleProvider) {
            // Already the full BC provider; nothing to do.
            return;
        }
        // Remove any pre-existing stripped "BC" (Android) so insertProviderAt is unambiguous.
        Security.removeProvider(PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
}
