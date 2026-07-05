// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardware-backed at-rest encryption for x3dhpq private key material.
 *
 * <p>Wraps secret blobs with an AES-256-GCM key held in the {@code AndroidKeyStore} under alias
 * {@link #KEY_ALIAS}. The key is created with {@code setUserAuthenticationRequired(false)} so it
 * works on devices with no lock screen or no biometrics enrolled, and (on API 28+) with
 * {@code setUnlockedDeviceRequired(true)} so the wrapped material can only be decrypted while the
 * device is unlocked. Plaintext is only ever materialised in memory on use.
 *
 * <p>Wrapped blobs are framed as:
 *
 * <pre>
 *   MAGIC(4 = "X3KV") || VERSION(1 = 0x01) || IV(12) || ciphertext-with-16-byte-GCM-tag
 * </pre>
 *
 * <p>{@link #unwrap(byte[])} passes through any blob that does not carry the magic/version prefix.
 * This transparently handles pre-existing plaintext rows (they decode unchanged and are re-wrapped
 * on the next write), so no schema migration is required. The 4-byte magic makes a false-positive
 * legacy detection negligible.
 */
public final class X3dhpqKeyVault {

    public static final String KEY_ALIAS = "x3dhpq_key_vault";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    // 4-byte magic "X3KV" identifying a wrapped blob, followed by a 1-byte version.
    private static final byte[] MAGIC = {'X', '3', 'K', 'V'};
    private static final byte VERSION = 0x01;

    private static final int IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int HEADER_LENGTH = MAGIC.length + 1 + IV_LENGTH; // magic + version + iv

    private static volatile X3dhpqKeyVault instance;

    private final SecureRandom secureRandom = new SecureRandom();

    private X3dhpqKeyVault() {}

    /** Process-wide singleton. */
    public static X3dhpqKeyVault getInstance() {
        X3dhpqKeyVault local = instance;
        if (local == null) {
            synchronized (X3dhpqKeyVault.class) {
                local = instance;
                if (local == null) {
                    local = new X3dhpqKeyVault();
                    instance = local;
                }
            }
        }
        return local;
    }

    /**
     * Encrypts {@code plaintext} under the hardware-backed key and returns the framed blob.
     *
     * <p>{@code null} is returned as {@code null}; a zero-length array is returned unchanged (empty
     * blobs carry no secret and stay distinguishable in-storage).
     */
    public byte[] wrap(final byte[] plaintext) {
        if (plaintext == null) {
            return null;
        }
        if (plaintext.length == 0) {
            return plaintext;
        }
        try {
            final SecretKey key = getOrCreateKey();
            final byte[] iv = new byte[IV_LENGTH];
            secureRandom.nextBytes(iv);
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            final byte[] ciphertext = cipher.doFinal(plaintext);
            final byte[] blob = new byte[HEADER_LENGTH + ciphertext.length];
            System.arraycopy(MAGIC, 0, blob, 0, MAGIC.length);
            blob[MAGIC.length] = VERSION;
            System.arraycopy(iv, 0, blob, MAGIC.length + 1, IV_LENGTH);
            System.arraycopy(ciphertext, 0, blob, HEADER_LENGTH, ciphertext.length);
            return blob;
        } catch (final Exception e) {
            throw new X3dhpqKeyVaultException("x3dhpq key vault: failed to wrap key material", e);
        }
    }

    /**
     * Reverses {@link #wrap(byte[])}. A {@code null} or empty input is returned unchanged. A blob
     * that does not carry the magic/version prefix is treated as LEGACY plaintext and returned
     * unchanged.
     */
    public byte[] unwrap(final byte[] blob) {
        if (blob == null || blob.length == 0) {
            return blob;
        }
        if (!isWrapped(blob)) {
            // Legacy passthrough: pre-existing plaintext row (or any non-vault blob).
            return blob;
        }
        try {
            final SecretKey key = getOrCreateKey();
            final byte[] iv = Arrays.copyOfRange(blob, MAGIC.length + 1, HEADER_LENGTH);
            final Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(blob, HEADER_LENGTH, blob.length - HEADER_LENGTH);
        } catch (final Exception e) {
            throw new X3dhpqKeyVaultException(
                    "x3dhpq key vault: failed to unwrap key material", e);
        }
    }

    private static boolean isWrapped(final byte[] blob) {
        if (blob.length < HEADER_LENGTH) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                return false;
            }
        }
        return blob[MAGIC.length] == VERSION;
    }

    private SecretKey getOrCreateKey() throws Exception {
        final KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        final KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        return generateKey();
    }

    private SecretKey generateKey() throws Exception {
        final KeyGenerator keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        final KeyGenParameterSpec.Builder builder =
                new KeyGenParameterSpec.Builder(
                                KEY_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        // No lock screen / biometric requirement so key generation succeeds on
                        // devices with no secure lock configured.
                        .setUserAuthenticationRequired(false);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // Hardware-bound but prompt-free: only usable while the device is unlocked.
            builder.setUnlockedDeviceRequired(true);
        }
        keyGenerator.init(builder.build());
        return keyGenerator.generateKey();
    }

    /** Unchecked wrapper surfaced when the KeyStore or crypto layer fails. */
    public static final class X3dhpqKeyVaultException extends RuntimeException {
        X3dhpqKeyVaultException(final String message, final Throwable cause) {
            super(message, cause);
        }
    }
}
