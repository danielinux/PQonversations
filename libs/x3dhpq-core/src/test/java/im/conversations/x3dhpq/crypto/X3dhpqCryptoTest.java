// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.KemCheckpoint;
import im.conversations.x3dhpq.types.SenderChain;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

class X3dhpqCryptoTest {

    @BeforeAll
    static void install() {
        // Register full BC provider before any AES-GCM operations.
        BouncyCastleInstaller.ensureRegistered();
    }

    // -------------------------------------------------------------------------
    // AES-256-GCM
    // -------------------------------------------------------------------------

    @Test
    void aesGcmRoundtrip() {
        byte[] key  = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad  = "associated-data".getBytes();
        byte[] pt   = "Hello, x3dhpq!".getBytes();
        Arrays.fill(key,   (byte) 0x42);
        Arrays.fill(nonce, (byte) 0x01);

        byte[] ct         = X3dhpqCrypto.aes256gcmEncrypt(key, nonce, pt, aad);
        // Ciphertext must be plaintext length + 16-byte tag.
        Assertions.assertEquals(pt.length + 16, ct.length, "ciphertext must be pt + 16-byte tag");

        byte[] decrypted  = X3dhpqCrypto.aes256gcmDecrypt(key, nonce, ct, aad);
        Assertions.assertArrayEquals(pt, decrypted, "decrypted plaintext must equal original");
    }

    @Test
    void aesGcmWrongTagThrows() {
        byte[] key   = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad   = "aad".getBytes();
        byte[] pt    = "secret".getBytes();
        Arrays.fill(key, (byte) 0x55);

        byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(key, nonce, pt, aad);
        // Flip the last byte of the tag.
        ct[ct.length - 1] ^= 0xFF;

        Assertions.assertThrows(X3dhpqCryptoException.class,
                () -> X3dhpqCrypto.aes256gcmDecrypt(key, nonce, ct, aad),
                "tampered tag must throw X3dhpqCryptoException");
    }

    @Test
    void aesGcmEmptyAad() {
        byte[] key   = new byte[32];
        byte[] nonce = new byte[12];
        byte[] pt    = "data".getBytes();
        Arrays.fill(key, (byte) 0x77);

        byte[] ct        = X3dhpqCrypto.aes256gcmEncrypt(key, nonce, pt, new byte[0]);
        byte[] decrypted = X3dhpqCrypto.aes256gcmDecrypt(key, nonce, ct, new byte[0]);
        Assertions.assertArrayEquals(pt, decrypted);
    }

    // -------------------------------------------------------------------------
    // Ed25519
    // -------------------------------------------------------------------------

    @Test
    void ed25519GenerateKeypairSizes() {
        KeyPair kp = X3dhpqCrypto.ed25519GenerateKeypair();
        Assertions.assertEquals(32, kp.priv.length, "Ed25519 priv must be 32 bytes");
        Assertions.assertEquals(32, kp.pub.length,  "Ed25519 pub must be 32 bytes");
    }

    @Test
    void ed25519SignVerifyRoundtrip() {
        KeyPair kp = X3dhpqCrypto.ed25519GenerateKeypair();
        byte[] msg = "test message".getBytes();

        byte[] sig = X3dhpqCrypto.ed25519Sign(kp.priv, msg);
        Assertions.assertEquals(64, sig.length, "Ed25519 signature must be 64 bytes");

        boolean ok = X3dhpqCrypto.ed25519Verify(kp.pub, msg, sig);
        Assertions.assertTrue(ok, "Ed25519 verify must return true for valid signature");
    }

    @Test
    void ed25519WrongKeyDoesNotVerify() {
        KeyPair kp1 = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair kp2 = X3dhpqCrypto.ed25519GenerateKeypair();
        byte[] msg  = "test message".getBytes();

        byte[] sig = X3dhpqCrypto.ed25519Sign(kp1.priv, msg);
        boolean ok = X3dhpqCrypto.ed25519Verify(kp2.pub, msg, sig);
        Assertions.assertFalse(ok, "Signature must not verify under wrong public key");
    }

    // -------------------------------------------------------------------------
    // X25519
    // -------------------------------------------------------------------------

    @Test
    void x25519GenerateKeypairSizes() {
        KeyPair kp = X3dhpqCrypto.x25519GenerateKeypair();
        Assertions.assertEquals(32, kp.priv.length, "X25519 priv must be 32 bytes");
        Assertions.assertEquals(32, kp.pub.length,  "X25519 pub must be 32 bytes");
    }

    @Test
    void x25519SharedSecretSymmetric() {
        KeyPair alice = X3dhpqCrypto.x25519GenerateKeypair();
        KeyPair bob   = X3dhpqCrypto.x25519GenerateKeypair();

        byte[] ss1 = X3dhpqCrypto.x25519SharedSecret(alice.priv, bob.pub);
        byte[] ss2 = X3dhpqCrypto.x25519SharedSecret(bob.priv,   alice.pub);

        Assertions.assertEquals(32, ss1.length, "X25519 shared secret must be 32 bytes");
        Assertions.assertArrayEquals(ss1, ss2, "DH shared secrets must be equal");
    }

    // -------------------------------------------------------------------------
    // ML-DSA-65
    // -------------------------------------------------------------------------

    @Test
    void mldsa65GenerateKeypairSizes() {
        KeyPair kp = X3dhpqCrypto.mldsa65GenerateKeypair();
        // BC encodes the full seed+private material: 4032 bytes priv, 1952 bytes pub.
        Assertions.assertEquals(4032, kp.priv.length, "ML-DSA-65 priv must be 4032 bytes");
        Assertions.assertEquals(1952, kp.pub.length,  "ML-DSA-65 pub must be 1952 bytes");
    }

    @Test
    void mldsa65SignVerifyRoundtrip() {
        KeyPair kp  = X3dhpqCrypto.mldsa65GenerateKeypair();
        byte[] msg  = "ml-dsa test".getBytes();

        byte[] sig = X3dhpqCrypto.mldsa65Sign(kp.priv, msg);
        Assertions.assertEquals(3309, sig.length, "ML-DSA-65 signature must be 3309 bytes");

        boolean ok = X3dhpqCrypto.mldsa65Verify(kp.pub, msg, sig);
        Assertions.assertTrue(ok, "ML-DSA-65 verify must return true for valid signature");
    }

    @Test
    void mldsa65WrongKeyDoesNotVerify() {
        KeyPair kp1 = X3dhpqCrypto.mldsa65GenerateKeypair();
        KeyPair kp2 = X3dhpqCrypto.mldsa65GenerateKeypair();
        byte[] msg  = "ml-dsa test".getBytes();

        byte[] sig = X3dhpqCrypto.mldsa65Sign(kp1.priv, msg);
        boolean ok = X3dhpqCrypto.mldsa65Verify(kp2.pub, msg, sig);
        Assertions.assertFalse(ok, "ML-DSA-65 signature must not verify under wrong public key");
    }

    // -------------------------------------------------------------------------
    // ML-KEM-768
    // -------------------------------------------------------------------------

    @Test
    void mlkem768GenerateKeypairSizes() {
        KemKeyPair kp = X3dhpqCrypto.mlkem768GenerateKeypair();
        Assertions.assertEquals(2400, kp.priv.length, "ML-KEM-768 priv must be 2400 bytes");
        Assertions.assertEquals(1184, kp.pub.length,  "ML-KEM-768 pub must be 1184 bytes");
    }

    @Test
    void mlkem768EncapsDecapsSharedSecretsMatch() {
        KemKeyPair    kp  = X3dhpqCrypto.mlkem768GenerateKeypair();
        KemEncapsulation enc = X3dhpqCrypto.mlkem768Encaps(kp.pub);

        Assertions.assertEquals(32,   enc.sharedSecret.length, "ML-KEM-768 shared secret must be 32 bytes");
        Assertions.assertEquals(1088, enc.ciphertext.length,   "ML-KEM-768 ciphertext must be 1088 bytes");

        byte[] ss2 = X3dhpqCrypto.mlkem768Decaps(kp.priv, enc.ciphertext);
        Assertions.assertArrayEquals(enc.sharedSecret, ss2, "Encaps and decaps shared secrets must match");
    }

    // -------------------------------------------------------------------------
    // Hash primitives — KATs
    // -------------------------------------------------------------------------

    @Test
    void blake2b160EmptyStringKat() {
        // Known answer: b2sum -l 160 /dev/null
        byte[] result = X3dhpqCrypto.blake2b160(new byte[0]);
        Assertions.assertEquals("3345524abf6bbe1809449224b5972c41790b6cf2", hex(result),
                "BLAKE2b-160 of empty string must match known vector");
    }

    @Test
    void sha256EmptyStringKat() {
        byte[] result = X3dhpqCrypto.sha256(new byte[0]);
        Assertions.assertEquals(
                "e3b0c44298fc1c149afbf4c8996fb924" +
                "27ae41e4649b934ca495991b7852b855",
                hex(result),
                "SHA-256 of empty string must match known vector");
    }

    @Test
    void sha512EmptyStringKat() {
        byte[] result = X3dhpqCrypto.sha512(new byte[0]);
        // SHA-512("") well-known value.
        Assertions.assertEquals(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                hex(result),
                "SHA-512 of empty string must match known vector");
    }

    @Test
    void hmacSha256Kat() {
        // key = 0xAA * 32, msg = 0x01; same constants as SenderChain A.3 step.
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0xAA);
        byte[] msg = new byte[]{0x01};

        byte[] result = X3dhpqCrypto.hmacSha256(key, msg);
        Assertions.assertEquals(
                "790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e",
                hex(result),
                "HMAC-SHA-256 must match A.3 message-key vector");
    }

    // -------------------------------------------------------------------------
    // scrypt
    // -------------------------------------------------------------------------

    @Test
    void scryptOutputLength() {
        byte[] out = X3dhpqCrypto.scrypt(
                "password".toCharArray(),
                "salt".getBytes(),
                1024, 8, 1, 32);
        Assertions.assertEquals(32, out.length, "scrypt output must match requested length");
    }

    @Test
    void scryptDeterministic() {
        char[] pass = "passphrase".toCharArray();
        byte[] salt = "nacl".getBytes();
        byte[] out1 = X3dhpqCrypto.scrypt(pass, salt, 1024, 8, 1, 64);
        byte[] out2 = X3dhpqCrypto.scrypt(pass, salt, 1024, 8, 1, 64);
        Assertions.assertArrayEquals(out1, out2, "scrypt must be deterministic");
    }

    // -------------------------------------------------------------------------
    // Cross-link with Wave B vectors — production facade wired into Wave B types
    // -------------------------------------------------------------------------

    // A.3: X3dhpqCrypto.HMAC_SHA256 must produce the same chain step as BcHmacSha256.
    @Test
    void crossLinkA3SenderChainViaProductionHmac() {
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0xAA);

        SenderChain chain = new SenderChain(0, ck);
        // Wire the production facade adapter instead of the test-only BcHmacSha256.
        byte[] mk = chain.step(X3dhpqCrypto.HMAC_SHA256);

        Assertions.assertEquals(
                "790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e",
                hex(mk),
                "Production HMAC_SHA256 must match A.3 message key vector");
        Assertions.assertEquals(
                "e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e",
                hex(chain.chainKey),
                "Production HMAC_SHA256 must match A.3 next chain key vector");
    }

    // A.5: X3dhpqCrypto.HKDF_SHA512 + SHA512 must produce the KemCheckpoint mix vector.
    @Test
    void crossLinkA5KemCheckpointViaProductionAdapters() {
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
                senderCK, kemSS, senderDH, kemCT, 42L, prevHistory,
                X3dhpqCrypto.HKDF_SHA512,
                X3dhpqCrypto.SHA512);

        Assertions.assertEquals(
                "a69de60e57332f72590af362634ee57f3002644a7d4a6fd86b2146dcaf3d24a7",
                hex(r.newCKs()),
                "Production HKDF_SHA512/SHA512 must match A.5 newCKs vector");
        Assertions.assertEquals(
                "fdb1f3d1eb083c9049170245004401f1649eae82d7d14620bdd64d717c39dce2",
                hex(r.newCKr()),
                "Production HKDF_SHA512/SHA512 must match A.5 newCKr vector");
        Assertions.assertEquals(
                "3cd70ff3b328c19fb5cb767d31e3e11e8c01e2860393fadd5bb7d3e689c1e10e",
                hex(r.newHistory()),
                "Production HKDF_SHA512/SHA512 must match A.5 newHistory vector");
    }

    // A.1: X3dhpqCrypto.BLAKE2B_160 must produce the same fingerprint as InlineBlake2b160.
    @Test
    void crossLinkA1FingerprintViaProductionBlake2b() {
        byte[] pubEd = new byte[32];
        for (int i = 0; i < 32; i++) pubEd[i] = (byte) (0x01 + i);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) 0xA5);

        AccountIdentityPub aip = new AccountIdentityPub(pubEd, pubMLDSA);
        // Wire the production facade adapter instead of InlineBlake2b160.
        String fp = aip.fingerprint(X3dhpqCrypto.BLAKE2B_160);

        Assertions.assertEquals("7AD37 1A1A3 67A62 B6533 1BC5A 2204C", fp,
                "Production BLAKE2B_160 must match A.1 fingerprint vector");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
