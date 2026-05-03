// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import im.conversations.x3dhpq.types.Blake2b160;
import im.conversations.x3dhpq.types.HkdfSha512;
import im.conversations.x3dhpq.types.HmacSha256;
import im.conversations.x3dhpq.types.Sha256;
import im.conversations.x3dhpq.types.Sha512;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

// Static facade exposing every primitive the x3dhpq protocol needs, backed by BouncyCastle 1.83.
// Call BouncyCastleInstaller.ensureRegistered() before using AES-GCM operations.
public final class X3dhpqCrypto {

    // Shared RNG instance; SecureRandom is thread-safe after construction.
    private static final SecureRandom RNG = new SecureRandom();

    private X3dhpqCrypto() {}

    // -------------------------------------------------------------------------
    // AES-256-GCM
    // -------------------------------------------------------------------------

    // Encrypts plaintext with AES-256-GCM; returns ciphertext || 16-byte tag.
    public static byte[] aes256gcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleInstaller.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("AES-GCM encrypt failed", e);
        }
    }

    // Decrypts AES-256-GCM ciphertext (ciphertext || tag); throws on authentication failure.
    public static byte[] aes256gcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleInstaller.PROVIDER_NAME);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertextWithTag);
        } catch (AEADBadTagException e) {
            throw new X3dhpqCryptoException("AES-GCM authentication tag mismatch", e);
        } catch (Exception e) {
            // Wrap other checked exceptions (e.g. BadPaddingException from older BC versions).
            if (e.getCause() instanceof AEADBadTagException) {
                throw new X3dhpqCryptoException("AES-GCM authentication tag mismatch", e);
            }
            throw new X3dhpqCryptoException("AES-GCM decrypt failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Ed25519
    // -------------------------------------------------------------------------

    // Generates a fresh Ed25519 key pair; priv and pub are raw 32-byte encodings.
    public static KeyPair ed25519GenerateKeypair() {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(RNG);
        Ed25519PublicKeyParameters  pub  = priv.generatePublicKey();
        return new KeyPair(priv.getEncoded(), pub.getEncoded());
    }

    // Signs msg with a raw 32-byte Ed25519 private key; returns the 64-byte signature.
    public static byte[] ed25519Sign(byte[] privKey, byte[] msg) {
        try {
            Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(privKey, 0);
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, priv);
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new X3dhpqCryptoException("Ed25519 sign failed", e);
        }
    }

    // Verifies an Ed25519 signature using a raw 32-byte public key.
    public static boolean ed25519Verify(byte[] pubKey, byte[] msg, byte[] sig) {
        try {
            Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(pubKey, 0);
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, pub);
            verifier.update(msg, 0, msg.length);
            return verifier.verifySignature(sig);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("Ed25519 verify failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // X25519
    // -------------------------------------------------------------------------

    // Generates a fresh X25519 key pair; priv and pub are raw 32-byte encodings.
    public static KeyPair x25519GenerateKeypair() {
        X25519PrivateKeyParameters priv = new X25519PrivateKeyParameters(RNG);
        X25519PublicKeyParameters  pub  = priv.generatePublicKey();
        return new KeyPair(priv.getEncoded(), pub.getEncoded());
    }

    // Computes the X25519 shared secret from a raw private key and a peer's raw public key.
    public static byte[] x25519SharedSecret(byte[] privKey, byte[] peerPub) {
        try {
            X25519PrivateKeyParameters priv = new X25519PrivateKeyParameters(privKey, 0);
            X25519PublicKeyParameters  peer = new X25519PublicKeyParameters(peerPub, 0);
            X25519Agreement agreement = new X25519Agreement();
            agreement.init(priv);
            byte[] secret = new byte[32];
            agreement.calculateAgreement(peer, secret, 0);
            return secret;
        } catch (Exception e) {
            throw new X3dhpqCryptoException("X25519 DH failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // ML-DSA-65 (FIPS 204)
    // -------------------------------------------------------------------------

    // Generates a fresh ML-DSA-65 key pair; priv is 4032 bytes, pub is 1952 bytes.
    public static KeyPair mldsa65GenerateKeypair() {
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(RNG, MLDSAParameters.ml_dsa_65));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();
        MLDSAPublicKeyParameters  pub  = (MLDSAPublicKeyParameters)  kp.getPublic();
        return new KeyPair(priv.getEncoded(), pub.getEncoded());
    }

    // Signs msg with an encoded ML-DSA-65 private key; returns the 3309-byte signature.
    public static byte[] mldsa65Sign(byte[] privKey, byte[] msg) {
        try {
            MLDSAPrivateKeyParameters priv =
                    new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, privKey);
            MLDSASigner signer = new MLDSASigner();
            signer.init(true, priv);
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) {
            throw new X3dhpqCryptoException("ML-DSA-65 sign failed", e);
        }
    }

    // Verifies an ML-DSA-65 signature using an encoded public key.
    public static boolean mldsa65Verify(byte[] pubKey, byte[] msg, byte[] sig) {
        try {
            MLDSAPublicKeyParameters pub =
                    new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pubKey);
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, pub);
            verifier.update(msg, 0, msg.length);
            return verifier.verifySignature(sig);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("ML-DSA-65 verify failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // ML-KEM-768 (FIPS 203)
    // -------------------------------------------------------------------------

    // Generates a fresh ML-KEM-768 key pair; priv is 2400 bytes, pub is 1184 bytes.
    public static KemKeyPair mlkem768GenerateKeypair() {
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(RNG, MLKEMParameters.ml_kem_768));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        MLKEMPrivateKeyParameters priv = (MLKEMPrivateKeyParameters) kp.getPrivate();
        MLKEMPublicKeyParameters  pub  = (MLKEMPublicKeyParameters)  kp.getPublic();
        return new KemKeyPair(priv.getEncoded(), pub.getEncoded());
    }

    // Encapsulates using the recipient's ML-KEM-768 public key; returns shared secret + ciphertext.
    public static KemEncapsulation mlkem768Encaps(byte[] pubKey) {
        try {
            MLKEMPublicKeyParameters pub =
                    new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, pubKey);
            MLKEMGenerator encap = new MLKEMGenerator(RNG);
            org.bouncycastle.crypto.SecretWithEncapsulation result =
                    (org.bouncycastle.crypto.SecretWithEncapsulation) encap.generateEncapsulated(pub);
            KemEncapsulation enc = new KemEncapsulation(result.getSecret(), result.getEncapsulation());
            // Wipe BC's internal secret buffer once we've copied it.
            result.destroy();
            return enc;
        } catch (Exception e) {
            throw new X3dhpqCryptoException("ML-KEM-768 encaps failed", e);
        }
    }

    // Decapsulates using the recipient's ML-KEM-768 private key; returns the 32-byte shared secret.
    public static byte[] mlkem768Decaps(byte[] privKey, byte[] ciphertext) {
        try {
            MLKEMPrivateKeyParameters priv =
                    new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, privKey);
            MLKEMExtractor decap = new MLKEMExtractor(priv);
            return decap.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("ML-KEM-768 decaps failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Hash primitives
    // -------------------------------------------------------------------------

    // Computes BLAKE2b-160 digest; constructor arg 160 selects digest size in bits.
    public static byte[] blake2b160(byte[] input) {
        Blake2bDigest digest = new Blake2bDigest(160);
        digest.update(input, 0, input.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }

    // Computes SHA-256 digest using the JDK standard provider.
    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("SHA-256 failed", e);
        }
    }

    // Computes SHA-512 digest using the JDK standard provider.
    public static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("SHA-512 failed", e);
        }
    }

    // Computes HMAC-SHA-256 using the JDK standard provider.
    public static byte[] hmacSha256(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new X3dhpqCryptoException("HMAC-SHA-256 failed", e);
        }
    }

    // Computes HKDF-SHA-512 (Extract + Expand) matching the wolfcrypt Go reference.
    public static byte[] hkdfSha512(byte[] salt, byte[] ikm, byte[] info, int length) {
        HKDFBytesGenerator hk = new HKDFBytesGenerator(new SHA512Digest());
        hk.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        hk.generateBytes(out, 0, length);
        return out;
    }

    // -------------------------------------------------------------------------
    // scrypt
    // -------------------------------------------------------------------------

    // Derives a key from passphrase using scrypt; intermediate byte buffer is wiped on exit.
    public static byte[] scrypt(char[] passphrase, byte[] salt, int n, int r, int p, int length) {
        byte[] passBytes = new String(passphrase).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        try {
            return SCrypt.generate(passBytes, salt, n, r, p, length);
        } finally {
            // Wipe passphrase bytes from the heap.
            Arrays.fill(passBytes, (byte) 0);
        }
    }

    // -------------------------------------------------------------------------
    // Production wiring for Wave B's pluggable interfaces
    // -------------------------------------------------------------------------

    // Production BLAKE2b-160 adapter; wires X3dhpqCrypto into types that accept Blake2b160.
    public static final Blake2b160 BLAKE2B_160 = X3dhpqCrypto::blake2b160;

    // Production SHA-256 adapter.
    public static final Sha256 SHA256 = X3dhpqCrypto::sha256;

    // Production SHA-512 adapter.
    public static final Sha512 SHA512 = X3dhpqCrypto::sha512;

    // Production HMAC-SHA-256 adapter.
    public static final HmacSha256 HMAC_SHA256 = X3dhpqCrypto::hmacSha256;

    // Production HKDF-SHA-512 adapter.
    public static final HkdfSha512 HKDF_SHA512 = X3dhpqCrypto::hkdfSha512;
}
