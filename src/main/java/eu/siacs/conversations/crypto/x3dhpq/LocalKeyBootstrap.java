// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import java.security.SecureRandom;

/**
 * Run-once-per-account bootstrap that generates and persists all local x3dhpq key material.
 * Idempotent: if an AIK row already exists for the account, returns it without regenerating.
 */
public final class LocalKeyBootstrap {

    public static final int DEFAULT_KEM_PREKEY_COUNT = 10;
    public static final int DEFAULT_ONE_TIME_PREKEY_COUNT = 100;

    // X3dhpqDao instead of concrete DatabaseBackend so tests can inject a fake.
    private final X3dhpqDao db;
    private final SecureRandom rng;

    public LocalKeyBootstrap(final DatabaseBackend db) {
        this((X3dhpqDao) db, new SecureRandom());
    }

    public LocalKeyBootstrap(final DatabaseBackend db, final SecureRandom rng) {
        this((X3dhpqDao) db, rng);
    }

    // Package-private constructor used by tests with a fake X3dhpqDao.
    LocalKeyBootstrap(final X3dhpqDao db, final SecureRandom rng) {
        if (db == null) throw new IllegalArgumentException("db must not be null");
        if (rng == null) throw new IllegalArgumentException("rng must not be null");
        this.db = db;
        this.rng = rng;
    }

    /**
     * Idempotent. If the account already has an AIK row, loads and returns it.
     * Otherwise generates AIK + DIK + DC + SPK + KEM pre-keys + OPKs in one transaction.
     * Partial state (AIK exists but no local device) fails loud — call reset to recover.
     */
    public BootstrapResult ensureBootstrapped(final Account account) {
        return ensureBootstrapped(account.getUuid());
    }

    /**
     * Idempotent bootstrap by explicit UUID string.
     * Same semantics as {@link #ensureBootstrapped(Account)}.
     */
    public BootstrapResult ensureBootstrapped(final String uuid) {

        // Fast path: account already fully bootstrapped.
        final DatabaseBackend.X3dhpqAccountIdentityRow existing =
                db.loadX3dhpqAccountIdentity(uuid);
        if (existing != null) {
            final var devices = db.listX3dhpqLocalDevices(uuid);
            if (devices.isEmpty()) {
                // Inconsistent state: AIK present but no device row.
                throw new IllegalStateException(
                        "x3dhpq: account "
                                + uuid
                                + " has AIK but no local device row — manual reset required");
            }
            return new BootstrapResult(
                    uuid,
                    devices.get(0).deviceId(),
                    existing.fingerprint(),
                    false,
                    db.loadLatestX3dhpqSignedPreKey(uuid) != null
                            ? db.loadLatestX3dhpqSignedPreKey(uuid).keyId()
                            : -1,
                    db.listX3dhpqKemPreKeyIds(uuid).size(),
                    db.listX3dhpqUnusedOneTimePreKeyIds(uuid).size());
        }

        // --- Generate everything fresh ---

        // Device ID: random 32-bit unsigned, non-zero.
        final int deviceId = generateDeviceId();

        // 1. AIK: Ed25519 + ML-DSA-65
        final KeyPair aikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair aikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        final AccountIdentityPub aip = new AccountIdentityPub(aikEd.pub, aikMldsa.pub);
        final AccountIdentityKey aik = new AccountIdentityKey(aikEd.priv, aikMldsa.priv, aip);

        // 2. DIK: Ed25519 + X25519 + ML-DSA-65
        final KeyPair dikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair dikX = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair dikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        final DeviceIdentityKey dik =
                new DeviceIdentityKey(
                        dikEd.priv, dikEd.pub,
                        dikX.priv, dikX.pub,
                        dikMldsa.priv, dikMldsa.pub);

        // 3. Build unsigned DC (createdAt in seconds since epoch).
        final long createdAt = System.currentTimeMillis() / 1000L;
        final DeviceCertificate unsignedDc =
                new DeviceCertificate(
                        1, deviceId,
                        dikEd.pub, dikX.pub, dikMldsa.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        null, null);

        // 4. Sign DC: SIG over signedPart() bytes directly (no prefix). Matches the
        // canonical Go reference at internal/x3dhpqcrypto/devicecert.go:Issue and
        // dino-fork's pairwise.vala:issue. Wave A erroneously prepended a
        // "X3DHPQ-DC-v1\0" prefix; that broke interop with both Go and dino.
        final byte[] signedPart = unsignedDc.signedPart();
        final byte[] dcSigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, signedPart);
        final byte[] dcSigMldsa = X3dhpqCrypto.mldsa65Sign(aikMldsa.priv, signedPart);
        final DeviceCertificate dc =
                new DeviceCertificate(
                        1, deviceId,
                        dikEd.pub, dikX.pub, dikMldsa.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        dcSigEd, dcSigMldsa);

        // 5. SPK: X25519 keypair signed by DIK (both algorithms); key id = 1.
        final int spkKeyId = 1;
        final KeyPair spk = X3dhpqCrypto.x25519GenerateKeypair();
        final byte[] spkSigEd = X3dhpqCrypto.ed25519Sign(dikEd.priv, spk.pub);
        final byte[] spkSigMldsa = X3dhpqCrypto.mldsa65Sign(dikMldsa.priv, spk.pub);

        // 6. KEM pre-keys (ids 1..N).
        final KemKeyPair[] kemKeys = new KemKeyPair[DEFAULT_KEM_PREKEY_COUNT];
        for (int i = 0; i < DEFAULT_KEM_PREKEY_COUNT; i++) {
            kemKeys[i] = X3dhpqCrypto.mlkem768GenerateKeypair();
        }

        // 7. OPKs (ids 1..N).
        final KeyPair[] opks = new KeyPair[DEFAULT_ONE_TIME_PREKEY_COUNT];
        for (int i = 0; i < DEFAULT_ONE_TIME_PREKEY_COUNT; i++) {
            opks[i] = X3dhpqCrypto.x25519GenerateKeypair();
        }

        // 8. Compute fingerprint.
        final String fingerprint = aip.fingerprint(X3dhpqCrypto.BLAKE2B_160);

        // 9. Persist all in a single transaction (SQLite serialises writes — idempotency via lock).
        db.beginTransaction();
        try {
            db.putX3dhpqAccountIdentity(uuid, aik.marshal(), aip.marshal(), fingerprint);
            db.putX3dhpqLocalDevice(uuid, deviceId, dik.marshal(), dc.marshal(), createdAt, DeviceCertificate.FLAG_PRIMARY);
            db.putX3dhpqSignedPreKey(uuid, spkKeyId, spk.pub, spk.priv, spkSigEd, spkSigMldsa, createdAt);
            for (int i = 0; i < DEFAULT_KEM_PREKEY_COUNT; i++) {
                db.putX3dhpqKemPreKey(uuid, i + 1, kemKeys[i].pub, kemKeys[i].priv);
            }
            for (int i = 0; i < DEFAULT_ONE_TIME_PREKEY_COUNT; i++) {
                db.putX3dhpqOneTimePreKey(uuid, i + 1, opks[i].pub, opks[i].priv);
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }

        return new BootstrapResult(
                uuid,
                deviceId,
                fingerprint,
                true,
                spkKeyId,
                DEFAULT_KEM_PREKEY_COUNT,
                DEFAULT_ONE_TIME_PREKEY_COUNT);
    }

    // Generates a non-zero random unsigned 32-bit device id.
    private int generateDeviceId() {
        int id;
        do {
            id = rng.nextInt();
        } while (id == 0);
        return id;
    }

    // Concatenates two byte arrays.
    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /** Immutable result returned by {@link #ensureBootstrapped}. */
    public static final class BootstrapResult {
        public final String accountUuid;
        public final int deviceId;
        /** 30-hex-char fingerprint in 6 groups of 5 separated by spaces (35 chars total). */
        public final String fingerprint;
        /** True only on the call that generated the keys; false on idempotent re-calls. */
        public final boolean wasNewlyCreated;
        public final int signedPreKeyId;
        public final int kemPreKeyCount;
        public final int oneTimePreKeyCount;

        BootstrapResult(
                final String accountUuid,
                final int deviceId,
                final String fingerprint,
                final boolean wasNewlyCreated,
                final int signedPreKeyId,
                final int kemPreKeyCount,
                final int oneTimePreKeyCount) {
            this.accountUuid = accountUuid;
            this.deviceId = deviceId;
            this.fingerprint = fingerprint;
            this.wasNewlyCreated = wasNewlyCreated;
            this.signedPreKeyId = signedPreKeyId;
            this.kemPreKeyCount = kemPreKeyCount;
            this.oneTimePreKeyCount = oneTimePreKeyCount;
        }
    }
}
