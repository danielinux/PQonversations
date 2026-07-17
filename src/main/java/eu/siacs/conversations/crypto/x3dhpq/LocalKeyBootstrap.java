// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import android.util.Log;
import eu.siacs.conversations.Config;
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

    /**
     * Local-only sentinel bit stored in {@code x3dhpq_local_device.flags} (§10.6.1).
     * Marks a device that has generated its DIK but has NOT been confirmed under an
     * account AIK yet — either because a genuine primary/AIK might already exist
     * elsewhere for this account (pending confirmation via CPace pairing) or because
     * the enrollment-gate check against the server has not resolved yet.
     *
     * <p>This bit MUST NEVER be published: {@link eu.siacs.conversations.crypto.x3dhpq.X3dhpqService#publishDeviceList()}
     * only ever runs once an {@code x3dhpq_account_identity} row exists (see the {@code
     * aikRow == null} guard there), and a pending device by construction has no such row,
     * so a pending row can never be signed/embedded in an outbound devicelist entry. On
     * confirmation via pairing ({@code PairToExistingActivity#installPairingResult}) the
     * row's flags are fully replaced by the primary-issued {@link DeviceCertificate}'s own
     * flags, clearing this bit. On promotion to genuine primary ({@link #promoteToPrimary}),
     * this bit is explicitly cleared and {@link DeviceCertificate#FLAG_PRIMARY} is set.
     *
     * <p>Chosen well above {@link DeviceCertificate#FLAG_PRIMARY} (bit 0) to avoid any
     * collision with spec-defined wire flag bits.
     */
    public static final int FLAG_PENDING_ENROLLMENT = 0x40;

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
     * Otherwise — per §10.6.1 — generates ONLY device-level material (DIK + SPK +
     * KEM pre-keys + OPKs, none of which require an AIK to create) and enters a
     * pending-enrollment state; it does NOT mint an account AIK. The caller
     * (normally {@link eu.siacs.conversations.crypto.x3dhpq.X3dhpqService#publishLocalState()})
     * is responsible for resolving the pending state against the account's own
     * published devicelist (see {@link #promoteToPrimary}) once connectivity allows
     * that network check — this method itself performs no network I/O.
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

        // Fast path: account already fully bootstrapped (has an AIK).
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
                    isPending(devices.get(0)),
                    db.loadLatestX3dhpqSignedPreKey(uuid) != null
                            ? db.loadLatestX3dhpqSignedPreKey(uuid).keyId()
                            : -1,
                    db.listX3dhpqKemPreKeyIds(uuid).size(),
                    db.listX3dhpqUnusedOneTimePreKeyIds(uuid).size());
        }

        // --- Genuinely first-ever call for this account/install (§10.6.1). ---
        //
        // The schema's FK (x3dhpq_local_device / prekey tables → x3dhpq_account_identity)
        // requires an AIK row to exist before any device/prekey row, so we mint the AIK
        // LOCALLY together with the device. Crucially the device is stamped
        // FLAG_PENDING_ENROLLMENT: publication is gated on that flag in
        // X3dhpqService#publishLocalState (it calls resolvePendingEnrollment() and
        // returns before publishDeviceList/publishOwnBundle), so the freshly minted AIK
        // is NEVER announced to contacts until the enrollment gate resolves — a genuine
        // first device is confirmed as primary and published, a secondary stays pending
        // and adopts the existing primary's AIK via pairing (which replaces this row).
        // This satisfies §10.6.1's intent (no premature/unexplained AIK rotation visible
        // to contacts) within the FK constraints; the local tentative AIK is discarded on
        // pairing.

        final int deviceId = generateDeviceId();

        // AIK: Ed25519 + ML-DSA-65 (minted locally; unpublished while pending).
        final KeyPair aikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair aikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        final AccountIdentityPub aip = new AccountIdentityPub(aikEd.pub, aikMldsa.pub);
        final AccountIdentityKey aik = new AccountIdentityKey(aikEd.priv, aikMldsa.priv, aip);
        final String fingerprint = aip.fingerprint(X3dhpqCrypto.BLAKE2B_160);

        // DIK: Ed25519 + X25519 + ML-DSA-65
        final KeyPair dikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair dikX = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair dikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        final DeviceIdentityKey dik =
                new DeviceIdentityKey(
                        dikEd.priv, dikEd.pub,
                        dikX.priv, dikX.pub,
                        dikMldsa.priv, dikMldsa.pub);

        // DC signed by the (local) AIK as primary. The DC carries FLAG_PRIMARY on the
        // wire; the local-only FLAG_PENDING_ENROLLMENT lives only in the device row's
        // flags column (never in the DC bytes), so confirming the device later is a pure
        // flag update with no re-sign needed.
        final long createdAt = System.currentTimeMillis() / 1000L;
        final DeviceCertificate unsignedDc =
                new DeviceCertificate(
                        1, deviceId,
                        dikEd.pub, dikX.pub, dikMldsa.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        null, null);
        final byte[] dcSignedPart = unsignedDc.signedPart();
        final byte[] dcSigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, dcSignedPart);
        final byte[] dcSigMldsa = X3dhpqCrypto.mldsa65Sign(aikMldsa.priv, dcSignedPart);
        final DeviceCertificate dc =
                new DeviceCertificate(
                        1, deviceId,
                        dikEd.pub, dikX.pub, dikMldsa.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        dcSigEd, dcSigMldsa);

        // SPK: X25519 keypair signed by DIK (both algorithms).
        final int spkKeyId = 1;
        final KeyPair spk = X3dhpqCrypto.x25519GenerateKeypair();
        final byte[] spkSigEd = X3dhpqCrypto.ed25519Sign(dikEd.priv, spk.pub);
        final byte[] spkSigMldsa = X3dhpqCrypto.mldsa65Sign(dikMldsa.priv, spk.pub);

        // KEM pre-keys (ids 1..N), each hybrid-signed by the DIK over its public
        // key bytes (spec §9.1): the KEM pre-key is the sole carrier of PQ (HNDL)
        // confidentiality, so it gets both an Ed25519 and an ML-DSA-65 signature.
        final KemKeyPair[] kemKeys = new KemKeyPair[DEFAULT_KEM_PREKEY_COUNT];
        final byte[][] kemSigEd = new byte[DEFAULT_KEM_PREKEY_COUNT][];
        final byte[][] kemSigMldsa = new byte[DEFAULT_KEM_PREKEY_COUNT][];
        for (int i = 0; i < DEFAULT_KEM_PREKEY_COUNT; i++) {
            kemKeys[i] = X3dhpqCrypto.mlkem768GenerateKeypair();
            kemSigEd[i] = X3dhpqCrypto.ed25519Sign(dikEd.priv, kemKeys[i].pub);
            kemSigMldsa[i] = X3dhpqCrypto.mldsa65Sign(dikMldsa.priv, kemKeys[i].pub);
        }

        // OPKs (ids 1..N).
        final KeyPair[] opks = new KeyPair[DEFAULT_ONE_TIME_PREKEY_COUNT];
        for (int i = 0; i < DEFAULT_ONE_TIME_PREKEY_COUNT; i++) {
            opks[i] = X3dhpqCrypto.x25519GenerateKeypair();
        }

        db.beginTransaction();
        try {
            // account_identity FIRST — local_device / prekey rows FK-reference it.
            db.putX3dhpqAccountIdentity(uuid, aik.marshal(), aip.marshal(), fingerprint);
            db.putX3dhpqLocalDevice(
                    uuid, deviceId, dik.marshal(), dc.marshal(), createdAt,
                    DeviceCertificate.FLAG_PRIMARY | FLAG_PENDING_ENROLLMENT);
            db.putX3dhpqSignedPreKey(uuid, spkKeyId, spk.pub, spk.priv, spkSigEd, spkSigMldsa, createdAt);
            for (int i = 0; i < DEFAULT_KEM_PREKEY_COUNT; i++) {
                db.putX3dhpqKemPreKey(
                        uuid, i + 1, kemKeys[i].pub, kemKeys[i].priv,
                        kemSigEd[i], kemSigMldsa[i]);
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
                true,
                spkKeyId,
                DEFAULT_KEM_PREKEY_COUNT,
                DEFAULT_ONE_TIME_PREKEY_COUNT);
    }

    /** True if {@code row} is a pending-enrollment placeholder (§10.6.1), not yet a full device. */
    public static boolean isPending(final DatabaseBackend.X3dhpqLocalDeviceRow row) {
        return row != null && (row.flags() & FLAG_PENDING_ENROLLMENT) != 0;
    }

    /**
     * Promotes a pending device (produced by {@link #ensureBootstrapped}) to genuine
     * primary: mints a fresh account AIK and issues a self-signed DC for the existing
     * DIK, clearing {@link #FLAG_PENDING_ENROLLMENT} and setting {@link
     * DeviceCertificate#FLAG_PRIMARY}. Only the caller may invoke this after confirming
     * (via a server round-trip) that NO AIK exists anywhere for this account — i.e. this
     * is genuinely the first device (§10.6.1) — or as part of an explicit, user-chosen
     * "generate a new identity" action (§10.6.4b), via {@link #mintFreshIdentity}.
     *
     * <p>Idempotent/race-safe: if an AIK already exists for {@code uuid} (e.g. a
     * concurrent pairing just completed and installed one), this returns that existing
     * state instead of minting a second one.
     */
    public BootstrapResult promoteToPrimary(final String uuid) {
        final var devices = db.listX3dhpqLocalDevices(uuid);
        if (devices.isEmpty()) {
            throw new IllegalStateException(
                    "x3dhpq: promoteToPrimary called for " + uuid
                            + " but no device row exists — call ensureBootstrapped first");
        }
        final DatabaseBackend.X3dhpqLocalDeviceRow pendingRow = devices.get(0);
        DatabaseBackend.X3dhpqAccountIdentityRow identity = db.loadX3dhpqAccountIdentity(uuid);

        // Common case (post-{@link #ensureBootstrapped}): the AIK was already minted
        // locally and the DC already signed as primary — confirming this device as
        // primary is a pure flag update (clear FLAG_PENDING_ENROLLMENT), so publication
        // may proceed. No re-mint, no re-sign.
        if (identity != null) {
            if (isPending(pendingRow)) {
                db.putX3dhpqLocalDevice(
                        uuid, pendingRow.deviceId(), pendingRow.dikPriv(), pendingRow.dc(),
                        pendingRow.createdAt(), DeviceCertificate.FLAG_PRIMARY);
            }
            return new BootstrapResult(
                    uuid,
                    pendingRow.deviceId(),
                    identity.fingerprint(),
                    true,
                    false,
                    db.loadLatestX3dhpqSignedPreKey(uuid) != null
                            ? db.loadLatestX3dhpqSignedPreKey(uuid).keyId()
                            : -1,
                    db.listX3dhpqKemPreKeyIds(uuid).size(),
                    db.listX3dhpqUnusedOneTimePreKeyIds(uuid).size());
        }

        // Defensive fallback: no AIK row yet (should not happen after ensureBootstrapped,
        // which mints the AIK). Mint one and re-sign the DC as primary under it.
        final DeviceIdentityKey dik = DeviceIdentityKey.unmarshal(pendingRow.dikPriv());
        final KeyPair aikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair aikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        final AccountIdentityPub aip = new AccountIdentityPub(aikEd.pub, aikMldsa.pub);
        final AccountIdentityKey aik = new AccountIdentityKey(aikEd.priv, aikMldsa.priv, aip);
        final DeviceCertificate unsignedDc =
                new DeviceCertificate(
                        1, pendingRow.deviceId(),
                        dik.getPubEd25519(), dik.getPubX25519(), dik.getPubMLDSA(),
                        pendingRow.createdAt(), (byte) DeviceCertificate.FLAG_PRIMARY,
                        null, null);
        final byte[] signedPart = unsignedDc.signedPart();
        final byte[] dcSigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, signedPart);
        final byte[] dcSigMldsa = X3dhpqCrypto.mldsa65Sign(aikMldsa.priv, signedPart);
        final DeviceCertificate dc =
                new DeviceCertificate(
                        1, pendingRow.deviceId(),
                        dik.getPubEd25519(), dik.getPubX25519(), dik.getPubMLDSA(),
                        pendingRow.createdAt(), (byte) DeviceCertificate.FLAG_PRIMARY,
                        dcSigEd, dcSigMldsa);
        final String fingerprint = aip.fingerprint(X3dhpqCrypto.BLAKE2B_160);
        db.beginTransaction();
        try {
            db.putX3dhpqAccountIdentity(uuid, aik.marshal(), aip.marshal(), fingerprint);
            db.putX3dhpqLocalDevice(
                    uuid, pendingRow.deviceId(), pendingRow.dikPriv(), dc.marshal(),
                    pendingRow.createdAt(), DeviceCertificate.FLAG_PRIMARY);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        return new BootstrapResult(
                uuid,
                pendingRow.deviceId(),
                fingerprint,
                true,
                false,
                db.loadLatestX3dhpqSignedPreKey(uuid) != null
                        ? db.loadLatestX3dhpqSignedPreKey(uuid).keyId()
                        : -1,
                db.listX3dhpqKemPreKeyIds(uuid).size(),
                db.listX3dhpqUnusedOneTimePreKeyIds(uuid).size());
    }

    /**
     * Recovery / task #58 "join an existing identity": demote a device that currently holds
     * its own account AIK (thinks it is primary — possibly after a wrong self-promotion on a
     * fork) BACK to pending-enrollment, WITHOUT touching its device key. Re-flags the local
     * device row as {@link #FLAG_PENDING_ENROLLMENT} (keeping its DIK, device_id, DC and
     * created_at) so it stops acting as primary and re-detects the account's existing
     * identity on the next {@code publishLocalState()} → {@code resolvePendingEnrollment()}.
     *
     * <p>The {@code x3dhpq_account_identity} row is intentionally NOT deleted here: {@code
     * x3dhpq_local_device} has an {@code ON DELETE CASCADE} FK to it, so dropping the identity
     * row would also destroy this device's DIK. Keeping the tentative AIK row is exactly the
     * shape {@link #ensureBootstrapped} leaves a genuine pending device in; the stale AIK is
     * overwritten when the device pairs as a secondary (adopting the account AIK pub) or is
     * re-confirmed as primary via {@link #promoteToPrimary} (which reuses the row) if no other
     * identity is found. Caller (X3dhpqService) is responsible for clearing the derived trust
     * caches and re-running the pending-enrollment resolution.
     */
    public void demoteToPending(final String uuid) {
        final var devices = db.listX3dhpqLocalDevices(uuid);
        if (devices.isEmpty()) {
            Log.w(Config.LOGTAG, "x3dhpq: demoteToPending called for " + uuid
                    + " but no local device row exists — nothing to demote");
            return;
        }
        final DatabaseBackend.X3dhpqLocalDeviceRow row = devices.get(0);
        if (isPending(row)) {
            Log.d(Config.LOGTAG, "x3dhpq: demoteToPending — device " + row.deviceId()
                    + " is already pending; no-op");
            return;
        }
        db.putX3dhpqLocalDevice(
                uuid, row.deviceId(), row.dikPriv(), row.dc(), row.createdAt(),
                DeviceCertificate.FLAG_PRIMARY | FLAG_PENDING_ENROLLMENT);
        Log.i(Config.LOGTAG, "x3dhpq: demoteToPending — device " + row.deviceId()
                + " re-flagged PENDING (DIK kept); will re-detect the account identity on next login");
    }

    /**
     * Explicit, user-chosen "generate a new identity" (§10.6.4b): destructive. Wipes any
     * local AIK/device state for {@code uuid} and mints a brand-new AIK + DIK + DC + SPK +
     * prekeys, becoming primary of a fresh identity. The caller (owned: {@code
     * X3dhpqService}) is responsible for the network-visible side effects this implies —
     * publishing a devicelist tombstone / {@code RotateAIK} audit entry for the OLD AIK so
     * contacts detect the reconstruction per §10.6.5 — this method only performs the local
     * key-material replacement.
     *
     * @return the freshly minted primary identity; never a pending result.
     */
    public BootstrapResult mintFreshIdentity(final String uuid) {
        db.beginTransaction();
        try {
            // Wipe the whole local identity. Deleting the account_identity row
            // cascades (ON DELETE CASCADE) to this account's local devices and
            // prekeys, giving ensureBootstrapped() a clean slate to mint into.
            for (final DatabaseBackend.X3dhpqLocalDeviceRow row : db.listX3dhpqLocalDevices(uuid)) {
                db.deleteX3dhpqLocalDevice(uuid, row.deviceId());
            }
            db.deleteX3dhpqAccountIdentity(uuid);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        // Re-run the normal fresh-device path (now guaranteed empty local state) to
        // generate a brand-new AIK + device material, then immediately confirm it as
        // primary — this account intentionally starts a fresh identity, bypassing the
        // pending gate.
        ensureBootstrapped(uuid);
        return promoteToPrimary(uuid);
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
        /**
         * True when this device has device-level material (DIK) but no account AIK yet
         * (§10.6.1 pending-enrollment). While true, the device MUST NOT be treated as
         * primary and MUST NOT publish an authoritative devicelist.
         */
        public final boolean pendingEnrollment;
        public final int signedPreKeyId;
        public final int kemPreKeyCount;
        public final int oneTimePreKeyCount;

        BootstrapResult(
                final String accountUuid,
                final int deviceId,
                final String fingerprint,
                final boolean wasNewlyCreated,
                final boolean pendingEnrollment,
                final int signedPreKeyId,
                final int kemPreKeyCount,
                final int oneTimePreKeyCount) {
            this.accountUuid = accountUuid;
            this.deviceId = deviceId;
            this.fingerprint = fingerprint;
            this.wasNewlyCreated = wasNewlyCreated;
            this.pendingEnrollment = pendingEnrollment;
            this.signedPreKeyId = signedPreKeyId;
            this.kemPreKeyCount = kemPreKeyCount;
            this.oneTimePreKeyCount = oneTimePreKeyCount;
        }
    }
}
