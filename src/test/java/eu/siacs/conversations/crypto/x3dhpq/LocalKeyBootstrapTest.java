package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class LocalKeyBootstrapTest {

    /**
     * Pure-Java in-memory stub implementing X3dhpqDao.
     * Avoids Android SQLite; tests run as plain JUnit4 on the JVM.
     */
    static final class FakeDao implements X3dhpqDao {

        int accountIdentityInserts = 0;
        int localDeviceInserts = 0;
        int signedPreKeyInserts = 0;
        int kemPreKeyInserts = 0;
        int oneTimePreKeyInserts = 0;
        int remoteDeviceInserts = 0;
        int remoteBundleInserts = 0;

        final Map<String, DatabaseBackend.X3dhpqAccountIdentityRow> identityRows = new HashMap<>();
        final Map<String, List<DatabaseBackend.X3dhpqLocalDeviceRow>> deviceRows = new HashMap<>();
        final Map<String, DatabaseBackend.X3dhpqSignedPreKeyRow> latestSpk = new HashMap<>();
        final Map<String, List<Integer>> kemKeyIds = new HashMap<>();
        // key: accountUuid + ":" + keyId
        final Map<String, DatabaseBackend.X3dhpqKemPreKeyRow> kemKeyRows = new HashMap<>();
        final Map<String, List<Integer>> opkIds = new HashMap<>();
        // key: accountUuid + ":" + keyId
        final Map<String, DatabaseBackend.X3dhpqOneTimePreKeyRow> opkRows = new HashMap<>();
        // key: accountUuid + ":" + peerJid + ":" + deviceId
        final Map<String, DatabaseBackend.X3dhpqRemoteDeviceRow> remoteDeviceRows = new HashMap<>();
        // key: accountUuid + ":" + peerJid + ":" + deviceId
        final Map<String, DatabaseBackend.X3dhpqRemoteBundleRow> remoteBundleRows = new HashMap<>();

        @Override
        public void putX3dhpqAccountIdentity(
                String accountUuid, byte[] aikPriv, byte[] aikPub, String fingerprint) {
            identityRows.put(
                    accountUuid,
                    new DatabaseBackend.X3dhpqAccountIdentityRow(
                            accountUuid, aikPriv, aikPub, fingerprint));
            accountIdentityInserts++;
        }

        @Override
        public DatabaseBackend.X3dhpqAccountIdentityRow loadX3dhpqAccountIdentity(
                String accountUuid) {
            return identityRows.get(accountUuid);
        }

        @Override
        public void deleteX3dhpqAccountIdentity(String accountUuid) {
            identityRows.remove(accountUuid);
            // Mimic the real schema's FK ON DELETE CASCADE.
            deviceRows.remove(accountUuid);
        }

        // key: accountUuid + ":" + ownerJid
        final Map<String, DatabaseBackend.X3dhpqDeviceListStateRow> deviceListStateRows =
                new HashMap<>();

        @Override
        public void putX3dhpqDeviceListState(
                String accountUuid,
                String ownerJid,
                long version,
                byte[] contentHash,
                boolean acceptedSigned,
                long updatedAt) {
            deviceListStateRows.put(
                    accountUuid + ":" + ownerJid,
                    new DatabaseBackend.X3dhpqDeviceListStateRow(
                            accountUuid, ownerJid, version, contentHash, acceptedSigned));
        }

        @Override
        public DatabaseBackend.X3dhpqDeviceListStateRow loadX3dhpqDeviceListState(
                String accountUuid, String ownerJid) {
            return deviceListStateRows.get(accountUuid + ":" + ownerJid);
        }

        @Override
        public void putX3dhpqLocalDevice(
                String accountUuid,
                int deviceId,
                byte[] dikPriv,
                byte[] dc,
                long createdAt,
                int flags) {
            final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                    deviceRows.computeIfAbsent(accountUuid, k -> new ArrayList<>());
            // Mimic the real INSERT ... ON CONFLICT REPLACE keyed on (account,device_id):
            // a re-put of the same device replaces the row (e.g. clearing the pending flag)
            // rather than appending a duplicate.
            rows.removeIf(r -> r.deviceId() == deviceId);
            rows.add(
                    new DatabaseBackend.X3dhpqLocalDeviceRow(
                            accountUuid, deviceId, dikPriv, dc, createdAt, flags));
            localDeviceInserts++;
        }

        @Override
        public List<DatabaseBackend.X3dhpqLocalDeviceRow> listX3dhpqLocalDevices(
                String accountUuid) {
            return deviceRows.getOrDefault(accountUuid, new ArrayList<>());
        }

        @Override
        public void deleteX3dhpqLocalDevice(String accountUuid, int deviceId) {
            final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows = deviceRows.get(accountUuid);
            if (rows != null) {
                rows.removeIf(r -> r.deviceId() == deviceId);
            }
        }

        final Map<String, List<DatabaseBackend.X3dhpqCoAccountDeviceRow>> coAccountDeviceRows =
                new HashMap<>();

        @Override
        public void putX3dhpqCoAccountDevice(
                String accountUuid, int deviceId, byte[] dc, long addedAt, int flags) {
            // mirrors the real DAO's PRIMARY KEY (account_uuid, device_id) upsert
            // (CONFLICT_REPLACE) — replace any existing row for this device id.
            final List<DatabaseBackend.X3dhpqCoAccountDeviceRow> rows =
                    coAccountDeviceRows.computeIfAbsent(accountUuid, k -> new ArrayList<>());
            rows.removeIf(r -> r.deviceId() == deviceId);
            rows.add(new DatabaseBackend.X3dhpqCoAccountDeviceRow(
                    accountUuid, deviceId, dc, addedAt, flags));
        }

        @Override
        public List<DatabaseBackend.X3dhpqCoAccountDeviceRow> listX3dhpqCoAccountDevices(
                String accountUuid) {
            return coAccountDeviceRows.getOrDefault(accountUuid, new ArrayList<>());
        }

        @Override
        public void pruneX3dhpqCoAccountDevicesNotIn(
                String accountUuid, java.util.Collection<Integer> keepIds) {
            final List<DatabaseBackend.X3dhpqCoAccountDeviceRow> rows =
                    coAccountDeviceRows.get(accountUuid);
            if (rows == null) return;
            rows.removeIf(r -> keepIds == null || !keepIds.contains(r.deviceId()));
        }

        @Override
        public void deleteX3dhpqCoAccountDevice(String accountUuid, int deviceId) {
            final List<DatabaseBackend.X3dhpqCoAccountDeviceRow> rows =
                    coAccountDeviceRows.get(accountUuid);
            if (rows != null) {
                rows.removeIf(r -> r.deviceId() == deviceId);
            }
        }

        // committed device-id set (devicelist shrink guard); key: accountUuid
        final Map<String, java.util.Set<Integer>> committedDeviceIds = new HashMap<>();

        @Override
        public void putX3dhpqCommittedDevices(
                String accountUuid, java.util.Collection<Integer> ids) {
            committedDeviceIds.put(
                    accountUuid,
                    ids == null
                            ? new java.util.HashSet<>()
                            : new java.util.HashSet<>(ids));
        }

        @Override
        public java.util.Set<Integer> loadX3dhpqCommittedDeviceIds(String accountUuid) {
            return committedDeviceIds.getOrDefault(accountUuid, new java.util.HashSet<>());
        }

        @Override
        public void putX3dhpqSignedPreKey(
                String accountUuid,
                int keyId,
                byte[] pubX,
                byte[] privX,
                byte[] sigEd,
                byte[] sigMldsa,
                long createdAt) {
            latestSpk.put(
                    accountUuid,
                    new DatabaseBackend.X3dhpqSignedPreKeyRow(
                            accountUuid, keyId, pubX, privX, sigEd, sigMldsa, createdAt));
            signedPreKeyInserts++;
        }

        @Override
        public DatabaseBackend.X3dhpqSignedPreKeyRow loadLatestX3dhpqSignedPreKey(
                String accountUuid) {
            return latestSpk.get(accountUuid);
        }

        @Override
        public void putX3dhpqKemPreKey(
                String accountUuid, int keyId, byte[] pub, byte[] priv) {
            kemKeyIds.computeIfAbsent(accountUuid, k -> new ArrayList<>()).add(keyId);
            kemKeyRows.put(accountUuid + ":" + keyId,
                    new DatabaseBackend.X3dhpqKemPreKeyRow(accountUuid, keyId, pub, priv));
            kemPreKeyInserts++;
        }

        @Override
        public List<Integer> listX3dhpqKemPreKeyIds(String accountUuid) {
            return kemKeyIds.getOrDefault(accountUuid, new ArrayList<>());
        }

        @Override
        public DatabaseBackend.X3dhpqKemPreKeyRow loadX3dhpqKemPreKey(String accountUuid, int keyId) {
            return kemKeyRows.get(accountUuid + ":" + keyId);
        }

        @Override
        public void putX3dhpqOneTimePreKey(
                String accountUuid, int keyId, byte[] pubX, byte[] privX) {
            opkIds.computeIfAbsent(accountUuid, k -> new ArrayList<>()).add(keyId);
            opkRows.put(accountUuid + ":" + keyId,
                    new DatabaseBackend.X3dhpqOneTimePreKeyRow(accountUuid, keyId, pubX, privX, false));
            oneTimePreKeyInserts++;
        }

        @Override
        public List<Integer> listX3dhpqUnusedOneTimePreKeyIds(String accountUuid) {
            return opkIds.getOrDefault(accountUuid, new ArrayList<>());
        }

        @Override
        public DatabaseBackend.X3dhpqOneTimePreKeyRow loadX3dhpqOneTimePreKey(String accountUuid, int keyId) {
            return opkRows.get(accountUuid + ":" + keyId);
        }

        @Override
        public void putX3dhpqRemoteDevice(
                String accountUuid, String peerJid, int deviceId, byte[] certMarshal, Long lastSeen) {
            final String key = accountUuid + ":" + peerJid + ":" + deviceId;
            remoteDeviceRows.put(
                    key,
                    new DatabaseBackend.X3dhpqRemoteDeviceRow(
                            accountUuid, peerJid, deviceId, certMarshal, lastSeen));
            remoteDeviceInserts++;
        }

        @Override
        public void pruneX3dhpqRemoteDevicesNotIn(
                String accountUuid, String peerJid, java.util.Collection<Integer> keepIds) {
            final java.util.Iterator<Map.Entry<String, DatabaseBackend.X3dhpqRemoteDeviceRow>> it =
                    remoteDeviceRows.entrySet().iterator();
            while (it.hasNext()) {
                final DatabaseBackend.X3dhpqRemoteDeviceRow row = it.next().getValue();
                if (!accountUuid.equals(row.accountUuid())) continue;
                if (!peerJid.equals(row.peerJid())) continue;
                if (keepIds == null || !keepIds.contains(row.deviceId())) {
                    it.remove();
                }
            }
        }

        @Override
        public List<DatabaseBackend.X3dhpqRemoteDeviceRow> listX3dhpqRemoteDevices(
                String accountUuid, String peerJid) {
            final List<DatabaseBackend.X3dhpqRemoteDeviceRow> result = new ArrayList<>();
            for (final Map.Entry<String, DatabaseBackend.X3dhpqRemoteDeviceRow> e :
                    remoteDeviceRows.entrySet()) {
                final DatabaseBackend.X3dhpqRemoteDeviceRow row = e.getValue();
                if (accountUuid.equals(row.accountUuid()) && peerJid.equals(row.peerJid())) {
                    result.add(row);
                }
            }
            return result;
        }

        @Override
        public void putX3dhpqRemoteBundle(
                String accountUuid,
                String peerJid,
                int deviceId,
                byte[] aikPubMarshal,
                byte[] bundleXml,
                long fetchedAt) {
            final String key = accountUuid + ":" + peerJid + ":" + deviceId;
            remoteBundleRows.put(
                    key,
                    new DatabaseBackend.X3dhpqRemoteBundleRow(
                            accountUuid, peerJid, deviceId, aikPubMarshal, bundleXml, fetchedAt));
            remoteBundleInserts++;
        }

        @Override
        public DatabaseBackend.X3dhpqRemoteBundleRow loadX3dhpqRemoteBundle(
                String accountUuid, String peerJid, int deviceId) {
            return remoteBundleRows.get(accountUuid + ":" + peerJid + ":" + deviceId);
        }

        // session rows; key: accountUuid + ":" + peerJid + ":" + deviceId
        final Map<String, DatabaseBackend.X3dhpqSessionRow> sessionRows = new HashMap<>();
        int sessionInserts = 0;
        // consumed OPK ids; key: accountUuid + ":" + keyId
        final java.util.Set<String> consumedOpkKeys = new java.util.HashSet<>();

        @Override
        public void putX3dhpqSession(
                String accountUuid, String peerJid, int deviceId, byte[] stateBlob, long updatedAt) {
            sessionRows.put(
                    accountUuid + ":" + peerJid + ":" + deviceId,
                    new DatabaseBackend.X3dhpqSessionRow(
                            accountUuid, peerJid, deviceId, stateBlob, updatedAt));
            sessionInserts++;
        }

        @Override
        public DatabaseBackend.X3dhpqSessionRow loadX3dhpqSession(
                String accountUuid, String peerJid, int deviceId) {
            return sessionRows.get(accountUuid + ":" + peerJid + ":" + deviceId);
        }

        @Override
        public void markX3dhpqOneTimePreKeyConsumed(String accountUuid, int keyId) {
            // Remove from unused OPK ids so re-publish logic works correctly.
            final List<Integer> ids = opkIds.getOrDefault(accountUuid, new ArrayList<>());
            ids.remove(Integer.valueOf(keyId));
            consumedOpkKeys.add(accountUuid + ":" + keyId);
        }

        // group session rows; key: accountUuid + ":" + roomJid
        final Map<String, DatabaseBackend.X3dhpqGroupSessionRow> groupSessionRows = new HashMap<>();

        @Override
        public void putX3dhpqGroupSession(
                String accountUuid, String roomJid, long epoch, byte[] stateBlob, long updatedAt) {
            groupSessionRows.put(
                    accountUuid + ":" + roomJid,
                    new DatabaseBackend.X3dhpqGroupSessionRow(
                            accountUuid, roomJid, epoch, stateBlob, updatedAt));
        }

        @Override
        public DatabaseBackend.X3dhpqGroupSessionRow loadX3dhpqGroupSession(
                String accountUuid, String roomJid) {
            return groupSessionRows.get(accountUuid + ":" + roomJid);
        }

        @Override
        public List<DatabaseBackend.X3dhpqRemoteDeviceRow> listAllX3dhpqRemoteDevices(
                String accountUuid) {
            final List<DatabaseBackend.X3dhpqRemoteDeviceRow> result = new ArrayList<>();
            for (final DatabaseBackend.X3dhpqRemoteDeviceRow row : remoteDeviceRows.values()) {
                if (accountUuid.equals(row.accountUuid())) {
                    result.add(row);
                }
            }
            return result;
        }

        @Override
        public byte[] getAuditTailHash(long accountId) { return null; }

        @Override
        public void setAuditTailHash(long accountId, byte[] tailHash) {}

        @Override
        public void putX3dhpqPairingSession(
                String accountUuid,
                byte[] sid,
                int role,
                String peerJid,
                String code,
                byte[] stateBlob,
                long expiresAt) {}

        @Override
        public DatabaseBackend.X3dhpqPairingSessionRow loadX3dhpqPairingSession(byte[] sid) {
            return null;
        }

        @Override
        public void updateX3dhpqPairingState(byte[] sid, byte[] stateBlob) {}

        @Override
        public void deleteX3dhpqPairingSession(byte[] sid) {}

        @Override
        public int sweepExpiredX3dhpqPairingSessions(long nowUnixSeconds) { return 0; }

        @Override
        public void beginTransaction() {}

        @Override
        public void setTransactionSuccessful() {}

        @Override
        public void endTransaction() {}

        int totalInserts() {
            return accountIdentityInserts
                    + localDeviceInserts
                    + signedPreKeyInserts
                    + kemPreKeyInserts
                    + oneTimePreKeyInserts;
        }
    }

    @Test
    public void testFreshAccountGeneratesAllKeys() {
        final FakeDao dao = new FakeDao();
        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(dao, new SecureRandom());
        final String uuid = "fresh-account-uuid";

        final LocalKeyBootstrap.BootstrapResult result = bootstrap.ensureBootstrapped(uuid);

        Assert.assertEquals("one account_identity insert", 1, dao.accountIdentityInserts);
        Assert.assertEquals("one local_device insert", 1, dao.localDeviceInserts);
        Assert.assertEquals("one SPK insert", 1, dao.signedPreKeyInserts);
        Assert.assertEquals(
                "N KEM pre-key inserts",
                LocalKeyBootstrap.DEFAULT_KEM_PREKEY_COUNT,
                dao.kemPreKeyInserts);
        Assert.assertEquals(
                "N OPK inserts",
                LocalKeyBootstrap.DEFAULT_ONE_TIME_PREKEY_COUNT,
                dao.oneTimePreKeyInserts);

        // 1 + 1 + 1 + 10 + 100 = 113
        Assert.assertEquals("total inserts", 113, dao.totalInserts());
        Assert.assertTrue("wasNewlyCreated must be true", result.wasNewlyCreated);
        Assert.assertNotNull("fingerprint must not be null", result.fingerprint);
        // 30 hex chars in 6 groups of 5 separated by spaces = 35 chars.
        Assert.assertEquals("fingerprint length must be 35", 35, result.fingerprint.length());
    }

    @Test
    public void testIdempotency() {
        final FakeDao dao = new FakeDao();
        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(dao, new SecureRandom());
        final String uuid = "idempotent-account-uuid";

        final LocalKeyBootstrap.BootstrapResult first = bootstrap.ensureBootstrapped(uuid);
        final int insertsAfterFirst = dao.totalInserts();

        final LocalKeyBootstrap.BootstrapResult second = bootstrap.ensureBootstrapped(uuid);

        // No additional inserts on second call.
        Assert.assertEquals(
                "no extra inserts on idempotent re-call", insertsAfterFirst, dao.totalInserts());
        Assert.assertEquals("fingerprint must be stable", first.fingerprint, second.fingerprint);
        Assert.assertFalse("wasNewlyCreated must be false on second call", second.wasNewlyCreated);
    }

    @Test
    public void testFingerprintMatchesAikPubFingerprint() {
        final FakeDao dao = new FakeDao();
        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(dao, new SecureRandom());
        final String uuid = "fp-check-uuid";

        final LocalKeyBootstrap.BootstrapResult result = bootstrap.ensureBootstrapped(uuid);

        final DatabaseBackend.X3dhpqAccountIdentityRow row = dao.loadX3dhpqAccountIdentity(uuid);
        Assert.assertNotNull("account identity row must exist", row);

        // Recompute fingerprint from the stored public key blob.
        final AccountIdentityPub storedPub = AccountIdentityPub.unmarshal(row.aikPub());
        final String recomputed = storedPub.fingerprint(X3dhpqCrypto.BLAKE2B_160);

        Assert.assertEquals(
                "stored fingerprint must match recomputed", result.fingerprint, recomputed);
    }

    @Test
    public void testDcSignatureVerifies() {
        final FakeDao dao = new FakeDao();
        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(dao, new SecureRandom());
        final String uuid = "dc-verify-uuid";

        bootstrap.ensureBootstrapped(uuid);

        final DatabaseBackend.X3dhpqAccountIdentityRow identityRow =
                dao.loadX3dhpqAccountIdentity(uuid);
        Assert.assertNotNull(identityRow);
        final AccountIdentityPub aikPub = AccountIdentityPub.unmarshal(identityRow.aikPub());

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> devices =
                dao.listX3dhpqLocalDevices(uuid);
        Assert.assertFalse("local device row must exist", devices.isEmpty());
        final DeviceCertificate dc = DeviceCertificate.unmarshal(devices.get(0).dc());

        // Signed bytes = signedPart() directly (no prefix; matches Go + dino-fork).
        final byte[] signedBytes = dc.signedPart();

        Assert.assertTrue(
                "DC Ed25519 signature must verify",
                X3dhpqCrypto.ed25519Verify(aikPub.getPubEd25519(), signedBytes, dc.getSigEd25519()));
        Assert.assertTrue(
                "DC ML-DSA-65 signature must verify",
                X3dhpqCrypto.mldsa65Verify(aikPub.getPubMLDSA(), signedBytes, dc.getSigMLDSA()));
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
