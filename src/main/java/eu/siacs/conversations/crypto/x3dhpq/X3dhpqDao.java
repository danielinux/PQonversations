// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import java.util.List;

/**
 * Data-access interface consumed by LocalKeyBootstrap and X3dhpqService.
 * DatabaseBackend implements this; tests supply a fake.
 */
public interface X3dhpqDao {

    // --- account identity ---
    void putX3dhpqAccountIdentity(String accountUuid, byte[] aikPriv, byte[] aikPub, String fingerprint);
    DatabaseBackend.X3dhpqAccountIdentityRow loadX3dhpqAccountIdentity(String accountUuid);
    // Deletes this account's AIK row; the FK ON DELETE CASCADE removes its local
    // devices and prekeys too. Used by the destructive "generate new identity" path.
    void deleteX3dhpqAccountIdentity(String accountUuid);

    // --- devicelist version + last-seen content state (§8.2, §8.5) ---
    void putX3dhpqDeviceListState(String accountUuid, String ownerJid, long version,
                                  byte[] contentHash, boolean acceptedSigned, long updatedAt);
    DatabaseBackend.X3dhpqDeviceListStateRow loadX3dhpqDeviceListState(String accountUuid, String ownerJid);

    // --- Trust Manifest Phase 2 per-owner rollback/fork guard state (contract §C.3) ---
    void putX3dhpqManifestState(String accountUuid, String ownerJid, long version,
                                byte[] blobHash, byte[] blob, long updatedAt);
    DatabaseBackend.X3dhpqManifestStateRow loadX3dhpqManifestState(String accountUuid, String ownerJid);
    void deleteX3dhpqManifestState(String accountUuid, String ownerJid);

    // --- local device ---
    void putX3dhpqLocalDevice(String accountUuid, int deviceId, byte[] dikPriv, byte[] dc, long createdAt, int flags);
    List<DatabaseBackend.X3dhpqLocalDeviceRow> listX3dhpqLocalDevices(String accountUuid);
    void deleteX3dhpqLocalDevice(String accountUuid, int deviceId);

    // --- co-account device: OTHER physical devices under this account's AIK that this
    // install did not itself generate (e.g. enrolled via pairing while acting as the
    // existing/primary side). Holds only the public DeviceCertificate; the private key
    // lives on the enrolled device. Unioned with x3dhpq_local_device when (re)publishing
    // the devicelist (§8.2) so every device the account knows about stays on `current`. ---
    void putX3dhpqCoAccountDevice(String accountUuid, int deviceId, byte[] dc, long addedAt, int flags);
    List<DatabaseBackend.X3dhpqCoAccountDeviceRow> listX3dhpqCoAccountDevices(String accountUuid);
    void pruneX3dhpqCoAccountDevicesNotIn(String accountUuid, java.util.Collection<Integer> keepIds);
    void deleteX3dhpqCoAccountDevice(String accountUuid, int deviceId);

    // --- committed device-id set (devicelist shrink guard): the device ids of the
    // most recently ACCEPTED (inbound, own list) or PUBLISHED (outbound) authoritative
    // devicelist. Independent of x3dhpq_local_device / x3dhpq_co_account_device (the
    // volatile tables used to BUILD the outbound list) so the guard in
    // X3dhpqService#publishDeviceList is not circular. ---
    void putX3dhpqCommittedDevices(String accountUuid, java.util.Collection<Integer> ids);
    java.util.Set<Integer> loadX3dhpqCommittedDeviceIds(String accountUuid);

    // --- device-audit DAG (§11.7): the multi-writer device-authorization ratchet
    // log folded by im.conversations.x3dhpq.types.DeviceDag to derive the account's
    // authorized device set. entryBlob is opaque DeviceAuditEntryV2.marshal() bytes;
    // entryHashHex is hex(SHA-256(entryBlob)), the ingest dedup key. ---
    void putX3dhpqDeviceAuditEntry(String accountUuid, String entryHashHex, byte[] entryBlob, long createdAt);
    List<DatabaseBackend.X3dhpqDeviceAuditEntryRow> listX3dhpqDeviceAuditEntries(String accountUuid);

    // --- signed pre-key ---
    void putX3dhpqSignedPreKey(String accountUuid, int keyId, byte[] pubX, byte[] privX, byte[] sigEd, byte[] sigMldsa, long createdAt);
    DatabaseBackend.X3dhpqSignedPreKeyRow loadLatestX3dhpqSignedPreKey(String accountUuid);

    // --- kem pre-key ---
    void putX3dhpqKemPreKey(
            String accountUuid, int keyId, byte[] pub, byte[] priv,
            byte[] sigEd25519, byte[] sigMldsa);
    List<Integer> listX3dhpqKemPreKeyIds(String accountUuid);
    DatabaseBackend.X3dhpqKemPreKeyRow loadX3dhpqKemPreKey(String accountUuid, int keyId);

    // --- one-time pre-key ---
    void putX3dhpqOneTimePreKey(String accountUuid, int keyId, byte[] pubX, byte[] privX);
    List<Integer> listX3dhpqUnusedOneTimePreKeyIds(String accountUuid);
    DatabaseBackend.X3dhpqOneTimePreKeyRow loadX3dhpqOneTimePreKey(String accountUuid, int keyId);

    // --- remote device (peer) ---
    void putX3dhpqRemoteDevice(String accountUuid, String peerJid, int deviceId, byte[] certMarshal, Long lastSeen);
    List<DatabaseBackend.X3dhpqRemoteDeviceRow> listX3dhpqRemoteDevices(String accountUuid, String peerJid);
    void pruneX3dhpqRemoteDevicesNotIn(String accountUuid, String peerJid, java.util.Collection<Integer> keepIds);

    // --- remote bundle (peer) ---
    void putX3dhpqRemoteBundle(String accountUuid, String peerJid, int deviceId, byte[] aikPubMarshal, byte[] bundleXml, long fetchedAt);
    DatabaseBackend.X3dhpqRemoteBundleRow loadX3dhpqRemoteBundle(String accountUuid, String peerJid, int deviceId);

    // --- session ---
    void putX3dhpqSession(String accountUuid, String peerJid, int deviceId, byte[] stateBlob, long updatedAt);
    DatabaseBackend.X3dhpqSessionRow loadX3dhpqSession(String accountUuid, String peerJid, int deviceId);

    // --- one-time pre-key lifecycle ---
    void markX3dhpqOneTimePreKeyConsumed(String accountUuid, int keyId);

    // --- group session ---
    void putX3dhpqGroupSession(String accountUuid, String roomJid, long epoch, byte[] stateBlob, long updatedAt);
    DatabaseBackend.X3dhpqGroupSessionRow loadX3dhpqGroupSession(String accountUuid, String roomJid);

    // --- group membership journal entries ---
    void putX3dhpqGroupMembershipEntry(String accountUuid, String roomJid, String entryHash,
                                       byte[] journalBlob, String itemId, long fetchedAt);
    List<DatabaseBackend.X3dhpqGroupMembershipRow> listX3dhpqGroupMembershipEntries(
            String accountUuid, String roomJid);

    // --- all remote devices (for AIK fp → JID lookup) ---
    List<DatabaseBackend.X3dhpqRemoteDeviceRow> listAllX3dhpqRemoteDevices(String accountUuid);

    // --- pairing session ---
    void putX3dhpqPairingSession(String accountUuid, byte[] sid, int role, String peerJid,
                                 String code, byte[] stateBlob, long expiresAt);
    DatabaseBackend.X3dhpqPairingSessionRow loadX3dhpqPairingSession(byte[] sid);
    void updateX3dhpqPairingState(byte[] sid, byte[] stateBlob);
    void deleteX3dhpqPairingSession(byte[] sid);
    int sweepExpiredX3dhpqPairingSessions(long nowUnixSeconds);

    // --- transactions ---
    void beginTransaction();
    void setTransactionSuccessful();
    void endTransaction();
}
