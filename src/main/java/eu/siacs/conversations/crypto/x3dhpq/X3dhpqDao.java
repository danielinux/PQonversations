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

    // --- local device ---
    void putX3dhpqLocalDevice(String accountUuid, int deviceId, byte[] dikPriv, byte[] dc, long createdAt, int flags);
    List<DatabaseBackend.X3dhpqLocalDeviceRow> listX3dhpqLocalDevices(String accountUuid);

    // --- signed pre-key ---
    void putX3dhpqSignedPreKey(String accountUuid, int keyId, byte[] pubX, byte[] privX, byte[] sigEd, byte[] sigMldsa, long createdAt);
    DatabaseBackend.X3dhpqSignedPreKeyRow loadLatestX3dhpqSignedPreKey(String accountUuid);

    // --- kem pre-key ---
    void putX3dhpqKemPreKey(String accountUuid, int keyId, byte[] pub, byte[] priv);
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

    // --- all remote devices (for AIK fp → JID lookup) ---
    List<DatabaseBackend.X3dhpqRemoteDeviceRow> listAllX3dhpqRemoteDevices(String accountUuid);

    // --- audit chain tail hash ---
    /** Returns the persisted SHA-256 tail hash for the account's audit chain, or null if none. */
    byte[] getAuditTailHash(long accountId);
    /** Persists the SHA-256 tail hash for the account's audit chain. */
    void setAuditTailHash(long accountId, byte[] tailHash);

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
