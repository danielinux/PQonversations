// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * x3dhpq-xep-draft.md §11.7: multi-writer device-audit DAG — convergence + single-AIK
 * authorization (plain JVM). Mirrors {@link MembershipDagTest}'s discipline; the
 * shared byte-vectors below MUST match the Vala engine's tests/device_dag.vala
 * byte-for-byte — that is the cross-language contract.
 */
class DeviceDagTest {

    // A signing identity: one account AIK keypair + its raw 20-byte fingerprint.
    private static final class Id {
        final byte[] edPriv, mlPriv;
        final AccountIdentityPub pub;
        final byte[] fp;      // raw 20 bytes
        final String fpHex;

        Id() {
            final KeyPair ed = X3dhpqCrypto.ed25519GenerateKeypair();
            final KeyPair ml = X3dhpqCrypto.mldsa65GenerateKeypair();
            this.edPriv = ed.priv;
            this.mlPriv = ml.priv;
            this.pub = new AccountIdentityPub(ed.pub, ml.pub);
            this.fp = X3dhpqCrypto.BLAKE2B_160.hash(pub.marshal());
            this.fpHex = DeviceAuditEntryV2.hex(fp);
        }
    }

    private final Map<String, Id> registry = new HashMap<>();

    private Id makeId() {
        final Id id = new Id();
        registry.put(id.fpHex, id);
        return id;
    }

    private DeviceDag.AikResolver resolver() {
        return fpHex -> {
            final Id id = registry.get(fpHex);
            return id == null ? null : id.pub;
        };
    }

    private DeviceAuditEntryV2 sign(Id signer, long lamport, long authorDeviceId, List<byte[]> parents,
                                     int action, byte[] payload, long ts) {
        final DeviceAuditEntryV2 unsigned =
                new DeviceAuditEntryV2(lamport, signer.fp, authorDeviceId, parents, action, payload, ts,
                        new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(signer.edPriv, sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(signer.mlPriv, sp);
        return new DeviceAuditEntryV2(lamport, signer.fp, authorDeviceId, parents, action, payload, ts, sigEd, sigMl);
    }

    private List<byte[]> heads(byte[] h) {
        final List<byte[]> l = new ArrayList<>();
        if (h != null) l.add(h);
        return l;
    }

    // A structurally-valid (but not cryptographically meaningful) DeviceCertificate,
    // sufficient for DeviceDag folding: the DAG never verifies the cert's own
    // signature, only the entry's hybrid signature under the pinned account AIK.
    private byte[] makeCertBytes(long deviceId) {
        final byte[] ed = new byte[32]; Arrays.fill(ed, (byte) 0x11);
        final byte[] x = new byte[32]; Arrays.fill(x, (byte) 0x22);
        final byte[] mldsa = new byte[1952]; Arrays.fill(mldsa, (byte) 0x33);
        final byte[] sigEd = new byte[64]; Arrays.fill(sigEd, (byte) 0x44);
        final byte[] sigMl = new byte[3309]; Arrays.fill(sigMl, (byte) 0x55);
        final DeviceCertificate dc = new DeviceCertificate(1, deviceId, ed, x, mldsa, 1000L, (byte) 0, sigEd, sigMl);
        return dc.marshal();
    }

    // -------------------------------------------------------------------------
    // Shared cross-language byte-vectors (§11.7). MUST match device_dag.vala's
    // DEVICE_AUDIT_V2_VECTOR / DEVICE_AUDIT_SNAPSHOT_VECTOR exactly.
    // -------------------------------------------------------------------------

    // lamport=1, signer_fp=20xAB, author_device_id=7, no parents,
    // action=RemoveDevice(2), payload=buildRemoveDevicePayload(0xCDCDCDCD), timestamp=0.
    static final String DEVICE_AUDIT_V2_VECTOR =
            "5833444850512d44657641756469742d763200" // "X3DHPQ-DevAudit-v2\0"
          + "0000000000000001"                       // lamport
          + "abababababababababababababababababababab" // signer_fp
          + "00000007"                                // author_device_id
          + "00000000"                                // parent_count
          + "02"                                       // action = RemoveDevice
          + "00000004"                                 // payload_len = 4
          + "cdcdcdcd"                                  // payload = device_id
          + "0000000000000000";                         // timestamp

    // lamport=2, signer_fp=20xAB, author_device_id=7, no parents, action=Snapshot(10),
    // payload=buildSnapshotPayload(owner_aik_fp=20xEF, epoch=5,
    //         devices=[{device_id=42, cert=8xEE}]), timestamp=0.
    static final String DEVICE_AUDIT_SNAPSHOT_VECTOR =
            "5833444850512d44657641756469742d763200" // "X3DHPQ-DevAudit-v2\0"
          + "0000000000000002"                       // lamport
          + "abababababababababababababababababababab" // signer_fp
          + "00000007"                                // author_device_id
          + "00000000"                                // parent_count
          + "0a"                                       // action = Snapshot
          + "00000030"                                 // payload_len = 48
          + "efefefefefefefefefefefefefefefefefefefef" // owner_aik_fp
          + "0000000000000005"                         // epoch
          + "00000001"                                 // device count
          + "0000002a"                                 // device_id = 42
          + "00000008"                                 // cert_len = 8
          + "eeeeeeeeeeeeeeee"                          // cert bytes
          + "0000000000000000";                         // timestamp

    @Test
    void signedPartVector() {
        final byte[] fp = new byte[20]; Arrays.fill(fp, (byte) 0xAB);
        final DeviceAuditEntryV2 e =
                new DeviceAuditEntryV2(1L, fp, 7L, new ArrayList<>(), DeviceAuditEntryV2.ACTION_REMOVE_DEVICE,
                        DeviceAuditEntryV2.buildRemoveDevicePayload(0xCDCDCDCDL), 0L, new byte[0], new byte[0]);
        assertEquals(DEVICE_AUDIT_V2_VECTOR, DeviceAuditEntryV2.hex(e.signedPart()));
    }

    @Test
    void snapshotVector() {
        final byte[] fp = new byte[20]; Arrays.fill(fp, (byte) 0xAB);
        final byte[] ownerFp = new byte[20]; Arrays.fill(ownerFp, (byte) 0xEF);
        final byte[] cert = new byte[8]; Arrays.fill(cert, (byte) 0xEE);
        final List<DeviceAuditEntryV2.SnapshotDevice> devices = new ArrayList<>();
        devices.add(new DeviceAuditEntryV2.SnapshotDevice(42L, cert));
        final byte[] payload = DeviceAuditEntryV2.buildSnapshotPayload(ownerFp, 5L, devices);
        final DeviceAuditEntryV2 e =
                new DeviceAuditEntryV2(2L, fp, 7L, new ArrayList<>(), DeviceAuditEntryV2.ACTION_SNAPSHOT,
                        payload, 0L, new byte[0], new byte[0]);
        assertEquals(DEVICE_AUDIT_SNAPSHOT_VECTOR, DeviceAuditEntryV2.hex(e.signedPart()));

        // round-trip the payload codec too.
        final DeviceAuditEntryV2.Snapshot parsed = DeviceAuditEntryV2.parseSnapshot(payload);
        assertNotNull(parsed);
        assertArrayEquals(ownerFp, parsed.ownerAikFp);
        assertEquals(5L, parsed.epoch);
        assertEquals(1, parsed.devices.size());
        assertEquals(42L, parsed.devices.get(0).deviceId);
        assertArrayEquals(cert, parsed.devices.get(0).certBytes);
    }

    @Test
    void marshalRoundtrip() {
        final Id owner = makeId();
        final byte[] payload = DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L));
        final DeviceAuditEntryV2 e = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE, payload, 1000);
        final byte[] wire = e.marshal();
        assertTrue(DeviceAuditEntryV2.isV2(wire));
        final DeviceAuditEntryV2 e2 = DeviceAuditEntryV2.unmarshal(wire);
        assertNotNull(e2);
        assertTrue(e2.verify(owner.pub));
        assertEquals(owner.fpHex, DeviceAuditEntryV2.hex(e2.getSignerFp()));
    }

    @Test
    void genesisAddDevice() {
        final Id owner = makeId();
        final DeviceAuditEntryV2 g = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L)), 1000);
        final DeviceDag dag = new DeviceDag();
        dag.ingest(g.marshal());
        final DeviceDag.DeviceState st = dag.recompute(resolver());
        assertEquals(owner.fpHex, st.currentAikFpHex);
        assertTrue(st.authorized.containsKey(1L));
    }

    @Test
    void unknownSignerRejected() {
        final Id owner = makeId();
        final Id intruder = makeId();
        final DeviceAuditEntryV2 g = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L)), 1000);
        final DeviceAuditEntryV2 bad = sign(intruder, 1, 99L, heads(g.computeHash()), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(99L, makeCertBytes(99L)), 1001);
        final DeviceDag dag = new DeviceDag();
        dag.ingest(g.marshal()); dag.ingest(bad.marshal());
        final DeviceDag.DeviceState st = dag.recompute(resolver());
        assertTrue(st.authorized.containsKey(1L));
        assertFalse(st.authorized.containsKey(99L), "entry from a non-pinned AIK must be rejected");
    }

    @Test
    void convergenceIndependentOfOrder() {
        final Id owner = makeId();
        final DeviceAuditEntryV2 g = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L)), 1000);
        final byte[] gh = g.computeHash();
        // Two authorized devices concurrently AddDevice different device_ids.
        final DeviceAuditEntryV2 a2 = sign(owner, 1, 2L, heads(gh), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(2L, makeCertBytes(2L)), 1001);
        final DeviceAuditEntryV2 a3 = sign(owner, 1, 3L, heads(gh), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(3L, makeCertBytes(3L)), 1002);
        final DeviceAuditEntryV2[] all = {g, a2, a3};

        final DeviceDag d1 = new DeviceDag();
        for (final DeviceAuditEntryV2 e : all) d1.ingest(e.marshal());
        final DeviceDag.DeviceState s1 = d1.recompute(resolver());

        final DeviceDag d2 = new DeviceDag();
        for (int i = all.length - 1; i >= 0; i--) d2.ingest(all[i].marshal());
        final DeviceDag.DeviceState s2 = d2.recompute(resolver());

        assertEquals(s1.authorized.keySet(), s2.authorized.keySet(), "authorized set converges regardless of ingest order");
        assertTrue(s1.authorized.containsKey(1L) && s1.authorized.containsKey(2L) && s1.authorized.containsKey(3L));
    }

    @Test
    void removalWinsOverConcurrentReAdd() {
        final Id owner = makeId();
        final DeviceAuditEntryV2 g = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L)), 1000);
        final DeviceAuditEntryV2 add2 = sign(owner, 1, 1L, heads(g.computeHash()), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(2L, makeCertBytes(2L)), 1001);
        final byte[] add2h = add2.computeHash();
        // Concurrent: remove device 2 vs re-add device 2 with a fresh cert — both build on add2 (siblings).
        final DeviceAuditEntryV2 rem = sign(owner, 2, 1L, heads(add2h), DeviceAuditEntryV2.ACTION_REMOVE_DEVICE,
                DeviceAuditEntryV2.buildRemoveDevicePayload(2L), 1002);
        final DeviceAuditEntryV2 readd = sign(owner, 2, 1L, heads(add2h), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(2L, makeCertBytes(2L)), 1003);
        final DeviceDag dag = new DeviceDag();
        for (final DeviceAuditEntryV2 e : new DeviceAuditEntryV2[]{g, add2, rem, readd}) dag.ingest(e.marshal());
        final DeviceDag.DeviceState st = dag.recompute(resolver());
        assertFalse(st.authorized.containsKey(2L), "removal must win over a concurrent (non-descendant) re-add");
        assertTrue(st.removed.contains(2L));
    }

    @Test
    void rotateAikResetsPin() {
        final Id owner = makeId();
        final Id newOwner = makeId();
        final DeviceAuditEntryV2 g = sign(owner, 0, 1L, heads(null), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(1L, makeCertBytes(1L)), 1000);
        final DeviceAuditEntryV2 rot = sign(owner, 1, 1L, heads(g.computeHash()), DeviceAuditEntryV2.ACTION_ROTATE_AIK,
                DeviceAuditEntryV2.buildRotateAikPayload(newOwner.pub.marshal()), 1001);
        final DeviceAuditEntryV2 add2 = sign(newOwner, 2, 1L, heads(rot.computeHash()), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(2L, makeCertBytes(2L)), 1002);
        // An entry still signed by the OLD AIK after rotation must be rejected.
        final DeviceAuditEntryV2 stale = sign(owner, 3, 1L, heads(add2.computeHash()), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(3L, makeCertBytes(3L)), 1003);
        final DeviceDag dag = new DeviceDag();
        for (final DeviceAuditEntryV2 e : new DeviceAuditEntryV2[]{g, rot, add2, stale}) dag.ingest(e.marshal());
        final DeviceDag.DeviceState st = dag.recompute(resolver());
        assertEquals(newOwner.fpHex, st.currentAikFpHex, "fold must be re-pinned to the new AIK after RotateAIK");
        assertTrue(st.authorized.containsKey(1L));
        assertTrue(st.authorized.containsKey(2L), "device added under the new AIK is authorized");
        assertFalse(st.authorized.containsKey(3L), "device added under the stale (pre-rotation) AIK must be rejected");
    }

    @Test
    void snapshotVirtualGenesisImport() {
        final Id owner = makeId();
        final byte[] c1 = makeCertBytes(10L);
        final byte[] c2 = makeCertBytes(11L);
        final List<DeviceAuditEntryV2.SnapshotDevice> devices = new ArrayList<>();
        devices.add(new DeviceAuditEntryV2.SnapshotDevice(10L, c1));
        devices.add(new DeviceAuditEntryV2.SnapshotDevice(11L, c2));
        final byte[] payload = DeviceAuditEntryV2.buildSnapshotPayload(owner.fp, 7L, devices);
        final DeviceAuditEntryV2 snap = sign(owner, 1, 1L, heads(null), DeviceAuditEntryV2.ACTION_SNAPSHOT, payload, 1000);

        // Snapshot alone: epoch is the asserted snapshot epoch.
        final DeviceDag snapOnlyDag = new DeviceDag();
        snapOnlyDag.ingest(snap.marshal());
        final DeviceDag.DeviceState snapOnlySt = snapOnlyDag.recompute(resolver());
        assertEquals(owner.fpHex, snapOnlySt.currentAikFpHex, "owner TOFU-pinned from the genesis snapshot's signer");
        assertTrue(snapOnlySt.authorized.containsKey(10L), "device imported from snapshot");
        assertTrue(snapOnlySt.authorized.containsKey(11L), "device imported from snapshot");
        assertEquals(7L, snapOnlySt.epoch);

        // A device added by an authorized (now-pinned) AIK after the bridging snapshot.
        final DeviceAuditEntryV2 add = sign(owner, 2, 1L, heads(snap.computeHash()), DeviceAuditEntryV2.ACTION_ADD_DEVICE,
                DeviceAuditEntryV2.buildAddDevicePayload(12L, makeCertBytes(12L)), 1001);
        final DeviceDag dag = new DeviceDag();
        dag.ingest(snap.marshal()); dag.ingest(add.marshal());
        final DeviceDag.DeviceState st = dag.recompute(resolver());
        assertTrue(st.authorized.containsKey(10L), "device imported from snapshot");
        assertTrue(st.authorized.containsKey(11L), "device imported from snapshot");
        assertTrue(st.authorized.containsKey(12L), "device added on top of the bridging snapshot");
    }
}
