// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.bundle.DikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.DikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Ik;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkeys;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opks;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Spk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkKey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkSig;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Builds DeviceList and Bundle Extension trees from persisted x3dhpq state.
 * Pure data construction: no crypto, no I/O.
 */
public final class X3dhpqStanzaBuilder {

    private X3dhpqStanzaBuilder() {}

    /**
     * Builds the DeviceList Extension for all local devices of the account.
     * Matches the dino-fork wire shape: devicelist[version, issued-at] > device[id, flags] > cert.
     */
    public static DeviceList buildDeviceList(
            final X3dhpqDao dao, final String accountUuid) {
        // Legacy/test convenience: version 1, current issued-at. The production
        // publish path (X3dhpqService) computes the monotonic version (§8.2) and
        // uses the explicit overload below.
        return buildDeviceList(dao, accountUuid, 1L, System.currentTimeMillis() / 1000L);
    }

    /**
     * Builds the DeviceList Extension for all local devices, with an explicit
     * monotonic {@code version} and {@code issuedAt} (§8.2). Devices are emitted
     * sorted by device_id ascending (unsigned) so the XML matches the canonical
     * signed input order of §8.3.
     */
    public static DeviceList buildDeviceList(
            final X3dhpqDao dao,
            final String accountUuid,
            final long version,
            final long issuedAt) {
        final DeviceList deviceList = new DeviceList();
        deviceList.setVersion(Long.toUnsignedString(version));
        deviceList.setIssuedAt(Long.toString(issuedAt));

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localDevices =
                new ArrayList<>(dao.listX3dhpqLocalDevices(accountUuid));
        // Sort by device_id ascending (unsigned) — canonical order of §8.3.
        localDevices.sort(
                Comparator.comparingLong(r -> ((DatabaseBackend.X3dhpqLocalDeviceRow) r).deviceId()
                        & 0xffffffffL));
        for (final DatabaseBackend.X3dhpqLocalDeviceRow row : localDevices) {
            final Device device = new Device();
            device.setDeviceId(row.deviceId());
            // added-at is the device's stable first-seen time (its DC creation
            // time); it is part of the signed input (§8.3) so it MUST be on the
            // wire (§8.4) and MUST NOT drift between republishes of the same list.
            device.setAddedAt(row.createdAt());
            // flags=1 means x3dhpq-capable per protocol spec
            device.setFlags(Integer.toString(row.flags()));

            final Cert cert = new Cert();
            cert.setContent(row.dc()); // dc() is the serialised DeviceCertificate
            device.setCert(cert);

            deviceList.addDevice(device);
        }
        return deviceList;
    }

    /**
     * Builds the Bundle Extension for the specified local device.
     * Matches dino-fork publish_bundle wire shape exactly.
     */
    public static Bundle buildBundle(
            final X3dhpqDao dao, final String accountUuid, final int deviceId) {

        // --- AIK ---
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                dao.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) {
            throw new IllegalStateException(
                    "x3dhpq: no AIK row for account " + accountUuid);
        }
        // aik_pub_marshal: uint16(1) | uint8(1) | 32 Ed25519 | 1952 ML-DSA = 1987 bytes
        final AccountIdentityPub aikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());

        // --- Local device: DC + DIK ---
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> deviceRows =
                dao.listX3dhpqLocalDevices(accountUuid);
        DatabaseBackend.X3dhpqLocalDeviceRow deviceRow = null;
        for (final DatabaseBackend.X3dhpqLocalDeviceRow r : deviceRows) {
            if (r.deviceId() == deviceId) {
                deviceRow = r;
                break;
            }
        }
        if (deviceRow == null) {
            throw new IllegalStateException(
                    "x3dhpq: no local device row for deviceId " + deviceId);
        }
        // dik_priv_marshal layout: privEd(32)|pubEd(32)|privX(32)|pubX(32)|privMLDSA(4032)|pubMLDSA(1952)
        final DeviceIdentityKey dik = DeviceIdentityKey.unmarshal(deviceRow.dikPriv());

        // --- SPK ---
        final DatabaseBackend.X3dhpqSignedPreKeyRow spkRow =
                dao.loadLatestX3dhpqSignedPreKey(accountUuid);
        if (spkRow == null) {
            throw new IllegalStateException(
                    "x3dhpq: no SPK row for account " + accountUuid);
        }

        // --- Build Bundle ---
        final Bundle bundle = new Bundle();

        final AikEd25519 aikEd = new AikEd25519();
        aikEd.setContent(aikPub.getPubEd25519());
        bundle.addExtension(aikEd);

        final AikMldsa aikMl = new AikMldsa();
        aikMl.setContent(aikPub.getPubMLDSA());
        bundle.addExtension(aikMl);

        final Dc dc = new Dc();
        dc.setContent(deviceRow.dc());
        bundle.addExtension(dc);

        final DikEd25519 dikEd = new DikEd25519();
        dikEd.setContent(dik.getPubEd25519());
        bundle.addExtension(dikEd);

        // ik = X25519 DH half of the device identity key (called dik-x25519 in dino)
        final Ik ik = new Ik();
        ik.setContent(dik.getPubX25519());
        bundle.addExtension(ik);

        final DikMldsa dikMl = new DikMldsa();
        dikMl.setContent(dik.getPubMLDSA());
        bundle.addExtension(dikMl);

        // SPK: id attr + <key> + <sig> (Ed25519 sig only; matches dino lines 162-165)
        final Spk spk = new Spk();
        spk.setId(spkRow.keyId());
        final SpkKey spkKey = new SpkKey();
        spkKey.setContent(spkRow.pubX25519());
        spk.addExtension(spkKey);
        final SpkSig spkSig = new SpkSig();
        spkSig.setContent(spkRow.sigEd25519()); // Ed25519 sig over SPK pub
        spk.addExtension(spkSig);
        bundle.addExtension(spk);

        // KEM pre-keys
        final Kemkeys kemkeys = new Kemkeys();
        final List<Integer> kemIds = dao.listX3dhpqKemPreKeyIds(accountUuid);
        for (final int kemId : kemIds) {
            final DatabaseBackend.X3dhpqKemPreKeyRow kemRow =
                    dao.loadX3dhpqKemPreKey(accountUuid, kemId);
            if (kemRow == null) continue;
            final Kemkey kemkey = new Kemkey();
            kemkey.setId(kemId);
            kemkey.setContent(kemRow.publicKey());
            kemkeys.addKemkey(kemkey);
        }
        bundle.addExtension(kemkeys);

        // OPKs (unused only)
        final Opks opks = new Opks();
        final List<Integer> opkIds = dao.listX3dhpqUnusedOneTimePreKeyIds(accountUuid);
        for (final int opkId : opkIds) {
            final DatabaseBackend.X3dhpqOneTimePreKeyRow opkRow =
                    dao.loadX3dhpqOneTimePreKey(accountUuid, opkId);
            if (opkRow == null) continue;
            final Opk opk = new Opk();
            opk.setId(opkId);
            opk.setContent(opkRow.pubX25519());
            opks.addOpk(opk);
        }
        bundle.addExtension(opks);

        return bundle;
    }
}
