// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Device list issued by an account identity, covering all devices and their certificates.
 *
 * SignedPart wire layout (mirrors Go devicelist.go SignedPart):
 *   "X3DHPQ-DeviceList-v1\x00" (21) | uint64 listVersion | int64 issuedAt
 *   | for each device: uint32 deviceId | int64 addedAt | uint8 flags | uint32 certLen | <cert.marshal()>
 *   (NO num_devices in the SignedPart — each device is self-delimiting via certLen; §8.3)
 *
 * marshal() wire layout (no signing prefix — version marker replaces it):
 *   uint16(1) | uint64 listVersion | int64 issuedAt | uint16 numDevices
 *   | per-device records (same as signedPart)
 *   | uint16 sigEdLen | sigEd | uint16 sigMLDSALen | sigMLDSA
 *
 * listVersion must strictly increase; callers enforce monotonicity before issuing.
 */
public final class DeviceList {

    // Signed-part prefix: "X3DHPQ-DeviceList-v1\x00" = 21 bytes
    static final byte[] DEVICE_LIST_PREFIX = {
        'X','3','D','H','P','Q','-','D','e','v','i','c','e','L','i','s','t','-','v','1',0x00
    };

    /**
     * One entry in the device list.
     */
    public static final class DeviceListEntry {
        final long deviceId;   // uint32 on wire
        final long addedAt;    // int64
        final byte flags;      // uint8
        final DeviceCertificate cert;
        // Verbatim base64-decoded <cert> bytes exactly as received on the wire, or
        // null when the entry was built locally (publish path). When present, these
        // MUST be fed into the SignedPart instead of cert.marshal() so an inbound
        // devicelist verifies over the issuer's exact bytes (x3dhpq §8.4).
        final byte[] rawCert;

        public DeviceListEntry(long deviceId, long addedAt, byte flags, DeviceCertificate cert) {
            this(deviceId, addedAt, flags, cert, null);
        }

        public DeviceListEntry(
                long deviceId, long addedAt, byte flags, DeviceCertificate cert, byte[] rawCert) {
            if (cert == null) throw new IllegalArgumentException("cert must not be null");
            this.deviceId = deviceId;
            this.addedAt  = addedAt;
            this.flags    = flags;
            this.cert     = cert;
            this.rawCert  = rawCert != null ? Arrays.copyOf(rawCert, rawCert.length) : null;
        }

        public long getDeviceId()       { return deviceId; }
        public long getAddedAt()        { return addedAt; }
        public byte getFlags()          { return flags; }
        public DeviceCertificate getCert() { return cert; }
        /** Verbatim wire cert bytes for verify-side SignedPart reconstruction, or null. */
        public byte[] getRawCert()      { return rawCert != null ? Arrays.copyOf(rawCert, rawCert.length) : null; }
    }

    final long listVersion;  // uint64 — must strictly increase
    final long issuedAt;     // int64
    final List<DeviceListEntry> devices;
    final byte[] sigEd25519;
    final byte[] sigMLDSA;

    public DeviceList(
            long listVersion,
            long issuedAt,
            List<DeviceListEntry> devices,
            byte[] sigEd25519,
            byte[] sigMLDSA) {
        this.listVersion = listVersion;
        this.issuedAt    = issuedAt;
        this.devices     = devices != null
                ? Collections.unmodifiableList(new ArrayList<>(devices))
                : Collections.emptyList();
        this.sigEd25519  = sigEd25519 != null ? Arrays.copyOf(sigEd25519, sigEd25519.length) : new byte[0];
        this.sigMLDSA    = sigMLDSA   != null ? Arrays.copyOf(sigMLDSA,   sigMLDSA.length)   : new byte[0];
    }

    public long getListVersion()          { return listVersion; }
    public long getIssuedAt()             { return issuedAt; }
    public List<DeviceListEntry> getDevices() { return devices; }
    public byte[] getSigEd25519()         { return Arrays.copyOf(sigEd25519, sigEd25519.length); }
    public byte[] getSigMLDSA()           { return Arrays.copyOf(sigMLDSA, sigMLDSA.length); }

    /**
     * Signed portion (includes prefix; excludes signatures).
     *
     * <p>Per spec §8.3: the SignedPart is {@code "X3DHPQ-DeviceList-v1\0" || uint64 version ||
     * int64 issued_at || (per-device …)} with NO version_marker and — crucially — NO num_devices
     * count field (each device is self-delimiting via its cert_len). Including num_devices here
     * (as this once did) made the signed bytes differ from Dino/Go by 2 bytes, so cross-client
     * devicelist signature verification always failed (rc=-229) and multi-device never worked.
     */
    public byte[] signedPart() {
        // compute per-device cert marshals up front to get sizes
        byte[][] certMarshals = new byte[devices.size()][];
        int totalDeviceBytes = 0;
        for (int i = 0; i < devices.size(); i++) {
            certMarshals[i] = devices.get(i).cert.marshal();
            totalDeviceBytes += 4 + 8 + 1 + 4 + certMarshals[i].length;
        }
        int size = DEVICE_LIST_PREFIX.length + 8 + 8 + totalDeviceBytes;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(DEVICE_LIST_PREFIX);
        buf.putLong(listVersion);
        buf.putLong(issuedAt);
        for (int i = 0; i < devices.size(); i++) {
            DeviceListEntry e = devices.get(i);
            buf.putInt((int) (e.deviceId & 0xffffffffL));
            buf.putLong(e.addedAt);
            buf.put(e.flags);
            buf.putInt(certMarshals[i].length);
            buf.put(certMarshals[i]);
        }
        return buf.array();
    }

    /** Full wire encoding. Go's Marshal() omits the prefix and instead writes uint16(1) as version marker. */
    public byte[] marshal() {
        byte[][] certMarshals = new byte[devices.size()][];
        int totalDeviceBytes = 0;
        for (int i = 0; i < devices.size(); i++) {
            certMarshals[i] = devices.get(i).cert.marshal();
            totalDeviceBytes += 4 + 8 + 1 + 4 + certMarshals[i].length;
        }
        int size = 2 + 8 + 8 + 2 + totalDeviceBytes + 2 + sigEd25519.length + 2 + sigMLDSA.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) 1); // version marker
        buf.putLong(listVersion);
        buf.putLong(issuedAt);
        buf.putShort((short) (devices.size() & 0xffff));
        for (int i = 0; i < devices.size(); i++) {
            DeviceListEntry e = devices.get(i);
            buf.putInt((int) (e.deviceId & 0xffffffffL));
            buf.putLong(e.addedAt);
            buf.put(e.flags);
            buf.putInt(certMarshals[i].length);
            buf.put(certMarshals[i]);
        }
        buf.putShort((short) (sigEd25519.length & 0xffff));
        buf.put(sigEd25519);
        buf.putShort((short) (sigMLDSA.length & 0xffff));
        buf.put(sigMLDSA);
        return buf.array();
    }

    public static DeviceList unmarshal(byte[] raw) {
        if (raw == null || raw.length < 2 + 8 + 8 + 2) {
            throw new IllegalArgumentException("DeviceList too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        int marker = buf.getShort() & 0xffff;
        if (marker != 1) throw new IllegalArgumentException("DeviceList: bad version marker " + marker);

        long listVersion = buf.getLong();
        long issuedAt    = buf.getLong();
        int numDevices   = buf.getShort() & 0xffff;

        List<DeviceListEntry> entries = new ArrayList<>(numDevices);
        for (int i = 0; i < numDevices; i++) {
            if (buf.remaining() < 4 + 8 + 1 + 4) {
                throw new IllegalArgumentException("DeviceList: truncated at device " + i);
            }
            long deviceId = buf.getInt() & 0xffffffffL;
            long addedAt  = buf.getLong();
            byte flags    = buf.get();
            int certLen   = buf.getInt();
            if (buf.remaining() < certLen) {
                throw new IllegalArgumentException("DeviceList: cert truncated at device " + i);
            }
            byte[] certBytes = new byte[certLen];
            buf.get(certBytes);
            DeviceCertificate cert = DeviceCertificate.unmarshal(certBytes);
            entries.add(new DeviceListEntry(deviceId, addedAt, flags, cert));
        }

        byte[] sigEd   = readField(buf);
        byte[] sigMLDSA = readField(buf);

        return new DeviceList(listVersion, issuedAt, entries, sigEd, sigMLDSA);
    }

    private static byte[] readField(ByteBuffer buf) {
        if (buf.remaining() < 2) throw new IllegalArgumentException("DeviceList: truncated at length");
        int len = buf.getShort() & 0xffff;
        if (buf.remaining() < len) throw new IllegalArgumentException("DeviceList: truncated at field");
        if (len == 0) return new byte[0];
        byte[] v = new byte[len];
        buf.get(v);
        return v;
    }
}
