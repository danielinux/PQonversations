// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * x3dhpq-xep-draft.md §11.8: sealed device-state tracker — inner plaintext payload.
 *
 * <p>Pins the EXACT byte layout {@code
 * eu.siacs.conversations.crypto.x3dhpq.X3dhpqService#buildDeviceTrackerPlaintextPayload}
 * (Android app module, not reachable from this plain-JVM {@code x3dhpq-core} test target)
 * produces:
 *
 * <pre>
 *   DEVTRACKER_PAYLOAD_DOMAIN ("X3DHPQ-DevTracker-Payload-v1\0")
 *   | u32 snapshot_len | &lt;§11.7 Snapshot payload&gt;   (DeviceAuditEntryV2.buildSnapshotPayload)
 *   | u32 head_count | { u32 head_len | head bytes }*
 *   | u8 has_aik_priv (0/1)
 * </pre>
 *
 * <p>This test reconstructs that exact framing here (rather than invoking the private,
 * Android-app-module method directly) using the shared, already cross-language-pinned
 * {@link DeviceAuditEntryV2#buildSnapshotPayload} codec for the Snapshot portion, so the
 * two halves that matter for interop — the Snapshot codec and the outer domain-separator/
 * framing bytes — are both exercised. The resulting hex is byte-for-byte IDENTICAL to the
 * vector asserted in dino.im's {@code plugins/x3dhpq/tests/device_tracker.vala}
 * ({@code DeviceTracker/payload_canonical_vector}) — that shared hex is the cross-client
 * contract this test and its Vala counterpart both lock down.
 *
 * <p>Note: the spec prose (x3dhpq-xep-draft.md §11.8) abbreviates the inner-payload domain
 * separator as {@code "X3DHPQ-DevTracker\0"}; the shipping engine actually signs/frames
 * with {@code "X3DHPQ-DevTracker-Payload-v1\0"} (see
 * {@code X3dhpqService.DEVTRACKER_PAYLOAD_DOMAIN}) — this is the literal byte sequence both
 * clients must agree on, so it is what this vector uses.
 */
class DeviceTrackerPayloadVectorTest {

    private static final byte[] DEVTRACKER_PAYLOAD_DOMAIN =
            "X3DHPQ-DevTracker-Payload-v1\0".getBytes(StandardCharsets.UTF_8);

    private static void writeU32(ByteArrayOutputStream out, int v) {
        out.write((v >>> 24) & 0xff);
        out.write((v >>> 16) & 0xff);
        out.write((v >>> 8) & 0xff);
        out.write(v & 0xff);
    }

    // Mirrors X3dhpqService#buildDeviceTrackerPlaintextPayload's framing exactly.
    private static byte[] buildPayload(byte[] snapshot, List<byte[]> heads, byte[] aikBlobOrNull) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(DEVTRACKER_PAYLOAD_DOMAIN, 0, DEVTRACKER_PAYLOAD_DOMAIN.length);
        writeU32(out, snapshot.length);
        out.write(snapshot, 0, snapshot.length);
        writeU32(out, heads.size());
        for (final byte[] h : heads) {
            writeU32(out, h.length);
            out.write(h, 0, h.length);
        }
        if (aikBlobOrNull != null) {
            out.write(1);
            writeU32(out, aikBlobOrNull.length);
            out.write(aikBlobOrNull, 0, aikBlobOrNull.length);
        } else {
            out.write(0);
        }
        return out.toByteArray();
    }

    // Shared cross-client vector: owner_aik_fp = bytes 0x00..0x13 (20 bytes), epoch=0,
    // devices=[(id=1, cert=DEADBEEF), (id=2, cert=<empty>)], one 32-byte head of 0x01,
    // no embedded AIK_priv (the has_aik_priv=0 case).
    private static final String CANONICAL_VECTOR_HEX =
            "5833444850512d446576547261636b65722d5061796c6f61642d763100"
          + "00000034"
          + "000102030405060708090a0b0c0d0e0f10111213"
          + "0000000000000000"
          + "00000002"
          + "0000000100000004deadbeef"
          + "0000000200000000"
          + "00000001"
          + "000000200101010101010101010101010101010101010101010101010101010101010101"
          + "00";

    @Test
    void devTrackerPayloadCanonicalVector() {
        final byte[] ownerFp = new byte[20];
        for (int i = 0; i < 20; i++) ownerFp[i] = (byte) i;

        final List<DeviceAuditEntryV2.SnapshotDevice> devices = new ArrayList<>();
        devices.add(new DeviceAuditEntryV2.SnapshotDevice(1L, new byte[] {
                (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef }));
        devices.add(new DeviceAuditEntryV2.SnapshotDevice(2L, new byte[0]));
        final byte[] snapshot = DeviceAuditEntryV2.buildSnapshotPayload(ownerFp, 0L, devices);

        final byte[] head = new byte[32];
        for (int i = 0; i < 32; i++) head[i] = 1;
        final List<byte[]> heads = new ArrayList<>();
        heads.add(head);

        final byte[] payload = buildPayload(snapshot, heads, null);
        assertEquals(CANONICAL_VECTOR_HEX, DeviceAuditEntryV2.hex(payload));

        // round-trip the Snapshot portion through the real parser too.
        final DeviceAuditEntryV2.Snapshot parsed = DeviceAuditEntryV2.parseSnapshot(snapshot);
        assertNotNull(parsed);
        assertArrayEquals(ownerFp, parsed.ownerAikFp);
        assertEquals(0L, parsed.epoch);
        assertEquals(2, parsed.devices.size());
        assertEquals(1L, parsed.devices.get(0).deviceId);
        assertArrayEquals(devices.get(0).certBytes, parsed.devices.get(0).certBytes);
        assertEquals(2L, parsed.devices.get(1).deviceId);
        assertEquals(0, parsed.devices.get(1).certBytes.length);
    }
}
