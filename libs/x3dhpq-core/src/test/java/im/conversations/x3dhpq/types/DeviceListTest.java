// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

class DeviceListTest {

    private DeviceCertificate makeCert(long deviceId) {
        byte[] ed  = new byte[32]; Arrays.fill(ed, (byte) 0x01);
        byte[] x   = new byte[32]; Arrays.fill(x,  (byte) 0x02);
        byte[] sig = new byte[64]; Arrays.fill(sig, (byte) 0xCC);
        return new DeviceCertificate(1, deviceId, ed, x, null, 1714000000L, (byte) 0, sig, sig);
    }

    private DeviceList makeDeviceList(long listVersion, int numDevices) {
        List<DeviceList.DeviceListEntry> entries = new ArrayList<>();
        for (int i = 0; i < numDevices; i++) {
            entries.add(new DeviceList.DeviceListEntry(
                    (long) (100 + i), 1714000000L + i, (byte) 0, makeCert(100 + i)));
        }
        byte[] sigEd    = new byte[64];   Arrays.fill(sigEd, (byte) 0xDD);
        byte[] sigMLDSA = new byte[3293]; Arrays.fill(sigMLDSA, (byte) 0xEE);
        return new DeviceList(listVersion, 1714500000L, entries, sigEd, sigMLDSA);
    }

    @Test
    void testRoundTripSingleDevice() {
        DeviceList orig = makeDeviceList(1L, 1);
        DeviceList decoded = DeviceList.unmarshal(orig.marshal());

        assertEquals(orig.getListVersion(), decoded.getListVersion());
        assertEquals(orig.getIssuedAt(), decoded.getIssuedAt());
        assertEquals(orig.getDevices().size(), decoded.getDevices().size());
        assertArrayEquals(orig.getSigEd25519(), decoded.getSigEd25519());
        assertArrayEquals(orig.getSigMLDSA(), decoded.getSigMLDSA());
    }

    @Test
    void testRoundTripTwoDevices() {
        DeviceList orig = makeDeviceList(2L, 2);
        DeviceList decoded = DeviceList.unmarshal(orig.marshal());
        assertEquals(2, decoded.getDevices().size());
        assertEquals(2L, decoded.getListVersion());
    }

    @Test
    void testVersionPreserved() {
        // marshal preserves listVersion values 1 and 2
        DeviceList dl1 = makeDeviceList(1L, 1);
        DeviceList dl2 = makeDeviceList(2L, 1);

        assertEquals(1L, DeviceList.unmarshal(dl1.marshal()).getListVersion());
        assertEquals(2L, DeviceList.unmarshal(dl2.marshal()).getListVersion());
    }

    @Test
    void testVersionMustIncreaseIsCallerContract() {
        // The type itself does not enforce monotonicity — callers do.
        // Verify that marshal still preserves the value (even if version goes backward,
        // the type serialises faithfully — the caller should have rejected it first).
        DeviceList old = makeDeviceList(5L, 1);
        DeviceList newer = makeDeviceList(6L, 1);

        assertEquals(5L, DeviceList.unmarshal(old.marshal()).getListVersion());
        assertEquals(6L, DeviceList.unmarshal(newer.marshal()).getListVersion());
        // This documents the contract: enforcement is the caller's job.
        assertTrue(newer.getListVersion() > old.getListVersion());
    }

    @Test
    void testPrefixLength() {
        assertEquals(21, DeviceList.DEVICE_LIST_PREFIX.length);
    }

    @Test
    void testEmptyDeviceList() {
        DeviceList dl = makeDeviceList(1L, 0);
        DeviceList decoded = DeviceList.unmarshal(dl.marshal());
        assertEquals(0, decoded.getDevices().size());
    }

    @Test
    void testDeviceFieldsPreserved() {
        DeviceList orig = makeDeviceList(3L, 2);
        DeviceList decoded = DeviceList.unmarshal(orig.marshal());
        for (int i = 0; i < orig.getDevices().size(); i++) {
            DeviceList.DeviceListEntry oe = orig.getDevices().get(i);
            DeviceList.DeviceListEntry de = decoded.getDevices().get(i);
            assertEquals(oe.getDeviceId(), de.getDeviceId());
            assertEquals(oe.getAddedAt(),  de.getAddedAt());
            assertEquals(oe.getFlags(),    de.getFlags());
        }
    }

    @Test
    void testUnmarshalBadMarker() {
        byte[] raw = new byte[30];
        raw[0] = 0x00; raw[1] = 0x02; // wrong marker
        assertThrows(IllegalArgumentException.class, () -> DeviceList.unmarshal(raw));
    }

    @Test
    void testUnmarshalTooShort() {
        assertThrows(IllegalArgumentException.class, () -> DeviceList.unmarshal(new byte[3]));
    }
}
