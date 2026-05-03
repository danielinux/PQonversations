// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class DeviceListSmokeTest {

    @Test
    public void serializeDeviceList() throws IOException {
        // Build a devicelist with one device and verify attributes survive serialisation.
        final DeviceList list = new DeviceList();
        list.setVersion("1");
        list.setIssuedAt("1234567890");

        final Device device = new Device();
        device.setDeviceId(42);
        device.setFlags("1");
        final Cert cert = new Cert();
        cert.setContent(new byte[]{0x00, 0x01, 0x02});
        device.setCert(cert);
        list.addDevice(device);

        Assert.assertEquals(1, list.getDevices().size());
        Assert.assertEquals(Integer.valueOf(42), list.getDevices().iterator().next().getDeviceId());

        final String xml = StreamElementWriter.asString(list);
        Assert.assertTrue(xml.contains("devicelist"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:devicelist:0"));
        Assert.assertTrue(xml.contains("version=\"1\""));
        Assert.assertTrue(xml.contains("issued-at=\"1234567890\""));
        Assert.assertTrue(xml.contains("id=\"42\""));
        Assert.assertTrue(xml.contains("flags=\"1\""));
        Assert.assertTrue(xml.contains("cert"));
    }
}
