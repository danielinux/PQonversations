package eu.siacs.conversations.generator;

import eu.siacs.conversations.xml.Element;
import eu.siacs.conversations.xml.Namespace;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

/**
 * Verifies that IqGenerator produces well-formed publish IQs for x3dhpq nodes.
 * Uses Robolectric so android.os.Bundle (used by PublishOptions) is available.
 */
@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class IqGeneratorX3dhpqTest {

    /** Construct IqGenerator with a null service; the two publish methods need nothing from it. */
    private static IqGenerator generator() {
        return new IqGenerator(null);
    }

    @Test
    public void generateX3dhpqPublishDeviceList_typeIsSet() {
        final DeviceList list = buildMinimalDeviceList();
        final Iq iq = generator().generateX3dhpqPublishDeviceList(list, "current");
        Assert.assertEquals("IQ type must be SET", Iq.Type.SET, iq.getType());
    }

    @Test
    public void generateX3dhpqPublishDeviceList_hasCorrectNode() {
        final DeviceList list = buildMinimalDeviceList();
        final Iq iq = generator().generateX3dhpqPublishDeviceList(list, "current");

        final Element pubsub = iq.findChild("pubsub", Namespace.PUB_SUB);
        Assert.assertNotNull("must have <pubsub> child", pubsub);

        final Element publish = pubsub.findChild("publish");
        Assert.assertNotNull("must have <publish> child", publish);
        Assert.assertEquals(
                "publish node must be X3DHPQ_DEVICELIST",
                Namespace.X3DHPQ_DEVICELIST,
                publish.getAttribute("node"));
    }

    @Test
    public void generateX3dhpqPublishDeviceList_itemIdIsCurrent() {
        final DeviceList list = buildMinimalDeviceList();
        final Iq iq = generator().generateX3dhpqPublishDeviceList(list, "current");

        final Element item =
                iq.findChild("pubsub", Namespace.PUB_SUB)
                        .findChild("publish")
                        .findChild("item");
        Assert.assertNotNull("must have <item> child", item);
        Assert.assertEquals("item id must be 'current'", "current", item.getAttribute("id"));
    }

    @Test
    public void generateX3dhpqPublishDeviceList_hasPublishOptions() {
        final DeviceList list = buildMinimalDeviceList();
        final Iq iq = generator().generateX3dhpqPublishDeviceList(list, "current");

        final Element pubsub = iq.findChild("pubsub", Namespace.PUB_SUB);
        Assert.assertNotNull(
                "must have <publish-options>", pubsub.findChild("publish-options"));
    }

    @Test
    public void generateX3dhpqPublishBundle_typeIsSet() {
        final Bundle bundle = buildMinimalBundle();
        final Iq iq = generator().generateX3dhpqPublishBundle(bundle, 99999);
        Assert.assertEquals("IQ type must be SET", Iq.Type.SET, iq.getType());
    }

    @Test
    public void generateX3dhpqPublishBundle_hasCorrectNode() {
        final Bundle bundle = buildMinimalBundle();
        final Iq iq = generator().generateX3dhpqPublishBundle(bundle, 99999);

        final Element publish =
                iq.findChild("pubsub", Namespace.PUB_SUB).findChild("publish");
        Assert.assertNotNull("must have <publish> child", publish);
        Assert.assertEquals(
                "publish node must be X3DHPQ_BUNDLE",
                Namespace.X3DHPQ_BUNDLE,
                publish.getAttribute("node"));
    }

    @Test
    public void generateX3dhpqPublishBundle_itemIdIsDecimalDeviceId() {
        final int deviceId = 99999;
        final Bundle bundle = buildMinimalBundle();
        final Iq iq = generator().generateX3dhpqPublishBundle(bundle, deviceId);

        final Element item =
                iq.findChild("pubsub", Namespace.PUB_SUB)
                        .findChild("publish")
                        .findChild("item");
        Assert.assertNotNull("must have <item> child", item);
        Assert.assertEquals(
                "item id must be decimal device-id",
                Integer.toString(deviceId),
                item.getAttribute("id"));
    }

    @Test
    public void generateX3dhpqPublishBundle_hasPublishOptions() {
        final Bundle bundle = buildMinimalBundle();
        final Iq iq = generator().generateX3dhpqPublishBundle(bundle, 1);

        final Element pubsub = iq.findChild("pubsub", Namespace.PUB_SUB);
        Assert.assertNotNull(
                "must have <publish-options>", pubsub.findChild("publish-options"));
    }

    // --- helpers ---

    private static DeviceList buildMinimalDeviceList() {
        final DeviceList list = new DeviceList();
        list.setVersion("1");
        list.setIssuedAt("1000000");
        final Device device = new Device();
        device.setDeviceId(42);
        device.setFlags("1");
        final Cert cert = new Cert();
        cert.setContent(new byte[]{0x01, 0x02});
        device.setCert(cert);
        list.addDevice(device);
        return list;
    }

    private static Bundle buildMinimalBundle() {
        final Bundle bundle = new Bundle();
        final AikEd25519 aik = new AikEd25519();
        aik.setContent(new byte[32]); // 32 zero bytes stand-in
        bundle.addExtension(aik);
        return bundle;
    }
}
