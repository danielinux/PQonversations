package eu.siacs.conversations.generator;

import eu.siacs.conversations.xml.Element;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.stanza.Iq;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

/**
 * Verifies that IqGenerator produces well-formed fetch IQs for x3dhpq nodes.
 * Uses Robolectric so android.os.Bundle (used by PublishOptions) is available.
 */
@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class IqGeneratorX3dhpqFetchTest {

    private static final Jid PEER = Jid.of("peer@example.org");

    private static IqGenerator generator() {
        return new IqGenerator(null);
    }

    @Test
    public void generateX3dhpqRequestDeviceList_typeIsGet() {
        final Iq iq = generator().generateX3dhpqRequestDeviceList(PEER);
        Assert.assertEquals("IQ type must be GET", Iq.Type.GET, iq.getType());
    }

    @Test
    public void generateX3dhpqRequestDeviceList_toIsSet() {
        final Iq iq = generator().generateX3dhpqRequestDeviceList(PEER);
        Assert.assertEquals("to must be the peer JID", PEER, iq.getTo());
    }

    @Test
    public void generateX3dhpqRequestDeviceList_hasPubsubChild() {
        final Iq iq = generator().generateX3dhpqRequestDeviceList(PEER);
        final Element pubsub = iq.findChild("pubsub", Namespace.PUB_SUB);
        Assert.assertNotNull("must have <pubsub xmlns=PUB_SUB> child", pubsub);
    }

    @Test
    public void generateX3dhpqRequestDeviceList_itemsNodeIsDevicelistNamespace() {
        final Iq iq = generator().generateX3dhpqRequestDeviceList(PEER);
        final Element items =
                iq.findChild("pubsub", Namespace.PUB_SUB).findChild("items");
        Assert.assertNotNull("must have <items> child", items);
        Assert.assertEquals(
                "items node must be X3DHPQ_DEVICELIST",
                Namespace.X3DHPQ_DEVICELIST,
                items.getAttribute("node"));
    }

    @Test
    public void generateX3dhpqRequestDeviceList_noItemChild() {
        // device-list fetch has no <item> filter; it fetches all (just the "current" item)
        final Iq iq = generator().generateX3dhpqRequestDeviceList(PEER);
        final Element items =
                iq.findChild("pubsub", Namespace.PUB_SUB).findChild("items");
        Assert.assertNull("devicelist fetch must not include an <item> filter", items.findChild("item"));
    }

    @Test
    public void generateX3dhpqRequestBundle_typeIsGet() {
        final Iq iq = generator().generateX3dhpqRequestBundle(PEER, 42);
        Assert.assertEquals("IQ type must be GET", Iq.Type.GET, iq.getType());
    }

    @Test
    public void generateX3dhpqRequestBundle_toIsSet() {
        final Iq iq = generator().generateX3dhpqRequestBundle(PEER, 42);
        Assert.assertEquals("to must be the peer JID", PEER, iq.getTo());
    }

    @Test
    public void generateX3dhpqRequestBundle_itemsNodeIsBundleNamespace() {
        final Iq iq = generator().generateX3dhpqRequestBundle(PEER, 42);
        final Element items =
                iq.findChild("pubsub", Namespace.PUB_SUB).findChild("items");
        Assert.assertNotNull("must have <items> child", items);
        Assert.assertEquals(
                "items node must be X3DHPQ_BUNDLE",
                Namespace.X3DHPQ_BUNDLE,
                items.getAttribute("node"));
    }

    @Test
    public void generateX3dhpqRequestBundle_itemIdIsDecimalDeviceId() {
        final Iq iq = generator().generateX3dhpqRequestBundle(PEER, 42);
        final Element item =
                iq.findChild("pubsub", Namespace.PUB_SUB)
                        .findChild("items")
                        .findChild("item");
        Assert.assertNotNull("must have <item id='42'/> child", item);
        Assert.assertEquals("item id must be '42'", "42", item.getAttribute("id"));
    }

    @Test
    public void generateX3dhpqRequestBundle_differentDeviceIdRoundTrips() {
        final Iq iq = generator().generateX3dhpqRequestBundle(PEER, 99999);
        final Element item =
                iq.findChild("pubsub", Namespace.PUB_SUB)
                        .findChild("items")
                        .findChild("item");
        Assert.assertEquals("item id must be '99999'", "99999", item.getAttribute("id"));
    }
}
