package eu.siacs.conversations.generator;

import android.os.Bundle;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xml.Element;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.forms.Data;
import eu.siacs.conversations.xmpp.pep.PublishOptions;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;

public class IqGenerator extends AbstractGenerator {

    public IqGenerator(final XmppConnectionService service) {
        super(service);
    }

    protected Iq publish(final String node, final Element item, final Bundle options) {
        final var packet = new Iq(Iq.Type.SET);
        final Element pubsub = packet.addChild("pubsub", Namespace.PUB_SUB);
        final Element publish = pubsub.addChild("publish");
        publish.setAttribute("node", node);
        publish.addChild(item);
        if (options != null) {
            final Element publishOptions = pubsub.addChild("publish-options");
            publishOptions.addChild(Data.create(Namespace.PUB_SUB_PUBLISH_OPTIONS, options));
        }
        return packet;
    }

    protected Iq publish(final String node, final Element item) {
        return publish(node, item, null);
    }

    private Iq retrieve(String node, Element item) {
        final var packet = new Iq(Iq.Type.GET);
        final Element pubsub = packet.addChild("pubsub", Namespace.PUB_SUB);
        final Element items = pubsub.addChild("items");
        items.setAttribute("node", node);
        if (item != null) {
            items.addChild(item);
        }
        return packet;
    }

    /**
     * Builds a standard XEP-0060 subscribe IQ for the given node and subscriber JID.
     */
    public Iq generatePubSubSubscription(final Jid to, final String node, final Jid subscriberJid) {
        final var packet = new Iq(Iq.Type.SET);
        packet.setTo(to);
        final Element pubsub = packet.addChild("pubsub", Namespace.PUB_SUB);
        pubsub.addChild("subscribe")
                .setAttribute("node", node)
                .setAttribute("jid", subscriberJid.toString());
        return packet;
    }

    public Iq requestPubsubConfiguration(Jid jid, String node) {
        return pubsubConfiguration(jid, node, null);
    }

    public Iq publishPubsubConfiguration(Jid jid, String node, Data data) {
        return pubsubConfiguration(jid, node, data);
    }

    private Iq pubsubConfiguration(Jid jid, String node, Data data) {
        final Iq packet = new Iq(data == null ? Iq.Type.GET : Iq.Type.SET);
        packet.setTo(jid);
        Element pubsub = packet.addChild("pubsub", "http://jabber.org/protocol/pubsub#owner");
        Element configure = pubsub.addChild("configure").setAttribute("node", node);
        if (data != null) {
            configure.addChild(data);
        }
        return packet;
    }

    /**
     * Fetches the x3dhpq devicelist from a peer's PEP node.
     */
    public Iq generateX3dhpqRequestDeviceList(final Jid peerJid) {
        final var packet = retrieve(Namespace.X3DHPQ_DEVICELIST, null);
        packet.setTo(peerJid);
        return packet;
    }

    /**
     * Fetches a specific device's bundle from a peer's PEP node.
     */
    public Iq generateX3dhpqRequestBundle(final Jid peerJid, final int deviceId) {
        final Element itemFilter = new Element("item");
        itemFilter.setAttribute("id", Integer.toString(deviceId));
        final var packet = retrieve(Namespace.X3DHPQ_BUNDLE, itemFilter);
        packet.setTo(peerJid);
        return packet;
    }

    /**
     * Publishes the x3dhpq device list to PEP node urn:xmppqr:x3dhpq:devicelist:0.
     * Item id is always "current"; max_items=1 since only the latest snapshot matters.
     */
    public Iq generateX3dhpqPublishDeviceList(
            final DeviceList list, final String itemId) {
        final Element item = new Element("item");
        item.setAttribute("id", itemId);
        // The <sig>/<mldsa-sig> are carried as the last children of <devicelist>
        // itself (added by the caller) so they survive the PEP +notify path where
        // a receiver is handed only the <devicelist> element.
        item.addChild(list); // DeviceList extends Element
        final Bundle options = PublishOptions.openAccess();
        options.putString("pubsub#persist_items", "true");
        options.putString("pubsub#max_items", "1");
        return publish(Namespace.X3DHPQ_DEVICELIST, item, options);
    }

    /**
     * Publishes the x3dhpq bundle to PEP node urn:xmppqr:x3dhpq:bundle:0.
     * Item id is the decimal device-id.
     */
    public Iq generateX3dhpqPublishBundle(
            final im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle bundle,
            final int deviceId) {
        final Element item = new Element("item");
        item.setAttribute("id", Integer.toString(deviceId));
        item.addChild(bundle); // Bundle extends Element
        final Bundle options = PublishOptions.openAccess();
        options.putString("pubsub#persist_items", "true");
        options.putString("pubsub#max_items", "10"); // headroom for re-publishes
        return publish(Namespace.X3DHPQ_BUNDLE, item, options);
    }
}
