package eu.siacs.conversations.generator;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.crypto.axolotl.AxolotlService;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xml.Element;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.forms.Data;
import eu.siacs.conversations.xmpp.pep.PublishOptions;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.MldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Sig;
import im.conversations.android.xmpp.model.x3dhpq.pair.VerifyDevice;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

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

    public Iq retrieveDeviceIds(final Jid to) {
        final var packet = retrieve(AxolotlService.PEP_DEVICE_LIST, null);
        if (to != null) {
            packet.setTo(to);
        }
        return packet;
    }

    public Iq retrieveBundlesForDevice(final Jid to, final int deviceid) {
        final var packet = retrieve(AxolotlService.PEP_BUNDLES + ":" + deviceid, null);
        packet.setTo(to);
        return packet;
    }

    public Iq retrieveVerificationForDevice(final Jid to, final int deviceid) {
        final var packet = retrieve(AxolotlService.PEP_VERIFICATION + ":" + deviceid, null);
        packet.setTo(to);
        return packet;
    }

    public Iq publishDeviceIds(final Set<Integer> ids, final Bundle publishOptions) {
        final Element item = new Element("item");
        item.setAttribute("id", "current");
        final Element list = item.addChild("list", AxolotlService.PEP_PREFIX);
        for (Integer id : ids) {
            final Element device = new Element("device");
            device.setAttribute("id", id);
            list.addChild(device);
        }
        return publish(AxolotlService.PEP_DEVICE_LIST, item, publishOptions);
    }

    public Iq publishBundles(
            final SignedPreKeyRecord signedPreKeyRecord,
            final IdentityKey identityKey,
            final Set<PreKeyRecord> preKeyRecords,
            final int deviceId,
            Bundle publishOptions) {
        final Element item = new Element("item");
        item.setAttribute("id", "current");
        final Element bundle = item.addChild("bundle", AxolotlService.PEP_PREFIX);
        final Element signedPreKeyPublic = bundle.addChild("signedPreKeyPublic");
        signedPreKeyPublic.setAttribute("signedPreKeyId", signedPreKeyRecord.getId());
        ECPublicKey publicKey = signedPreKeyRecord.getKeyPair().getPublicKey();
        signedPreKeyPublic.setContent(Base64.encodeToString(publicKey.serialize(), Base64.NO_WRAP));
        final Element signedPreKeySignature = bundle.addChild("signedPreKeySignature");
        signedPreKeySignature.setContent(
                Base64.encodeToString(signedPreKeyRecord.getSignature(), Base64.NO_WRAP));
        final Element identityKeyElement = bundle.addChild("identityKey");
        identityKeyElement.setContent(
                Base64.encodeToString(identityKey.serialize(), Base64.NO_WRAP));

        final Element prekeys = bundle.addChild("prekeys", AxolotlService.PEP_PREFIX);
        for (PreKeyRecord preKeyRecord : preKeyRecords) {
            final Element prekey = prekeys.addChild("preKeyPublic");
            prekey.setAttribute("preKeyId", preKeyRecord.getId());
            prekey.setContent(
                    Base64.encodeToString(
                            preKeyRecord.getKeyPair().getPublicKey().serialize(), Base64.NO_WRAP));
        }

        return publish(AxolotlService.PEP_BUNDLES + ":" + deviceId, item, publishOptions);
    }

    public Iq publishVerification(
            byte[] signature, X509Certificate[] certificates, final int deviceId) {
        final Element item = new Element("item");
        item.setAttribute("id", "current");
        final Element verification = item.addChild("verification", AxolotlService.PEP_PREFIX);
        final Element chain = verification.addChild("chain");
        for (int i = 0; i < certificates.length; ++i) {
            try {
                Element certificate = chain.addChild("certificate");
                certificate.setContent(
                        Base64.encodeToString(certificates[i].getEncoded(), Base64.NO_WRAP));
                certificate.setAttribute("index", i);
            } catch (CertificateEncodingException e) {
                Log.d(Config.LOGTAG, "could not encode certificate");
            }
        }
        verification
                .addChild("signature")
                .setContent(Base64.encodeToString(signature, Base64.NO_WRAP));
        return publish(AxolotlService.PEP_VERIFICATION + ":" + deviceId, item);
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
        return generateX3dhpqPublishDeviceList(list, itemId, null, null);
    }

    /**
     * Publishes the signed x3dhpq device list (§8.4). When {@code sigEd25519} and
     * {@code sigMldsa} are non-null they are emitted as {@code <sig>} and
     * {@code <mldsa-sig>} siblings of {@code <devicelist>} inside the item, per the
     * §8.4 example. Passing null signatures publishes an unsigned (legacy) list.
     */
    public Iq generateX3dhpqPublishDeviceList(
            final DeviceList list,
            final String itemId,
            final byte[] sigEd25519,
            final byte[] sigMldsa) {
        final Element item = new Element("item");
        item.setAttribute("id", itemId);
        item.addChild(list); // DeviceList extends Element
        if (sigEd25519 != null && sigMldsa != null) {
            final Sig sig = new Sig();
            sig.setContent(sigEd25519);
            item.addChild(sig);
            final MldsaSig mldsaSig = new MldsaSig();
            mldsaSig.setContent(sigMldsa);
            item.addChild(mldsaSig);
        }
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

    /**
     * Asks the local server to fan out a verify-device hint to the user's other
     * authenticated resources. Used by a freshly-bound device with no DC yet
     * to discover existing primary resources for pairing. See XEP §15.8.
     * Sent to the bare JID; server reply contains <peers count='N'/>.
     */
    public Iq generateX3dhpqVerifyDevice(final int deviceId) {
        final var packet = new Iq(Iq.Type.SET);
        final VerifyDevice verify = packet.addExtension(new VerifyDevice());
        verify.setDeviceId(deviceId);
        verify.setTransport("message");
        return packet;
    }
}
