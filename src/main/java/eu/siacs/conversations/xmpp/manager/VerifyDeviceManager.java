package eu.siacs.conversations.xmpp.manager;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.xmpp.XmppConnection;
import im.conversations.android.xmpp.model.x3dhpq.pair.PairHello;

/**
 * Bridges an inbound serverless pairing rendezvous {@code <pair-hello>} (XEP §10.1a) to the
 * pairing UI. A {@code <pair-hello>} reaches an existing primary device either via self-PEP
 * {@code +notify} (method B, published to the joining device's own PEP node) or as a directed
 * {@code <message>} (method A, sent after a QR scan). In both cases {@link #handlePairHello}
 * reads the new device's {@code full-jid} + {@code sid} and broadcasts
 * {@link #ACTION_X3DHPQ_PAIR_NEW_DEVICE} so the existing-device UI initiates the pairing FSM
 * (sends {@code PairingMsgPAKE1} toward that full JID).
 *
 * <p>This replaces the removed project-internal server {@code <verify-device>} fan-out: rendezvous
 * now runs entirely over standard PEP/PubSub and message routing.
 */
public class VerifyDeviceManager extends AbstractManager {

    /** Broadcast action fired when a pair-hello rendezvous arrives from a joining device. */
    public static final String ACTION_X3DHPQ_PAIR_NEW_DEVICE =
            "eu.siacs.conversations.X3DHPQ_PAIR_NEW_DEVICE";

    /** Intent extra: the bare JID of the local account (String). */
    public static final String EXTRA_ACCOUNT_JID = "account_jid";

    /** Intent extra: the full JID of the joining device that wants to pair (String). */
    public static final String EXTRA_NEW_RESOURCE = "new_resource";

    /** Intent extra: the uint32 device-id the new resource intends to claim (int). */
    public static final String EXTRA_DEVICE_ID = "device_id";

    /** Intent extra: the CPace session id carried by {@code <pair-hello>} (base64url, no padding). */
    public static final String EXTRA_SID = "sid";

    public VerifyDeviceManager(final Context context, final XmppConnection connection) {
        super(context, connection);
    }

    /**
     * Handles an inbound serverless rendezvous {@code <pair-hello>} (XEP §10.1a), arriving either
     * via self-PEP {@code +notify} (method B) or as a directed {@code <message>} (method A). Reads
     * the new device's {@code full-jid} and {@code sid} and broadcasts
     * {@link #ACTION_X3DHPQ_PAIR_NEW_DEVICE} so the existing-device pairing UI initiates the FSM
     * (i.e. sends {@code PairingMsgPAKE1} toward that full JID).
     *
     * <p>Ignores our own {@code pair-hello} (the publisher receives its own self-PEP notification):
     * only a resource whose full JID differs from ours acts as the existing primary.
     *
     * @param hello the parsed {@code <pair-hello>} element
     */
    public void handlePairHello(final PairHello hello) {
        if (hello == null) {
            Log.w(Config.LOGTAG, getAccount().getJid().asBareJid()
                    + ": handlePairHello called without <pair-hello> element");
            return;
        }
        final String fullJid = hello.getFullJid();
        final String sid = hello.getSid();
        final Long deviceId = hello.getDeviceId();

        if (fullJid == null || fullJid.isEmpty() || sid == null || sid.isEmpty()) {
            Log.w(Config.LOGTAG, getAccount().getJid().asBareJid()
                    + ": <pair-hello> missing full-jid or sid — dropping");
            return;
        }

        // Never act on our own pair-hello echoed back to us via self-PEP.
        if (fullJid.equals(getAccount().getJid().toString())) {
            Log.d(Config.LOGTAG, getAccount().getJid().asBareJid()
                    + ": ignoring our own pair-hello (full-jid=" + fullJid + ")");
            return;
        }

        Log.d(Config.LOGTAG, getAccount().getJid().asBareJid()
                + ": received pair-hello from full-jid=" + fullJid
                + " device-id=" + deviceId);

        final Intent intent = new Intent(ACTION_X3DHPQ_PAIR_NEW_DEVICE);
        intent.putExtra(EXTRA_ACCOUNT_JID, getAccount().getJid().asBareJid().toString());
        intent.putExtra(EXTRA_NEW_RESOURCE, fullJid);
        intent.putExtra(EXTRA_DEVICE_ID, deviceId != null ? deviceId.intValue() : 0);
        intent.putExtra(EXTRA_SID, sid);

        context.sendBroadcast(intent);
    }
}
