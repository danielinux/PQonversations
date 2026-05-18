package eu.siacs.conversations.xmpp.manager;

import android.content.Context;
import android.content.Intent;
import android.util.Log;
import androidx.annotation.NonNull;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.xmpp.XmppConnection;
import im.conversations.android.xmpp.IqErrorException;
import im.conversations.android.xmpp.model.error.Condition;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.stanza.Message;
import im.conversations.android.xmpp.model.x3dhpq.pair.Peers;
import im.conversations.android.xmpp.model.x3dhpq.pair.VerifyDevice;
import java.util.function.BiConsumer;

/**
 * Manager for the project-internal {@code <verify-device>} flow defined in XEP §15.8.
 *
 * <p>Two responsibilities:
 * <ol>
 *   <li>Outbound — {@link #announceNewDevice} sends an IQ-set to the user's own bare JID asking
 *       the server to fan out a headline hint to all other authenticated resources.
 *   <li>Inbound — {@link #handleHeadlineMessage} is called by the message dispatch layer when a
 *       {@code <message type='headline'>} arrives whose direct child is
 *       {@code <verify-device xmlns='urn:xmppqr:x3dhpq:pair:0'>}. It broadcasts an
 *       {@link Intent} so that the pairing UI can react.
 * </ol>
 *
 * <!-- Activity wiring is in PairNewDeviceActivity (separate file) -->
 */
public class VerifyDeviceManager extends AbstractManager {

    /** Broadcast action fired when a verify-device headline arrives from a peer resource. */
    public static final String ACTION_X3DHPQ_PAIR_NEW_DEVICE =
            "eu.siacs.conversations.X3DHPQ_PAIR_NEW_DEVICE";

    /** Intent extra: the bare JID of the local account (String). */
    public static final String EXTRA_ACCOUNT_JID = "account_jid";

    /** Intent extra: the full JID of the newly-bound resource that wants to pair (String). */
    public static final String EXTRA_NEW_RESOURCE = "new_resource";

    /** Intent extra: the uint32 device-id the new resource intends to claim (int). */
    public static final String EXTRA_DEVICE_ID = "device_id";

    public VerifyDeviceManager(final Context context, final XmppConnection connection) {
        super(context, connection);
    }

    /**
     * Sends a {@code <verify-device>} IQ-set to the user's own bare JID and reports the result.
     *
     * <p>The IQ is built inline following the same logic as
     * {@code IqGenerator.generateX3dhpqVerifyDevice(deviceId)}: an IQ-set containing a
     * {@code <verify-device xmlns='urn:xmppqr:x3dhpq:pair:0' device-id='…' transport='message'/>}
     * child. No {@code to} attribute is set; the connection's send pipeline addresses the stanza
     * to the local bare JID by default (per §15.8).
     *
     * @param deviceId the uint32 device-id the new device intends to claim
     * @param callback receives {@code (peersCount, null)} on success, or {@code (0, throwable)}
     *     on {@code <not-acceptable/>} / other error or timeout
     */
    public void announceNewDevice(final int deviceId, final BiConsumer<Integer, Throwable> callback) {
        final Iq packet = new Iq(Iq.Type.SET);
        final VerifyDevice verify = packet.addExtension(new VerifyDevice());
        verify.setDeviceId(deviceId);
        verify.setTransport("message");

        Log.d(
                Config.LOGTAG,
                getAccount().getJid().asBareJid()
                        + ": sending verify-device IQ for device-id="
                        + deviceId);

        final var future = this.connection.sendIqPacket(packet);
        Futures.addCallback(
                future,
                new FutureCallback<>() {
                    @Override
                    public void onSuccess(final Iq result) {
                        final Peers peers = result.getExtension(Peers.class);
                        final int count = (peers != null && peers.getCount() != null)
                                ? peers.getCount()
                                : 0;
                        Log.d(
                                Config.LOGTAG,
                                getAccount().getJid().asBareJid()
                                        + ": verify-device succeeded, peers="
                                        + count);
                        callback.accept(count, null);
                    }

                    @Override
                    public void onFailure(@NonNull final Throwable throwable) {
                        final boolean notAcceptable =
                                throwable instanceof IqErrorException iqError
                                && iqError.getErrorCondition() instanceof Condition.NotAcceptable;
                        if (notAcceptable) {
                            Log.d(
                                    Config.LOGTAG,
                                    getAccount().getJid().asBareJid()
                                            + ": verify-device returned <not-acceptable/>"
                                            + " — no peer resources bound (first device)");
                        } else {
                            Log.w(
                                    Config.LOGTAG,
                                    getAccount().getJid().asBareJid()
                                            + ": verify-device failed",
                                    throwable);
                        }
                        callback.accept(0, throwable);
                    }
                },
                MoreExecutors.directExecutor());
    }

    /**
     * Handles an inbound {@code <message type='headline'>} that carries a
     * {@code <verify-device xmlns='urn:xmppqr:x3dhpq:pair:0'>} child.
     *
     * <p>Extracts {@code new-resource} and {@code device-id} from the element and broadcasts a
     * sticky {@link Intent} with action {@link #ACTION_X3DHPQ_PAIR_NEW_DEVICE} so that the
     * pairing UI can present the "pair with new device?" prompt.
     *
     * <p>The dispatch wiring (calling this method from {@code MessageParser} on headline messages)
     * is handled in a separate task and is NOT performed here.
     *
     * <!-- Activity wiring is in PairNewDeviceActivity (separate file) -->
     *
     * @param packet the inbound headline {@link Message} stanza
     */
    public void handleHeadlineMessage(final Message packet) {
        final VerifyDevice verifyDevice = packet.getExtension(VerifyDevice.class);
        if (verifyDevice == null) {
            Log.w(
                    Config.LOGTAG,
                    getAccount().getJid().asBareJid()
                            + ": handleHeadlineMessage called without <verify-device> child");
            return;
        }

        final String newResource = verifyDevice.getNewResource();
        final Integer deviceId = verifyDevice.getDeviceId();

        if (newResource == null || deviceId == null) {
            Log.w(
                    Config.LOGTAG,
                    getAccount().getJid().asBareJid()
                            + ": <verify-device> headline missing new-resource or device-id"
                            + " — dropping");
            return;
        }

        Log.d(
                Config.LOGTAG,
                getAccount().getJid().asBareJid()
                        + ": received verify-device headline from new-resource="
                        + newResource
                        + " device-id="
                        + deviceId);

        final Intent intent = new Intent(ACTION_X3DHPQ_PAIR_NEW_DEVICE);
        intent.putExtra(EXTRA_ACCOUNT_JID, getAccount().getJid().asBareJid().toString());
        intent.putExtra(EXTRA_NEW_RESOURCE, newResource);
        intent.putExtra(EXTRA_DEVICE_ID, deviceId.intValue());

        context.sendBroadcast(intent);
    }
}
