package im.conversations.android.xmpp.processor;

import static eu.siacs.conversations.utils.Random.SECURE_RANDOM;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.util.Log;
import androidx.core.app.NotificationCompat;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.R;
import eu.siacs.conversations.crypto.x3dhpq.LocalKeyBootstrap;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.http.ServiceOutageStatus;
import eu.siacs.conversations.services.NotificationService;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.ui.PairToExistingActivity;
import eu.siacs.conversations.xmpp.XmppConnection;
import eu.siacs.conversations.xmpp.manager.ClientStateIndicationManager;
import eu.siacs.conversations.xmpp.manager.JingleManager;
import eu.siacs.conversations.xmpp.manager.MultiUserChatManager;
import eu.siacs.conversations.xmpp.manager.VerifyDeviceManager;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class AccountStateProcessor extends XmppConnection.Delegate
        implements Consumer<Account.State> {

    private final XmppConnectionService service;

    public AccountStateProcessor(final XmppConnectionService service, XmppConnection connection) {
        super(service.getApplicationContext(), connection);
        this.service = service;
    }

    @Override
    public void accept(final Account.State status) {
        final var account = getAccount();
        if (ServiceOutageStatus.isPossibleOutage(status)) {
            this.service.fetchServiceOutageStatus(account);
        }
        this.service.updateAccountUi();

        if (account.getStatus() == Account.State.ONLINE || account.getStatus().isError()) {
            this.service.getQuickConversationsService().signalAccountStateChange();
        }

        if (account.getStatus() == Account.State.ONLINE) {
            // register x3dhpq +notify caps once per stream (no-op; features are in DiscoManager)
            account.getX3dhpqService().registerNotifyFeatures();
            // bootstrap local x3dhpq key material (no-op if already bootstrapped)
            final LocalKeyBootstrap.BootstrapResult x3dhpqBootstrap =
                    new LocalKeyBootstrap(this.service.databaseBackend).ensureBootstrapped(account);
            if (x3dhpqBootstrap.wasNewlyCreated) {
                Log.d(
                        Config.LOGTAG,
                        account.getJid().asBareJid()
                                + ": x3dhpq bootstrapped, fp="
                                + x3dhpqBootstrap.fingerprint);
            }
            // publish devicelist + bundle on every login (PEP dedupes by item id)
            account.getX3dhpqService().publishLocalState();
            // announce new device to peer resources only on fresh bootstrap (first sign-in)
            if (x3dhpqBootstrap.wasNewlyCreated) {
                final var verifyMgr = getManager(VerifyDeviceManager.class);
                verifyMgr.announceNewDevice(x3dhpqBootstrap.deviceId, (peersCount, err) -> {
                    if (err != null) {
                        Log.d(Config.LOGTAG, "verify-device announce failed: " + err.getMessage());
                        return;
                    }
                    Log.d(Config.LOGTAG, "verify-device announced; peers=" + peersCount);
                    if (peersCount == null || peersCount <= 0) {
                        // First device on this account — nothing to do.
                        return;
                    }
                    // Secondary device: auto-launch the pairing wizard. Prefer
                    // an in-foreground activity over a passive notification so
                    // the user is dropped straight into the sync-code prompt.
                    // Falls back to a notification if the activity launch
                    // can't fire (e.g., app is fully backgrounded).
                    final Intent pairIntent =
                            PairToExistingActivity.makeIntent(context, account.getUuid());
                    pairIntent.setFlags(
                            Intent.FLAG_ACTIVITY_NEW_TASK
                                    | Intent.FLAG_ACTIVITY_CLEAR_TOP
                                    | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                    try {
                        context.startActivity(pairIntent);
                    } catch (final Exception e) {
                        Log.w(
                                Config.LOGTAG,
                                "could not foreground PairToExistingActivity; posting notification",
                                e);
                        final PendingIntent pendingIntent =
                                PendingIntent.getActivity(
                                        context,
                                        account.getUuid().hashCode(),
                                        pairIntent,
                                        PendingIntent.FLAG_UPDATE_CURRENT
                                                | PendingIntent.FLAG_IMMUTABLE);
                        final NotificationCompat.Builder builder =
                                new NotificationCompat.Builder(
                                                context,
                                                NotificationService.MESSAGES_NOTIFICATION_CHANNEL)
                                        .setSmallIcon(R.drawable.ic_app_icon_notification)
                                        .setContentTitle(
                                                context.getString(
                                                        R.string.x3dhpq_secondary_device_detected_title))
                                        .setContentText(
                                                context.getString(
                                                        R.string.x3dhpq_secondary_device_detected_text,
                                                        peersCount))
                                        .setAutoCancel(true)
                                        .setContentIntent(pendingIntent);
                        final NotificationManager nm =
                                (NotificationManager)
                                        context.getSystemService(
                                                android.content.Context.NOTIFICATION_SERVICE);
                        nm.notify(account.getUuid().hashCode(), builder.build());
                    }
                });
            }
            synchronized (this.service.mLowPingTimeoutMode) {
                if (this.service.mLowPingTimeoutMode.remove(account.getJid().asBareJid())) {
                    Log.d(
                            Config.LOGTAG,
                            account.getJid().asBareJid() + ": leaving low ping timeout mode");
                }
            }
            if (account.setShowErrorNotification(true)) {
                this.service.databaseBackend.updateAccount(account);
            }
            final var csiManager = getManager(ClientStateIndicationManager.class);
            if (csiManager.hasFeature()) {
                if (this.service.checkListeners()) {
                    csiManager.indicateInactive();
                } else {
                    csiManager.indicateActive();
                }
            }
            final var mucManager = getManager(MultiUserChatManager.class);
            final var conversations = this.service.getConversations();
            for (final var conversation : conversations) {
                final boolean inProgressJoin = mucManager.isJoinInProgress(conversation);
                if (conversation.getAccount() == account && !inProgressJoin) {
                    this.service.sendUnsentMessages(conversation);
                }
            }
            this.service.scheduleWakeUpCall(
                    Config.PING_MAX_INTERVAL * 1000L, account.getUuid().hashCode());
        } else if (account.getStatus() == Account.State.OFFLINE
                || account.getStatus() == Account.State.DISABLED
                || account.getStatus() == Account.State.LOGGED_OUT) {
            this.service.resetSendingToWaiting(account);
            if (account.isConnectionEnabled() && this.service.isInLowPingTimeoutMode(account)) {
                Log.d(
                        Config.LOGTAG,
                        account.getJid().asBareJid()
                                + ": went into offline state during low ping mode."
                                + " reconnecting now");
                this.service.reconnectAccount(account, false);
            } else {
                final int timeToReconnect = SECURE_RANDOM.nextInt(10) + 2;
                this.service.scheduleWakeUpCall(timeToReconnect, account.getUuid().hashCode());
            }
        } else if (account.getStatus() == Account.State.REGISTRATION_SUCCESSFUL) {
            this.service.databaseBackend.updateAccount(account);
            this.service.reconnectAccount(account, false);
        } else if (account.getStatus() != Account.State.CONNECTING) {
            this.service.resetSendingToWaiting(account);
            if (connection != null && account.getStatus().isAttemptReconnect()) {
                final boolean aggressive =
                        account.getStatus() == Account.State.SEE_OTHER_HOST
                                || getManager(JingleManager.class).hasJingleRtpConnection();
                final int next = connection.getTimeToNextAttempt(aggressive);
                final boolean lowPingTimeoutMode = this.service.isInLowPingTimeoutMode(account);
                if (next <= 0) {
                    Log.d(
                            Config.LOGTAG,
                            account.getJid().asBareJid()
                                    + ": error connecting account. reconnecting now."
                                    + " lowPingTimeout="
                                    + lowPingTimeoutMode);
                    this.service.reconnectAccount(account, false);
                } else {
                    final int attempt = connection.getAttempt() + 1;
                    Log.d(
                            Config.LOGTAG,
                            account.getJid().asBareJid()
                                    + ": error connecting account. try again in "
                                    + next
                                    + "s for the "
                                    + attempt
                                    + " time. lowPingTimeout="
                                    + lowPingTimeoutMode
                                    + ", aggressive="
                                    + aggressive);
                    this.service.scheduleWakeUpCall(next, account.getUuid().hashCode());
                    if (aggressive) {
                        this.service.internalPingExecutor.schedule(
                                service::manageAccountConnectionStatesInternal,
                                (next * 1000L) + 50,
                                TimeUnit.MILLISECONDS);
                    }
                }
            }
        }
        this.service.getNotificationService().updateErrorNotification();
    }
}
