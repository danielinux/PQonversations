// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.ui;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import com.google.zxing.WriterException;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.R;
import eu.siacs.conversations.crypto.x3dhpq.PairingSessionService;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.services.BarcodeProvider;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.manager.VerifyDeviceManager;
import im.conversations.x3dhpq.protocol.PairingFsm;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.PairingCode;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Shows a pairing code and QR for the existing primary device.  The new device scans
 * the QR (or types the code), after which a {@link VerifyDeviceManager#ACTION_X3DHPQ_PAIR_NEW_DEVICE}
 * broadcast arrives carrying the new device's full JID, and we drive the existing-side FSM.
 */
public class PairNewDeviceActivity extends XmppActivity {

    private static final String LOGTAG = "PairNewDeviceActivity";

    public static final String EXTRA_ACCOUNT = "account_uuid";

    /**
     * Optional boolean intent extra: when true, immediately launches the QR scanner for the
     * §10.6.2 "new-device-presents" confirm flow instead of waiting on this screen showing
     * its own code. Set by the devices screen's "Confirm a waiting device" entry point.
     */
    public static final String EXTRA_AUTO_CONFIRM_PENDING = "auto_confirm_pending";

    /** Request code for scanning a PENDING device's own QR (§10.6.2 new-device-presents). */
    private static final int REQUEST_SCAN_PENDING_DEVICE_QR = 0x3A1C;

    // Views
    private TextView mCodeView;
    private ImageView mQrView;
    private TextView mStatusView;
    private Button mCancelButton;
    private Button mConfirmPendingDeviceButton;

    // State set in onBackendConnected
    private String mAccountUuid;
    private Account mAccount;
    private byte[] mSid;
    private String mRawCode;
    private PairingFsm.Options mOpts;

    private PairingSessionService mPairingService;

    private final Handler mHandler = new Handler(Looper.getMainLooper());

    // ---- Broadcast receiver waiting for the new device's full JID ----

    private BroadcastReceiver mPairReceiver;
    private boolean mStartedFsm = false;

    // ---- PairingSessionService listener ----

    private final PairingSessionService.Listener mPairingListener =
            new PairingSessionService.Listener() {
                @Override
                public void onPairingComplete(
                        final byte[] sid,
                        final PairingFsm.Result result,
                        final DeviceCertificate issuedCert) {
                    // Existing/primary side: issuedCert is the DC we just minted (under
                    // our own AIK) for the newly enrolled device. Persist it into the
                    // account-wide co-device store and republish the signed devicelist
                    // so contacts — and any other co-account device — learn about it.
                    // Without this the new device stays invisible on `current` and
                    // messages sent to it are silently dropped (§8.2).
                    if (issuedCert != null && mAccount != null) {
                        try {
                            xmppConnectionService.databaseBackend.putX3dhpqCoAccountDevice(
                                    mAccount.getUuid(),
                                    (int) issuedCert.getDeviceId(),
                                    issuedCert.marshal(),
                                    issuedCert.getCreatedAt(),
                                    issuedCert.getFlags() & 0xff);
                            mAccount.getX3dhpqService().publishDeviceList();
                            // §10.6.3: append + publish the AddDevice audit entry so this
                            // sibling passes the audit-chain trust gate on every device
                            // (including this one) that later observes the account's own
                            // devicelist — without this, X3dhpqService#verifiedAddDeviceIds
                            // would refuse to trust the very device we just confirmed.
                            mAccount.getX3dhpqService()
                                    .publishAddDeviceAuditEntry(
                                            (int) issuedCert.getDeviceId(), issuedCert);
                        } catch (final Exception e) {
                            Log.e(
                                    Config.LOGTAG,
                                    LOGTAG
                                            + ": failed to persist/publish newly enrolled device",
                                    e);
                        }
                    }
                    mHandler.post(
                            () -> {
                                mStatusView.setText(R.string.x3dhpq_pair_status_done);
                                mCancelButton.setEnabled(false);
                                // Auto-finish after 2 s
                                mHandler.postDelayed(PairNewDeviceActivity.this::finish, 2000);
                            });
                }

                @Override
                public void onPairingFailed(final byte[] sid, final Throwable error) {
                    final String reason = error != null ? error.getMessage() : "unknown";
                    mHandler.post(
                            () -> {
                                mStatusView.setText(
                                        getString(R.string.x3dhpq_pair_status_failed, reason));
                                mCancelButton.setEnabled(true);
                            });
                }
            };

    // ---- Factory ----

    public static Intent makeIntent(final Context ctx, final String accountUuid) {
        final Intent intent = new Intent(ctx, PairNewDeviceActivity.class);
        intent.putExtra(EXTRA_ACCOUNT, accountUuid);
        return intent;
    }

    /**
     * §10.6.2 "Confirm a waiting device" entry point: same screen, but immediately opens the
     * QR scanner for the pending device's own code/QR instead of showing this device's code
     * first. Used by the devices screen's dedicated "confirm" button so that flow is one tap.
     */
    public static Intent makeIntentConfirmPending(final Context ctx, final String accountUuid) {
        final Intent intent = makeIntent(ctx, accountUuid);
        intent.putExtra(EXTRA_AUTO_CONFIRM_PENDING, true);
        return intent;
    }

    // ---- Lifecycle ----

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pair_new_device);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.x3dhpq_pair_new_device_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        mAccountUuid = getIntent().getStringExtra(EXTRA_ACCOUNT);

        mCodeView = findViewById(R.id.pairing_code);
        mQrView = findViewById(R.id.pairing_qr);
        mStatusView = findViewById(R.id.pairing_status);
        mCancelButton = findViewById(R.id.pair_cancel_button);
        mConfirmPendingDeviceButton = findViewById(R.id.confirm_pending_device_button);

        mStatusView.setText(R.string.x3dhpq_pair_status_waiting);

        mCancelButton.setOnClickListener(v -> finish());
        mConfirmPendingDeviceButton.setOnClickListener(v -> launchPendingDeviceQrScanner());
    }

    /**
     * §10.6.2 "new-device-presents" direction: launches the QR scanner to read a
     * pending device's own {@code xmppqr-pair:} URI (full JID + code + sid all in
     * one), then drives the existing-side FSM straight at it — no passive pair-hello
     * wait needed since the QR already carries everything.
     */
    private void launchPendingDeviceQrScanner() {
        final Intent intent = new Intent(this, ScanQrCodeActivity.class);
        startActivityForResult(intent, REQUEST_SCAN_PENDING_DEVICE_QR);
    }

    @Override
    public void onBackendConnected() {
        if (mAccountUuid == null) {
            Log.w(Config.LOGTAG, LOGTAG + ": no account UUID in intent");
            finish();
            return;
        }
        mAccount = xmppConnectionService.findAccountByUuid(mAccountUuid);
        if (mAccount == null) {
            Log.w(Config.LOGTAG, LOGTAG + ": account not found: " + mAccountUuid);
            finish();
            return;
        }

        // Only initialise once (onBackendConnected may be called again on reconnect).
        if (mSid != null) {
            return;
        }

        // Generate 9 random decimal digits and append a Luhn check digit.
        final SecureRandom rng = new SecureRandom();
        final StringBuilder nineSb = new StringBuilder(9);
        for (int i = 0; i < 9; i++) {
            nineSb.append((char) ('0' + rng.nextInt(10)));
        }
        final String nineDigits = nineSb.toString();
        mRawCode = nineDigits + PairingCode.luhnCheckChar(nineDigits);

        // Display formatted code ("DDD-DDD-DDD-C").
        mCodeView.setText(PairingCode.format(mRawCode));

        // Generate 32-byte random session-id.
        mSid = new byte[32];
        rng.nextBytes(mSid);

        // Render QR (§10.1a method A): xmppqr-pair:<full_jid>?code=<raw_code>&sid=<base64url_sid>
        // The full JID (including this device's resource) is where the scanning device sends the
        // directed <pair-hello> trigger, so we receive it and send PAKE1 back.
        final String fullJid = mAccount.getJid().toString();
        final String sidB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(mSid);
        final String qrUri =
                "xmppqr-pair:" + fullJid + "?code=" + mRawCode + "&sid=" + sidB64;

        try {
            final int sizePx = 512; // pixels; ImageView is 240dp, 512 is sufficient
            final Bitmap bm = BarcodeProvider.create2dBarcodeBitmap(qrUri, sizePx);
            mQrView.setImageBitmap(bm);
        } catch (final WriterException e) {
            Log.e(Config.LOGTAG, LOGTAG + ": could not render QR code", e);
            // Fallback: hide the ImageView and show the URI as text
            mQrView.setVisibility(android.view.View.GONE);
            final TextView qrFallback = new TextView(this);
            qrFallback.setText(qrUri);
            qrFallback.setTextIsSelectable(true);
            // TODO: render QR — BarcodeProvider failed
        }

        // Build FSM options: fresh random uint32 device-id, sharePrimary=false.
        final long newDeviceId = Integer.toUnsignedLong(rng.nextInt());
        mOpts = new PairingFsm.Options(newDeviceId, false, new byte[0], (byte) 0);

        // Obtain (or lazily create) the PairingSessionService for this account.
        mPairingService = mAccount.getX3dhpqService().getPairingSessionService();
        mPairingService.addListener(mPairingListener);

        // Register broadcast receiver for verify-device headline from the new device.
        registerPairReceiver();

        // §10.6.2 "Confirm a waiting device" shortcut: skip straight to scanning the
        // pending device's own code/QR instead of waiting on this screen showing ours.
        if (getIntent().getBooleanExtra(EXTRA_AUTO_CONFIRM_PENDING, false)) {
            mHandler.post(this::launchPendingDeviceQrScanner);
        }
    }

    /** Registers the broadcast receiver that listens for the new device's full JID. */
    private void registerPairReceiver() {
        if (mPairReceiver != null) {
            return; // already registered
        }
        mPairReceiver =
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(final Context ctx, final Intent intent) {
                        if (!VerifyDeviceManager.ACTION_X3DHPQ_PAIR_NEW_DEVICE.equals(
                                intent.getAction())) {
                            return;
                        }

                        // Filter by account JID to avoid acting on another account's broadcast.
                        final String accountJid =
                                intent.getStringExtra(VerifyDeviceManager.EXTRA_ACCOUNT_JID);
                        final String myBareJid =
                                mAccount != null
                                        ? mAccount.getJid().asBareJid().toString()
                                        : null;
                        if (myBareJid != null && !myBareJid.equals(accountJid)) {
                            return;
                        }

                        if (mStartedFsm) {
                            return; // ignore duplicate broadcasts
                        }
                        mStartedFsm = true;

                        final String newResource =
                                intent.getStringExtra(VerifyDeviceManager.EXTRA_NEW_RESOURCE);
                        if (newResource == null || newResource.isEmpty()) {
                            Log.w(
                                    Config.LOGTAG,
                                    LOGTAG + ": received pair broadcast but new_resource is empty");
                            return;
                        }

                        // Use the sid carried in the <pair-hello> (§10.1a): for method A it equals
                        // the sid we put in the QR; for method B it is the new device's own sid.
                        // Both sides must agree on the same sid for CPace. Fall back to mSid.
                        byte[] sessionId = mSid;
                        final String sidB64Url =
                                intent.getStringExtra(VerifyDeviceManager.EXTRA_SID);
                        if (sidB64Url != null && !sidB64Url.isEmpty()) {
                            try {
                                sessionId =
                                        Base64.getUrlDecoder().decode(sidB64Url);
                            } catch (final IllegalArgumentException e) {
                                Log.w(
                                        Config.LOGTAG,
                                        LOGTAG + ": invalid base64url sid in pair-hello broadcast;"
                                                + " falling back to local sid");
                            }
                        }

                        Log.d(
                                Config.LOGTAG,
                                LOGTAG + ": received pair-hello broadcast, new_resource="
                                        + newResource);

                        mHandler.post(() -> mStatusView.setText(
                                R.string.x3dhpq_pair_status_verifying));

                        // Drive the existing-side FSM now that we know the new device's full JID.
                        final Jid peerJid;
                        try {
                            peerJid = Jid.of(newResource);
                        } catch (final IllegalArgumentException e) {
                            Log.w(Config.LOGTAG, LOGTAG + ": invalid peer JID: " + newResource, e);
                            return;
                        }

                        try {
                            mPairingService.startAsExisting(sessionId, mRawCode, peerJid, mOpts);
                        } catch (final Exception e) {
                            Log.e(Config.LOGTAG, LOGTAG + ": startAsExisting failed", e);
                            final String reason = e.getMessage();
                            mHandler.post(
                                    () -> mStatusView.setText(
                                            getString(
                                                    R.string.x3dhpq_pair_status_failed,
                                                    reason != null ? reason : "FSM init failed")));
                        }
                    }
                };

        final IntentFilter filter =
                new IntentFilter(VerifyDeviceManager.ACTION_X3DHPQ_PAIR_NEW_DEVICE);
        registerReceiver(mPairReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
    }

    @Override
    public void onActivityResult(final int requestCode, final int resultCode, final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_SCAN_PENDING_DEVICE_QR) {
            return;
        }
        if (resultCode != RESULT_OK || data == null) {
            return;
        }
        final String scanned = data.getStringExtra(ScanQrCodeActivity.INTENT_EXTRA_RESULT);
        if (scanned == null || scanned.isEmpty()) {
            return;
        }
        confirmPendingDeviceFromUri(scanned);
    }

    /**
     * Parses a pending device's own {@code xmppqr-pair:<full_jid>?code=<code>&sid=<sid>}
     * URI (§10.6.2, same wire format as §10.1a Method A, roles reversed: HERE the
     * scanned JID belongs to the NEW device, not an existing one) and immediately
     * drives the existing-side FSM at it. Unlike the passive pair-hello flow used by
     * the default "show my code" screen, no rendezvous round-trip is needed: the QR
     * already carries full JID + code + sid together.
     */
    private void confirmPendingDeviceFromUri(final String uri) {
        final String PREFIX = "xmppqr-pair:";
        if (!uri.startsWith(PREFIX)) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        final String rest = uri.substring(PREFIX.length());
        final int qMark = rest.indexOf('?');
        if (qMark < 0) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        final String fullJidStr = rest.substring(0, qMark);
        final String query = rest.substring(qMark + 1);
        String code = null;
        String sidB64 = null;
        for (final String param : query.split("&")) {
            if (param.startsWith("code=")) {
                code = param.substring(5);
            } else if (param.startsWith("sid=")) {
                sidB64 = param.substring(4);
            }
        }
        if (code == null || sidB64 == null) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        final String validatedCode;
        try {
            validatedCode = im.conversations.x3dhpq.types.PairingCode.parse(code);
        } catch (final IllegalArgumentException e) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        final byte[] sid;
        try {
            sid = Base64.getUrlDecoder().decode(sidB64);
        } catch (final IllegalArgumentException e) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        final Jid pendingFullJid;
        try {
            pendingFullJid = Jid.of(fullJidStr);
        } catch (final IllegalArgumentException e) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }
        if (mAccount == null || !mAccount.getJid().asBareJid().equals(pendingFullJid.asBareJid())) {
            mStatusView.setText(R.string.x3dhpq_pair_status_wrong_account);
            return;
        }
        if (mStartedFsm) {
            return; // a pairing is already in flight from this screen
        }
        mStartedFsm = true;
        mStatusView.setText(R.string.x3dhpq_pair_status_verifying);
        try {
            mPairingService.startAsExisting(sid, validatedCode, pendingFullJid, mOpts);
        } catch (final Exception e) {
            Log.e(Config.LOGTAG, LOGTAG + ": startAsExisting (confirm pending device) failed", e);
            mStartedFsm = false;
            final String reason = e.getMessage();
            mStatusView.setText(
                    getString(
                            R.string.x3dhpq_pair_status_failed,
                            reason != null ? reason : "FSM init failed"));
        }
    }

    @Override
    protected void refreshUiReal() {
        // Nothing to refresh on reconnect — state is fully in-memory.
    }

    @Override
    protected void onDestroy() {
        if (mPairReceiver != null) {
            try {
                unregisterReceiver(mPairReceiver);
            } catch (final IllegalArgumentException ignored) {
                // receiver was never fully registered
            }
            mPairReceiver = null;
        }
        if (mPairingService != null) {
            mPairingService.removeListener(mPairingListener);
        }
        super.onDestroy();
    }
}
