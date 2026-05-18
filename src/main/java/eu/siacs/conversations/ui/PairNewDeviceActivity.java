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

    // Views
    private TextView mCodeView;
    private ImageView mQrView;
    private TextView mStatusView;
    private Button mCancelButton;

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

        mStatusView.setText(R.string.x3dhpq_pair_status_waiting);

        mCancelButton.setOnClickListener(v -> finish());
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

        // Render QR: xmppqr-pair:<bare_jid>?code=<raw_code>&sid=<base64url_sid>
        final String bareJid = mAccount.getJid().asBareJid().toString();
        final String sidB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(mSid);
        final String qrUri =
                "xmppqr-pair:" + bareJid + "?code=" + mRawCode + "&sid=" + sidB64;

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

                        Log.d(
                                Config.LOGTAG,
                                LOGTAG + ": received verify-device broadcast, new_resource="
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
                            mPairingService.startAsExisting(mSid, mRawCode, peerJid, mOpts);
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
