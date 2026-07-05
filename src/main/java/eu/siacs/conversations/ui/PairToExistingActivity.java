// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.R;
import eu.siacs.conversations.crypto.x3dhpq.PairingSessionService;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.x3dhpq.protocol.PairingFsm;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.PairingCode;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * New-device-side pairing activity. The user either scans the QR shown on the existing primary
 * device, or types the 10-digit code manually. Once the code + sid are in hand we call
 * {@link PairingSessionService#prepareAsNew} to register the New-side FSM and wait for the
 * existing device's PAKE1 to arrive via the XMPP message stream.
 */
public class PairToExistingActivity extends XmppActivity {

    private static final String LOGTAG = "PairToExistingActivity";

    public static final String EXTRA_ACCOUNT = "account_uuid";

    /** Request code used with startActivityForResult for QR scanning. */
    private static final int REQUEST_SCAN_QR = 0x3A1B;

    // ---- Views ----
    private Button mScanQrButton;
    private EditText mCodeInput;
    private Button mPairButton;
    private TextView mStatusView;

    // ---- State ----
    private String mAccountUuid;
    private Account mAccount;
    private PairingSessionService mPairingService;

    private final Handler mHandler = new Handler(Looper.getMainLooper());

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
                                if (result != null) {
                                    installPairingResult(result);
                                }
                                mStatusView.setText(R.string.x3dhpq_pair_status_done);
                                mScanQrButton.setEnabled(false);
                                mPairButton.setEnabled(false);
                                // Auto-finish after 2 s
                                mHandler.postDelayed(PairToExistingActivity.this::finish, 2000);
                            });
                }

                @Override
                public void onPairingFailed(final byte[] sid, final Throwable error) {
                    final String reason = error != null ? error.getMessage() : "unknown";
                    mHandler.post(
                            () -> {
                                mStatusView.setText(
                                        getString(R.string.x3dhpq_pair_status_failed, reason));
                                // Re-enable buttons so the user can retry.
                                mScanQrButton.setEnabled(true);
                                mPairButton.setEnabled(true);
                            });
                }
            };

    // ---- Factory ----

    public static Intent makeIntent(final Context ctx, final String accountUuid) {
        final Intent intent = new Intent(ctx, PairToExistingActivity.class);
        intent.putExtra(EXTRA_ACCOUNT, accountUuid);
        return intent;
    }

    // ---- Lifecycle ----

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pair_to_existing);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.x3dhpq_pair_to_existing_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        mAccountUuid = getIntent().getStringExtra(EXTRA_ACCOUNT);

        mScanQrButton = findViewById(R.id.scan_qr_button);
        mCodeInput = findViewById(R.id.pairing_code_input);
        mPairButton = findViewById(R.id.pair_button);
        mStatusView = findViewById(R.id.pair_status);

        // Buttons disabled until backend is connected.
        mScanQrButton.setEnabled(false);
        mPairButton.setEnabled(false);

        mScanQrButton.setOnClickListener(v -> launchQrScanner());
        mPairButton.setOnClickListener(v -> onPairButtonClicked());

        // Auto-format the manual code input as the user types.
        mCodeInput.addTextChangedListener(new PairingCodeWatcher());
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

        mPairingService = mAccount.getPairingSessionService();
        if (mPairingService == null) {
            Log.w(Config.LOGTAG, LOGTAG + ": PairingSessionService unavailable; finishing");
            android.widget.Toast.makeText(
                            this,
                            "Pairing service unavailable; try again after the account is online.",
                            android.widget.Toast.LENGTH_LONG)
                    .show();
            finish();
            return;
        }
        mPairingService.addListener(mPairingListener);

        mScanQrButton.setEnabled(true);
        mPairButton.setEnabled(true);
    }

    @Override
    protected void refreshUiReal() {
        // No UI state to refresh on reconnect.
    }

    @Override
    protected void onDestroy() {
        if (mPairingService != null) {
            mPairingService.removeListener(mPairingListener);
        }
        super.onDestroy();
    }

    // ---- QR scanning ----

    private void launchQrScanner() {
        final Intent intent = new Intent(this, ScanQrCodeActivity.class);
        startActivityForResult(intent, REQUEST_SCAN_QR);
    }

    @Override
    public void onActivityResult(final int requestCode, final int resultCode, final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode != REQUEST_SCAN_QR) {
            return;
        }
        if (resultCode != RESULT_OK || data == null) {
            return;
        }

        final String scanned = data.getStringExtra(ScanQrCodeActivity.INTENT_EXTRA_RESULT);
        if (scanned == null || scanned.isEmpty()) {
            return;
        }

        handlePairingUri(scanned);
    }

    /**
     * Parses {@code xmppqr-pair:<full_jid>?code=<10digits>&sid=<base64-url-sid>} (§10.1a method A)
     * and initiates the new-side pairing FSM, then sends a directed {@code <pair-hello>} to the
     * existing device's full JID so it initiates PAKE1 back toward us.
     */
    private void handlePairingUri(final String uri) {
        // Expected form: xmppqr-pair:<full_jid>?code=<code>&sid=<base64-url-sid>
        final String PREFIX = "xmppqr-pair:";
        if (!uri.startsWith(PREFIX)) {
            Log.w(Config.LOGTAG, LOGTAG + ": not a pairing URI: " + uri);
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

        // Parse query parameters: code= and sid=
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

        // Validate code via PairingCode.parse (Luhn check included).
        final String validatedCode;
        try {
            validatedCode = PairingCode.parse(code);
        } catch (final IllegalArgumentException e) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }

        // Decode sid from base64-url.
        final byte[] sid;
        try {
            sid = Base64.getUrlDecoder().decode(sidB64);
        } catch (final IllegalArgumentException e) {
            Log.w(Config.LOGTAG, LOGTAG + ": invalid base64-url sid in QR: " + e.getMessage());
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }

        // Parse the existing device's FULL JID (including resource) from the QR.
        final Jid peerFullJid;
        try {
            peerFullJid = Jid.of(fullJidStr);
        } catch (final IllegalArgumentException e) {
            Log.w(Config.LOGTAG, LOGTAG + ": invalid JID in QR: " + fullJidStr);
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            return;
        }

        // Validate that the JID in the QR belongs to our account (wrong-account safeguard).
        final Jid myBareJid = mAccount.getJid().asBareJid();
        if (!myBareJid.equals(peerFullJid.asBareJid())) {
            Log.w(
                    Config.LOGTAG,
                    LOGTAG
                            + ": QR JID "
                            + peerFullJid
                            + " != our JID "
                            + myBareJid
                            + "; refusing");
            mStatusView.setText(R.string.x3dhpq_pair_status_wrong_account);
            return;
        }

        if (startPairingAsNew(sid, validatedCode, peerFullJid)) {
            // Method A rendezvous (§10.1a): send a directed, secret-free <pair-hello> carrying our
            // full JID + sid to the existing device so it initiates PAKE1 back toward us. We do NOT
            // send PAKE1 ourselves — we wait for it.
            final var x3dhpqService = mAccount.getX3dhpqService();
            if (x3dhpqService != null) {
                x3dhpqService.sendDirectedPairHello(peerFullJid, sid);
            } else {
                Log.w(Config.LOGTAG, LOGTAG + ": X3dhpqService unavailable; cannot send pair-hello");
            }
        }
    }

    // ---- Manual code entry ----

    private void onPairButtonClicked() {
        final String raw = mCodeInput.getText().toString();
        final String validatedCode;
        try {
            validatedCode = PairingCode.parse(raw);
        } catch (final IllegalArgumentException e) {
            mStatusView.setText(R.string.x3dhpq_pair_status_invalid_uri);
            Toast.makeText(this, R.string.x3dhpq_pair_status_invalid_uri, Toast.LENGTH_SHORT)
                    .show();
            return;
        }

        // For manual entry (method B) we don't have a peer full JID from a QR — use our own
        // bare JID as the peerJid parameter (informational; the existing device initiates PAKE1).
        final Jid ownBareJid = mAccount.getJid().asBareJid();

        // Generate a fresh 32-byte random session id (method B: the new device owns the sid).
        final byte[] sid = new byte[32];
        new SecureRandom().nextBytes(sid);

        if (startPairingAsNew(sid, validatedCode, ownBareJid)) {
            // Method B rendezvous (§10.1a): publish <pair-hello> to our own PEP node so an
            // existing primary resource receives it via self-PEP +notify and sends PAKE1.
            final var x3dhpqService = mAccount.getX3dhpqService();
            if (x3dhpqService != null) {
                x3dhpqService.publishPairHello(sid);
            } else {
                Log.w(Config.LOGTAG, LOGTAG + ": X3dhpqService unavailable; cannot publish pair-hello");
            }
        }
    }

    // ---- Core initiation ----

    private boolean startPairingAsNew(
            final byte[] sid, final String code, final Jid peerJid) {
        mStatusView.setText(R.string.x3dhpq_pair_status_waiting);
        mScanQrButton.setEnabled(false);
        mPairButton.setEnabled(false);

        try {
            mPairingService.prepareAsNew(sid, code, peerJid);
            Log.d(Config.LOGTAG, LOGTAG + ": prepareAsNew registered, waiting for PAKE1 from existing device");
            return true;
        } catch (final Exception e) {
            Log.e(Config.LOGTAG, LOGTAG + ": prepareAsNew failed", e);
            final String reason = e.getMessage();
            mStatusView.setText(
                    getString(
                            R.string.x3dhpq_pair_status_failed,
                            reason != null ? reason : "setup failed"));
            mScanQrButton.setEnabled(true);
            mPairButton.setEnabled(true);
            return false;
        }
    }

    // ---- Install pairing result ----

    /**
     * Installs the device identity + account identity delivered by the existing primary device
     * into the local database.
     *
     * <p>{@link im.conversations.x3dhpq.protocol.PairingFsm.Result} carries:
     * <ul>
     *   <li>{@code aikPub}   — the existing account's {@link im.conversations.x3dhpq.types.AccountIdentityPub}
     *   <li>{@code cert}     — the new {@link DeviceCertificate} issued by the primary
     *   <li>{@code aikPriv}  — the full {@link im.conversations.x3dhpq.types.AccountIdentityKey}
     *                          (includes ML-DSA private key so this device can sign as primary)
     *   <li>{@code stateBlob}— opaque extra state (unused for now)
     * </ul>
     *
     * <p>TODO: extract a {@code LocalKeyBootstrap.installFromPairing(result)} helper once the
     * exact on-wire pre-key material from the existing device is defined. For now we persist the
     * DC and AIK directly via the DAO. The device's DIK was already bootstrapped locally (by
     * {@link eu.siacs.conversations.crypto.x3dhpq.LocalKeyBootstrap#ensureBootstrapped}) before
     * pairing started; the existing device just issued us a signed DC for it.
     */
    private void installPairingResult(final PairingFsm.Result result) {
        if (mAccount == null || !xmppConnectionServiceBound) {
            return;
        }
        final DatabaseBackend dao = xmppConnectionService.databaseBackend;

        try {
            dao.beginTransaction();
            try {
                // Persist the AIK (full private key so this device can act as primary later).
                if (result.aikPriv != null) {
                    final String fingerprint =
                            result.aikPub != null
                                    ? result.aikPub.fingerprint(
                                            im.conversations.x3dhpq.crypto.X3dhpqCrypto.BLAKE2B_160)
                                    : "";
                    dao.putX3dhpqAccountIdentity(
                            mAccountUuid,
                            result.aikPriv.marshal(),
                            result.aikPub != null ? result.aikPub.marshal() : new byte[0],
                            fingerprint);
                }

                // Persist the device certificate issued by the existing primary.
                if (result.cert != null) {
                    final java.util.List<eu.siacs.conversations.persistance.DatabaseBackend.X3dhpqLocalDeviceRow> devices =
                            dao.listX3dhpqLocalDevices(mAccountUuid);
                    if (!devices.isEmpty()) {
                        final eu.siacs.conversations.persistance.DatabaseBackend.X3dhpqLocalDeviceRow dev =
                                devices.get(0);
                        dao.putX3dhpqLocalDevice(
                                mAccountUuid,
                                dev.deviceId(),
                                dev.dikPriv(),
                                result.cert.marshal(),
                                dev.createdAt(),
                                result.cert.getFlags() & 0xFF);
                    }
                }

                dao.setTransactionSuccessful();
            } finally {
                dao.endTransaction();
            }
            Log.d(Config.LOGTAG, LOGTAG + ": pairing result installed into database");
        } catch (final Exception e) {
            Log.e(Config.LOGTAG, LOGTAG + ": failed to install pairing result", e);
        }
    }

    // ---- TextWatcher for formatted code input ----

    /**
     * Formats digits typed into the code input as "DDD-DDD-DDD-C" while preserving the cursor.
     * Strips all non-digit characters before re-formatting so the user can paste or delete freely.
     */
    private static final class PairingCodeWatcher implements TextWatcher {

        private boolean mSelfChange = false;

        @Override
        public void beforeTextChanged(
                final CharSequence s, final int start, final int count, final int after) {}

        @Override
        public void onTextChanged(
                final CharSequence s, final int start, final int before, final int count) {}

        @Override
        public void afterTextChanged(final Editable s) {
            if (mSelfChange) {
                return;
            }
            // Extract only digits, up to 10.
            final StringBuilder digits = new StringBuilder();
            for (int i = 0; i < s.length() && digits.length() < 10; i++) {
                final char c = s.charAt(i);
                if (c >= '0' && c <= '9') {
                    digits.append(c);
                }
            }

            // Re-format as DDD-DDD-DDD-C inserting dashes at positions 3, 6, 9.
            final StringBuilder formatted = new StringBuilder();
            for (int i = 0; i < digits.length(); i++) {
                if (i == 3 || i == 6 || i == 9) {
                    formatted.append('-');
                }
                formatted.append(digits.charAt(i));
            }

            final String result = formatted.toString();
            if (!result.equals(s.toString())) {
                mSelfChange = true;
                s.replace(0, s.length(), result);
                mSelfChange = false;
            }
        }
    }
}
