// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import com.google.zxing.WriterException;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.R;
import eu.siacs.conversations.crypto.x3dhpq.PairingSessionService;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.services.BarcodeProvider;
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
    private Button mShowMyCodeButton;
    private android.view.View mShowMyCodeContainer;
    private TextView mMyCodeView;
    private ImageView mMyQrView;

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
                                    // Trust Manifest Phase 2 (§D3): fetch + verify + fold the
                                    // account manifest so this newcomer sees itself + siblings
                                    // once the confirmer's ADD lands.
                                    if (mAccount != null && mAccount.getX3dhpqService() != null) {
                                        mAccount.getX3dhpqService().fetchAndAdoptManifest();
                                    }
                                }
                                mStatusView.setText(R.string.x3dhpq_pair_status_done);
                                mScanQrButton.setEnabled(false);
                                mPairButton.setEnabled(false);
                                // Auto-finish after 2 s
                                mHandler.postDelayed(PairToExistingActivity.this::finish, 2000);
                            });
                }

                @Override
                public void onPairingRetryable(final byte[] sid, final String reason) {
                    // Non-fatal: a device tried with the wrong code; we're still waiting for a
                    // matching one. Tell the user why (they likely mistyped) without ending.
                    mHandler.post(
                            () -> mStatusView.setText(R.string.x3dhpq_pair_status_code_retry));
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
        mShowMyCodeButton = findViewById(R.id.show_my_code_button);
        mShowMyCodeContainer = findViewById(R.id.show_my_code_container);
        mMyCodeView = findViewById(R.id.my_pairing_code);
        mMyQrView = findViewById(R.id.my_pairing_qr);

        // §10.6.2 single tested direction: this pending device PRESENTS its own
        // code/QR; an existing authorized device enters it. The opposite direction
        // (scan/type a code shown by the existing device) is intentionally not
        // offered, so hide the scan button, the manual code field and its submit
        // button — only "Show my code" remains.
        mScanQrButton.setVisibility(android.view.View.GONE);
        mCodeInput.setVisibility(android.view.View.GONE);
        mPairButton.setVisibility(android.view.View.GONE);

        // Button disabled until backend is connected.
        mShowMyCodeButton.setEnabled(false);
        mShowMyCodeButton.setOnClickListener(v -> onShowMyCodeClicked());
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
        mShowMyCodeButton.setEnabled(true);
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

    // ---- §10.6.2 "new-device-presents" direction ----

    /**
     * This pending device generates its OWN code/QR and displays it, instead of
     * consuming one shown by an existing device. The FSM convention (§10.1a) is
     * unchanged — the EXISTING device always sends {@code PairingMsgPAKE1} first — so
     * this device just registers the New-side FSM immediately (mirroring {@link
     * #startPairingAsNew}) and waits. A human reads the code (or scans the QR) off
     * this screen and enters/scans it on the existing/primary device's "Confirm a new
     * device" screen, which drives {@code startAsExisting} straight at our full JID —
     * no separate rendezvous round-trip is required for the QR path since the QR
     * already carries our full JID + code + sid. We ALSO publish a {@code
     * <pair-hello>} (method B) so a primary that is only passively listening (not
     * actively scanning) still gets a prompt with our JID + sid ready for the user to
     * type our code into.
     */
    private void onShowMyCodeClicked() {
        if (mAccount == null || mPairingService == null) {
            return;
        }
        mShowMyCodeButton.setEnabled(false);
        mScanQrButton.setEnabled(false);
        mPairButton.setEnabled(false);

        final SecureRandom rng = new SecureRandom();
        final StringBuilder nineSb = new StringBuilder(9);
        for (int i = 0; i < 9; i++) {
            nineSb.append((char) ('0' + rng.nextInt(10)));
        }
        final String nineDigits = nineSb.toString();
        final String rawCode = nineDigits + PairingCode.luhnCheckChar(nineDigits);
        mMyCodeView.setText(PairingCode.format(rawCode));

        final byte[] sid = new byte[32];
        rng.nextBytes(sid);

        final Jid ownFullJid = mAccount.getJid();
        try {
            // Register the New-side FSM now; the existing/primary device's PAKE1 will
            // arrive addressed to our full JID and be routed to this FSM by sid —
            // exactly the same inbound path prepareAsNew always relied on.
            mPairingService.prepareAsNew(sid, rawCode, ownFullJid.asBareJid());
        } catch (final Exception e) {
            Log.e(Config.LOGTAG, LOGTAG + ": prepareAsNew (show-my-code) failed", e);
            mStatusView.setText(
                    getString(
                            R.string.x3dhpq_pair_status_failed,
                            e.getMessage() != null ? e.getMessage() : "setup failed"));
            mShowMyCodeButton.setEnabled(true);
            mScanQrButton.setEnabled(true);
            mPairButton.setEnabled(true);
            return;
        }

        // Render our own QR: xmppqr-pair:<our_full_jid>?code=<code>&sid=<sid> — an
        // existing device that scans this learns our full JID + code + sid in one
        // step and can call startAsExisting immediately.
        final String sidB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sid);
        final String qrUri = "xmppqr-pair:" + ownFullJid + "?code=" + rawCode + "&sid=" + sidB64;
        try {
            final Bitmap bm = BarcodeProvider.create2dBarcodeBitmap(qrUri, 512);
            mMyQrView.setImageBitmap(bm);
        } catch (final WriterException e) {
            Log.e(Config.LOGTAG, LOGTAG + ": could not render QR code", e);
            mMyQrView.setVisibility(android.view.View.GONE);
        }
        mShowMyCodeContainer.setVisibility(android.view.View.VISIBLE);

        // Method B fallback (no camera on the primary side): a self-PEP pair-hello
        // lets a passively-listening primary prompt the user to type the code shown
        // here, without requiring a scan.
        final var x3dhpqService = mAccount.getX3dhpqService();
        if (x3dhpqService != null) {
            x3dhpqService.publishPairHello(sid);
        }

        mStatusView.setText(R.string.x3dhpq_pair_status_waiting);
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
                // Capture this device's own local key row (device_id + DIK priv +
                // created_at) BEFORE adopting the account AIK. The DIK was bootstrapped
                // locally before pairing; the AIK adoption below must not lose it.
                final java.util.List<eu.siacs.conversations.persistance.DatabaseBackend.X3dhpqLocalDeviceRow>
                        preAdoptDevices = dao.listX3dhpqLocalDevices(mAccountUuid);
                final eu.siacs.conversations.persistance.DatabaseBackend.X3dhpqLocalDeviceRow selfDevice =
                        preAdoptDevices.isEmpty() ? null : preAdoptDevices.get(0);

                // Embrace the account membership: adopt the account AIK, dropping
                // this device's own provisional one. The PUBLIC part is adopted
                // unconditionally so this device shows the account fingerprint and
                // can verify/anchor the account audit chain; the PRIVATE part is
                // adopted only when the confirmer shared it (share_primary), making
                // this device a full authorized manager. Mirrors Dino's
                // apply_paired_identity. Without adopting the pub, a device kept its
                // own AIK and stayed fail-closed (wrong fingerprint, chain can't
                // anchor) — the bug seen when share_primary was false.
                if (result.aikPub != null) {
                    final String fingerprint =
                            result.aikPub.fingerprint(
                                    im.conversations.x3dhpq.crypto.X3dhpqCrypto.BLAKE2B_160);
                    // Trust Manifest Phase 2 (contract §E): the account AIK *pub* is adopted
                    // (needed to verify the manifest genesis + pin the account root), but
                    // AIK_priv NO LONGER travels and is never adopted here — a newcomer
                    // manages the account by appearing in the manifest fold and signing
                    // under its own DIK, not by holding AIK_priv.
                    dao.putX3dhpqAccountIdentity(
                            mAccountUuid,
                            new byte[0],
                            result.aikPub.marshal(),
                            fingerprint);
                }

                // Persist the device certificate issued by the existing primary onto our
                // own local device row (captured before the AIK adoption above, so it
                // survives even if a future change reintroduces a cascading identity write).
                if (result.cert != null && selfDevice != null) {
                    dao.putX3dhpqLocalDevice(
                            mAccountUuid,
                            selfDevice.deviceId(),
                            selfDevice.dikPriv(),
                            result.cert.marshal(),
                            selfDevice.createdAt(),
                            result.cert.getFlags() & 0xFF);
                } else if (result.cert != null) {
                    Log.e(
                            Config.LOGTAG,
                            LOGTAG
                                    + ": no local device row at pairing install — cannot bind"
                                    + " issued DC; device would be stranded");
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
