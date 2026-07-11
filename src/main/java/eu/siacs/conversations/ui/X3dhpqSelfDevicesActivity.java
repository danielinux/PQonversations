package eu.siacs.conversations.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import eu.siacs.conversations.R;
import eu.siacs.conversations.crypto.x3dhpq.X3dhpqService;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * The device-management screen for an x3dhpq account (§8, §10.6, §11): the account's AIK
 * fingerprint, every associated device (this install's own device plus every co-account
 * sibling, §10.6.3 trust-gated), both pairing directions (§10.6.2), the §10.6.4
 * registration-choice UX while pending, explicit per-device revocation (§8.6), and the
 * §10.6.5 peer re-trust list.
 */
public class X3dhpqSelfDevicesActivity extends XmppActivity {

    public static final String EXTRA_ACCOUNT = "account_uuid";

    private TextView mAikFingerprintView;
    private TextView mLocalDeviceIdView;
    private ListView mDeviceListView;
    private Button mAddDeviceButton;
    private Button mConfirmWaitingDeviceButton;
    private View mPendingEnrollmentBanner;
    private TextView mPendingEnrollmentTitleView;
    private TextView mPendingEnrollmentTextView;
    private Button mAssociateExistingIdentityButton;
    private Button mGenerateNewIdentityButton;
    private View mBlockedIdentitiesContainer;
    private ListView mBlockedIdentitiesList;
    private View mJoinRequestBanner;
    private TextView mJoinRequestTextView;
    private Button mReviewJoinRequestButton;

    private String mAccountUuid;
    private Account mAccount;

    private DeviceAdapter mAdapter;
    private final List<X3dhpqService.AssociatedDevice> mDevices = new ArrayList<>();
    private ArrayAdapter<String> mBlockedAdapter;
    private final List<String> mBlockedPeers = new ArrayList<>();

    public static Intent makeIntent(final Context ctx, final String accountUuid) {
        final Intent intent = new Intent(ctx, X3dhpqSelfDevicesActivity.class);
        intent.putExtra(EXTRA_ACCOUNT, accountUuid);
        return intent;
    }

    @Override
    protected void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_x3dhpq_self_devices);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(R.string.x3dhpq_self_devices_title);
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        mAccountUuid = getIntent().getStringExtra(EXTRA_ACCOUNT);

        mAikFingerprintView = findViewById(R.id.aik_fingerprint);
        mLocalDeviceIdView = findViewById(R.id.local_device_id);
        mDeviceListView = findViewById(R.id.device_list);
        mAddDeviceButton = findViewById(R.id.add_device_button);
        mConfirmWaitingDeviceButton = findViewById(R.id.confirm_waiting_device_button);
        mPendingEnrollmentBanner = findViewById(R.id.pending_enrollment_banner);
        mPendingEnrollmentTitleView = findViewById(R.id.pending_enrollment_title);
        mPendingEnrollmentTextView = findViewById(R.id.pending_enrollment_text);
        mAssociateExistingIdentityButton = findViewById(R.id.associate_existing_identity_button);
        mGenerateNewIdentityButton = findViewById(R.id.generate_new_identity_button);
        mBlockedIdentitiesContainer = findViewById(R.id.blocked_identities_container);
        mBlockedIdentitiesList = findViewById(R.id.blocked_identities_list);
        mJoinRequestBanner = findViewById(R.id.join_request_banner);
        mJoinRequestTextView = findViewById(R.id.join_request_text);
        mReviewJoinRequestButton = findViewById(R.id.review_join_request_button);

        mAdapter = new DeviceAdapter();
        mDeviceListView.setAdapter(mAdapter);

        mBlockedAdapter =
                new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, mBlockedPeers);
        mBlockedIdentitiesList.setAdapter(mBlockedAdapter);
        mBlockedIdentitiesList.setOnItemClickListener(
                (parent, view, position, id) -> showRetrustDialog(mBlockedPeers.get(position)));

        // §10.6.2 "Link a new device": this device shows its own code/QR for a new device
        // to scan (also listens passively for a self-PEP pair-hello, method B).
        mAddDeviceButton.setOnClickListener(
                v -> startActivity(PairNewDeviceActivity.makeIntent(this, mAccountUuid)));
        // §10.6.2 "Confirm a waiting device": jump straight to scanning the code/QR a
        // pending device is already showing (new-device-presents direction).
        mConfirmWaitingDeviceButton.setOnClickListener(
                v -> startActivity(PairNewDeviceActivity.makeIntentConfirmPending(this, mAccountUuid)));
        // §10.6.4a: the default, non-destructive registration choice — pair this pending
        // device under the account's existing identity.
        mAssociateExistingIdentityButton.setOnClickListener(
                v -> startActivity(PairToExistingActivity.makeIntent(this, mAccountUuid)));
        mGenerateNewIdentityButton.setOnClickListener(v -> showGenerateNewIdentityDialog());
        // §11.8 queued enrollment request: jump straight to the "confirm a waiting
        // device" scan flow, same entry point as the manual button, and clear the
        // banner state now that a human is acting on it.
        mReviewJoinRequestButton.setOnClickListener(
                v -> {
                    if (mAccount != null) {
                        eu.siacs.conversations.xmpp.manager.VerifyDeviceManager.clearPendingJoinRequest(
                                this, mAccount.getJid().asBareJid().toString());
                    }
                    startActivity(PairNewDeviceActivity.makeIntentConfirmPending(this, mAccountUuid));
                });
    }

    /** §10.6.4b: destructive confirmation dialog before minting a brand-new identity. */
    private void showGenerateNewIdentityDialog() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.x3dhpq_generate_new_identity_button)
                .setMessage(R.string.x3dhpq_generate_new_identity_confirm)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(
                        R.string.x3dhpq_generate_new_identity_button,
                        (dialog, which) -> {
                            if (mAccount != null && xmppConnectionServiceBound) {
                                mAccount.getX3dhpqService().performAccountReset();
                                Toast.makeText(this, R.string.x3dhpq_pair_status_done, Toast.LENGTH_LONG)
                                        .show();
                                refresh();
                            }
                        })
                .create()
                .show();
    }

    /** §10.6.5: explicit re-trust confirmation for a peer whose identity was reconstructed. */
    private void showRetrustDialog(final String peerBareJid) {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.x3dhpq_retrust_button)
                .setMessage(getString(R.string.x3dhpq_blocked_identities_help) + "\n\n" + peerBareJid)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(
                        R.string.x3dhpq_retrust_button,
                        (dialog, which) -> {
                            if (mAccount != null && xmppConnectionServiceBound) {
                                try {
                                    mAccount.getX3dhpqService()
                                            .reTrustIdentity(eu.siacs.conversations.xmpp.Jid.of(peerBareJid));
                                } catch (final IllegalArgumentException ignored) {
                                    // malformed JID string; nothing to do
                                }
                                refresh();
                            }
                        })
                .create()
                .show();
    }

    @Override
    public void onBackendConnected() {
        if (mAccountUuid == null) {
            return;
        }
        mAccount = xmppConnectionService.findAccountByUuid(mAccountUuid);
        if (mAccount == null) {
            return;
        }
        refresh();
    }

    /** Refresh the list view from the DAO + current devicelist. */
    public void refresh() {
        if (mAccountUuid == null || !xmppConnectionServiceBound || mAccount == null) {
            return;
        }
        final DatabaseBackend dao = xmppConnectionService.databaseBackend;
        final X3dhpqService service = mAccount.getX3dhpqService();

        // --- AIK fingerprint (prominent, for OOB compare) ---
        final DatabaseBackend.X3dhpqAccountIdentityRow identityRow =
                dao.loadX3dhpqAccountIdentity(mAccountUuid);
        if (identityRow != null && identityRow.fingerprint() != null) {
            mAikFingerprintView.setText(identityRow.fingerprint());
        } else {
            mAikFingerprintView.setText(R.string.x3dhpq_aik_fp_label);
        }

        // --- §10.6.1/§10.6.4 pending-enrollment banner, extended by §11.8: a device
        //     that lost the ability to decrypt the sealed device-state tracker (offline
        //     revocation detection) is shown the same associate-or-reset choice. ---
        final boolean pendingEnrollment = service.isPendingEnrollment();
        final boolean revoked = !pendingEnrollment && service.isDisabledByTrackerRevocation();
        final boolean pending = pendingEnrollment || revoked;
        mPendingEnrollmentBanner.setVisibility(pending ? View.VISIBLE : View.GONE);
        if (revoked) {
            mPendingEnrollmentTitleView.setText(R.string.x3dhpq_identity_revoked_title);
            mPendingEnrollmentTextView.setText(R.string.x3dhpq_identity_revoked_text);
        } else {
            mPendingEnrollmentTitleView.setText(R.string.x3dhpq_pending_enrollment_title);
            mPendingEnrollmentTextView.setText(R.string.x3dhpq_pending_enrollment_text);
        }
        mDeviceListView.setVisibility(pending ? View.GONE : View.VISIBLE);
        mAddDeviceButton.setEnabled(!pending);
        mConfirmWaitingDeviceButton.setEnabled(!pending);

        // --- §11.8 queued enrollment request banner ---
        final String joinRequestFullJid = eu.siacs.conversations.xmpp.manager.VerifyDeviceManager
                .getPendingJoinRequestFullJid(this, mAccount.getJid().asBareJid().toString());
        if (joinRequestFullJid != null && !pending) {
            mJoinRequestBanner.setVisibility(View.VISIBLE);
            mJoinRequestTextView.setText(
                    getString(R.string.x3dhpq_join_request_text, joinRequestFullJid));
        } else {
            mJoinRequestBanner.setVisibility(View.GONE);
        }

        // --- associated devices: union of this install's own device + every co-account
        //     sibling, §10.6.3 trust-gated (empty while pending — see above). ---
        final Integer ownDeviceId = service.getOwnDeviceIdOrNull();
        if (!pending && ownDeviceId != null) {
            mLocalDeviceIdView.setText(
                    getString(R.string.x3dhpq_self_devices_title)
                            + " — device id: "
                            + Integer.toUnsignedString(ownDeviceId));
        } else {
            mLocalDeviceIdView.setText("");
        }

        mDevices.clear();
        if (!pending) {
            mDevices.addAll(service.listAssociatedDevices());
        }
        mAdapter.notifyDataSetChanged();

        // --- §10.6.5 blocked/unconfirmed identities awaiting explicit re-trust ---
        mBlockedPeers.clear();
        for (final eu.siacs.conversations.entities.Conversation c :
                xmppConnectionService.getConversations()) {
            if (c.getAccount() == mAccount && service.isIdentityBlocked(c)) {
                mBlockedPeers.add(c.getAddress().asBareJid().toString());
            }
        }
        mBlockedIdentitiesContainer.setVisibility(mBlockedPeers.isEmpty() ? View.GONE : View.VISIBLE);
        mBlockedAdapter.notifyDataSetChanged();
    }

    @Override
    protected void refreshUiReal() {
        refresh();
    }

    // ---- ListView adapter ----

    private class DeviceAdapter extends ArrayAdapter<X3dhpqService.AssociatedDevice> {

        DeviceAdapter() {
            super(X3dhpqSelfDevicesActivity.this, 0, mDevices);
        }

        @NonNull
        @Override
        public View getView(
                final int position,
                @Nullable final View convertView,
                @NonNull final ViewGroup parent) {
            final View row;
            if (convertView == null) {
                row =
                        LayoutInflater.from(getContext())
                                .inflate(R.layout.item_x3dhpq_device, parent, false);
            } else {
                row = convertView;
            }

            final X3dhpqService.AssociatedDevice device = mDevices.get(position);

            final TextView labelView = row.findViewById(R.id.device_label);
            final TextView statusView = row.findViewById(R.id.device_status);
            final TextView fingerprintView = row.findViewById(R.id.device_fingerprint);
            final TextView addedAtView = row.findViewById(R.id.device_added_at);
            final Button revokeButton = row.findViewById(R.id.device_revoke_button);

            final StringBuilder label = new StringBuilder();
            label.append("Device ").append(Integer.toUnsignedString(device.deviceId));
            if (device.thisDevice) {
                label.append(" — ").append(getString(R.string.x3dhpq_device_this_device));
            }
            labelView.setText(label.toString());

            final String role =
                    getString(
                            device.primary
                                    ? R.string.x3dhpq_device_role_primary
                                    : R.string.x3dhpq_device_role_secondary);
            final String status =
                    getString(
                            device.confirmed
                                    ? R.string.x3dhpq_device_status_confirmed
                                    : R.string.x3dhpq_device_status_pending);
            statusView.setText(role + " · " + status);

            if (device.cert != null) {
                fingerprintView.setText(device.cert.fingerprint(X3dhpqCrypto.BLAKE2B_160));
            } else {
                fingerprintView.setText(R.string.x3dhpq_device_fingerprint_unavailable);
            }

            final Date addedDate = new Date(device.addedAt * 1000L);
            final String dateStr =
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                            .format(addedDate);
            addedAtView.setText(getString(R.string.x3dhpq_device_added_at, dateStr));

            revokeButton.setOnClickListener(v -> showRemoveDeviceDialog(device));

            return row;
        }
    }

    private void showRemoveDeviceDialog(final X3dhpqService.AssociatedDevice device) {
        final MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(this);
        builder.setTitle(R.string.x3dhpq_remove_device);
        final String deviceIdStr = Integer.toUnsignedString(device.deviceId);
        builder.setMessage(
                device.thisDevice
                        ? getString(R.string.x3dhpq_remove_this_device_confirm, deviceIdStr)
                        : getString(R.string.x3dhpq_remove_device_confirm, deviceIdStr));
        builder.setNegativeButton(R.string.cancel, null);
        builder.setPositiveButton(
                R.string.x3dhpq_remove_device,
                (dialog, which) -> removeDevice(device));
        builder.create().show();
    }

    private void removeDevice(final X3dhpqService.AssociatedDevice device) {
        if (mAccount == null || !xmppConnectionServiceBound) {
            Toast.makeText(this, "Not connected", Toast.LENGTH_SHORT).show();
            return;
        }
        // Revokes the device (§8.6): republishes the signed devicelist with a bumped
        // version omitting it, appends a RemoveDevice audit entry, and tears down its
        // local key material / sessions (self-revoke and revoking a sibling both go
        // through the same account-level operation).
        mAccount.getX3dhpqService().revokeOwnDevice(device.deviceId);
        Toast.makeText(
                        this,
                        "Removed device " + Integer.toUnsignedString(device.deviceId),
                        Toast.LENGTH_LONG)
                .show();
        refresh();
    }
}
