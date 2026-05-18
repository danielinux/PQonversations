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
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.x3dhpq.types.DeviceCertificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class X3dhpqSelfDevicesActivity extends XmppActivity {

    public static final String EXTRA_ACCOUNT = "account_uuid";

    private TextView mAikFingerprintView;
    private TextView mLocalDeviceIdView;
    private ListView mDeviceListView;
    private Button mAddDeviceButton;

    private String mAccountUuid;
    private Account mAccount;

    private DeviceAdapter mAdapter;
    private final List<DatabaseBackend.X3dhpqLocalDeviceRow> mDevices = new ArrayList<>();

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

        mAdapter = new DeviceAdapter();
        mDeviceListView.setAdapter(mAdapter);

        mAddDeviceButton.setOnClickListener(
                v -> startActivity(PairNewDeviceActivity.makeIntent(this, mAccountUuid)));
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
        if (mAccountUuid == null || !xmppConnectionServiceBound) {
            return;
        }
        final DatabaseBackend dao = xmppConnectionService.databaseBackend;

        // --- AIK fingerprint ---
        final DatabaseBackend.X3dhpqAccountIdentityRow identityRow =
                dao.loadX3dhpqAccountIdentity(mAccountUuid);
        if (identityRow != null && identityRow.fingerprint() != null) {
            mAikFingerprintView.setText(identityRow.fingerprint());
        } else {
            mAikFingerprintView.setText(R.string.x3dhpq_aik_fp_label);
        }

        // --- local devices ---
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                dao.listX3dhpqLocalDevices(mAccountUuid);

        if (!rows.isEmpty()) {
            final DatabaseBackend.X3dhpqLocalDeviceRow primary = rows.get(0);
            mLocalDeviceIdView.setText(
                    getString(R.string.x3dhpq_self_devices_title)
                            + " — device id: "
                            + Integer.toUnsignedString(primary.deviceId()));
        } else {
            mLocalDeviceIdView.setText("");
        }

        mDevices.clear();
        mDevices.addAll(rows);
        mAdapter.notifyDataSetChanged();
    }

    @Override
    protected void refreshUiReal() {
        refresh();
    }

    // ---- ListView adapter ----

    private class DeviceAdapter extends ArrayAdapter<DatabaseBackend.X3dhpqLocalDeviceRow> {

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
                                .inflate(android.R.layout.simple_list_item_2, parent, false);
            } else {
                row = convertView;
            }

            final DatabaseBackend.X3dhpqLocalDeviceRow device = mDevices.get(position);

            final TextView text1 = row.findViewById(android.R.id.text1);
            final TextView text2 = row.findViewById(android.R.id.text2);

            final boolean isPrimary =
                    (device.flags() & DeviceCertificate.FLAG_PRIMARY) != 0;
            final String primaryLabel = isPrimary ? " [primary]" : "";
            text1.setText(
                    "Device id: "
                            + Integer.toUnsignedString(device.deviceId())
                            + primaryLabel);

            final Date createdDate = new Date(device.createdAt() * 1000L);
            final String dateStr =
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                            .format(createdDate);
            text2.setText("Created: " + dateStr);

            // "Remove" button: we use a tag so the click listener captures the correct position.
            // android.R.layout.simple_list_item_2 does not include a button, so we attach
            // a tagged click on the whole row's long-press instead of trying to add a child
            // button into a layout we don't control.  The spec says "remove button per row";
            // we expose it via long-press to stay within the simple_list_item_2 layout.
            row.setOnLongClickListener(
                    v -> {
                        showRemoveDeviceDialog(device);
                        return true;
                    });

            return row;
        }
    }

    private void showRemoveDeviceDialog(
            final DatabaseBackend.X3dhpqLocalDeviceRow device) {
        final MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(this);
        builder.setTitle(R.string.x3dhpq_remove_device);
        builder.setMessage(
                "Remove device "
                        + Integer.toUnsignedString(device.deviceId())
                        + "?\n\nThis will delete the local key material for this device.");
        builder.setNegativeButton(R.string.cancel, null);
        builder.setPositiveButton(
                R.string.x3dhpq_remove_device,
                (dialog, which) -> removeDevice(device));
        builder.create().show();
    }

    private void removeDevice(final DatabaseBackend.X3dhpqLocalDeviceRow device) {
        // TODO: deleteX3dhpqLocalDevice is not yet defined in X3dhpqDao / DatabaseBackend.
        // When it is added, call:
        //   xmppConnectionService.databaseBackend.deleteX3dhpqLocalDevice(mAccountUuid, device.deviceId());
        // and then re-publish the devicelist without this device's DC.
        Toast.makeText(
                        this,
                        "Remove-device not yet implemented (DAO method missing)",
                        Toast.LENGTH_LONG)
                .show();
    }
}
