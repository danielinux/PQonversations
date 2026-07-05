package eu.siacs.conversations.ui;

import android.widget.Toast;
import de.gultsch.common.MiniUri;
import eu.siacs.conversations.R;

// OMEMO has been removed from this app; x3dhpq is the sole E2EE. This class is
// retained only as a thin base providing QR-code scanning for the activities
// that still extend it (ContactDetailsActivity, EditAccountActivity).
public abstract class OmemoActivity extends QrCodeScanningActivity {

    protected String mSelectedFingerprint;

    protected MiniUri.Xmpp mPendingFingerprintVerificationUri = null;

    protected void onQrCodeScanned(final String code) {
        final MiniUri miniUri;
        try {
            miniUri = MiniUri.tryParse(code.trim());
        } catch (final IllegalArgumentException e) {
            Toast.makeText(this, R.string.invalid_barcode, Toast.LENGTH_LONG).show();
            return;
        }
        if (miniUri instanceof MiniUri.Xmpp xmpp && xmpp.isAddress()) {
            if (xmppConnectionServiceBound) {
                processFingerprintVerification(xmpp);
            } else {
                this.mPendingFingerprintVerificationUri = xmpp;
            }
        } else if (miniUri instanceof MiniUri.Transformable transformable
                && transformable.transform() instanceof MiniUri.Xmpp xmpp
                && xmpp.isAddress()) {
            if (xmppConnectionServiceBound) {
                processFingerprintVerification(xmpp);
            } else {
                this.mPendingFingerprintVerificationUri = xmpp;
            }
        } else {
            Toast.makeText(this, R.string.invalid_barcode, Toast.LENGTH_LONG).show();
        }
    }

    protected abstract void processFingerprintVerification(MiniUri.Xmpp uri);
}
