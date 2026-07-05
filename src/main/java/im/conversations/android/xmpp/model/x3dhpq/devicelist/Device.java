package im.conversations.android.xmpp.model.x3dhpq.devicelist;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Per-device entry inside a devicelist; id and flags match the dino wire format.
@XmlElement(name = "device")
public class Device extends Extension {

    public Device() {
        super(Device.class);
    }

    public Integer getDeviceId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("id")));
    }

    public void setDeviceId(final int deviceId) {
        this.setAttribute("id", deviceId);
    }

    // added-at: unix seconds the device id was first added to the account.
    // Part of the signed devicelist input (§8.3); MUST be carried on the wire
    // (§8.4) so a receiver can reconstruct the identical SignedPart.
    public Long getAddedAt() {
        final String v = this.getAttribute("added-at");
        if (Strings.isNullOrEmpty(v)) {
            return null;
        }
        try {
            return Long.parseLong(v.trim());
        } catch (final NumberFormatException e) {
            return null;
        }
    }

    public void setAddedAt(final long addedAt) {
        this.setAttribute("added-at", Long.toString(addedAt));
    }

    // flags bitmask; 1 = capable of x3dhpq per protocol spec.
    public String getFlags() {
        return this.getAttribute("flags");
    }

    public void setFlags(final String flags) {
        this.setAttribute("flags", flags);
    }

    public Cert getCert() {
        return this.getExtension(Cert.class);
    }

    public void setCert(final Cert cert) {
        this.setExtension(cert);
    }
}
