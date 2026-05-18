package im.conversations.android.xmpp.model.x3dhpq.pair;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Project-internal `<verify-device>` extension to NS_PAIR. Used in two
// directions: as a child of an outbound IQ-set asking the server to
// announce the new resource, and as a child of an inbound headline
// `<message>` notifying existing devices that a new resource has bound.
@XmlElement(name = "verify-device")
public class VerifyDevice extends Extension {

    public VerifyDevice() {
        super(VerifyDevice.class);
    }

    public Integer getDeviceId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("device-id")));
    }

    public void setDeviceId(final int deviceId) {
        this.setAttribute("device-id", deviceId);
    }

    public String getTransport() {
        return this.getAttribute("transport");
    }

    public void setTransport(final String transport) {
        this.setAttribute("transport", transport);
    }

    public String getNewResource() {
        return this.getAttribute("new-resource");
    }

    public void setNewResource(final String newResource) {
        this.setAttribute("new-resource", newResource);
    }
}
