package im.conversations.android.xmpp.model.x3dhpq.devicelist;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import java.util.Collection;

// Root element of the x3dhpq devicelist PEP item (§8 of the XEP draft).
@XmlElement(name = "devicelist")
public class DeviceList extends Extension {

    public DeviceList() {
        super(DeviceList.class);
    }

    public String getVersion() {
        return this.getAttribute("version");
    }

    public void setVersion(final String version) {
        this.setAttribute("version", version);
    }

    public String getIssuedAt() {
        return this.getAttribute("issued-at");
    }

    // issued-at is a Unix timestamp string as published by the dino fork.
    public void setIssuedAt(final String issuedAt) {
        this.setAttribute("issued-at", issuedAt);
    }

    public Collection<Device> getDevices() {
        return this.getExtensions(Device.class);
    }

    public void addDevice(final Device device) {
        this.addExtension(device);
    }
}
