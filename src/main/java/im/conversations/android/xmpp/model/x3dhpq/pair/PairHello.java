package im.conversations.android.xmpp.model.x3dhpq.pair;

import com.google.common.base.Strings;
import com.google.common.primitives.Longs;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Serverless pairing rendezvous element (XEP §10.1a). Carries only addressing —
// the new device's `device-id`, its `full-jid`, and the CPace session id `sid`
// (base64url, no padding). No secret/key material is ever placed here.
//
// Method B: the new device publishes this to its OWN PEP node
// `urn:xmppqr:x3dhpq:pair:0` (item `current`, whitelist access); the existing
// primary receives it via self-PEP +notify.
// Method A: the new device sends the same element in a directed <message> to the
// existing device's full JID (learned from the scanned QR).
// Either way the existing device reads `full-jid`+`sid` and sends PairingMsgPAKE1.
@XmlElement(name = "pair-hello")
public class PairHello extends Extension {

    public PairHello() {
        super(PairHello.class);
    }

    /** The new device's uint32 device-id, as a decimal string. */
    public Long getDeviceId() {
        return Longs.tryParse(Strings.nullToEmpty(this.getAttribute("device-id")));
    }

    public void setDeviceId(final int deviceId) {
        this.setAttribute("device-id", Integer.toUnsignedString(deviceId));
    }

    /** The new device's full JID (including resource) — where PAKE1 is sent. */
    public String getFullJid() {
        return this.getAttribute("full-jid");
    }

    public void setFullJid(final String fullJid) {
        this.setAttribute("full-jid", fullJid);
    }

    /** The CPace session id, base64url with no padding. */
    public String getSid() {
        return this.getAttribute("sid");
    }

    public void setSid(final String sid) {
        this.setAttribute("sid", sid);
    }
}
