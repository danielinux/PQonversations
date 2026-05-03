package im.conversations.android.xmpp.model.x3dhpq.pair;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Cross-device pairing message; step is the protocol step number, sid is the session id.
// Base64 payload is the binary-marshalled PairingMsg from x3dhpq-core.
@XmlElement(name = "pair")
public class Pair extends Extension implements ByteContent {

    public Pair() {
        super(Pair.class);
    }

    public Integer getStep() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("step")));
    }

    public void setStep(final int step) {
        this.setAttribute("step", step);
    }

    public String getSid() {
        return this.getAttribute("sid");
    }

    public void setSid(final String sid) {
        this.setAttribute("sid", sid);
    }
}
