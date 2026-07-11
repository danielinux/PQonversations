package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// AES-256-GCM ciphertext of the message body (base64-encoded).
// The optional {@code type} attribute signals the payload kind:
//   absent / "chat"  – normal UTF-8 encrypted body (default)
//   "sender-chain"   – serialised SenderChainAnnouncement for group crypto (§13)
@XmlElement(name = "payload")
public class Payload extends Extension implements ByteContent {

    public Payload() {
        super(Payload.class);
    }

    public String getType() {
        return this.getAttribute("type");
    }

    public void setType(final String type) {
        this.setAttribute("type", type);
    }

    public boolean isSenderChain() {
        return "sender-chain".equals(getType());
    }

    // "group-sync" bundles the SenderChainAnnouncement with the membership journal
    // (delivered over the pairwise channel so it doesn't depend on MUC MAM).
    public boolean isGroupSync() {
        return "group-sync".equals(getType());
    }
}
