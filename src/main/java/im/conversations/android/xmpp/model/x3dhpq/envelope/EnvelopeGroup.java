package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

/**
 * Root element of a group-encrypted message: {@code <x3dhpq-group>} in
 * {@code urn:xmppqr:x3dhpq:envelope:0}.
 *
 * Attributes:
 *   sender-aik-fp – hex fingerprint of the sender's AIK (for recv-chain lookup)
 *
 * Children:
 *   {@code <hdr>}  – base64 of GroupMessageHeader.marshal() (14 bytes)
 *   {@code <ct>}   – base64 of AES-256-GCM ciphertext + 16-byte tag
 *
 * This element wraps {@code <message type='groupchat'>}.
 */
@XmlElement(name = "x3dhpq-group")
public class EnvelopeGroup extends Extension {

    public EnvelopeGroup() {
        super(EnvelopeGroup.class);
    }

    public String getSenderAikFp() {
        return this.getAttribute("sender-aik-fp");
    }

    public void setSenderAikFp(final String fp) {
        this.setAttribute("sender-aik-fp", fp);
    }

    /** Returns the decoded GroupMessageHeader bytes, or an empty array if absent. */
    public byte[] getHdrBytes() {
        final Hdr hdrEl = this.getExtension(Hdr.class);
        if (hdrEl == null) return new byte[0];
        return hdrEl.asBytes();
    }

    /** Sets the {@code <hdr>} child from raw bytes (base64-encodes internally). */
    public void setHdrBytes(final byte[] hdrBytes) {
        final Hdr hdrEl = new Hdr();
        hdrEl.setContent(hdrBytes);
        this.setExtension(hdrEl);
    }

    /** Returns the decoded ciphertext bytes, or an empty array if absent. */
    public byte[] getCtBytes() {
        final GroupCt ctEl = this.getExtension(GroupCt.class);
        if (ctEl == null) return new byte[0];
        return ctEl.asBytes();
    }

    /** Sets the {@code <ct>} child from raw bytes (base64-encodes internally). */
    public void setCtBytes(final byte[] ct) {
        final GroupCt ctEl = new GroupCt();
        ctEl.setContent(ct);
        this.setExtension(ctEl);
    }
}
