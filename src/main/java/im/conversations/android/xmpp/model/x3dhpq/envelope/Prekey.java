package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Prekey block present only on the initial (session-bootstrapping) message.
@XmlElement(name = "prekey")
public class Prekey extends Extension {

    public Prekey() {
        super(Prekey.class);
    }

    // ek is the base64-encoded ephemeral X25519 public key.
    public String getEk() {
        return this.getAttribute("ek");
    }

    public void setEk(final String ek) {
        this.setAttribute("ek", ek);
    }

    // opk-id identifies which one-time pre-key was consumed (0 means none).
    public String getOpkId() {
        return this.getAttribute("opk-id");
    }

    public void setOpkId(final int opkId) {
        this.setAttribute("opk-id", opkId);
    }

    // kemkey-id identifies which KEM pre-key was consumed.
    public String getKemkeyId() {
        return this.getAttribute("kemkey-id");
    }

    public void setKemkeyId(final int kemkeyId) {
        this.setAttribute("kemkey-id", kemkeyId);
    }

    // kem-ct is the base64-encoded KEM ciphertext.
    public String getKemCt() {
        return this.getAttribute("kem-ct");
    }

    public void setKemCt(final String kemCt) {
        this.setAttribute("kem-ct", kemCt);
    }

    // dc, aik-ed25519, aik-mldsa reuse bundle element names but live in envelope NS.
    public PrekeyDc getDc() {
        return this.getExtension(PrekeyDc.class);
    }

    public PrekeyAikEd25519 getAikEd25519() {
        return this.getExtension(PrekeyAikEd25519.class);
    }

    public PrekeyAikMldsa getAikMldsa() {
        return this.getExtension(PrekeyAikMldsa.class);
    }
}
