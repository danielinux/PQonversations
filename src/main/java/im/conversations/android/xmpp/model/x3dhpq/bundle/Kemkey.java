package im.conversations.android.xmpp.model.x3dhpq.bundle;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// A single ML-KEM-768 pre-key. Structured like <spk>: an id attribute plus a
// <key> (1184-byte pubkey), a <sig> (DIK Ed25519 sig) and a <mldsa-sig> (DIK
// ML-DSA-65 sig), the pair forming the hybrid KEM signature required by §9.1.
// The <key>/<sig> children reuse SpkKey/SpkSig (same element names/namespace).
@XmlElement(name = "kemkey")
public class Kemkey extends Extension {

    public Kemkey() {
        super(Kemkey.class);
    }

    public Integer getId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("id")));
    }

    public void setId(final int id) {
        this.setAttribute("id", id);
    }

    public SpkKey getKey() {
        return this.getExtension(SpkKey.class);
    }

    public SpkSig getSig() {
        return this.getExtension(SpkSig.class);
    }

    public KemMldsaSig getMldsaSig() {
        return this.getExtension(KemMldsaSig.class);
    }
}
