package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import java.util.Collection;

// Root element of an x3dhpq bundle PEP item (§9.1 of the XEP draft).
@XmlElement(name = "bundle")
public class Bundle extends Extension {

    public Bundle() {
        super(Bundle.class);
    }

    public AikEd25519 getAikEd25519() {
        return this.getExtension(AikEd25519.class);
    }

    public AikMldsa getAikMldsa() {
        return this.getExtension(AikMldsa.class);
    }

    public Dc getDc() {
        return this.getExtension(Dc.class);
    }

    public DikEd25519 getDikEd25519() {
        return this.getExtension(DikEd25519.class);
    }

    // ik holds the X25519 device identity key (dik-x25519 in dino nomenclature).
    public Ik getIk() {
        return this.getExtension(Ik.class);
    }

    public DikMldsa getDikMldsa() {
        return this.getExtension(DikMldsa.class);
    }

    public Spk getSpk() {
        return this.getExtension(Spk.class);
    }

    public Kemkeys getKemkeys() {
        return this.getExtension(Kemkeys.class);
    }

    public Opks getOpks() {
        return this.getExtension(Opks.class);
    }
}
