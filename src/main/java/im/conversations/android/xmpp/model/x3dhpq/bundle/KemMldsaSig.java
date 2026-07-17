package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// ML-DSA-65 signature by the DIK over a KEM pre-key's public key; base64 text
// content. Paired with the reused <key>/<sig> (SpkKey/SpkSig) children inside a
// <kemkey> to form the hybrid KEM signature (spec §9.1). Distinct element name
// from the SPK (which is Ed25519-only) so both coexist in the bundle namespace.
@XmlElement(name = "mldsa-sig")
public class KemMldsaSig extends Extension implements ByteContent {

    public KemMldsaSig() {
        super(KemMldsaSig.class);
    }
}
