package im.conversations.android.xmpp.model.x3dhpq.devtracker;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.MldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Sig;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Key;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Payload;
import java.util.Collection;

/**
 * x3dhpq-xep-draft.md §11.8: the sealed device-state tracker PEP item, published at
 * {@code urn:xmppqr:x3dhpq:devtracker:0} (item {@code current}, {@code +notify},
 * whitelist/owner-only access — this is account-internal state, never read by contacts).
 *
 * <p>Reuses the exact 1:1 pairwise-envelope wire shape (§9.3/§9.3a, {@link
 * im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope}): one {@code <key
 * rid=..>} block per authorized device (hybrid X25519+ML-KEM-768 {@code <emk>}-sealed
 * transport key, {@code <hdr>} ratchet header, and — since every seal is a fresh,
 * self-contained PQXDH "first message" so that "decryptability = authorization" holds
 * even for a device with no prior session state — a {@code <prekey>} block), plus one
 * AES-256-GCM {@code <payload>} carrying the folded {@code DeviceState}. Deliberately
 * does NOT subclass {@code Envelope} (which fixes its own {@code @XmlElement} identity
 * in its no-arg constructor); {@link
 * eu.siacs.conversations.crypto.x3dhpq.XmppX3dhpqMessage#fromExtension} is fed a
 * throwaway {@code Envelope} copy of this element's fields on the decrypt path instead,
 * keeping the shared message-envelope class untouched.
 *
 * <p>The whole item is additionally AIK-signed (hybrid): {@code <sig>}/{@code
 * <mldsa-sig>} are the last children of {@code <devtracker>} (mirrors §8.4's devicelist
 * placement, so they survive the PEP {@code +notify} path where a receiver is handed
 * only this element).
 *
 * <p>{@code sender-device}/{@code sender-jid} record which device authored this publish
 * (§11.6 "was this you?" UX only — never an authorization input).
 */
@XmlElement(name = "devtracker")
public class DevTracker extends Extension {

    public DevTracker() {
        super(DevTracker.class);
    }

    public String getSenderDevice() {
        return this.getAttribute("sender-device");
    }

    public void setSenderDevice(final int senderDevice) {
        this.setAttribute("sender-device", senderDevice);
    }

    public String getSenderJid() {
        return this.getAttribute("sender-jid");
    }

    public void setSenderJid(final String senderJid) {
        this.setAttribute("sender-jid", senderJid);
    }

    public String getTs() {
        return this.getAttribute("ts");
    }

    public void setTs(final String ts) {
        this.setAttribute("ts", ts);
    }

    public Collection<Key> getKeys() {
        return this.getExtensions(Key.class);
    }

    public void addKey(final Key key) {
        this.addExtension(key);
    }

    public Payload getPayload() {
        return this.getExtension(Payload.class);
    }

    public void setPayload(final Payload payload) {
        this.setExtension(payload);
    }

    /** Monotonic per-account counter (§8.2-style rollback guard), advanced on every republish. */
    public String getVersion() {
        return this.getAttribute("version");
    }

    public void setVersion(final long version) {
        this.setAttribute("version", Long.toUnsignedString(version));
    }

    public String getIssuedAt() {
        return this.getAttribute("issued-at");
    }

    public void setIssuedAt(final long issuedAtUnixSeconds) {
        this.setAttribute("issued-at", Long.toString(issuedAtUnixSeconds));
    }

    // Hybrid AIK signature over the tracker SignedPart (domain-separated digest of
    // version, issued-at, the payload ciphertext, and the per-recipient key blocks).
    // NOT covered by the SignedPart itself, mirroring devicelist's §8.4 placement.
    public Sig getSig() {
        return this.getExtension(Sig.class);
    }

    public void setSig(final byte[] sigEd25519) {
        final Sig sig = new Sig();
        sig.setContent(sigEd25519);
        this.addExtension(sig);
    }

    public MldsaSig getMldsaSig() {
        return this.getExtension(MldsaSig.class);
    }

    public void setMldsaSig(final byte[] sigMldsa) {
        final MldsaSig mldsaSig = new MldsaSig();
        mldsaSig.setContent(sigMldsa);
        this.addExtension(mldsaSig);
    }
}
