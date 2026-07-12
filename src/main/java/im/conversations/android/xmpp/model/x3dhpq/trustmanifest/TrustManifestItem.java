// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.android.xmpp.model.x3dhpq.trustmanifest;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

/**
 * Trust Manifest Phase 2 transport element (contract §A). A single
 * {@code <trustmanifest xmlns="urn:xmppqr:x3dhpq:trustmanifest:0">} whose TEXT CHILD is
 * {@code base64(im.conversations.x3dhpq.types.TrustManifest.marshal())}. No structured
 * child elements — the whole manifest (head + embedded entries + head sig) is the single
 * marshalled, byte-identical (Phase 1 KAT-locked) blob. Robust to XML-formatting
 * differences between clients.
 */
@XmlElement(name = "trustmanifest")
public class TrustManifestItem extends Extension implements ByteContent {

    public TrustManifestItem() {
        super(TrustManifestItem.class);
    }
}
