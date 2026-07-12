// SPDX-License-Identifier: AGPL-3.0-or-later
// Namespace for the Trust Manifest Phase 2 PEP item
// (wire: urn:xmppqr:x3dhpq:trustmanifest:0). The whole TrustManifest.marshal() blob is
// carried as base64 text of the single <trustmanifest> element (contract §A).
@XmlPackage(namespace = Namespace.X3DHPQ_TRUSTMANIFEST)
package im.conversations.android.xmpp.model.x3dhpq.trustmanifest;

import im.conversations.android.annotation.XmlPackage;
import eu.siacs.conversations.xml.Namespace;
