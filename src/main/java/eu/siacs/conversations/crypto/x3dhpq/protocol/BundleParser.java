// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq.protocol;

import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkeys;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opks;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Spk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkKey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkSig;
import im.conversations.x3dhpq.protocol.BundleData;

import java.util.ArrayList;
import java.util.List;

// Converts a parsed XML Bundle extension into the Android-XML-free BundleData POJO.
// Lives in the app package because Bundle and related classes reference Android XML infrastructure.
public final class BundleParser {

    private BundleParser() {}

    /**
     * Extracts all raw-byte fields from the given XML Bundle extension into a BundleData.
     * Any missing optional fields (e.g. no OPKs) become empty lists or null byte arrays.
     *
     * @throws IllegalArgumentException if mandatory fields (dikX25519Pub, spkPub, kemPreKeys) are absent
     */
    public static BundleData fromBundle(Bundle bundle) {
        if (bundle == null) throw new IllegalArgumentException("bundle must not be null");

        // AIK fields — optional for the DH but required to verify trust chain.
        byte[] aikEd25519Pub = bundle.getAikEd25519() != null
                ? bundle.getAikEd25519().asBytes() : null;
        byte[] aikMldsaPub = bundle.getAikMldsa() != null
                ? bundle.getAikMldsa().asBytes() : null;
        byte[] dcMarshal = bundle.getDc() != null
                ? bundle.getDc().asBytes() : null;

        // DIK fields.
        byte[] dikEd25519Pub = bundle.getDikEd25519() != null
                ? bundle.getDikEd25519().asBytes() : null;
        // ik element holds the X25519 half of the device identity key.
        byte[] dikX25519Pub = bundle.getIk() != null ? bundle.getIk().asBytes() : null;
        if (dikX25519Pub == null || dikX25519Pub.length == 0) {
            throw new IllegalArgumentException("bundle is missing the ik (dik-x25519) element");
        }
        byte[] dikMldsaPub = bundle.getDikMldsa() != null
                ? bundle.getDikMldsa().asBytes() : null;

        // SPK.
        Spk spkEl = bundle.getSpk();
        if (spkEl == null) throw new IllegalArgumentException("bundle is missing the spk element");
        Integer spkId = spkEl.getId();
        if (spkId == null) throw new IllegalArgumentException("spk element is missing its id");
        SpkKey spkKeyEl = spkEl.getKey();
        byte[] spkPub = spkKeyEl != null ? spkKeyEl.asBytes() : null;
        if (spkPub == null || spkPub.length == 0) {
            throw new IllegalArgumentException("spk element is missing the key sub-element");
        }
        SpkSig spkSigEl = spkEl.getSig();
        byte[] spkSig = spkSigEl != null ? spkSigEl.asBytes() : null;

        // KEM pre-keys.
        List<BundleData.KemPreKey> kemPreKeys = new ArrayList<>();
        Kemkeys kemkeysEl = bundle.getKemkeys();
        if (kemkeysEl != null) {
            for (Kemkey k : kemkeysEl.getKemkeys()) {
                Integer kid = k.getId();
                byte[] kpub = k.asBytes();
                if (kid != null && kpub != null && kpub.length > 0) {
                    kemPreKeys.add(new BundleData.KemPreKey(kid, kpub));
                }
            }
        }
        if (kemPreKeys.isEmpty()) {
            throw new IllegalArgumentException("bundle has no usable KEM pre-keys");
        }

        // OPKs — optional.
        List<BundleData.OneTimePreKey> opks = new ArrayList<>();
        Opks opksEl = bundle.getOpks();
        if (opksEl != null) {
            for (Opk o : opksEl.getOpks()) {
                Integer oid = o.getId();
                byte[] opub = o.asBytes();
                if (oid != null && opub != null && opub.length == 32) {
                    opks.add(new BundleData.OneTimePreKey(oid, opub));
                }
            }
        }

        return new BundleData(
                aikEd25519Pub,
                aikMldsaPub,
                dcMarshal,
                dikEd25519Pub,
                dikX25519Pub,
                dikMldsaPub,
                spkId,
                spkPub,
                spkSig,
                kemPreKeys,
                opks);
    }
}
