// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import com.google.common.io.BaseEncoding;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Emk;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Hdr;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Key;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Payload;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Prekey;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyAikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyAikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyDc;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.protocol.MessageHeader;
import im.conversations.x3dhpq.protocol.Session;
import im.conversations.x3dhpq.protocol.SessionException;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Builder and parser for x3dhpq-encrypted message envelopes.
 */
public class XmppX3dhpqMessage {

    private final Account account;
    private final Jid from;
    public final int senderDeviceId;
    private final long timestamp;

    // payload key (32 bytes) + nonce (12 bytes) = 44 bytes transport key
    private byte[] payloadKey;
    private byte[] payloadNonce;

    // AES-256-GCM(payloadKey, payloadNonce, plaintext, aad=empty)
    private byte[] payloadCiphertext;

    // per-recipient encrypted transport-key payloads; key = "jidBare:deviceId"
    private final Map<String, EncryptedKey> keys = new HashMap<>();

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    public static class EncryptedKey {
        public final byte[] header;        // MessageHeader.marshal()
        public final byte[] encryptedKey;  // Session.encrypt(transportKey).ciphertext
        public final PrekeyMetadata prekey; // null for non-first messages

        public EncryptedKey(byte[] header, byte[] encryptedKey, PrekeyMetadata prekey) {
            this.header = header;
            this.encryptedKey = encryptedKey;
            this.prekey = prekey;
        }
    }

    public static class PrekeyMetadata {
        public final byte[] ephemeralPub;   // 32 bytes
        public final int    opkId;
        public final int    kemKeyId;
        public final byte[] kemCiphertext;  // 1088 bytes
        public final byte[] dcMarshal;
        public final byte[] aikEd25519Pub;  // 32 bytes
        public final byte[] aikMldsaPub;    // 1952 bytes

        public PrekeyMetadata(
                byte[] ephemeralPub, int opkId, int kemKeyId,
                byte[] kemCiphertext, byte[] dcMarshal,
                byte[] aikEd25519Pub, byte[] aikMldsaPub) {
            this.ephemeralPub    = ephemeralPub;
            this.opkId           = opkId;
            this.kemKeyId        = kemKeyId;
            this.kemCiphertext   = kemCiphertext;
            this.dcMarshal       = dcMarshal;
            this.aikEd25519Pub   = aikEd25519Pub;
            this.aikMldsaPub     = aikMldsaPub;
        }
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    private XmppX3dhpqMessage(Account account, Jid from, int senderDeviceId, long timestamp) {
        this.account        = account;
        this.from           = from;
        this.senderDeviceId = senderDeviceId;
        this.timestamp      = timestamp;
    }

    /**
     * Build a fresh outbound message.
     * Generates payload key + nonce and AES-256-GCM encrypts the body (empty AAD, matching dino-fork).
     */
    public static XmppX3dhpqMessage createOutbound(
            Account account, Jid from, int senderDeviceId, byte[] plaintextBody) {
        final XmppX3dhpqMessage msg = new XmppX3dhpqMessage(
                account, from, senderDeviceId, System.currentTimeMillis());

        // generate 32-byte payload key and 12-byte nonce (empty AAD matches dino manager.vala:215)
        final SecureRandom rng = new SecureRandom();
        msg.payloadKey   = new byte[32];
        msg.payloadNonce = new byte[12];
        rng.nextBytes(msg.payloadKey);
        rng.nextBytes(msg.payloadNonce);

        msg.payloadCiphertext = X3dhpqCrypto.aes256gcmEncrypt(
                msg.payloadKey, msg.payloadNonce, plaintextBody, new byte[0]);
        return msg;
    }

    /**
     * Build a fresh outbound message whose payload is raw binary (e.g. a SenderChainAnnouncement).
     * The raw bytes are AES-256-GCM encrypted with a fresh key+nonce (empty AAD).
     * Use {@link #isSenderChainPayload()} to signal the recipient to dispatch accordingly.
     */
    public static XmppX3dhpqMessage createOutboundWithRawPayload(
            Account account, Jid from, int senderDeviceId, byte[] rawPayload) {
        final XmppX3dhpqMessage msg = createOutbound(account, from, senderDeviceId, rawPayload);
        msg.senderChainPayload = true;
        return msg;
    }

    private boolean senderChainPayload = false;
    private String payloadTypeOverride = null;

    public boolean isSenderChainPayload() {
        return senderChainPayload;
    }

    /** Override the &lt;payload type&gt; attribute (e.g. "group-sync"). */
    public void setPayloadType(final String type) {
        this.payloadTypeOverride = type;
    }

    /**
     * Encrypt the transport key (payloadKey || payloadNonce) once per recipient device.
     * If firstMessage is true, attach the prekey metadata block so the receiver can run PQXDH.
     */
    public void addRecipient(
            Jid recipientBareJid,
            int deviceId,
            Session session,
            boolean firstMessage,
            PrekeyMetadata prekeyOrNull) {
        // transport key = payloadKey(32) || payloadNonce(12) = 44 bytes
        final byte[] transportKey = concat(payloadKey, payloadNonce);
        final Session.EncryptResult enc = session.encrypt(transportKey);

        final EncryptedKey ek = new EncryptedKey(
                enc.header.marshal(),
                enc.ciphertext,
                firstMessage ? prekeyOrNull : null);

        final String mapKey = recipientBareJid.asBareJid().toString() + ":" + deviceId;
        keys.put(mapKey, ek);
    }

    // -------------------------------------------------------------------------
    // Conversion to/from the typed Extension model (C1 classes)
    // -------------------------------------------------------------------------

    /** Build the typed Envelope extension ready to attach to a message stanza. */
    public Envelope toExtension() {
        final Envelope env = new Envelope();
        env.setSenderDevice(senderDeviceId);
        env.setSenderJid(from.asBareJid().toString());
        env.setTs(DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(timestamp)));

        for (final Map.Entry<String, EncryptedKey> entry : keys.entrySet()) {
            final String mapKey   = entry.getKey();
            final EncryptedKey ek = entry.getValue();
            final int rid         = parseDeviceIdFromMapKey(mapKey);

            final Key keyEl = new Key();
            keyEl.setRecipientDeviceId(rid);

            final Hdr hdr = new Hdr();
            hdr.setContent(ek.header);
            keyEl.addExtension(hdr);

            final Emk emk = new Emk();
            emk.setContent(ek.encryptedKey);
            keyEl.addExtension(emk);

            if (ek.prekey != null) {
                final Prekey pk = buildPrekeyElement(ek.prekey);
                keyEl.addExtension(pk);
            }

            env.addKey(keyEl);
        }

        final Payload payload = new Payload();
        payload.setContent(payloadCiphertext);
        if (payloadTypeOverride != null) {
            payload.setType(payloadTypeOverride);
        } else if (senderChainPayload) {
            payload.setType("sender-chain");
        }
        env.setPayload(payload);

        return env;
    }

    private static Prekey buildPrekeyElement(PrekeyMetadata pm) {
        final Prekey pk = new Prekey();
        pk.setEk(BaseEncoding.base64().encode(pm.ephemeralPub));
        pk.setOpkId(pm.opkId);
        pk.setKemkeyId(pm.kemKeyId);
        pk.setKemCt(BaseEncoding.base64().encode(pm.kemCiphertext));

        final PrekeyDc dc = new PrekeyDc();
        dc.setContent(pm.dcMarshal);
        pk.addExtension(dc);

        final PrekeyAikEd25519 aikEd = new PrekeyAikEd25519();
        aikEd.setContent(pm.aikEd25519Pub);
        pk.addExtension(aikEd);

        final PrekeyAikMldsa aikMl = new PrekeyAikMldsa();
        aikMl.setContent(pm.aikMldsaPub);
        pk.addExtension(aikMl);

        return pk;
    }

    /**
     * Parse an inbound Envelope extension into an XmppX3dhpqMessage view.
     * Payload ciphertext is stored for later decryption via {@link #decrypt}.
     */
    public static XmppX3dhpqMessage fromExtension(
            Account account, Jid messageFrom, Envelope envelope) {
        final int senderDeviceId;
        try {
            senderDeviceId = Integer.parseInt(envelope.getSenderDevice());
        } catch (final NumberFormatException e) {
            throw new IllegalArgumentException("invalid sender-device in x3dhpq envelope", e);
        }

        final XmppX3dhpqMessage msg = new XmppX3dhpqMessage(
                account, messageFrom, senderDeviceId, System.currentTimeMillis());

        // read payload ciphertext
        final Payload payloadEl = envelope.getPayload();
        if (payloadEl != null) {
            msg.payloadCiphertext = payloadEl.asBytes();
        }

        // read per-recipient key blocks; index by "senderJid:rid" for findKeyForDevice
        final Collection<Key> keyEls = envelope.getKeys();
        if (keyEls == null) return msg;

        for (final Key keyEl : keyEls) {
            final Integer rid = keyEl.getRecipientDeviceId();
            if (rid == null) continue;

            final Hdr hdrEl = keyEl.getHdr();
            final Emk emkEl = keyEl.getEmk();
            if (hdrEl == null || emkEl == null) continue;

            final byte[] headerBytes = hdrEl.asBytes();
            final byte[] encKeyBytes = emkEl.asBytes();

            PrekeyMetadata prekeyMeta = null;
            final Prekey pkEl = keyEl.getPrekey();
            if (pkEl != null) {
                final byte[] ek    = decodeBase64Attr(pkEl.getEk());
                final int opkId    = parseIntAttr(pkEl.getOpkId(), 0);
                final int kemId    = parseIntAttr(pkEl.getKemkeyId(), 0);
                final byte[] kemCt = decodeBase64Attr(pkEl.getKemCt());
                final byte[] dc    = pkEl.getDc()         != null ? pkEl.getDc().asBytes()         : new byte[0];
                final byte[] aikEd = pkEl.getAikEd25519() != null ? pkEl.getAikEd25519().asBytes() : new byte[0];
                final byte[] aikMl = pkEl.getAikMldsa()   != null ? pkEl.getAikMldsa().asBytes()   : new byte[0];
                prekeyMeta = new PrekeyMetadata(ek, opkId, kemId, kemCt, dc, aikEd, aikMl);
            }

            final String mapKey = messageFrom.asBareJid().toString() + ":" + rid;
            msg.keys.put(mapKey, new EncryptedKey(headerBytes, encKeyBytes, prekeyMeta));
        }

        return msg;
    }

    /**
     * Find the encrypted-key block addressed to the given local device id.
     * Iterates all keys regardless of recipient JID.
     */
    public EncryptedKey findKeyForDevice(int recipientDeviceId) {
        for (final Map.Entry<String, EncryptedKey> e : keys.entrySet()) {
            final int rid = parseDeviceIdFromMapKey(e.getKey());
            if (rid == recipientDeviceId) {
                return e.getValue();
            }
        }
        return null;
    }

    /**
     * Decrypt the transport key from an EncryptedKey block using the given session,
     * then decrypt the payload ciphertext.
     * Returns plaintext bytes.
     */
    public byte[] decrypt(Session session, EncryptedKey k) throws SessionException {
        final MessageHeader header = MessageHeader.unmarshal(k.header);
        // session.decrypt returns the transport key (44 bytes = payloadKey || payloadNonce)
        final byte[] transportKey = session.decrypt(header, k.encryptedKey);
        if (transportKey == null || transportKey.length < 44) {
            throw new SessionException("transport key decrypt produced too few bytes");
        }
        final byte[] pKey   = Arrays.copyOf(transportKey, 32);
        final byte[] pNonce = Arrays.copyOfRange(transportKey, 32, 44);
        // empty AAD matches dino-fork manager.vala:215 (aes256gcm_encrypt(payload_key, payload_nonce, body))
        return X3dhpqCrypto.aes256gcmDecrypt(pKey, pNonce, payloadCiphertext, new byte[0]);
    }

    // -------------------------------------------------------------------------
    // Package-visible for tests
    // -------------------------------------------------------------------------

    byte[] getPayloadKey()        { return payloadKey   != null ? Arrays.copyOf(payloadKey,        payloadKey.length)        : null; }
    byte[] getPayloadNonce()      { return payloadNonce  != null ? Arrays.copyOf(payloadNonce,      payloadNonce.length)      : null; }
    byte[] getPayloadCiphertext() { return payloadCiphertext != null ? Arrays.copyOf(payloadCiphertext, payloadCiphertext.length) : null; }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int parseDeviceIdFromMapKey(String mapKey) {
        // mapKey = "jid:deviceId" — last colon separates the device id
        final int lastColon = mapKey.lastIndexOf(':');
        if (lastColon < 0) return -1;
        try {
            return Integer.parseInt(mapKey.substring(lastColon + 1));
        } catch (final NumberFormatException e) {
            return -1;
        }
    }

    private static byte[] decodeBase64Attr(String value) {
        if (value == null || value.isEmpty()) return new byte[0];
        return BaseEncoding.base64().decode(value);
    }

    private static int parseIntAttr(String value, int fallback) {
        if (value == null) return fallback;
        try {
            return Integer.parseInt(value);
        } catch (final NumberFormatException e) {
            return fallback;
        }
    }
}
