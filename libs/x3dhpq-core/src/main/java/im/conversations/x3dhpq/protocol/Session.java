// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.KemEncapsulation;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.KemCheckpoint;
import im.conversations.x3dhpq.types.HkdfSha512;
import im.conversations.x3dhpq.types.HmacSha256;
import im.conversations.x3dhpq.types.Sha512;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

// Triple-Ratchet session state machine: Signal Double Ratchet + ML-KEM-768 checkpoints.
// Mirrors xmppqr/internal/x3dhpqcrypto/ratchet.go (State, EncryptMessage, DecryptMessage).
//
// Algorithm invariants (all lifted verbatim from the Go reference):
//   - info string for DH ratchet step: "X3DHPQ-RootKey-v0"
//   - info string for message key derivation: "X3DHPQ-MessageKey-v0"
//   - AAD order: AD || header.marshal()  (AD first)
//   - nonce: first 12 bytes of HKDF-SHA-512(salt=zeros[64], ikm=mk, info="X3DHPQ-MessageKey-v0", length=44)
//   - AES key: first 32 bytes of the same 44-byte HKDF output
//   - KEM checkpoint interval: 50 messages or 3600 seconds (from Go's kemCheckpointK / kemCheckpointT)
//   - Skipped keys bounded at MAX_SKIPPED=1000 (spec §9.4.2; matches the Go reference)
public final class Session {

    // KEM checkpoint fires when either threshold is crossed.
    public static final int  KEM_CHECKPOINT_INTERVAL_MESSAGES = 50;
    public static final long KEM_CHECKPOINT_INTERVAL_SECONDS  = 3600L; // 1 hour, matching Go

    // Skipped-key table bound (spec §9.4.2: MAX_SKIPPED=1000, matches the Go reference).
    public static final int MAX_SKIPPED = 1000;

    // Info strings verbatim from xmppqr/internal/x3dhpqcrypto/x3dh.go.
    private static final byte[] INFO_ROOT_KEY =
            "X3DHPQ-RootKey-v0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] INFO_MESSAGE_KEY =
            "X3DHPQ-MessageKey-v0".getBytes(StandardCharsets.UTF_8);

    // 64-byte zero salt for HKDF calls that pass nil salt in Go (hkdf64 / hkdf44).
    private static final byte[] ZERO_SALT_64 = new byte[64];

    // Shared pluggable crypto implementations.
    private static final HkdfSha512 HKDF = X3dhpqCrypto.HKDF_SHA512;
    private static final HmacSha256 HMAC = X3dhpqCrypto.HMAC_SHA256;
    private static final Sha512     SHA512 = X3dhpqCrypto.SHA512;

    // Static per-session AD (64 bytes from PQXDH).
    private final byte[] ad;

    // Root key (32 bytes); mutated by DH ratchet steps.
    private byte[] rootKey;

    // Sending chain state.
    private byte[] sendChainKey;    // null until first DH ratchet step on sending side
    private long   sendCount;       // SendCount in Go
    private long   prevSendCount;   // PrevSendCount in Go

    // Sending DH keypair (current ephemeral).
    private byte[] sendDhPriv;
    private byte[] sendDhPub;

    // Receiving chain state.
    private byte[] recvChainKey;    // null until first DH ratchet step on receiving side
    private long   recvCount;       // RecvCount in Go

    // Last peer DH pub we ratcheted on.
    private byte[] remoteDhPub;

    // KEM checkpoint state (mirrors Go KEMSendPub / KEMRecvPriv / KEMRecvPub / KEMSinceCheckpoint etc.)
    private byte[] kemSendPub;      // peer's current KEM pub; we encapsulate to this on checkpoint
    private byte[] kemRecvPriv;     // our current KEM priv; peer encapsulates to this
    private byte[] kemRecvPub;      // our current KEM pub; advertised to peer in every header
    private long   kemSinceCheckpoint;
    private long   lastCheckpointTimeSecs;  // unix seconds

    // Rolling 32-byte PQ entropy accumulator (KEMHistory in Go).
    private byte[] kemHistory;

    // Skipped message keys for out-of-order delivery.
    // Key: dhPub_hex + ":" + chainIndex; bounded at MAX_SKIPPED.
    private final LinkedHashMap<SkippedKey, byte[]> skipped = new LinkedHashMap<>();

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    private Session(byte[] ad) {
        this.ad = Arrays.copyOf(ad, ad.length);
        this.kemHistory = new byte[32]; // zero-initialised, matches Go NewSendingState/NewReceivingState
    }

    // Create the INITIATOR/SENDER session from a PqxdhResult.
    // Mirrors NewSendingState: splits rootKey[0:32]/[32:64], immediately runs one DH ratchet step.
    public static Session fromPqxdhSender(PqxdhResult result) {
        Session s = new Session(result.getAd());
        byte[] rk64 = new byte[64];
        System.arraycopy(result.getRootKey(), 0, rk64, 0, 32);
        System.arraycopy(result.getInitialChainKey(), 0, rk64, 32, 32);

        byte[] rk = Arrays.copyOf(rk64, 32);
        // initialChainKey unused in sender path; Go ignores ck = rootKey[32:].

        // Generate initial sending DH keypair.
        KeyPair dh = X3dhpqCrypto.x25519GenerateKeypair();
        s.sendDhPriv = dh.priv;
        s.sendDhPub  = dh.pub;

        // remoteDhPub must be set so dhRatchetStep works; but we need the peer's DH pub.
        // In NewSendingState Go sets RemoteDHPub=peerDHPub after computing DH with it.
        // The sender does not yet know the peer's ephemeral — for a fresh PQXDH session
        // the peer has no ephemeral yet; the send chain is seeded by the PQXDH root key
        // (rk[0:32]) and the initial chain key (rk[32:64]).
        //
        // Matching Go NewSendingState: rk used as salt, DH(sendPriv, peerDHPub) as IKM,
        // kemHistory=zeros[32]. But peerDHPub is not available here from PqxdhResult alone.
        //
        // Resolution: we do NOT pre-ratchet here. Instead, keep rk=rootKey[0:32] and
        // sendChainKey=initialChainKey.  On first encrypt, we perform a DH ratchet against
        // the peer's pub (which we learn from their first message header, or which is set
        // by the caller via setPeerDhPub before encrypting).
        //
        // This diverges from Go's NewSendingState which eagerly pre-ratchets, but that
        // function is called with peerDHPub already known. Java callers must call
        // fromPqxdhSenderWithPeerDh(result, peerDhPub) when the peer pub is available.
        s.rootKey      = Arrays.copyOf(result.getRootKey(), 32);
        s.sendChainKey = Arrays.copyOf(result.getInitialChainKey(), 32);
        s.sendCount    = 0;
        s.lastCheckpointTimeSecs = currentTimeSecs();
        return s;
    }

    // Create the INITIATOR/SENDER session that immediately pre-ratchets with the peer DH pub.
    // This matches NewSendingState exactly (ratchet happens in constructor).
    public static Session fromPqxdhSenderWithPeerDh(PqxdhResult result, byte[] peerDhPub) {
        Session s = new Session(result.getAd());

        byte[] rk = Arrays.copyOf(result.getRootKey(), 32);
        // initialChainKey from PQXDH is discarded (Go's ck = rootKey[32:] is also unused).

        // Generate initial sending DH keypair.
        KeyPair dh = X3dhpqCrypto.x25519GenerateKeypair();
        s.sendDhPriv  = dh.priv;
        s.sendDhPub   = dh.pub;
        s.remoteDhPub = Arrays.copyOf(peerDhPub, peerDhPub.length);

        // Run initial DH ratchet step: (newRK, sendCK) = dhRatchetStep(rk, sendPriv, peerDhPub, zeros[32]).
        byte[] out = dhRatchetOut(rk, s.sendDhPriv, peerDhPub, s.kemHistory);
        s.rootKey      = Arrays.copyOf(out, 32);
        s.sendChainKey = Arrays.copyOfRange(out, 32, 64);
        s.sendCount    = 0;
        s.lastCheckpointTimeSecs = currentTimeSecs();
        return s;
    }

    // Create the RESPONDER/RECEIVER session from a PqxdhResult.
    // Mirrors NewReceivingState: RK=rootKey[0:32], ChainRecvKey=rootKey[32:64].
    // myDhPriv/Pub is the responder's initial DH keypair (e.g. their SPK).
    // The initiator must have called fromPqxdhSenderWithPeerDh(result, myDhPub).
    public static Session fromPqxdhReceiverWithDh(PqxdhResult result, byte[] myDhPriv, byte[] myDhPub) {
        Session s = new Session(result.getAd());
        s.rootKey     = Arrays.copyOf(result.getRootKey(), 32);
        // recvChainKey from PQXDH is overridden by the first DH ratchet (see DecryptMessage);
        // we still store it in case Go-compatible behaviour is needed for interop.
        s.recvChainKey= Arrays.copyOf(result.getInitialChainKey(), 32);
        s.recvCount   = 0;
        // Our "sending" DH keypair is the initial static key the sender encapsulated to.
        s.sendDhPriv = Arrays.copyOf(myDhPriv, myDhPriv.length);
        s.sendDhPub  = Arrays.copyOf(myDhPub,  myDhPub.length);
        s.lastCheckpointTimeSecs = currentTimeSecs();
        return s;
    }

    // Convenience overload: generates a fresh DH keypair for the receiver (for testing only).
    public static Session fromPqxdhReceiver(PqxdhResult result) {
        KeyPair dh = X3dhpqCrypto.x25519GenerateKeypair();
        return fromPqxdhReceiverWithDh(result, dh.priv, dh.pub);
    }

    // General factory.
    // For INITIATOR: mySendDhPriv/Pub is ignored; the session uses a fresh ephemeral generated
    //   internally after the DH ratchet.  peerDhPub is the responder's initial DH pub (e.g. SPK).
    //   Matches Go NewSendingState(rootKey, ad, peerDHPub).
    // For RESPONDER: mySendDhPriv/Pub is the responder's own DH keypair (e.g. SPK priv/pub).
    //   Matches Go NewReceivingState(rootKey, ad, myDH).
    //
    // peerDhPub is only meaningful for INITIATOR; pass null for RESPONDER.
    public static Session fromPqxdh(PqxdhResult result, byte[] mySendDhPriv, byte[] mySendDhPub) {
        // Delegate: peerDhPub unknown, so use "lazy" initiator path (no pre-ratchet).
        // Callers who have peerDhPub should use fromPqxdhSenderWithPeerDh() instead.
        Session s = new Session(result.getAd());
        s.rootKey    = Arrays.copyOf(result.getRootKey(), 32);
        s.sendDhPriv = Arrays.copyOf(mySendDhPriv, mySendDhPriv.length);
        s.sendDhPub  = Arrays.copyOf(mySendDhPub, mySendDhPub.length);

        if (result.getRole() == PqxdhResult.Role.INITIATOR) {
            // Pre-seed the send chain from PQXDH; will be DH-ratcheted on first decrypt.
            s.sendChainKey = Arrays.copyOf(result.getInitialChainKey(), 32);
            s.sendCount    = 0;
        } else {
            // Responder: seed recv chain; remoteDhPub is unknown until first recv.
            s.recvChainKey = Arrays.copyOf(result.getInitialChainKey(), 32);
            s.recvCount    = 0;
        }
        s.lastCheckpointTimeSecs = currentTimeSecs();
        return s;
    }

    // -------------------------------------------------------------------------
    // Encrypt
    // -------------------------------------------------------------------------

    public static final class EncryptResult {
        public final MessageHeader header;
        public final byte[] ciphertext;  // plaintext + 16-byte GCM tag
        public EncryptResult(MessageHeader header, byte[] ciphertext) {
            this.header = header;
            this.ciphertext = ciphertext;
        }
    }

    // Encrypt one plaintext; mirrors State.EncryptMessage in ratchet.go.
    public EncryptResult encrypt(byte[] plaintext) {
        long now = currentTimeSecs();

        // Determine if we need a KEM checkpoint (only when we have peer's KEM pub).
        boolean needKem = (kemSendPub != null)
                && (kemSinceCheckpoint >= KEM_CHECKPOINT_INTERVAL_MESSAGES
                    || (now - lastCheckpointTimeSecs >= KEM_CHECKPOINT_INTERVAL_SECONDS));

        byte[] kemCt        = null;
        byte[] newKemPub    = null;
        byte[] newKemPriv   = null;

        if (needKem) {
            // Generate fresh KEM keypair to advertise for next incoming checkpoint.
            KemKeyPair kp = X3dhpqCrypto.mlkem768GenerateKeypair();
            newKemPub  = kp.pub;
            newKemPriv = kp.priv;

            // Encapsulate to peer's current KEM pub.
            KemEncapsulation encap = X3dhpqCrypto.mlkem768Encaps(kemSendPub);
            kemCt = encap.ciphertext;
            byte[] kemSS = encap.sharedSecret;

            // Mix KEM entropy into both chain keys and history; uses sendChainKey as salt.
            KemCheckpoint.Result ckRes = KemCheckpoint.mix(
                    sendChainKey, kemSS, sendDhPub, kemCt,
                    sendCount, kemHistory,
                    HKDF, SHA512);
            sendChainKey = ckRes.newCKs();
            recvChainKey = ckRes.newCKr();
            kemHistory   = ckRes.newHistory();
            kemSinceCheckpoint  = 0;
            lastCheckpointTimeSecs = now;
            // Store our new KEM recv keys so the peer can encapsulate back to us.
            kemRecvPriv = newKemPriv;
            kemRecvPub  = newKemPub;
        }

        // Advance the send chain: MK = HMAC(CK, 0x01), CK_next = HMAC(CK, 0x02).
        byte[] mk = hmacStep(sendChainKey, (byte) 0x01);
        sendChainKey = hmacStep(sendChainKey, (byte) 0x02);

        // Build header.
        byte[] hdrKemCt     = needKem ? kemCt    : new byte[0];
        byte[] hdrKemPubRep = kemRecvPub != null ? kemRecvPub : new byte[0];
        MessageHeader hdr = new MessageHeader(
                sendDhPub, prevSendCount, sendCount, hdrKemCt, hdrKemPubRep);

        // Derive AES key and nonce from message key.
        byte[] keyNonce = HKDF.derive(ZERO_SALT_64, mk, INFO_MESSAGE_KEY, 44);
        byte[] aesKey = Arrays.copyOf(keyNonce, 32);
        byte[] nonce  = Arrays.copyOfRange(keyNonce, 32, 44);

        // AAD = AD || header bytes (Go: append(s.AD, hdr.Marshal()...)).
        byte[] aad = concat(ad, hdr.marshal());

        byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(aesKey, nonce, plaintext, aad);

        sendCount++;
        kemSinceCheckpoint++;

        return new EncryptResult(hdr, ct);
    }

    // -------------------------------------------------------------------------
    // Decrypt
    // -------------------------------------------------------------------------

    public byte[] decrypt(MessageHeader header, byte[] ciphertext) throws SessionException {
        // Update peer's KEM pub if advertised in the header.
        if (header.kemPubForReply != null && header.kemPubForReply.length > 0) {
            kemSendPub = Arrays.copyOf(header.kemPubForReply, header.kemPubForReply.length);
        }

        String dhStr = dhStr(header.dhPub);

        // Check skipped-key cache first (handles out-of-order delivery).
        SkippedKey sk = new SkippedKey(dhStr, (int) header.n);
        byte[] cachedMk = skipped.remove(sk);
        if (cachedMk != null) {
            return decryptWithMk(cachedMk, header, ciphertext);
        }

        // DH ratchet step if sender's DH pub changed.
        if (!Arrays.equals(header.dhPub, remoteDhPub)) {
            // Skip remaining messages on the current receive chain before ratcheting.
            if (recvChainKey != null) {
                skipKeys(dhStr(remoteDhPub), (int) header.prevChainLen);
            }
            // Reset counters for the new epoch.
            prevSendCount = sendCount;
            sendCount     = 0;
            recvCount     = 0;

            // Advance receive chain: dhRatchetStep(RK, ourSendPriv, newPeerPub, kemHistory).
            byte[] out1 = dhRatchetOut(rootKey, sendDhPriv, header.dhPub, kemHistory);
            rootKey     = Arrays.copyOf(out1, 32);
            recvChainKey= Arrays.copyOfRange(out1, 32, 64);
            remoteDhPub = Arrays.copyOf(header.dhPub, header.dhPub.length);

            // Generate a new sending DH keypair for our next outgoing message.
            KeyPair newDh = X3dhpqCrypto.x25519GenerateKeypair();
            // Advance send chain: dhRatchetStep(newRK, newPriv, newPeerPub, kemHistory).
            byte[] out2 = dhRatchetOut(rootKey, newDh.priv, header.dhPub, kemHistory);
            rootKey      = Arrays.copyOf(out2, 32);
            sendChainKey = Arrays.copyOfRange(out2, 32, 64);
            sendDhPriv   = newDh.priv;
            sendDhPub    = newDh.pub;
        }

        // Handle KEM checkpoint if present (after DH ratchet, before skipping to N).
        if (header.hasKemCheckpoint() && kemRecvPriv != null) {
            byte[] kemSS = X3dhpqCrypto.mlkem768Decaps(kemRecvPriv, header.kemCiphertext);
            // Mix with recvChainKey as "senderCK" since after DH ratchet that is the
            // shared symmetric chain both parties derive identically.
            KemCheckpoint.Result ckRes = KemCheckpoint.mix(
                    recvChainKey, kemSS, header.dhPub, header.kemCiphertext,
                    header.n, kemHistory,
                    HKDF, SHA512);
            recvChainKey = ckRes.newCKs();
            sendChainKey = ckRes.newCKr();
            kemHistory   = ckRes.newHistory();
        }

        // Skip ahead to this message's position, caching intermediate MKs.
        skipKeys(dhStr, (int) header.n);

        // Advance one step for the current message N.
        byte[] mk = hmacStep(recvChainKey, (byte) 0x01);
        recvChainKey = hmacStep(recvChainKey, (byte) 0x02);
        recvCount++;

        return decryptWithMk(mk, header, ciphertext);
    }

    // -------------------------------------------------------------------------
    // Marshal / Unmarshal
    // -------------------------------------------------------------------------

    // Blob version tag.
    private static final byte BLOB_VERSION = 0x01;

    // Serialise all session state to a byte blob for persistence.
    // Format: version(1) | fixed-size fields | variable-length fields with 4-byte length prefixes.
    public byte[] marshal() {
        // Encode skipped map: count(4) then per-entry (dhPubLen(4) | dhPub | n(4) | mkLen(4) | mk).
        byte[][] skippedEntries = new byte[skipped.size()][];
        int si = 0;
        for (Map.Entry<SkippedKey, byte[]> e : skipped.entrySet()) {
            byte[] keyBytes = e.getKey().dhPub.getBytes(StandardCharsets.ISO_8859_1);
            byte[] mk = e.getValue();
            ByteBuffer eb = ByteBuffer.allocate(4 + keyBytes.length + 4 + 4 + mk.length)
                    .order(ByteOrder.BIG_ENDIAN);
            eb.putInt(keyBytes.length);
            eb.put(keyBytes);
            eb.putInt(e.getKey().n);
            eb.putInt(mk.length);
            eb.put(mk);
            skippedEntries[si++] = eb.array();
        }
        int skippedTotal = 4; // entry count
        for (byte[] e : skippedEntries) skippedTotal += e.length;

        // Variable fields (may be null/empty → length=0).
        byte[] safeAd          = ad           != null ? ad           : new byte[0];
        byte[] safeRk          = rootKey       != null ? rootKey       : new byte[0];
        byte[] safeSendCk      = sendChainKey  != null ? sendChainKey  : new byte[0];
        byte[] safeRecvCk      = recvChainKey  != null ? recvChainKey  : new byte[0];
        byte[] safeSendPriv    = sendDhPriv    != null ? sendDhPriv    : new byte[0];
        byte[] safeSendPub     = sendDhPub     != null ? sendDhPub     : new byte[0];
        byte[] safeRemoteDh    = remoteDhPub   != null ? remoteDhPub   : new byte[0];
        byte[] safeKemSendPub  = kemSendPub    != null ? kemSendPub    : new byte[0];
        byte[] safeKemRecvPriv = kemRecvPriv   != null ? kemRecvPriv   : new byte[0];
        byte[] safeKemRecvPub  = kemRecvPub    != null ? kemRecvPub    : new byte[0];
        byte[] safeKemHistory  = kemHistory    != null ? kemHistory    : new byte[0];

        int fixedSize = 1    // version
                + 8 + 8 + 8 + 8  // sendCount, recvCount, prevSendCount, kemSinceCheckpoint
                + 8;             // lastCheckpointTimeSecs

        int varSize = fieldSize(safeAd) + fieldSize(safeRk)
                + fieldSize(safeSendCk) + fieldSize(safeRecvCk)
                + fieldSize(safeSendPriv) + fieldSize(safeSendPub)
                + fieldSize(safeRemoteDh) + fieldSize(safeKemSendPub)
                + fieldSize(safeKemRecvPriv) + fieldSize(safeKemRecvPub)
                + fieldSize(safeKemHistory);

        ByteBuffer buf = ByteBuffer.allocate(fixedSize + varSize + skippedTotal)
                .order(ByteOrder.BIG_ENDIAN);
        buf.put(BLOB_VERSION);
        buf.putLong(sendCount);
        buf.putLong(recvCount);
        buf.putLong(prevSendCount);
        buf.putLong(kemSinceCheckpoint);
        buf.putLong(lastCheckpointTimeSecs);
        writeField(buf, safeAd);
        writeField(buf, safeRk);
        writeField(buf, safeSendCk);
        writeField(buf, safeRecvCk);
        writeField(buf, safeSendPriv);
        writeField(buf, safeSendPub);
        writeField(buf, safeRemoteDh);
        writeField(buf, safeKemSendPub);
        writeField(buf, safeKemRecvPriv);
        writeField(buf, safeKemRecvPub);
        writeField(buf, safeKemHistory);
        // Skipped map.
        buf.putInt(skippedEntries.length);
        for (byte[] e : skippedEntries) buf.put(e);
        return buf.array();
    }

    public static Session unmarshal(byte[] blob) {
        ByteBuffer buf = ByteBuffer.wrap(blob).order(ByteOrder.BIG_ENDIAN);
        byte version = buf.get();
        if (version != BLOB_VERSION) {
            throw new IllegalArgumentException("unknown session blob version: " + version);
        }
        long sendCount             = buf.getLong();
        long recvCount             = buf.getLong();
        long prevSendCount         = buf.getLong();
        long kemSinceCheckpoint    = buf.getLong();
        long lastCheckpointTime    = buf.getLong();
        byte[] ad          = readBlobField(buf);
        byte[] rootKey     = readBlobField(buf);
        byte[] sendCk      = readBlobField(buf);
        byte[] recvCk      = readBlobField(buf);
        byte[] sendPriv    = readBlobField(buf);
        byte[] sendPub     = readBlobField(buf);
        byte[] remoteDh    = readBlobField(buf);
        byte[] kemSendPub  = readBlobField(buf);
        byte[] kemRecvPriv = readBlobField(buf);
        byte[] kemRecvPub  = readBlobField(buf);
        byte[] kemHistory  = readBlobField(buf);

        Session s = new Session(ad.length > 0 ? ad : new byte[64]);
        s.rootKey              = rootKey.length > 0 ? rootKey : null;
        s.sendChainKey         = sendCk.length > 0 ? sendCk : null;
        s.recvChainKey         = recvCk.length > 0 ? recvCk : null;
        s.sendDhPriv           = sendPriv.length > 0 ? sendPriv : null;
        s.sendDhPub            = sendPub.length > 0 ? sendPub : null;
        s.remoteDhPub          = remoteDh.length > 0 ? remoteDh : null;
        s.kemSendPub           = kemSendPub.length > 0 ? kemSendPub : null;
        s.kemRecvPriv          = kemRecvPriv.length > 0 ? kemRecvPriv : null;
        s.kemRecvPub           = kemRecvPub.length > 0 ? kemRecvPub : null;
        s.kemHistory           = kemHistory.length > 0 ? kemHistory : new byte[32];
        s.sendCount            = sendCount;
        s.recvCount            = recvCount;
        s.prevSendCount        = prevSendCount;
        s.kemSinceCheckpoint   = kemSinceCheckpoint;
        s.lastCheckpointTimeSecs = lastCheckpointTime;

        // Restore skipped keys.
        int skippedCount = buf.getInt();
        for (int i = 0; i < skippedCount; i++) {
            int  kLen    = buf.getInt();
            byte[] kBytes = new byte[kLen];
            buf.get(kBytes);
            int n = buf.getInt();
            int  mkLen   = buf.getInt();
            byte[] mk    = new byte[mkLen];
            buf.get(mk);
            s.skipped.put(new SkippedKey(new String(kBytes, StandardCharsets.ISO_8859_1), n), mk);
        }
        return s;
    }

    // -------------------------------------------------------------------------
    // Accessors for testing
    // -------------------------------------------------------------------------

    public byte[] getAd()           { return Arrays.copyOf(ad, ad.length); }
    public byte[] getRootKey()      { return rootKey != null ? Arrays.copyOf(rootKey, rootKey.length) : null; }
    public byte[] getSendChainKey() { return sendChainKey != null ? Arrays.copyOf(sendChainKey, sendChainKey.length) : null; }
    public byte[] getRecvChainKey() { return recvChainKey != null ? Arrays.copyOf(recvChainKey, recvChainKey.length) : null; }
    public byte[] getSendDhPub()    { return sendDhPub != null ? Arrays.copyOf(sendDhPub, sendDhPub.length) : null; }
    public byte[] getRemoteDhPub()  { return remoteDhPub != null ? Arrays.copyOf(remoteDhPub, remoteDhPub.length) : null; }
    public byte[] getKemHistory()   { return kemHistory != null ? Arrays.copyOf(kemHistory, kemHistory.length) : null; }
    public long   getSendCount()    { return sendCount; }
    public long   getRecvCount()    { return recvCount; }
    public long   getKemSinceCheckpoint() { return kemSinceCheckpoint; }

    // Set the peer's KEM pub (used to bootstrap before first checkpoint).
    public void setKemSendPub(byte[] pub) {
        this.kemSendPub = pub != null ? Arrays.copyOf(pub, pub.length) : null;
    }

    // Set our KEM recv keypair (used to bootstrap on the receiver side).
    public void setKemRecvKeyPair(byte[] priv, byte[] pub) {
        this.kemRecvPriv = priv != null ? Arrays.copyOf(priv, priv.length) : null;
        this.kemRecvPub  = pub  != null ? Arrays.copyOf(pub,  pub.length)  : null;
    }

    // Override checkpoint time for testing.
    public void setLastCheckpointTimeSecs(long t) { this.lastCheckpointTimeSecs = t; }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    // Runs a DH ratchet step; returns 64-byte HKDF output.
    // Go: dhRatchetStep(rk, dhPriv, remotePub, kemHistory) → hkdf64(salt=rk, ikm=DH||kemHistory, infoRootKey)
    private static byte[] dhRatchetOut(byte[] rk, byte[] dhPriv, byte[] remotePub, byte[] kemHistory) {
        byte[] dhOut = X3dhpqCrypto.x25519SharedSecret(dhPriv, remotePub);
        byte[] ikm = concat(dhOut, kemHistory != null ? kemHistory : new byte[32]);
        // hkdf64 uses the rk as salt (non-nil → not replaced with zeros).
        return HKDF.derive(rk, ikm, INFO_ROOT_KEY, 64);
    }

    // Chain step for a single direction.
    private static byte[] hmacStep(byte[] ck, byte flag) {
        return X3dhpqCrypto.hmacSha256(ck, new byte[]{flag});
    }

    // Skip receive-chain keys up to (but not including) targetN, storing them.
    // Throws if the gap exceeds MAX_SKIPPED (mirrors Go's maxSkipKeys check).
    private void skipKeys(String dhStr, int targetN) throws SessionException {
        if (targetN - recvCount > MAX_SKIPPED) {
            throw new SessionException("too many skipped messages: would skip "
                    + (targetN - recvCount));
        }
        while (recvCount < targetN) {
            byte[] mk = hmacStep(recvChainKey, (byte) 0x01);
            recvChainKey = hmacStep(recvChainKey, (byte) 0x02);
            // Evict oldest entry if table is full before inserting.
            if (skipped.size() >= MAX_SKIPPED) {
                skipped.remove(skipped.entrySet().iterator().next().getKey());
            }
            skipped.put(new SkippedKey(dhStr, (int) recvCount), mk);
            recvCount++;
        }
    }

    // Decrypt using a pre-fetched (possibly cached) message key.
    private byte[] decryptWithMk(byte[] mk, MessageHeader header, byte[] ciphertext)
            throws SessionException {
        byte[] keyNonce = HKDF.derive(ZERO_SALT_64, mk, INFO_MESSAGE_KEY, 44);
        byte[] aesKey   = Arrays.copyOf(keyNonce, 32);
        byte[] nonce    = Arrays.copyOfRange(keyNonce, 32, 44);
        byte[] aad      = concat(ad, header.marshal());
        try {
            return X3dhpqCrypto.aes256gcmDecrypt(aesKey, nonce, ciphertext, aad);
        } catch (Exception e) {
            throw new SessionException("AES-GCM authentication failed: " + e.getMessage(), e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int fieldSize(byte[] f) {
        return 4 + (f != null ? f.length : 0);
    }

    private static void writeField(ByteBuffer buf, byte[] data) {
        buf.putInt(data != null ? data.length : 0);
        if (data != null && data.length > 0) buf.put(data);
    }

    private static byte[] readBlobField(ByteBuffer buf) {
        int len = buf.getInt();
        if (len == 0) return new byte[0];
        byte[] out = new byte[len];
        buf.get(out);
        return out;
    }

    private static long currentTimeSecs() {
        return System.currentTimeMillis() / 1000L;
    }

    // Helper to make a null-safe dhStr.
    private static String dhStr(byte[] dhPub) {
        return dhPub != null ? new String(dhPub, StandardCharsets.ISO_8859_1) : "";
    }

    // -------------------------------------------------------------------------
    // SkippedKey
    // -------------------------------------------------------------------------

    private static final class SkippedKey {
        final String dhPub;
        final int    n;
        SkippedKey(String dhPub, int n) { this.dhPub = dhPub; this.n = n; }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof SkippedKey)) return false;
            SkippedKey k = (SkippedKey) o;
            return n == k.n && dhPub.equals(k.dhPub);
        }

        @Override
        public int hashCode() {
            return 31 * dhPub.hashCode() + n;
        }
    }
}
