// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.CPaceCrypto;
import im.conversations.x3dhpq.types.CPaceRole;
import im.conversations.x3dhpq.types.CPaceState;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import im.conversations.x3dhpq.types.PairingMsg;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class PairingFsm {

    public static final int FLAG_PRIMARY = 1;

    public enum Step { INIT, SENT_PAKE1, SENT_CONFIRM, WAIT_DIK, SENT_PAYLOAD, DONE }

    public static class PairingException extends Exception {
        public PairingException(String msg) { super(msg); }
    }

    public static class Options {
        public final long newDeviceId;
        public final boolean sharePrimary;
        public final byte[] stateBlob;
        public final byte newDeviceFlags;

        public Options(long newDeviceId, boolean sharePrimary, byte[] stateBlob, byte newDeviceFlags) {
            this.newDeviceId = newDeviceId;
            this.sharePrimary = sharePrimary;
            this.stateBlob = stateBlob != null ? stateBlob.clone() : new byte[0];
            this.newDeviceFlags = newDeviceFlags;
        }
    }

    public static class Result {
        public final AccountIdentityPub aikPub;
        public final DeviceCertificate cert;
        public final AccountIdentityKey aikPriv;
        public final byte[] stateBlob;

        public Result(AccountIdentityPub aikPub, DeviceCertificate cert, AccountIdentityKey aikPriv, byte[] stateBlob) {
            this.aikPub = aikPub;
            this.cert = cert;
            this.aikPriv = aikPriv;
            this.stateBlob = stateBlob != null ? stateBlob.clone() : new byte[0];
        }
    }

    public static final class Existing {
        private final AccountIdentityKey aik;
        private final CPaceState cpace;
        private final byte[] sid;
        private final Options opts;
        private byte[] sessionKey;
        private Step step = Step.INIT;
        private long encCounter = 0L;
        private long decCounter = 0L;
        private DeviceCertificate issuedCert;

        public Existing(AccountIdentityKey aik, String code, byte[] sid, Options opts) throws Exception {
            BouncyCastleInstaller.ensureRegistered();
            this.aik = aik;
            this.sid = sid.clone();
            this.opts = opts;
            this.cpace = CPaceCrypto.newSession(
                    CPaceRole.INITIATOR,
                    code.getBytes(StandardCharsets.UTF_8),
                    sid,
                    "", "", "", "",
                    new byte[0], new byte[0],
                    "device-pairing");
        }

        public PairingMsg step(PairingMsg in) throws PairingException, Exception {
            switch (step) {
                case INIT: {
                    byte[] Y = CPaceCrypto.message1(cpace, new SecureRandom());
                    step = Step.SENT_PAKE1;
                    return new PairingMsg(PairingMsg.TYPE_PAKE1, Y);
                }
                case SENT_PAKE1: {
                    if (in == null || in.getType() != PairingMsg.TYPE_PAKE2) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    sessionKey = CPaceCrypto.process(cpace, in.getPayload());
                    byte[] tag = CPaceCrypto.confirm(cpace, sessionKey);
                    step = Step.SENT_CONFIRM;
                    return new PairingMsg(PairingMsg.TYPE_CONFIRM, tag);
                }
                case SENT_CONFIRM: {
                    if (in == null || in.getType() != PairingMsg.TYPE_CONFIRM) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    if (!CPaceCrypto.verifyConfirm(cpace, sessionKey, in.getPayload())) {
                        throw new PairingException("pairing: authentication failed (wrong code or key confirm)");
                    }
                    step = Step.WAIT_DIK;
                    return null;
                }
                case WAIT_DIK: {
                    if (in == null || in.getType() != PairingMsg.TYPE_PAYLOAD) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    byte[] plain;
                    try {
                        plain = decryptPayload(in.getPayload());
                    } catch (Exception e) {
                        throw new PairingException("pairing: authentication failed (wrong code or key confirm)");
                    }
                    DeviceIdentityKey dik = unmarshalDIKPub(plain);
                    byte flags = opts.newDeviceFlags;
                    if (opts.sharePrimary) {
                        flags |= (byte) FLAG_PRIMARY;
                    }
                    long createdAt = System.currentTimeMillis() / 1000L;
                    // Build an unsigned stub to get the canonical signedPart bytes.
                    DeviceCertificate stub = new DeviceCertificate(
                            1,
                            opts.newDeviceId,
                            dik.getPubEd25519(),
                            dik.getPubX25519(),
                            dik.getPubMLDSA(),
                            createdAt,
                            flags,
                            new byte[0],
                            new byte[0]);
                    byte[] sp = stub.signedPart();
                    byte[] sigEd = X3dhpqCrypto.ed25519Sign(aik.getPrivEd25519(), sp);
                    byte[] sigMldsa = X3dhpqCrypto.mldsa65Sign(aik.getPrivMLDSA(), sp);
                    DeviceCertificate dc = new DeviceCertificate(
                            1,
                            opts.newDeviceId,
                            dik.getPubEd25519(),
                            dik.getPubX25519(),
                            dik.getPubMLDSA(),
                            createdAt,
                            flags,
                            sigEd,
                            sigMldsa);
                    issuedCert = dc;
                    byte[] issuancePayload = marshalIssuancePayload(dc, aik, opts.sharePrimary, opts.stateBlob);
                    byte[] enc = encryptPayload(issuancePayload);
                    step = Step.SENT_PAYLOAD;
                    return new PairingMsg(PairingMsg.TYPE_PAYLOAD, enc);
                }
                case SENT_PAYLOAD: {
                    if (in == null || in.getType() != PairingMsg.TYPE_ACK) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    byte[] plain;
                    try {
                        plain = decryptPayload(in.getPayload());
                    } catch (Exception e) {
                        throw new PairingException("pairing: authentication failed (wrong code or key confirm)");
                    }
                    if (!"ok".equals(new String(plain, StandardCharsets.UTF_8))) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    step = Step.DONE;
                    return null;
                }
                default:
                    throw new PairingException("pairing: protocol violation");
            }
        }

        public boolean isDone() { return step == Step.DONE; }

        public DeviceCertificate getIssuedCert() { return issuedCert; }

        private byte[] encryptPayload(byte[] plaintext) {
            byte[] nonce = makeNonce((byte) 'E', encCounter++);
            return X3dhpqCrypto.aes256gcmEncrypt(sessionKey, nonce, plaintext, sid);
        }

        private byte[] decryptPayload(byte[] ciphertext) {
            byte[] nonce = makeNonce((byte) 'N', decCounter++);
            return X3dhpqCrypto.aes256gcmDecrypt(sessionKey, nonce, ciphertext, sid);
        }
    }

    public static final class New {
        private final DeviceIdentityKey dik;
        private final CPaceState cpace;
        private final byte[] sid;
        private byte[] sessionKey;
        private Step step = Step.INIT;
        private long encCounter = 0L;
        private long decCounter = 0L;
        private Result result;

        public New(DeviceIdentityKey dik, String code, byte[] sid) throws Exception {
            BouncyCastleInstaller.ensureRegistered();
            this.dik = dik;
            this.sid = sid.clone();
            this.cpace = CPaceCrypto.newSession(
                    CPaceRole.RESPONDER,
                    code.getBytes(StandardCharsets.UTF_8),
                    sid,
                    "", "", "", "",
                    new byte[0], new byte[0],
                    "device-pairing");
        }

        public PairingMsg step(PairingMsg in) throws PairingException, Exception {
            switch (step) {
                case INIT: {
                    if (in == null || in.getType() != PairingMsg.TYPE_PAKE1) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    byte[] msg1 = CPaceCrypto.message1(cpace, new SecureRandom());
                    sessionKey = CPaceCrypto.process(cpace, in.getPayload());
                    step = Step.SENT_PAKE1;
                    return new PairingMsg(PairingMsg.TYPE_PAKE2, msg1);
                }
                case SENT_PAKE1: {
                    if (in == null || in.getType() != PairingMsg.TYPE_CONFIRM) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    if (!CPaceCrypto.verifyConfirm(cpace, sessionKey, in.getPayload())) {
                        throw new PairingException("pairing: authentication failed (wrong code or key confirm)");
                    }
                    byte[] tag = CPaceCrypto.confirm(cpace, sessionKey);
                    step = Step.SENT_CONFIRM;
                    return new PairingMsg(PairingMsg.TYPE_CONFIRM, tag);
                }
                case SENT_CONFIRM: {
                    // Caller passes null here; no inbound expected.
                    byte[] dikPayload = marshalDIKPub(dik);
                    byte[] enc = encryptPayload(dikPayload);
                    step = Step.WAIT_DIK;
                    return new PairingMsg(PairingMsg.TYPE_PAYLOAD, enc);
                }
                case WAIT_DIK: {
                    if (in == null || in.getType() != PairingMsg.TYPE_PAYLOAD) {
                        throw new PairingException("pairing: protocol violation");
                    }
                    byte[] plain;
                    try {
                        plain = decryptPayload(in.getPayload());
                    } catch (Exception e) {
                        throw new PairingException("pairing: authentication failed (wrong code or key confirm)");
                    }
                    result = unmarshalIssuancePayload(plain);
                    byte[] ackEnc = encryptPayload("ok".getBytes(StandardCharsets.UTF_8));
                    step = Step.DONE;
                    return new PairingMsg(PairingMsg.TYPE_ACK, ackEnc);
                }
                default:
                    throw new PairingException("pairing: protocol violation");
            }
        }

        public boolean isDone() { return step == Step.DONE; }

        public Result getResult() { return result; }

        private byte[] encryptPayload(byte[] plaintext) {
            byte[] nonce = makeNonce((byte) 'N', encCounter++);
            return X3dhpqCrypto.aes256gcmEncrypt(sessionKey, nonce, plaintext, sid);
        }

        private byte[] decryptPayload(byte[] ciphertext) {
            byte[] nonce = makeNonce((byte) 'E', decCounter++);
            return X3dhpqCrypto.aes256gcmDecrypt(sessionKey, nonce, ciphertext, sid);
        }
    }

    // makeNonce mirrors pairing.go line 316:
    // nonce[0] = roleTag, nonce[1..3] = 0x00, nonce[4..11] = uint64 BE counter
    private static byte[] makeNonce(byte roleTag, long counter) {
        byte[] nonce = new byte[12];
        nonce[0] = roleTag;
        // nonce[1..3] already zero from array initialisation
        ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.BIG_ENDIAN).putLong(counter);
        return nonce;
    }

    // marshalDIKPub mirrors pairing.go line 326: uint16(len)|bytes for each of ed/x/mldsa.
    private static byte[] marshalDIKPub(DeviceIdentityKey dik) {
        byte[] ed = dik.getPubEd25519();
        byte[] x  = dik.getPubX25519();
        byte[] ml = dik.getPubMLDSA();
        ByteBuffer buf = ByteBuffer.allocate(2 + ed.length + 2 + x.length + 2 + ml.length)
                .order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) (ed.length & 0xffff));
        buf.put(ed);
        buf.putShort((short) (x.length & 0xffff));
        buf.put(x);
        buf.putShort((short) (ml.length & 0xffff));
        buf.put(ml);
        return buf.array();
    }

    // unmarshalDIKPub mirrors pairing.go line 346; priv fields are zeroed since only pubs are on wire.
    private static DeviceIdentityKey unmarshalDIKPub(byte[] b) throws PairingException {
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        byte[] ed = readField2(buf);
        byte[] x  = readField2(buf);
        byte[] ml = readField2(buf);
        // DeviceIdentityKey validates exact sizes; zero-fill the priv fields.
        byte[] privEd = new byte[32];   // ED25519_PRIV_SIZE
        byte[] privX  = new byte[32];   // X25519_PRIV_SIZE
        byte[] privMl = new byte[4032]; // MLDSA65_PRIV_SIZE
        try {
            return new DeviceIdentityKey(privEd, ed, privX, x, privMl, ml);
        } catch (IllegalArgumentException e) {
            throw new PairingException("pairing: protocol violation");
        }
    }

    // marshalIssuancePayload mirrors pairing.go lines 380–415.
    // Wire: uint16(dc)|dc | uint16(aikPub)|aikPub | uint8(hasPriv) | uint16(aikPriv)|aikPriv | uint32(stateLen)|state
    private static byte[] marshalIssuancePayload(
            DeviceCertificate dc, AccountIdentityKey aik, boolean sharePriv, byte[] stateBlob) {
        byte[] dcBytes     = dc.marshal();
        byte[] aikPubBytes = aik.getPublic().marshal();
        byte[] aikPrivBytes = sharePriv ? marshalAIKPriv(aik) : new byte[0];
        byte   hasPriv     = (byte) (sharePriv ? 1 : 0);
        int size = 2 + dcBytes.length
                 + 2 + aikPubBytes.length
                 + 1
                 + 2 + aikPrivBytes.length
                 + 4 + stateBlob.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) (dcBytes.length & 0xffff));
        buf.put(dcBytes);
        buf.putShort((short) (aikPubBytes.length & 0xffff));
        buf.put(aikPubBytes);
        buf.put(hasPriv);
        buf.putShort((short) (aikPrivBytes.length & 0xffff));
        buf.put(aikPrivBytes);
        buf.putInt(stateBlob.length);
        buf.put(stateBlob);
        return buf.array();
    }

    // unmarshalIssuancePayload mirrors pairing.go lines 418–490.
    private static Result unmarshalIssuancePayload(byte[] b) throws PairingException {
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        byte[] dcBytes = readField2(buf);
        DeviceCertificate dc;
        try {
            dc = DeviceCertificate.unmarshal(dcBytes);
        } catch (Exception e) {
            throw new PairingException("pairing: protocol violation");
        }

        byte[] aikPubBytes = readField2(buf);
        AccountIdentityPub aikPub;
        try {
            aikPub = AccountIdentityPub.unmarshal(aikPubBytes);
        } catch (Exception e) {
            throw new PairingException("pairing: protocol violation");
        }

        if (!buf.hasRemaining()) throw new PairingException("pairing: protocol violation");
        byte hasPriv = buf.get();

        byte[] aikPrivBytes = readField2(buf);

        if (buf.remaining() < 4) throw new PairingException("pairing: protocol violation");
        int stateLen = buf.getInt();
        if (buf.remaining() < stateLen) throw new PairingException("pairing: protocol violation");
        byte[] stateBlob = new byte[stateLen];
        buf.get(stateBlob);

        AccountIdentityKey aikPriv = null;
        if (hasPriv == 1 && aikPrivBytes.length > 0) {
            try {
                aikPriv = unmarshalAIKPriv(aikPrivBytes);
            } catch (Exception e) {
                throw new PairingException("pairing: protocol violation");
            }
        }

        return new Result(aikPub, dc, aikPriv, stateBlob);
    }

    // marshalAIKPriv: stores priv_ed25519 | pub_ed25519 | priv_mldsa | pub_mldsa (4 length-prefixed fields).
    // Extends the Go 3-field format by also including priv_mldsa so the new device can sign.
    private static byte[] marshalAIKPriv(AccountIdentityKey aik) {
        byte[] privEd = aik.getPrivEd25519();
        byte[] pubEd  = aik.getPublic().getPubEd25519();
        byte[] privMl = aik.getPrivMLDSA();
        byte[] pubMl  = aik.getPublic().getPubMLDSA();
        ByteBuffer buf = ByteBuffer.allocate(
                2 + privEd.length + 2 + pubEd.length + 2 + privMl.length + 2 + pubMl.length)
                .order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) (privEd.length & 0xffff));
        buf.put(privEd);
        buf.putShort((short) (pubEd.length & 0xffff));
        buf.put(pubEd);
        buf.putShort((short) (privMl.length & 0xffff));
        buf.put(privMl);
        buf.putShort((short) (pubMl.length & 0xffff));
        buf.put(pubMl);
        return buf.array();
    }

    // unmarshalAIKPriv: reverse of marshalAIKPriv (4 fields).
    private static AccountIdentityKey unmarshalAIKPriv(byte[] b) throws PairingException {
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
        byte[] privEd = readField2(buf);
        byte[] pubEd  = readField2(buf);
        byte[] privMl = readField2(buf);
        byte[] pubMl  = readField2(buf);
        try {
            AccountIdentityPub pub = new AccountIdentityPub(pubEd, pubMl);
            return new AccountIdentityKey(privEd, privMl, pub);
        } catch (IllegalArgumentException e) {
            throw new PairingException("pairing: protocol violation");
        }
    }

    // readField2 reads a uint16-length-prefixed field from buf; throws PairingException on underflow.
    private static byte[] readField2(ByteBuffer buf) throws PairingException {
        if (buf.remaining() < 2) throw new PairingException("pairing: protocol violation");
        int len = buf.getShort() & 0xffff;
        if (buf.remaining() < len) throw new PairingException("pairing: protocol violation");
        byte[] v = new byte[len];
        buf.get(v);
        return v;
    }

    private PairingFsm() {}
}
