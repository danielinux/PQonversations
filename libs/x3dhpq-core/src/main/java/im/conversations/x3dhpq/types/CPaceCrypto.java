// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.rfc7748.X25519;

public final class CPaceCrypto {

    private CPaceCrypto() {}

    public static CPaceState newSession(
            CPaceRole role,
            byte[] password,
            byte[] sid,
            String bareJid,
            String initiatorJid,
            String responderJid,
            String serverDomain,
            byte[] initiatorAikPub,
            byte[] responderAikPub,
            String purpose) {

        byte[] transcript = CPaceTranscript.build(
                bareJid, initiatorJid, responderJid, serverDomain,
                initiatorAikPub, responderAikPub, purpose);

        byte[] h2cInput = buildH2CInput(password, sid, transcript);
        byte[] g = Curve25519Elligator2.hashToCurveX25519(h2cInput, CPace.DST);
        return new CPaceState(role, sid, transcript, g);
    }

    public static byte[] message1(CPaceState state, SecureRandom rng) {
        byte[] y = new byte[32];
        rng.nextBytes(y);
        y[0]  &= 248;
        y[31] &= 127;
        y[31] |= 64;

        byte[] Y = new byte[32];
        X25519.scalarMult(y, 0, state.getG(), 0, Y, 0);
        state.setEphemeral(y, Y);
        return Y;
    }

    public static byte[] process(CPaceState state, byte[] peerMsg) throws CPaceException {
        if (peerMsg == null || peerMsg.length != 32) {
            throw new CPaceException("cpace: malformed peer message");
        }
        if (CPace.isLowOrderPoint(peerMsg)) {
            throw new CPaceException("cpace: low-order peer message");
        }

        byte[] K = new byte[32];
        X25519.scalarMult(state.getYScalar(), 0, peerMsg, 0, K, 0);

        byte[] ma = state.getMyMsg();
        byte[] mb = peerMsg;
        if (lexCompare(ma, mb) > 0) {
            byte[] tmp = ma;
            ma = mb;
            mb = tmp;
        }

        byte[] thInput = buildSessionTranscriptInput(state.getSid(), state.getTranscript(), ma, mb);
        byte[] transcriptHash = sha512(thInput);

        byte[] ikm = concat(K, transcriptHash);
        byte[] prk = hkdfExtract(state.getSid(), ikm);
        return hkdfExpand(prk, "CPace-SessionKey-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8), 32);
    }

    public static byte[] confirm(CPaceState state, byte[] sessionKey) {
        byte[] prk = hkdfExtract(state.getSid(), sessionKey);
        byte[] label = state.getRole() == CPaceRole.INITIATOR
                ? "CPace-ConfirmA-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8)
                : "CPace-ConfirmB-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] info = concat(label, state.getSid());
        return hkdfExpand(prk, info, 16);
    }

    public static boolean verifyConfirm(CPaceState state, byte[] sessionKey, byte[] peerTag) {
        byte[] prk = hkdfExtract(state.getSid(), sessionKey);
        byte[] label = state.getRole() == CPaceRole.INITIATOR
                ? "CPace-ConfirmB-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8)
                : "CPace-ConfirmA-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] info = concat(label, state.getSid());
        byte[] expected = hkdfExpand(prk, info, 16);
        return MessageDigest.isEqual(expected, peerTag);
    }

    // pack = uint16-be(len) || bytes — mirrors packField() in cpace.go
    private static void pack(ByteArrayOutputStream out, byte[] field) {
        int len = field.length;
        out.write((len >>> 8) & 0xff);
        out.write(len & 0xff);
        out.write(field, 0, field.length);
    }

    // Mirrors buildH2CInput() in cpace.go: pack(prs) || pack(sid) || pack(transcript)
    private static byte[] buildH2CInput(byte[] prs, byte[] sid, byte[] transcript) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                2 + prs.length + 2 + sid.length + 2 + transcript.length);
        pack(out, prs);
        pack(out, sid);
        pack(out, transcript);
        return out.toByteArray();
    }

    // Mirrors the thInput construction in Process() in cpace.go.
    private static byte[] buildSessionTranscriptInput(
            byte[] sid, byte[] transcript, byte[] ma, byte[] mb) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                CPace.SESSION_TRANSCRIPT_PREFIX.length + 2 + sid.length
                + 2 + transcript.length + 2 + ma.length + 2 + mb.length);
        out.write(CPace.SESSION_TRANSCRIPT_PREFIX, 0, CPace.SESSION_TRANSCRIPT_PREFIX.length);
        pack(out, sid);
        pack(out, transcript);
        pack(out, ma);
        pack(out, mb);
        return out.toByteArray();
    }

    // Lexicographic compare on byte arrays (unsigned).
    private static int lexCompare(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int diff = (a[i] & 0xff) - (b[i] & 0xff);
            if (diff != 0) return diff;
        }
        return Integer.compare(a.length, b.length);
    }

    private static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-512 unavailable", e);
        }
    }

    // HKDF-Extract(salt, ikm) → prk = HMAC-SHA512(salt, ikm) per RFC 5869 §2.2.
    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha512(salt, ikm);
    }

    // HKDF-Expand(prk, info, length) → okm using SHA-512.
    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA512Digest());
        hkdf.init(HKDFParameters.skipExtractParameters(prk, info));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
    }

    // HMAC-SHA512(key, data) — used for HKDF-Extract.
    private static byte[] hmacSha512(byte[] key, byte[] data) {
        org.bouncycastle.crypto.macs.HMac hmac =
                new org.bouncycastle.crypto.macs.HMac(new SHA512Digest());
        hmac.init(new org.bouncycastle.crypto.params.KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    public static class CPaceException extends RuntimeException {
        public CPaceException(String msg) { super(msg); }
    }
}
