// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.Arrays;

// In-memory CPace session state; mirrors CPaceState struct in cpace.go.
// No wire Marshal/Unmarshal: the protocol transmits individual PAKE messages over XEP IQ stanzas,
// not a serialised state blob.  Wave A will add cryptographic operations on top.
public final class CPaceState {

    private final CPaceRole role;
    private final byte[] sid;
    private byte[] transcript;
    private byte[] yScalar;   // ephemeral scalar (set after message-1)
    private byte[] g;         // generator point derived by hash-to-curve
    private byte[] myMsg;     // our X25519 public share (set after message-1)

    public CPaceState(CPaceRole role, byte[] sid, byte[] transcript, byte[] g) {
        this.role       = role;
        this.sid        = sid != null ? Arrays.copyOf(sid, sid.length) : new byte[0];
        this.transcript = transcript != null ? Arrays.copyOf(transcript, transcript.length) : new byte[0];
        this.g          = g != null ? Arrays.copyOf(g, g.length) : new byte[0];
    }

    public CPaceRole getRole()       { return role; }
    public byte[]    getSid()        { return Arrays.copyOf(sid, sid.length); }
    public byte[]    getTranscript() { return Arrays.copyOf(transcript, transcript.length); }
    public byte[]    getG()          { return Arrays.copyOf(g, g.length); }
    public byte[]    getYScalar()    { return yScalar != null ? Arrays.copyOf(yScalar, yScalar.length) : null; }
    public byte[]    getMyMsg()      { return myMsg != null ? Arrays.copyOf(myMsg, myMsg.length) : null; }

    // Called by Wave A after generating the ephemeral scalar and public share.
    public void setEphemeral(byte[] yScalar, byte[] myMsg) {
        this.yScalar = yScalar != null ? Arrays.copyOf(yScalar, yScalar.length) : null;
        this.myMsg   = myMsg   != null ? Arrays.copyOf(myMsg,   myMsg.length)   : null;
    }
}
