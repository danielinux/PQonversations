// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

// Assembles the CPace transcript byte-string per cpace.go buildTranscript().
// Layout:
//   "X3DHPQ-CPace-Transcript-v1\x00"
//   packField(bareJid)            uint16-len-prefixed
//   packField(initiatorJid)
//   packField(responderJid)
//   packField(domain)
//   packField(initiatorAikMarshal)
//   packField(responderAikMarshal)
//   0x49 ('I')                    fixed initiator role marker
//   0x52 ('R')                    fixed responder role marker
//   packField(purpose)
public final class CPaceTranscript {

    private CPaceTranscript() {}

    public static byte[] build(
            String bareJid,
            String initiatorJid,
            String responderJid,
            String domain,
            byte[] initiatorAikMarshal,
            byte[] responderAikMarshal,
            String purpose) {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(CPace.TRANSCRIPT_PREFIX);
            packField(out, utf8(bareJid));
            packField(out, utf8(initiatorJid));
            packField(out, utf8(responderJid));
            packField(out, utf8(domain));
            packField(out, initiatorAikMarshal != null ? initiatorAikMarshal : new byte[0]);
            packField(out, responderAikMarshal != null ? responderAikMarshal : new byte[0]);
            out.write(0x49); // 'I' initiator role marker
            out.write(0x52); // 'R' responder role marker
            packField(out, utf8(purpose));
        } catch (java.io.IOException e) {
            // ByteArrayOutputStream never throws IOException
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }

    // Appends uint16(len) || bytes to out.
    static void packField(ByteArrayOutputStream out, byte[] field) throws java.io.IOException {
        int len = field.length;
        out.write((len >>> 8) & 0xff);
        out.write(len & 0xff);
        out.write(field);
    }

    private static byte[] utf8(String s) {
        if (s == null) return new byte[0];
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
