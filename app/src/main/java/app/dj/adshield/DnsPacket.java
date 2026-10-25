package app.dj.adshield;

import java.util.Arrays;

/**
 * Minimal IPv4 / UDP / DNS helpers.
 * Pure Java (no Android imports) so it can be unit-tested on a plain JVM.
 * Every parser here treats its input as hostile: malformed data returns null, never throws.
 */
final class DnsPacket {
    private DnsPacket() {}

    static final int TYPE_A = 1;
    static final int TYPE_AAAA = 28;
    static final int CLASS_IN = 1;

    /** A parsed single-question DNS query that arrived inside an IPv4/UDP packet. */
    static final class Query {
        final byte[] srcIp = new byte[4];
        final byte[] dstIp = new byte[4];
        int srcPort;
        int dstPort;
        byte[] dns;        // private copy of the UDP payload (the DNS message)
        String qname;      // lower-case, no trailing dot
        int qtype;
        int qclass;
        int questionEnd;   // offset in dns[] just past the question section
    }

    /** Returns null for anything that is not a well-formed single-question IPv4/UDP DNS query to port 53. */
    static Query parse(byte[] p, int len) {
        if (p == null || len > p.length || len < 20 + 8 + 12) return null;
        int vihl = p[0] & 0xFF;
        if ((vihl >> 4) != 4) return null;
        int ihl = (vihl & 0x0F) * 4;
        if (ihl < 20 || len < ihl + 8 + 12) return null;
        if ((p[9] & 0xFF) != 17) return null;                   // UDP only
        int totalLen = u16(p, 2);
        if (totalLen < ihl + 8 + 12 || totalLen > len) return null;
        if ((u16(p, 6) & 0x3FFF) != 0) return null;             // fragment (MF set or offset != 0)
        int udpLen = u16(p, ihl + 4);
        if (udpLen < 8 + 12 || ihl + udpLen > totalLen) return null;
        if (u16(p, ihl + 2) != 53) return null;                 // destination port must be DNS

        int dnsOff = ihl + 8;
        int dnsLen = udpLen - 8;
        int end = dnsOff + dnsLen;
        int flags = u16(p, dnsOff + 2);
        if ((flags & 0x8000) != 0) return null;                 // a response, not a query
        if (((flags >> 11) & 0xF) != 0) return null;            // opcode must be QUERY
        if (u16(p, dnsOff + 4) != 1) return null;               // exactly one question

        StringBuilder name = new StringBuilder();
        int i = dnsOff + 12;
        int encoded = 0;
        while (true) {
            if (i >= end) return null;
            int l = p[i++] & 0xFF;
            if (l == 0) break;
            if ((l & 0xC0) != 0) return null;                   // no compression pointers in a question
            if (i + l > end) return null;
            encoded += l + 1;
            if (encoded > 253) return null;
            if (name.length() > 0) name.append('.');
            for (int k = 0; k < l; k++) {
                int c = p[i + k] & 0xFF;
                if (c >= 'A' && c <= 'Z') c += 32;
                name.append((char) c);
            }
            i += l;
        }
        if (i + 4 > end) return null;

        Query q = new Query();
        System.arraycopy(p, 12, q.srcIp, 0, 4);
        System.arraycopy(p, 16, q.dstIp, 0, 4);
        q.srcPort = u16(p, ihl);
        q.dstPort = u16(p, ihl + 2);
        q.qname = name.toString();
        q.qtype = u16(p, i);
        q.qclass = u16(p, i + 2);
        q.questionEnd = (i + 4) - dnsOff;
        q.dns = Arrays.copyOfRange(p, dnsOff, dnsOff + dnsLen);
        return q;
    }

    /**
     * Answer for a blocked name: A -> 0.0.0.0, AAAA -> ::, any other type (HTTPS/SVCB, TXT, ...) -> empty NOERROR.
     * Short TTL so allow-list edits take effect quickly.
     */
    static byte[] buildBlockedResponse(Query q) {
        boolean a = q.qtype == TYPE_A && q.qclass == CLASS_IN;
        boolean aaaa = q.qtype == TYPE_AAAA && q.qclass == CLASS_IN;
        int ansLen = a ? 16 : (aaaa ? 28 : 0);   // 2 name ptr + 2 type + 2 class + 4 ttl + 2 rdlen + rdata
        byte[] r = new byte[q.questionEnd + ansLen];
        System.arraycopy(q.dns, 0, r, 0, q.questionEnd);
        int rd = u16(q.dns, 2) & 0x0100;
        put16(r, 2, 0x8000 | rd | 0x0080);       // QR + copy RD + RA, RCODE = NOERROR
        put16(r, 4, 1);
        put16(r, 6, ansLen > 0 ? 1 : 0);
        put16(r, 8, 0);
        put16(r, 10, 0);
        if (ansLen > 0) {
            int o = q.questionEnd;
            r[o++] = (byte) 0xC0;
            r[o++] = 0x0C;                        // pointer to the question name
            put16(r, o, q.qtype); o += 2;
            put16(r, o, q.qclass); o += 2;
            put16(r, o, 0); put16(r, o + 2, 60); o += 4;   // TTL = 60 s
            put16(r, o, a ? 4 : 16);              // RDATA stays all zeros
        }
        return r;
    }

    /** SERVFAIL so apps fail fast when no upstream answered. */
    static byte[] buildServfail(Query q) {
        byte[] r = new byte[q.questionEnd];
        System.arraycopy(q.dns, 0, r, 0, q.questionEnd);
        int rd = u16(q.dns, 2) & 0x0100;
        put16(r, 2, 0x8000 | rd | 0x0080 | 2);   // RCODE = SERVFAIL
        put16(r, 4, 1);
        put16(r, 6, 0);
        put16(r, 8, 0);
        put16(r, 10, 0);
        return r;
    }

    /** Wraps a UDP payload in IPv4 + UDP headers with valid checksums. */
    static byte[] wrapUdpIpv4(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort,
                              byte[] payload, int off, int len) {
        int total = 20 + 8 + len;
        byte[] o = new byte[total];
        o[0] = 0x45;
        put16(o, 2, total);
        put16(o, 6, 0x4000);                      // DF
        o[8] = 64;                                // TTL
        o[9] = 17;                                // UDP
        System.arraycopy(srcIp, 0, o, 12, 4);
        System.arraycopy(dstIp, 0, o, 16, 4);
        put16(o, 10, ~fold(sum(o, 0, 20, 0)) & 0xFFFF);

        put16(o, 20, srcPort);
        put16(o, 22, dstPort);
        put16(o, 24, 8 + len);
        System.arraycopy(payload, off, o, 28, len);
        long s = sum(o, 12, 8, 0);                // pseudo header: src + dst
        s += 17;                                  // zero + protocol
        s += 8 + len;                             // UDP length
        s = sum(o, 20, 8 + len, s);
        int c = ~fold(s) & 0xFFFF;
        put16(o, 26, c == 0 ? 0xFFFF : c);
        return o;
    }

    // ---- checksum helpers (also used by the self-test) ----

    static long sum(byte[] b, int off, int len, long init) {
        long s = init;
        int i = off;
        int end = off + len;
        while (i + 1 < end) {
            s += ((b[i] & 0xFF) << 8) | (b[i + 1] & 0xFF);
            i += 2;
        }
        if (i < end) s += (b[i] & 0xFF) << 8;
        return s;
    }

    static int fold(long s) {
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        return (int) s;
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    static void put16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }
}
