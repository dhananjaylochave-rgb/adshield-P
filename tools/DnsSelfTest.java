package app.dj.adshield;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/** Plain-JVM checks for the packet + blocklist logic. Run: java -cp <classes> app.dj.adshield.DnsSelfTest <blocklist.txt> */
public class DnsSelfTest {
    static int checks = 0;

    static void ok(boolean cond, String what) {
        checks++;
        if (!cond) {
            System.err.println("FAIL: " + what);
            System.exit(1);
        }
    }

    static byte[] dnsQuery(String name, int type, boolean edns) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(new byte[]{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, (byte) (edns ? 1 : 0)});
        for (String label : name.split("\\.")) {
            b.write(label.length());
            b.write(label.getBytes("ISO-8859-1"));
        }
        b.write(0);
        b.write(new byte[]{(byte) (type >> 8), (byte) type, 0, 1});
        if (edns) b.write(new byte[]{0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0});
        return b.toByteArray();
    }

    static final byte[] CLIENT = {10, 111, (byte) 222, 1};
    static final byte[] SERVER = {10, 111, (byte) 222, 2};

    static byte[] packet(byte[] dns) {
        return DnsPacket.wrapUdpIpv4(CLIENT, 40000, SERVER, 53, dns, 0, dns.length);
    }

    static boolean checksumsValid(byte[] p) {
        if (DnsPacket.fold(DnsPacket.sum(p, 0, 20, 0)) != 0xFFFF) return false;
        int udpLen = DnsPacket.u16(p, 24);
        long s = DnsPacket.sum(p, 12, 8, 0) + 17 + udpLen;
        s = DnsPacket.sum(p, 20, udpLen, s);
        return DnsPacket.fold(s) == 0xFFFF;
    }

    public static void main(String[] args) throws Exception {
        // ---- parsing ----
        byte[] pkt = packet(dnsQuery("Ads.Example.COM", 1, true));
        ok(checksumsValid(pkt), "wrapped packet has valid IP + UDP checksums");
        DnsPacket.Query q = DnsPacket.parse(pkt, pkt.length);
        ok(q != null, "query parses");
        ok("ads.example.com".equals(q.qname), "qname lower-cased: " + q.qname);
        ok(q.qtype == 1 && q.qclass == 1, "qtype/qclass");
        ok(q.srcPort == 40000 && q.dstPort == 53, "ports");
        ok(Arrays.equals(q.srcIp, CLIENT) && Arrays.equals(q.dstIp, SERVER), "addresses");

        // ---- blocked answers ----
        byte[] a = DnsPacket.buildBlockedResponse(q);
        ok(a[0] == 0x12 && a[1] == 0x34, "response echoes ID");
        ok((DnsPacket.u16(a, 2) & 0x8000) != 0, "QR set");
        ok((DnsPacket.u16(a, 2) & 0x000F) == 0, "RCODE NOERROR");
        ok((DnsPacket.u16(a, 2) & 0x0100) != 0, "RD copied");
        ok(DnsPacket.u16(a, 6) == 1 && DnsPacket.u16(a, 10) == 0, "one answer, no additional");
        ok(a.length == q.questionEnd + 16, "A answer length");
        for (int i = a.length - 4; i < a.length; i++) ok(a[i] == 0, "A rdata is 0.0.0.0");
        ok(DnsPacket.u16(a, q.questionEnd + 10) == 4, "A rdlength 4");

        byte[] aaaaPkt = packet(dnsQuery("ads.example.com", 28, false));
        DnsPacket.Query q6 = DnsPacket.parse(aaaaPkt, aaaaPkt.length);
        byte[] a6 = DnsPacket.buildBlockedResponse(q6);
        ok(a6.length == q6.questionEnd + 28, "AAAA answer length");
        ok(DnsPacket.u16(a6, q6.questionEnd + 10) == 16, "AAAA rdlength 16");

        byte[] httpsPkt = packet(dnsQuery("ads.example.com", 65, false));
        DnsPacket.Query qh = DnsPacket.parse(httpsPkt, httpsPkt.length);
        byte[] ah = DnsPacket.buildBlockedResponse(qh);
        ok(DnsPacket.u16(ah, 6) == 0 && ah.length == qh.questionEnd, "HTTPS/SVCB gets empty NOERROR");

        byte[] sf = DnsPacket.buildServfail(q);
        ok((DnsPacket.u16(sf, 2) & 0x000F) == 2, "SERVFAIL rcode");

        byte[] reply = DnsPacket.wrapUdpIpv4(SERVER, 53, q.srcIp, q.srcPort, a, 0, a.length);
        ok(checksumsValid(reply), "reply packet checksums valid");
        ok(DnsPacket.u16(reply, 20) == 53 && DnsPacket.u16(reply, 22) == 40000, "reply ports swapped");
        byte[] odd = DnsPacket.wrapUdpIpv4(SERVER, 53, CLIENT, 1234, new byte[]{1, 2, 3}, 0, 3);
        ok(checksumsValid(odd), "odd-length payload checksum valid");

        // ---- hostile / malformed input never throws and never parses ----
        ok(DnsPacket.parse(new byte[0], 0) == null, "empty");
        ok(DnsPacket.parse(pkt, 10) == null, "truncated");
        byte[] tcp = pkt.clone(); tcp[9] = 6;
        ok(DnsPacket.parse(tcp, tcp.length) == null, "TCP ignored");
        byte[] wrongPort = pkt.clone(); wrongPort[23] = 80;
        ok(DnsPacket.parse(wrongPort, wrongPort.length) == null, "non-53 port ignored");
        byte[] frag = pkt.clone(); frag[6] = 0x20;
        ok(DnsPacket.parse(frag, frag.length) == null, "fragment ignored");
        byte[] resp = pkt.clone(); resp[28 + 2] |= (byte) 0x80;
        ok(DnsPacket.parse(resp, resp.length) == null, "DNS response ignored");
        byte[] v6 = pkt.clone(); v6[0] = 0x65;
        ok(DnsPacket.parse(v6, v6.length) == null, "IPv6 header ignored");
        byte[] ptr = pkt.clone(); ptr[28 + 12] = (byte) 0xC0;
        ok(DnsPacket.parse(ptr, ptr.length) == null, "compression pointer in question rejected");
        byte[] two = pkt.clone(); two[28 + 5] = 2;
        ok(DnsPacket.parse(two, two.length) == null, "qdcount 2 rejected");
        byte[] longLabel = pkt.clone(); longLabel[28 + 12] = 60;
        ok(DnsPacket.parse(longLabel, longLabel.length) == null, "label overrunning packet rejected");
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 40; i++) longName.append("abcdefg.");
        longName.append("com");
        byte[] lp = packet(dnsQuery(longName.toString(), 1, false));
        ok(DnsPacket.parse(lp, lp.length) == null, "name over 253 bytes rejected");

        Random rnd = new Random(42);
        for (int i = 0; i < 300000; i++) {
            byte[] f = new byte[rnd.nextInt(120)];
            rnd.nextBytes(f);
            if (f.length > 20 && rnd.nextBoolean()) { f[0] = 0x45; f[9] = 17; }
            DnsPacket.parse(f, f.length);              // must not throw
            byte[] m = pkt.clone();                    // mutate a valid packet
            m[rnd.nextInt(m.length)] = (byte) rnd.nextInt(256);
            DnsPacket.Query mq = DnsPacket.parse(m, m.length);
            if (mq != null) {                          // anything that still parses must build valid answers
                DnsPacket.buildBlockedResponse(mq);
                DnsPacket.buildServfail(mq);
            }
        }
        ok(true, "300k fuzz iterations without exception");

        // ---- blocklist matching ----
        Blocklist bl = Blocklist.load(new FileInputStream(args[0]));
        System.out.println("blocklist size: " + bl.size());
        ok(bl.size() > 50000, "list has plenty of entries");
        Set<String> none = Collections.emptySet();
        for (String d : new String[]{"doubleclick.net", "ad.doubleclick.net", "a.b.c.doubleclick.net"})
            ok(bl.isBlocked(d, none), "blocked: " + d);
        for (String d : new String[]{"google.com", "www.google.com", "github.com", "raw.githubusercontent.com",
                "youtube.com", "www.youtube.com", "wikipedia.org", "paytm.com", "hdfcbank.com",
                "onlinesbi.sbi", "amazon.in", "flipkart.com", "whatsapp.com", "api.anthropic.com", "com", "localhost"})
            ok(!bl.isBlocked(d, none), "must NOT be blocked: " + d);
        Set<String> allow = new HashSet<>(Collections.singleton("doubleclick.net"));
        ok(!bl.isBlocked("ad.doubleclick.net", allow), "allow-list overrides parent block");

        Set<String> parsed = Blocklist.parseList("  Example.COM  # note\n*.foo.bar\n.baz.qux.\n\n# only comment\r\nlast.one");
        ok(parsed.equals(new HashSet<>(Arrays.asList("example.com", "foo.bar", "baz.qux", "last.one"))),
                "allow-list parsing: " + parsed);

        System.out.println("ALL " + checks + " CHECKS PASSED");
    }
}
