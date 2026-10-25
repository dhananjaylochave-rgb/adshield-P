package app.dj.adshield;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Local DNS sinkhole.
 *
 * The VPN only claims ONE route: a /32 for a private fake DNS server address. The phone's resolver sends its
 * lookups there; everything else (all real traffic) bypasses the VPN completely and is never seen by this app.
 * Blocked names are answered locally; allowed names are forwarded over a protected socket to the upstream
 * resolver chosen in the app.
 */
public class AdBlockVpnService extends VpnService {
    static final String ACTION_STOP = "app.dj.adshield.STOP";

    private static final String DNS_ADDR = "10.111.222.2";
    private static final byte[] DNS_ADDR_BYTES = {10, 111, (byte) 222, 2};

    private final Object writeLock = new Object();
    private ParcelFileDescriptor tun;
    private FileInputStream tunIn;
    private FileOutputStream tunOut;
    private Thread reader;
    private ThreadPoolExecutor pool;
    private volatile Blocklist blocklist;
    private volatile boolean active;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;   // also reached via system "Always-on VPN" restarts
    }

    private synchronized void startVpn() {
        if (active) return;
        Shared.loadPrefs(this);
        try (InputStream in = getAssets().open("blocklist.txt")) {
            blocklist = Blocklist.load(in);
            Shared.blocklistSize = blocklist.size();
        } catch (IOException e) {
            blocklist = null;   // fail open: DNS still works, just nothing is blocked
            Shared.blocklistSize = 0;
        }

        ParcelFileDescriptor pfd = new Builder()
                .setSession("AdShield")
                .addAddress("10.111.222.1", 32)
                .addDnsServer(DNS_ADDR)
                .addRoute(DNS_ADDR, 32)
                .setMtu(1500)
                .setBlocking(true)
                .establish();
        if (pfd == null) {   // VPN permission was revoked or not yet granted
            stopSelf();
            return;
        }
        tun = pfd;
        tunIn = new FileInputStream(pfd.getFileDescriptor());
        tunOut = new FileOutputStream(pfd.getFileDescriptor());
        pool = new ThreadPoolExecutor(4, 16, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(256),
                new ThreadPoolExecutor.DiscardPolicy());
        active = true;
        Shared.running = true;

        reader = new Thread(this::readLoop, "adshield-reader");
        reader.start();
    }

    private void readLoop() {
        byte[] buf = new byte[32767];
        try {
            while (active) {
                int n = tunIn.read(buf);
                if (n < 0) break;
                if (n > 0) handlePacket(buf, n);
            }
        } catch (IOException ignored) {
            // stream closed by stopVpn(), or the tunnel went away
        } finally {
            if (active) {   // died on its own - clean up so the UI does not claim we are protecting
                stopVpn();
                stopSelf();
            }
        }
    }

    private void handlePacket(byte[] buf, int n) {
        final DnsPacket.Query q = DnsPacket.parse(buf, n);
        if (q == null) return;
        Shared.total.incrementAndGet();
        Blocklist bl = blocklist;
        if (bl != null && bl.isBlocked(q.qname, Shared.allow)) {
            Shared.blocked.incrementAndGet();
            Shared.noteBlocked(q.qname);
            byte[] resp = DnsPacket.buildBlockedResponse(q);
            writeReply(q, resp, resp.length);
            return;
        }
        try {
            pool.execute(() -> forward(q));
        } catch (RejectedExecutionException ignored) {
            // shutting down
        }
    }

    private void forward(DnsPacket.Query q) {
        for (InetAddress up : Shared.upstream()) {
            if (!active) return;
            DatagramSocket s = null;
            try {
                s = new DatagramSocket();
                if (!protect(s)) continue;   // keep our own forwarding traffic out of the tunnel
                s.setSoTimeout(2500);
                s.connect(up, 53);
                s.send(new DatagramPacket(q.dns, q.dns.length));
                byte[] rb = new byte[4096];
                DatagramPacket rp = new DatagramPacket(rb, rb.length);
                s.receive(rp);
                if (rp.getLength() >= 12 && rb[0] == q.dns[0] && rb[1] == q.dns[1]) {
                    writeReply(q, rb, rp.getLength());
                    return;
                }
            } catch (IOException ignored) {
                // timeout or network error: try the next upstream address
            } finally {
                if (s != null) s.close();
            }
        }
        byte[] fail = DnsPacket.buildServfail(q);   // fail fast instead of hanging the app
        writeReply(q, fail, fail.length);
    }

    private void writeReply(DnsPacket.Query q, byte[] payload, int len) {
        byte[] pkt = DnsPacket.wrapUdpIpv4(DNS_ADDR_BYTES, 53, q.srcIp, q.srcPort, payload, 0, len);
        try {
            synchronized (writeLock) {
                FileOutputStream out = tunOut;
                if (out != null) out.write(pkt);
            }
        } catch (IOException ignored) {
            // tunnel closed
        }
    }

    private synchronized void stopVpn() {
        active = false;
        Shared.running = false;
        if (pool != null) {
            pool.shutdownNow();
            pool = null;
        }
        closeQuietly(tunIn);     // closing the stream wakes the blocked reader thread
        closeQuietly(tunOut);
        closeQuietly(tun);
        tunIn = null;
        tunOut = null;
        tun = null;
        if (reader != null) {
            reader.interrupt();
            reader = null;
        }
    }

    private static void closeQuietly(Closeable c) {
        if (c == null) return;
        try {
            c.close();
        } catch (IOException ignored) {
            // nothing useful to do
        }
    }

    @Override
    public void onRevoke() {
        stopVpn();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }
}
