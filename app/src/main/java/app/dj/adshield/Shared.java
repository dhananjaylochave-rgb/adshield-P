package app.dj.adshield;

import android.content.Context;
import android.content.SharedPreferences;

import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * App-wide state shared by the UI and the VPN service (both live in the same process).
 * Everything here stays in memory or in this app's private preferences - nothing is ever sent anywhere.
 */
final class Shared {
    private Shared() {}

    static final String PREFS = "adshield";
    static final String KEY_UPSTREAM = "upstream";
    static final String KEY_ALLOW = "allow";

    /** Resolver choices: display name, then IPv4 and IPv6 addresses (tried in that order). */
    static final String[] UPSTREAM_NAMES = {
            "Cloudflare (1.1.1.1)", "Google (8.8.8.8)", "Quad9 (9.9.9.9)"};
    private static final String[][] UPSTREAM_ADDRS = {
            {"1.1.1.1", "2606:4700:4700::1111"},
            {"8.8.8.8", "2001:4860:4860::8888"},
            {"9.9.9.9", "2620:fe::fe"}};

    static final AtomicLong total = new AtomicLong();
    static final AtomicLong blocked = new AtomicLong();
    static volatile boolean running;
    static volatile int blocklistSize;
    static volatile Set<String> allow = Collections.emptySet();
    static volatile int upstreamIndex;

    private static final ArrayDeque<String> RECENT = new ArrayDeque<>();

    static void loadPrefs(Context c) {
        SharedPreferences sp = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        allow = Blocklist.parseList(sp.getString(KEY_ALLOW, ""));
        int idx = sp.getInt(KEY_UPSTREAM, 0);
        upstreamIndex = (idx >= 0 && idx < UPSTREAM_NAMES.length) ? idx : 0;
    }

    /** Literal IP addresses only, so no DNS lookup ever happens while building these. */
    static InetAddress[] upstream() {
        String[] addrs = UPSTREAM_ADDRS[upstreamIndex];
        List<InetAddress> out = new ArrayList<>();
        for (String a : addrs) {
            try {
                out.add(InetAddress.getByName(a));
            } catch (Exception ignored) {
                // skip an unparsable literal (cannot happen with the constants above)
            }
        }
        return out.toArray(new InetAddress[0]);
    }

    static void noteBlocked(String domain) {
        synchronized (RECENT) {
            RECENT.addFirst(domain);
            while (RECENT.size() > 60) RECENT.removeLast();
        }
    }

    static List<String> recentBlocked() {
        synchronized (RECENT) {
            return new ArrayList<>(RECENT);
        }
    }

    static void resetCounters() {
        total.set(0);
        blocked.set(0);
        synchronized (RECENT) {
            RECENT.clear();
        }
    }
}
