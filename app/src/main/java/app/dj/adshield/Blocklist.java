package app.dj.adshield;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** In-memory domain blocklist with suffix matching. Pure Java. */
final class Blocklist {
    private final HashSet<String> domains;

    private Blocklist(HashSet<String> domains) {
        this.domains = domains;
    }

    /** One domain per line; blank lines and lines starting with '#' are ignored. */
    static Blocklist load(InputStream in) throws IOException {
        HashSet<String> set = new HashSet<>(1 << 17);
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 16)) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.charAt(0) == '#') continue;
                set.add(line.toLowerCase(Locale.ROOT));
            }
        }
        return new Blocklist(set);
    }

    int size() {
        return domains.size();
    }

    /**
     * True if {@code name} or any parent domain (never the bare TLD) is on the list,
     * unless {@code allow} contains the name or one of its parents - the allow-list always wins.
     */
    boolean isBlocked(String name, Set<String> allow) {
        boolean blocked = false;
        String s = name;
        while (true) {
            if (allow != null && allow.contains(s)) return false;
            if (domains.contains(s)) blocked = true;
            int dot = s.indexOf('.');
            if (dot < 0) break;
            s = s.substring(dot + 1);
            if (s.indexOf('.') < 0) break;       // stop before the bare TLD
        }
        return blocked;
    }

    /** Parses the user's allow-list text: one domain per line, '#' comments, "*." / "." prefixes ignored. */
    static Set<String> parseList(String raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptySet();
        HashSet<String> out = new HashSet<>();
        for (String line : raw.split("\\r?\\n")) {
            int hash = line.indexOf('#');
            if (hash >= 0) line = line.substring(0, hash);
            line = line.trim().toLowerCase(Locale.ROOT);
            while (line.startsWith("*.") || line.startsWith(".")) {
                line = line.startsWith("*.") ? line.substring(2) : line.substring(1);
            }
            if (line.endsWith(".")) line = line.substring(0, line.length() - 1);
            if (!line.isEmpty()) out.add(line);
        }
        return out;
    }
}
