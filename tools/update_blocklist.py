#!/usr/bin/env python3
"""Build app/src/main/assets/blocklist.txt from the StevenBlack unified hosts file (MIT licence).

Usage:
    python3 tools/update_blocklist.py            # download the latest list
    python3 tools/update_blocklist.py hosts.txt  # use a local copy

The input is treated as untrusted: only strictly valid hostnames survive.
"""
import datetime
import re
import sys
import urllib.request

URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
OUT = "app/src/main/assets/blocklist.txt"

LABEL = r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?"
HOST_RE = re.compile(rf"^{LABEL}(\.{LABEL})+$")
SKIP = {"localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
        "0.0.0.0"}


def read_source(argv):
    if len(argv) > 1:
        with open(argv[1], "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    with urllib.request.urlopen(URL, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")


def main():
    text = read_source(sys.argv)
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("0.0.0.0", "127.0.0.1"):
            continue
        host = parts[1].lower().rstrip(".")
        if host in SKIP or len(host) > 253 or not HOST_RE.match(host):
            continue
        domains.add(host)
    if len(domains) < 10000:
        sys.exit(f"refusing to write: only {len(domains)} domains parsed (bad download?)")
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("# AdShield blocklist - derived from StevenBlack/hosts (MIT licence)\n")
        f.write("# https://github.com/StevenBlack/hosts\n")
        f.write(f"# generated {datetime.date.today().isoformat()}, {len(domains)} domains\n")
        for d in sorted(domains):
            f.write(d + "\n")
    print(f"wrote {len(domains)} domains to {OUT}")


if __name__ == "__main__":
    main()
