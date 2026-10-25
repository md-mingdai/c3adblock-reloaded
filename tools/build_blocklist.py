#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 100k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
"""
import re
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~100k entries / 0.5 MB
# (Hagezi's wildcard lists drop subdomains the firmware's parent-matching already covers).
# Want more? swap light-onlydomains.txt -> pro-onlydomains.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',  # Hagezi Light (wildcard = domain + subdomains)
]

# Hosts a phone probes to decide whether a Wi-Fi network "has internet": Android fetches
# http://<host>/generate_204 and flags the network 无法访问互联网 / "no internet" when that fails, and
# vendor ROMs bring their own hosts. Some blocklists include a few of them (Hagezi Light lists
# conn1-5.coloros.com), and then a phone using this DNS reports the network as offline although
# everything works. They are dropped from the output whichever source lists them.
# Only exact entries can be dropped: the device also matches parent domains, so a *listed parent* of
# one of these still blocks it (main() warns about that).
CONNECTIVITY_PROBES = (
    'connectivitycheck.gstatic.com', 'connectivitycheck.android.com',      # Google / stock Android
    'connect.rom.miui.com',                                                  # Xiaomi
    'connectivitycheck.platform.hicloud.com',                                # Huawei
    'conn1.coloros.com', 'conn2.coloros.com', 'conn3.coloros.com',           # ColorOS (OPPO / OnePlus / realme)
    'conn4.coloros.com', 'conn5.coloros.com',
)

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    # utf-8-sig: explicit (the platform default, e.g. cp936 on Chinese Windows, mangles UTF-8 lists)
    # and it drops a leading BOM, which would otherwise glue itself to the first line's IP and
    # silently lose that entry.
    if os.path.exists(src):
        with open(src, encoding='utf-8-sig', errors='ignore') as fh:
            return fh.read()
    print(f'  downloading {src} ...', file=sys.stderr)
    with urllib.request.urlopen(src, timeout=180) as resp:
        return resp.read().decode('utf-8-sig', 'ignore')

def main():
    global ALLOW_MISSING
    args = [a for a in sys.argv[1:] if a != '--allow-missing']
    ALLOW_MISSING = '--allow-missing' in sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    dropped = sorted(domains.intersection(CONNECTIVITY_PROBES))
    if dropped:
        domains.difference_update(dropped)
        print(f'connectivity hosts: {len(dropped)} kept reachable ({", ".join(dropped)})', file=sys.stderr)
    for host in CONNECTIVITY_PROBES:
        labels = host.split('.')
        for i in range(1, len(labels) - 1):          # the parents the firmware tries: down to two labels
            parent = '.'.join(labels[i:])
            if parent in domains:
                print(f'!! {parent} is listed, so {host} is still blocked on the device (parent match)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)
    if not domains:
        # Sources that parse to nothing (wrong file, upstream changed format ...) must not leave an
        # empty blob behind that looks like a successful build -- the device rejects it, but a
        # release/CI step would happily publish it.
        print('!! no domains parsed from any source -- nothing written', file=sys.stderr)
        sys.exit(1)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
