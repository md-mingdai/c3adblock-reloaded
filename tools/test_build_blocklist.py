import pathlib
import subprocess
import sys
import tempfile
import unittest

from build_blocklist import CONNECTIVITY_PROBES, HASH_BYTES, fnv, norm

TOOL = pathlib.Path(__file__).with_name('build_blocklist.py')


def run_tool(root, sources, *flags):
    """Run build_blocklist.py in `root`; returns (CompletedProcess, blob bytes or None)."""
    output = root / 'blocklist.bin'
    proc = subprocess.run([sys.executable, str(TOOL), str(output), *map(str, sources), *flags],
                          capture_output=True, text=True)
    return proc, (output.read_bytes() if output.exists() else None)


def build(source_text, encoding='utf-8'):
    """Write `source_text` (str or bytes) to a temp source file and build it."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        source = root / 'src.txt'
        source.write_bytes(source_text if isinstance(source_text, bytes) else source_text.encode(encoding))
        return run_tool(root, [source])


def entries(data):
    return [int.from_bytes(data[i:i + HASH_BYTES], 'little') for i in range(0, len(data), HASH_BYTES)]


def hashes_of(*domains):
    return {fnv(d.encode()) for d in domains}


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        proc, data = build('0.0.0.0 ads.example.com tracker.example.com # comment\n'
                           '127.0.0.1 metrics.example.com\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)),
                         hashes_of('ads.example.com', 'tracker.example.com', 'metrics.example.com'))

    def test_fnv_matches_firmware_golden_vectors(self):
        # Values produced by the firmware's fnv40() algorithm (64-bit FNV-1a, low 40 bits) in C.
        # If these ever change, every blocklist already built or shipped stops matching on-device.
        self.assertEqual(fnv(b'example.com'), 0x634e2714c6)
        self.assertEqual(fnv(b'ads.example.com'), 0x58979aa55e)
        self.assertEqual(fnv(b'doubleclick.net'), 0xcd127775cd)
        self.assertEqual(fnv(b'a.b.example.org'), 0xb4cc609a98)

    def test_adguard_rules_and_allowlist(self):
        proc, data = build('||ads.example.com^\n'
                           '@@||ok.example.org^\n'
                           '||ok.example.org^\n'
                           '||mod.example.net^$important\n'   # has modifiers: cannot be expressed, skipped
                           '/^regex$/\n'
                           '! a comment\n'
                           '[Adblock Plus 2.0]\n'
                           'plain.example.com\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)), hashes_of('ads.example.com', 'plain.example.com'))

    def test_output_is_sorted_unique_whole_entries(self):
        domains = [f'host{i}.example{i % 7}.com' for i in range(500)] + ['host1.example1.com']  # one duplicate
        proc, data = build('\n'.join(f'0.0.0.0 {d}' for d in reversed(domains)) + '\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(data) % HASH_BYTES, 0)
        found = entries(data)
        # the firmware binary-searches the file as little-endian integers, so numeric order matters
        self.assertEqual(found, sorted(set(found)))
        self.assertEqual(set(found), hashes_of(*domains))

    def test_names_are_normalised_like_the_firmware_does(self):
        # firmware: lower-case, "www." stripped from the query; tool: same, plus trailing dot
        proc, data = build('0.0.0.0 WWW.Example.COM.\n127.0.0.1 localhost\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)), hashes_of('example.com'))

    def test_utf8_bom_does_not_drop_the_first_entry(self):
        proc, data = build(b'\xef\xbb\xbf0.0.0.0 first.example.com\n0.0.0.0 second.example.com\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)), hashes_of('first.example.com', 'second.example.com'))

    def test_sources_that_parse_to_nothing_are_an_error(self):
        proc, data = build('# only a comment\n127.0.0.1 localhost\n')
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(data, 'no output file may be left behind for an empty build')

    def test_unreadable_source_fails_unless_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            good = root / 'good.txt'
            good.write_text('0.0.0.0 ads.example.com\n', encoding='utf-8')
            missing = root / 'does-not-exist.txt'

            proc, data = run_tool(root, [good, missing])
            self.assertNotEqual(proc.returncode, 0)

            proc, data = run_tool(root, [good, missing], '--allow-missing')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(set(entries(data)), hashes_of('ads.example.com'))

    def test_connectivity_probe_hosts_never_make_it_into_the_list(self):
        # A phone flags the Wi-Fi "no internet" when its probe host is blocked (Hagezi Light lists
        # conn1-5.coloros.com), whichever syntax the source uses.
        proc, data = build('0.0.0.0 ads.example.com\n'
                           '0.0.0.0 conn1.coloros.com\n'
                           '||connectivitycheck.gstatic.com^\n'
                           'connect.rom.miui.com\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)), hashes_of('ads.example.com'))
        self.assertIn('connectivity hosts: 3 kept reachable', proc.stderr)

    def test_listed_parent_of_a_probe_host_is_reported_not_dropped(self):
        # The device matches parent domains too, so the parent keeps blocking the probe host.
        # Dropping the parent would unblock everything under it, so the tool only says so.
        proc, data = build('0.0.0.0 coloros.com\n0.0.0.0 ads.example.com\n')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(set(entries(data)), hashes_of('coloros.com', 'ads.example.com'))
        self.assertIn('coloros.com is listed, so conn1.coloros.com is still blocked', proc.stderr)

    def test_probe_hosts_are_spelled_the_way_the_tool_normalises_names(self):
        self.assertEqual(len(set(CONNECTIVITY_PROBES)), len(CONNECTIVITY_PROBES))
        for host in CONNECTIVITY_PROBES:
            self.assertEqual(norm(host), host)


if __name__ == '__main__':
    unittest.main()
