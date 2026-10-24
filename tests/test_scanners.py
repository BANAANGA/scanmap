import os
import tempfile
import unittest

from app.scanners import (
    ValidationError,
    build_argv,
    build_nmap,
    build_zmap,
    validate_nmap_target,
    validate_zmap_target,
)


class NmapTest(unittest.TestCase):
    def test_defaults(self):
        argv = build_nmap({"target": "192.168.1.0/24"})
        self.assertEqual(argv[0], "nmap")
        self.assertIn("-sT", argv)
        self.assertIn("-p", argv)
        self.assertEqual(argv[-1], "192.168.1.0/24")

    def test_targets_are_normalised(self):
        self.assertEqual(
            validate_nmap_target("10.0.0.0/24, 10.0.1.1 10.0.2.1"),
            "10.0.0.0/24,10.0.1.1,10.0.2.1",
        )

    def test_ping_scan_has_no_ports(self):
        argv = build_nmap({"target": "example.com", "scan": "ping"})
        self.assertIn("-sn", argv)
        self.assertNotIn("-p", argv)

    def test_options(self):
        argv = build_nmap(
            {
                "target": "10.0.0.1",
                "scan": "syn",
                "ports": "22,80,443",
                "timing": "T4",
                "service_detection": True,
                "version_intensity": 9,
                "default_scripts": True,
                "scripts": "http-title,vulners",
                "os_detection": True,
                "no_ping": True,
                "open_only": True,
            }
        )
        for flag in ("-sS", "-T4", "-sV", "-sC", "-O", "-Pn", "--open"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("-p") + 1], "22,80,443")
        self.assertEqual(argv[argv.index("--version-intensity") + 1], "9")
        self.assertEqual(argv[argv.index("--script") + 1], "http-title,vulners")

    def test_target_injection_rejected(self):
        for bad in [
            "",
            " ",
            "-iL /etc/passwd",
            "10.0.0.1; id",
            "10.0.0.1 && id",
            "$(id)",
            "`id`",
            "10.0.0.1 | tee /tmp/x",
            "a/b/c",
            "10.0.0.1' ",
        ]:
            with self.subTest(target=bad), self.assertRaises(ValidationError):
                build_nmap({"target": bad})

    def test_bad_ports_rejected(self):
        for bad in ["", "abc", "-p-", "1-", "22 80", "22;80"]:
            with self.subTest(ports=bad), self.assertRaises(ValidationError):
                build_nmap({"target": "10.0.0.1", "ports": bad})

    def test_bad_scripts_rejected(self):
        for bad in ["--script=foo", "http-title & id", "http-title;id", "$(id)"]:
            with self.subTest(scripts=bad), self.assertRaises(ValidationError):
                build_nmap({"target": "10.0.0.1", "scripts": bad})

    def test_bad_choice_rejected(self):
        with self.assertRaises(ValidationError):
            build_nmap({"target": "10.0.0.1", "scan": "magic"})
        with self.assertRaises(ValidationError):
            build_nmap({"target": "10.0.0.1", "timing": "T9"})


class ZmapTest(unittest.TestCase):
    def test_defaults(self):
        argv = build_zmap({"target": "192.168.1.0/24"})
        self.assertEqual(argv[0], "zmap")
        self.assertEqual(argv[argv.index("-p") + 1], "443")
        self.assertEqual(argv[argv.index("-B") + 1], "1M")
        self.assertEqual(argv[argv.index("-M") + 1], "tcp_synscan")
        self.assertEqual(argv[argv.index("-f") + 1], "saddr,dport")
        self.assertEqual(argv[-1], "192.168.1.0/24")

    def test_options(self):
        argv = build_zmap(
            {
                "target": "10.0.0.0/8",
                "port": 80,
                "bandwidth": "10m",
                "rate": 5000,
                "interface": "eth0",
                "source_port": 40000,
                "probe_module": "icmp_echoscan",
                "output_fields": "saddr,ttl",
                "max_targets": 100,
                "cooldown": True,
                "dry_run": True,
            }
        )
        self.assertEqual(argv[argv.index("-B") + 1], "10M")
        self.assertEqual(argv[argv.index("-r") + 1], "5000")
        self.assertEqual(argv[argv.index("-i") + 1], "eth0")
        # -s is --source-port; -S would be --source-ip.
        self.assertEqual(argv[argv.index("-s") + 1], "40000")
        self.assertNotIn("-S", argv)
        self.assertEqual(argv[argv.index("-M") + 1], "icmp_echoscan")
        self.assertEqual(argv[argv.index("-f") + 1], "saddr,ttl")
        self.assertEqual(argv[argv.index("-n") + 1], "100")
        self.assertIn("-d", argv)
        self.assertIn("-c", argv)

    def test_results_are_written_to_stdout(self):
        argv = build_zmap({"target": "8.8.8.8/32"})
        self.assertEqual(argv[argv.index("-o") + 1], "-")

    def test_verbosity_takes_a_level(self):
        # `zmap -v` alone swallows the next flag ("invalid numeric value: -p").
        argv = build_zmap({"target": "8.8.8.8/32"})
        self.assertEqual(argv[argv.index("-v") + 1], "4")

    def test_private_target_ignores_builtin_blocklist(self):
        for target in ("192.168.1.0/24", "10.0.0.1", "127.0.0.1/32", "fe80::1"):
            with self.subTest(target=target):
                argv = build_zmap({"target": target})
                self.assertEqual(argv[argv.index("-b") + 1], "/dev/null")

    def test_public_target_keeps_builtin_blocklist(self):
        argv = build_zmap({"target": "8.8.8.8/32"})
        self.assertNotIn("-b", argv)
        argv = build_zmap({"target": "8.8.8.8/32", "disable_default_blacklist": True})
        self.assertEqual(argv[argv.index("-b") + 1], "/dev/null")

    def test_icmp_scan_drops_tcp_only_fields(self):
        argv = build_zmap(
            {"target": "10.0.0.0/8", "probe_module": "icmp_echoscan", "output_fields": "saddr,dport"}
        )
        self.assertEqual(argv[argv.index("-f") + 1], "saddr")

    def test_tcp_field_names_match_zmap(self):
        argv = build_zmap(
            {"target": "10.0.0.0/8", "output_fields": "saddr,sport,dport,seqnum,acknum"}
        )
        self.assertEqual(argv[argv.index("-f") + 1], "saddr,sport,dport,seqnum,acknum")

    def test_single_target_only(self):
        with self.assertRaises(ValidationError):
            validate_zmap_target("10.0.0.0/24,10.0.1.0/24")

    def test_bad_targets_rejected(self):
        for bad in ["", "-", "-i eth0", "10.0.0.1/24/7", "example.com", "10.0.0.1;id"]:
            with self.subTest(target=bad), self.assertRaises(ValidationError):
                build_zmap({"target": bad})

    def test_bad_bandwidth_and_fields(self):
        with self.assertRaises(ValidationError):
            build_zmap({"target": "10.0.0.0/8", "bandwidth": "fast"})
        with self.assertRaises(ValidationError):
            build_zmap({"target": "10.0.0.0/8", "output_fields": "saddr,password"})
        with self.assertRaises(ValidationError):
            build_zmap({"target": "10.0.0.0/8", "port": 70000})

    def test_blocklist_must_stay_in_data_dir(self):
        with tempfile.TemporaryDirectory() as data_dir, tempfile.NamedTemporaryFile() as outside:
            with self.assertRaises(ValidationError):
                build_zmap({"target": "10.0.0.0/8", "blocklist": outside.name}, data_dir)

            inside = os.path.join(data_dir, "blocklist.txt")
            with open(inside, "w", encoding="utf-8") as handle:
                handle.write("192.168.1.1/32\n")
            argv = build_zmap({"target": "10.0.0.0/8", "blocklist": "blocklist.txt"}, data_dir)
            self.assertEqual(argv[argv.index("-b") + 1], os.path.realpath(inside))

    def test_missing_blocklist_rejected(self):
        with tempfile.TemporaryDirectory() as data_dir:
            with self.assertRaises(ValidationError):
                build_zmap({"target": "10.0.0.0/8", "blocklist": "nope.txt"}, data_dir)


class DispatchTest(unittest.TestCase):
    def test_build_argv(self):
        self.assertEqual(build_argv("nmap", {"target": "10.0.0.1"})[0], "nmap")
        self.assertEqual(build_argv("zmap", {"target": "10.0.0.0/8"})[0], "zmap")

    def test_unknown_scanner(self):
        with self.assertRaises(ValidationError):
            build_argv("masscan", {"target": "10.0.0.1"})

    def test_params_must_be_object(self):
        with self.assertRaises(ValidationError):
            build_argv("nmap", ["10.0.0.1"])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
