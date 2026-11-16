"""M-3 / M-2: destinations the proxy must never reach, however they are named."""

import time

from tests.e2e.harness import (INTERNAL_TARGETS, ORIGIN_V4, Proxy, ProxyTestCase, http_request, requires_current,
                               tunnel, unique)


def _policy(hosts):
    origins = []
    for host in hosts:
        origins += [f"https://{host}", f"http://{host}"]
    return {"version": 1, "principals": {"demo": origins}}


class InternalDestinationTests(ProxyTestCase):
    """Even when policy allows the NAME, the address it resolves to must be refused."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.names = list(INTERNAL_TARGETS) + ["mixed.test", "rebind.test"]
        cls.proxy = Proxy(policy=_policy(cls.names + ["example.com"])).start()
        cls.creds = ("demo", "demo-password")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_hostnames_resolving_to_internal_addresses(self):  # E-M3-01..16
        for name, address in INTERNAL_TARGETS.items():
            with self.subTest(name=name, address=address):
                result = tunnel(self.proxy, f"{name}:443", self.creds)
                self.assertFalse(result.established, result)
                r = http_request(self.proxy, f"http://{name}/", self.creds)
                self.assertNotEqual(r.status, 200, f"{name} over HTTP")
                self.assertNotReached(address)

    def test_mixed_public_and_internal_answer(self):  # E-M3-17
        result = tunnel(self.proxy, "mixed.test:443", self.creds)
        self.assertFalse(result.established, result)
        self.assertNotReached("169.254.169.254")

    def test_dns_rebinding(self):  # E-M3-18
        self.fx.dns.set_sequence("rebind.test", [[ORIGIN_V4], ["169.254.169.254"]], ttl=0)
        for _ in range(8):
            tunnel(self.proxy, "rebind.test:443", self.creds)
            http_request(self.proxy, "http://rebind.test/", self.creds)
            time.sleep(0.2)
        self.assertNotReached("169.254.169.254")

    def test_positive_control(self):
        self.assertTrue(tunnel(self.proxy, "example.com:443", self.creds).established)


class LiteralAndEncodedAddressTests(ProxyTestCase):
    """IP literals and alternate numeric encodings, even if a policy lists them."""

    LITERALS = ["169.254.169.254", "[::ffff:169.254.169.254]", "[::ffff:a9fe:a9fe]", "0xa9fea9fe",
                "169.254.43518", "2852039166", "[64:ff9b::a9fe:a9fe]", "[fd00:ec2::254]", "10.0.0.5",
                "[2002:a9fe:a9fe::1]", "168.63.129.16", "192.0.0.192"]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        origins = []
        for literal in cls.LITERALS:
            origins += [f"https://{literal}", f"http://{literal}"]
        valid = []
        from clearideas_egress.policy import PolicyError, _origin  # noqa: F401
        for origin in origins:
            try:
                _origin(origin)
                valid.append(origin)
            except Exception:
                pass  # the remediated policy loader refuses ambiguous numeric hosts outright
        cls.proxy = Proxy(policy={"version": 1, "principals": {"demo": valid}}).start()
        cls.creds = ("demo", "demo-password")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_literals_refused(self):
        for literal in self.LITERALS:
            with self.subTest(literal=literal):
                result = tunnel(self.proxy, f"{literal}:443", self.creds, sni=None)
                self.assertFalse(result.established, result)
                r = http_request(self.proxy, f"http://{literal}/", self.creds)
                self.assertNotEqual(r.status, 200)
        time.sleep(0.3)
        for address, listener in self.fx.internal.items():
            self.assertEqual(listener.hits, [], address)


@requires_current("operator deny-list extension")
class OperatorDenyListTests(ProxyTestCase):
    def test_extra_deny_cidrs(self):  # E-M3-19
        proxy = Proxy(policy=_policy(["example.com"]))
        extra = proxy.run_dir / "extra-deny.txt"
        extra.write_text("# operator: block this public origin\n93.184.215.14/32\n")
        proxy.extra_env["EGRESS_EXTRA_DENY_CIDRS_FILE"] = str(extra)
        with proxy:
            self.assertFalse(tunnel(proxy, "example.com:443", ("demo", "demo-password")).established)
            self.assertNotEqual(http_request(proxy, "http://example.com/", ("demo", "demo-password")).status, 200)


@requires_current("network backstop ruleset")
class NetworkBackstopTests(ProxyTestCase):
    """E-M3-20: the shipped nftables ruleset stops internal access even if Squid is misconfigured."""

    RULESET = __import__("pathlib").Path(__file__).resolve().parents[2] / "deploy" / "nftables" / "egress-proxy.nft"

    def _broken_proxy(self):
        # Simulate a configuration/parser failure: remove Squid's own destination checks.
        return Proxy(policy=_policy(["imds.test", "nat64-imds.test", "example.com"]),
                     mutate_config=lambda text: text.replace(" !to_localhost !private_dst", ""))

    def test_backstop(self):
        import subprocess
        imds = self.fx.internal["169.254.169.254"]
        with self._broken_proxy() as proxy:
            # Without the backstop the broken proxy reaches the metadata address (proves the test can fail).
            before = len(imds.hits)
            tunnel(proxy, "imds.test:443", ("demo", "demo-password"))
            time.sleep(0.3)
            self.assertGreater(len(imds.hits), before, "control: broken config should reach the metadata listener")
            # In this sandbox clients and proxy share one namespace, so client->proxy traffic to the
            # listener address (10.20.0.1, inside 10.0.0.0/8) is "output" too. In production it is
            # inbound. Exempt it the way an operator edits the defines.
            ruleset = proxy.run_dir / "backstop.nft"
            ruleset.write_text(self.RULESET.read_text().replace(
                "define CONTROL_V4 = { 127.0.0.1 }", "define CONTROL_V4 = { 127.0.0.1, 10.20.0.1 }"))
            subprocess.run(["nft", "-f", str(ruleset)], check=True, capture_output=True)
            try:
                before = len(imds.hits), len(self.fx.internal["64:ff9b::a9fe:a9fe"].hits)
                self.assertFalse(tunnel(proxy, "imds.test:443", ("demo", "demo-password")).established)
                self.assertNotEqual(http_request(proxy, "http://imds.test/", ("demo", "demo-password")).status, 200)
                self.assertFalse(tunnel(proxy, "nat64-imds.test:443", ("demo", "demo-password")).established)
                time.sleep(0.3)
                self.assertEqual((len(imds.hits), len(self.fx.internal["64:ff9b::a9fe:a9fe"].hits)), before)
                # Evidence the requests reached Squid and were ALLOWED by policy, i.e. only the
                # network layer stopped them (not a client-side failure).
                allowed_hosts = {a["host"] for a in proxy.audit_records("decision") if a["decision"] == "allow"}
                self.assertTrue({"imds.test", "nat64-imds.test"} <= allowed_hosts, allowed_hosts)
                attempts = [r for r in proxy.access_records() if "imds.test" in r.get("url", "")]
                self.assertGreaterEqual(len(attempts), 3)
                self.assertFalse([r for r in attempts if r.get("decision") == "origin_not_allowed"])
                # DNS (resolver allowlisted) and public destinations keep working.
                self.assertTrue(tunnel(proxy, "example.com:443", ("demo", "demo-password")).established)
                counters = subprocess.run(["nft", "list", "table", "inet", "egress_backstop"],
                                          capture_output=True, text=True).stdout
                self.assertRegex(counters, r"counter packets [1-9]")
            finally:
                subprocess.run(["nft", "delete", "table", "inet", "egress_backstop"], capture_output=True)
