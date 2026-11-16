import ipaddress
import itertools
import json
import re
import tempfile
import unittest
from pathlib import Path

from clearideas_egress.render import Settings, SettingsError, deny_cidrs, render

DNS_ACL_TYPES = {"dst", "dstdomain", "dstdom_regex", "dst_as"}
BUILTIN_DNS_ACLS = {"to_localhost", "to_linklocal"}
REQUIRED = ["httpd_suppress_version_string on", "relaxed_header_parser off", "email_err_data off", "via off",
            "forwarded_for delete", "cachemgr_passwd disable all", "cache deny all", "dns_defnames off",
            "reply_header_access Server deny all", "uri_whitespace deny", "request_start_timeout"]


def base_env(**overrides):
    directory = Path(tempfile.mkdtemp())
    (directory / "keys").mkdir()
    env = {"EGRESS_RUN_DIR": str(directory / "run"), "EGRESS_AUTH_KEYS_DIR": str(directory / "keys"),
           "EGRESS_POLICY_FILE": str(directory / "policy.json"), "EGRESS_PYTHON": "/usr/bin/python3"}
    env.update(overrides)
    return env


def variants():
    for auth, tls, lb, ttl, mode, maxconn, checks, scope in itertools.product(
            ("token", "htpasswd", "signed-headers"), ("sni", "off"), ("", "10.30.0.0/24"), ("0", "300"),
            ("connect", "origination", "both"), ("64", "0"), (False, True), ("api", "origin")):
        env = base_env(EGRESS_TLS_ENFORCEMENT=tls, EGRESS_DECISION_TTL=ttl, EGRESS_TRUSTED_PROXY_CIDRS=lb,
                       EGRESS_AUTH_MODE=auth, EGRESS_HTPASSWD_FILE="/etc/egress/htpasswd", EGRESS_MODE=mode,
                       EGRESS_SIGNING_KEYS_DIR="/etc/egress/signing", EGRESS_MAX_CONN_PER_CLIENT=maxconn)
        env["EGRESS_DECISION_SCOPE"] = scope
        if checks:
            env["EGRESS_REVOKED_FILE"] = "/etc/egress/revoked"
        yield (auth, tls, lb, ttl, mode, maxconn, scope), env


def render_env(env):
    settings = Settings.from_env(env)
    if settings.auth_mode == "htpasswd":
        import clearideas_egress.render as module
        original = module._find_ncsa
        module._find_ncsa = lambda: "/usr/lib/squid/basic_ncsa_auth"
        try:
            return render(settings)
        finally:
            module._find_ncsa = original
    return render(settings)


def directives(text):
    return [line.split() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


class ConfigLintTests(unittest.TestCase):
    """Invariants from the security review, checked on every rendered variant."""

    def test_invariants(self):
        for name, env in variants():
            with self.subTest(variant=name):
                lines = directives(render_env(env))
                acl_types = {}
                for words in lines:
                    if words[0] == "acl":
                        acl_types.setdefault(words[1], words[2])
                auth, tls, lb, ttl, mode, maxconn, scope = name
                dns_acls = {n for n, t in acl_types.items() if t in DNS_ACL_TYPES} | BUILTIN_DNS_ACLS
                helper_acls = {n for n, t in acl_types.items() if t == "external"}
                self.assertTrue({"policy_allowed"} <= helper_acls)
                access = [w[1:] for w in lines if w[0] == "http_access"]
                text_raw = "\n".join(" ".join(w) for w in lines)

                # Signed-header mode: signature check precedes policy; never cached; policy reads
                # identity from annotations only (never from raw client headers).
                policy_def = next(w for w in lines if w[:2] == ["external_acl_type", "egress_policy"])
                self.assertFalse(any(t.startswith("%>{") for t in policy_def), policy_def)
                self.assertIn("%note{egress_identity_}", policy_def)
                allow = next(r for r in access if r[0] == "allow" and "policy_allowed" in r)
                # Per-request checks are never cached and run after (never instead of) the decision.
                if "request_ok" in allow:
                    self.assertGreater(allow.index("request_ok"), allow.index("policy_allowed"))
                    request_def = next(w for w in lines if w[:2] == ["external_acl_type", "egress_request"])
                    self.assertIn("ttl=0", request_def)
                    self.assertIn("negative_ttl=0", request_def)
                if auth == "signed-headers":
                    self.assertLess(allow.index("signed_ok"), allow.index("policy_allowed"))
                    signed_def = next(w for w in lines if w[:2] == ["external_acl_type", "egress_signed"])
                    self.assertIn("ttl=0", signed_def)
                    self.assertIn("negative_ttl=0", signed_def)
                    self.assertNotIn("auth_param", text_raw)
                else:
                    self.assertIn(["deny", "!authenticated"], access)
                    self.assertIn("auth_param basic casesensitive on", text_raw)
                for header in ("X-Egress-Run-Id", "X-Egress-Timestamp", "X-Egress-Nonce", "X-Egress-Signature"):
                    self.assertIn(f"request_header_access {header} deny all", text_raw)
                # Squid reserves annotation names without a trailing "_" (and logs their values).
                for note in re.findall(r"%note\{([^}]+)\}", text_raw) + [w[3] for w in lines if w[0] == "acl" and w[2] == "note"]:
                    self.assertTrue(note.endswith("_") or note == "clt_conn_tag", note)
                if mode == "origination":
                    self.assertIn(["deny", "CONNECT"], access)
                    self.assertLess(access.index(["deny", "CONNECT"]), len(access) - 1)
                if mode in ("origination", "both"):
                    self.assertIn("tls_outgoing_options min-version=1.2", text_raw)
                self.assertEqual("too_many_conns" in text_raw, maxconn != "0")

                # 1. no DNS-triggering ACL before the policy decision (review C-1)
                policy_index = next(i for i, rule in enumerate(access) if "policy_allowed" in rule)
                for rule in access[:policy_index]:
                    self.assertFalse({a.lstrip("!") for a in rule[1:]} & dns_acls, rule)
                policy_rule = access[policy_index]
                for token in policy_rule[1:]:
                    if token.lstrip("!") in dns_acls:
                        self.assertGreater(policy_rule.index(token), policy_rule.index("policy_allowed"))

                # 2. helper-backed ACLs: positive form, allow/splice lines only (review H-3)
                for words in lines:
                    if words[0] in {"http_access", "ssl_bump", "http_reply_access", "adapted_http_access"}:
                        for token in words[2:]:
                            if token.lstrip("!") in helper_acls:
                                self.assertFalse(token.startswith("!"), words)
                                self.assertIn(words[1], {"allow", "splice"}, words)

                # 3./4. manager first, deny all last, terminate all last (review H-4)
                # Manager: only on the loopback admin port, and denied everywhere else first (review H-4).
                manager_index = access.index(["deny", "manager"])
                self.assertEqual(access[:manager_index],
                                 [["allow", "manager", "admin_port", "localhost"], ["deny", "admin_port"]])
                ports = [w for w in lines if w[0] == "http_port"]
                admin = [w for w in ports if "name=admin" in w]
                self.assertEqual(len(admin), 1)
                self.assertTrue(admin[0][1].startswith("127.0.0.1:"), admin)
                public_actions = next(w for w in lines if w[:3] == ["cachemgr_passwd", "none", "info"])[2:]
                self.assertFalse({"client_list", "active_requests", "username_cache", "config", "ipcache",
                                  "fqdncache"} & set(public_actions))
                self.assertEqual(access[-1], ["deny", "all"])
                bumps = [w[1:] for w in lines if w[0] == "ssl_bump"]
                if tls == "sni" and mode != "origination":
                    self.assertEqual(bumps[-1], ["terminate", "all"])
                    self.assertIn(["peek", "step1"], bumps)
                else:
                    self.assertEqual(bumps, [])

                # 5. hardening present (review M-4)
                text = "\n".join(" ".join(w) for w in lines)
                for required in REQUIRED:
                    self.assertIn(required, text)
                if auth == "token":
                    self.assertIn('auth_param basic key_extras "%>a"', text)
                if lb:
                    self.assertIn("require-proxy-header", text)
                    self.assertIn("proxy_protocol_access deny all", text)
                # "api": the helper keeps scoped approvals, Squid must not cache allows itself.
                self.assertIn(f"ttl={0 if scope == 'api' else ttl} ", text)
                self.assertEqual("%>rp" in " ".join(policy_def), scope != "origin")


class ProfileAndCredentialRenderTests(unittest.TestCase):
    def test_custom_profile(self):
        env = base_env(EGRESS_MODE="origination", EGRESS_AUTH_MODE="signed-headers", EGRESS_SIGNING_KEYS_DIR="/k",
                       EGRESS_SIGNED_IDENTITY="jobId=X-Acme-Job,runnerId=X-Acme-Runner",
                       EGRESS_SIGNED_PRINCIPAL="runnerId", EGRESS_SIGNED_HEADER_PREFIX="X-Acme-")
        text = render(Settings.from_env(env))
        self.assertIn("%>{X-Acme-Job} %>{X-Acme-Runner} %>{X-Acme-Timestamp} %>{X-Acme-Nonce} %>{X-Acme-Signature}", text)
        for header in ("X-Acme-Job", "X-Acme-Runner", "X-Acme-Signature"):
            self.assertIn(f"request_header_access {header} deny all", text)
        with self.assertRaises(SettingsError):
            Settings.from_env({**env, "EGRESS_SIGNED_IDENTITY": "job id=X"})

    def test_credentials(self):
        directory = Path(tempfile.mkdtemp())
        creds = directory / "c.json"
        creds.write_text(json.dumps({"version": 1, "rules": [
            {"id": "openai", "origin": "https://api.openai.com", "header": "Authorization", "value": "Bearer {secret}",
             "secretFile": "/run/secrets/openai", "stripHeaders": ["OpenAI-Organization"]}]}))
        text = render(Settings.from_env(base_env(EGRESS_MODE="origination", EGRESS_CREDENTIALS_FILE=str(creds))))
        self.assertIn("acl egress_cred_openai note egress_cred_ openai", text)
        self.assertIn("request_header_access authorization deny egress_cred_openai", text)
        self.assertIn("request_header_access openai-organization deny egress_cred_openai", text)
        self.assertIn('request_header_add authorization "Bearer %note{egress_secret_}" egress_cred_openai', text)
        with self.assertRaises(SettingsError):
            Settings.from_env(base_env(EGRESS_MODE="connect", EGRESS_CREDENTIALS_FILE=str(creds)))


class SettingsTests(unittest.TestCase):
    def test_write_runtime_requires_keys(self):
        from clearideas_egress.render import write_runtime
        env = base_env(EGRESS_TLS_ENFORCEMENT="off")
        Path(env["EGRESS_POLICY_FILE"]).write_text('{"version":1,"principals":{}}')
        with self.assertRaises(SettingsError):  # keys dir exists but is empty
            write_runtime(Settings.from_env(env))

    def test_injection_rejected(self):
        for key, value in [
            ("EGRESS_RUN_DIR", "/run/egress\nhttp_access allow all"),
            ("EGRESS_RUN_DIR", "relative/path"),
            ("EGRESS_RUN_DIR", "/run/../etc"),
            ("EGRESS_VISIBLE_HOSTNAME", "egress\nhttp_access allow all"),
            ("EGRESS_ACCESS_LOG", "stdio:/x y"),
            ("EGRESS_TRUSTED_PROXY_CIDRS", "10.0.0.0/8\nhttp_access allow all"),
            ("EGRESS_DNS_NAMESERVERS", "8.8.8.8;rm"),
            ("EGRESS_REQUEST_BODY_MAX_SIZE", "10 MB\nacl x"),
            ("EGRESS_DECISION_TTL", "5\nhttp_access allow all"),
            ("EGRESS_DECISION_TTL", "-1"),
            ("EGRESS_LISTEN_PORT", "80"),
            ("EGRESS_TLS_ENFORCEMENT", "maybe"),
            ("EGRESS_AUTH_MODE", "none"),
            ("EGRESS_PYTHON", "/usr/bin/python3 -c evil"),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(SettingsError):
                render(Settings.from_env(base_env(**{key: value})))

    def test_backend_and_auth_required(self):
        env = base_env()
        del env["EGRESS_POLICY_FILE"]
        with self.assertRaises(SettingsError):
            Settings.from_env(env)
        with self.assertRaises(SettingsError):
            Settings.from_env(base_env(EGRESS_POLICY_URL="https://x.example/"))
        env = base_env()
        del env["EGRESS_AUTH_KEYS_DIR"]
        with self.assertRaises(SettingsError):
            Settings.from_env(env)
        with self.assertRaises(SettingsError):
            Settings.from_env(base_env(EGRESS_AUTH_MODE="htpasswd"))

    def test_defaults(self):
        text = render(Settings.from_env(base_env()))
        for expected in ["http_port 3128 ssl-bump", "ttl=0 negative_ttl=5", "credentialsttl 60 seconds",
                         "%>rP %>rp %note{egress_principal_}", "--scope=api",
                         "request_body_max_size 25 MB", "maxconn 256", "concurrency=128",
                         "deny_info 503:PROXY_UNAVAILABLE egress_retry_503", 'reply_header_add Retry-After "1" egress_retry_503', "access_log stdio:/dev/stdout egress_json"]:
            self.assertIn(expected, text)

    def test_deny_list(self):
        settings = Settings.from_env(base_env())
        entries = {ipaddress.ip_network(line) for line in deny_cidrs(settings).split()}
        for must in ["169.254.0.0/16", "64:ff9b::/96", "2002::/16", "2001::/32", "168.63.129.16/32", "ff00::/8",
                     "192.0.0.0/24", "fc00::/7", "100.64.0.0/10"]:
            self.assertIn(ipaddress.ip_network(must), entries)
        self.assertNotIn(ipaddress.ip_network("::ffff:0:0/96"), entries)
        extra = Path(tempfile.mkdtemp()) / "extra"
        extra.write_text("# comment\n203.0.113.7\n10.9.0.0/16  # inline\n")
        more = {ipaddress.ip_network(l) for l in deny_cidrs(Settings.from_env(
            base_env(EGRESS_EXTRA_DENY_CIDRS_FILE=str(extra)))).split()}
        self.assertIn(ipaddress.ip_network("203.0.113.7/32"), more)
        extra.write_text("not-a-cidr\n")
        with self.assertRaises(SettingsError):
            deny_cidrs(Settings.from_env(base_env(EGRESS_EXTRA_DENY_CIDRS_FILE=str(extra))))


class ErrorPageTests(unittest.TestCase):
    def test_error_ca_settings(self):
        import clearideas_egress.render as module
        from unittest import mock
        ca = {"EGRESS_ERROR_CA_CERT_FILE": "/etc/egress/ca.pem", "EGRESS_ERROR_CA_KEY_FILE": "/etc/egress/ca.key"}
        with mock.patch.object(module, "find_certgen", lambda: "/usr/lib/squid/security_file_certgen"):
            text = render(Settings.from_env(base_env(**ca)))
        self.assertIn("tls-cert=/etc/egress/ca.pem tls-key=/etc/egress/ca.key generate-host-certificates=on", text)
        self.assertIn("sslcrtd_program ", text)
        # Never a bump action: the CA is only used to deliver the proxy's own errors.
        bumps = [line.split()[1] for line in text.splitlines() if line.startswith("ssl_bump ")]
        self.assertEqual(set(bumps), {"splice", "peek", "terminate"})
        for bad in ({"EGRESS_ERROR_CA_CERT_FILE": "/etc/egress/ca.pem"},
                    {**ca, "EGRESS_TLS_ENFORCEMENT": "off"},
                    {**ca, "EGRESS_MODE": "origination"},
                    {**ca, "EGRESS_TLS_PORT_CERT_FILE": "/a.pem", "EGRESS_TLS_PORT_KEY_FILE": "/a.key"},
                    {"EGRESS_ERROR_CA_CERT_FILE": "/etc/egress/ca.pem\nhttp_access allow all",
                     "EGRESS_ERROR_CA_KEY_FILE": "/k"}):
            with self.subTest(bad=bad), self.assertRaises(SettingsError):
                Settings.from_env(base_env(**bad))
        self.assertNotIn("generate-host-certificates=on", render(Settings.from_env(base_env())))

    def test_error_reply_marking(self):
        text = render(Settings.from_env(base_env()))
        self.assertIn("error_directory ", text)
        self.assertIn("reply_header_access X-Egress-Error deny all", text)
        self.assertLess(text.index("reply_header_access X-Egress-Error deny all"),
                        text.index('reply_header_add X-Egress-Error "denied"'))
        self.assertNotIn("ERR_CACHE_ACCESS_DENIED", text.split("acl egress_squid_error squid_error", 1)[1].split("\n")[0])

    def test_pages(self):
        from clearideas_egress import errorpages
        directory = Path(tempfile.mkdtemp())
        errorpages.write_pages(directory, "egress-1")
        denied = (directory / "ERR_ACCESS_DENIED").read_text()
        for needle in ("code: denied", "@Squid{%ea}", "decision_id: @Squid{%{egress_decision_}note}", "instance: egress-1"):
            self.assertIn(needle, denied)
        for name in errorpages.SQUID_PAGES + (errorpages.UNRESOLVED, errorpages.UNAVAILABLE):
            text = (directory / name).read_text()
            self.assertNotIn("squid", text.replace("@Squid{", "").lower(), name)
            # Squid %-codes: only the ones we mean (a stray % would be substituted).
            self.assertEqual(set(re.findall(r"%([A-Za-z])", text.replace("%ea", "").replace("%{egress", ""))) - {"u", "T", "E"},
                             set(), name)
        self.assertIn("code: unresolved", (directory / errorpages.UNRESOLVED).read_text())


if __name__ == "__main__":
    unittest.main()
