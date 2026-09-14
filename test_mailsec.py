import unittest
from unittest.mock import patch

import dns.exception
import dns.resolver

import mailsec


class MailsecLogicTests(unittest.TestCase):
    def analyse_spf(self, records):
        with patch.object(mailsec, "txt_lookup", return_value=records):
            return mailsec.analyse_spf("example.com")

    def analyse_dmarc(self, records):
        with patch.object(mailsec, "txt_lookup", return_value=records):
            return mailsec.analyse_dmarc("example.com")

    def test_spf_reject_all(self):
        result = self.analyse_spf(["v=spf1 include:_spf.example.net -all"])
        self.assertEqual(result["grade"], "PASS")
        self.assertEqual(result["all_qualifier"], "-all")
        self.assertEqual(result["direct_lookup_terms"], 1)

    def test_bare_all_is_pass_all(self):
        result = self.analyse_spf(["v=spf1 all"])
        self.assertEqual(result["grade"], "FAIL")
        self.assertEqual(result["all_qualifier"], "+all")

    def test_multiple_spf_records_are_permerror(self):
        result = self.analyse_spf(["v=spf1 -all", "v=spf1 ~all"])
        self.assertEqual(result["grade"], "FAIL")
        self.assertIn("Multiple SPF", result["issues"][0])

    def test_terms_after_all_are_flagged(self):
        result = self.analyse_spf(["v=spf1 -all include:_spf.example.net"])
        self.assertEqual(result["grade"], "WARN")
        self.assertIn("unreachable", " ".join(result["issues"]))

    def test_dmarc_reject(self):
        result = self.analyse_dmarc(
            ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        )
        self.assertEqual(result["grade"], "PASS")
        self.assertEqual(result["effective_policy"], "reject")

    def test_dmarc_test_mode_lowers_effective_policy(self):
        result = self.analyse_dmarc(["v=DMARC1; p=reject; t=y"])
        self.assertEqual(result["grade"], "WARN")
        self.assertEqual(result["effective_policy"], "quarantine")

    def test_weaker_subdomain_policy_is_flagged(self):
        result = self.analyse_dmarc(["v=DMARC1; p=reject; sp=none"])
        self.assertEqual(result["grade"], "WARN")
        self.assertIn("subdomain impersonation", " ".join(result["issues"]))

    def test_multiple_dmarc_records_disable_policy(self):
        result = self.analyse_dmarc(
            ["v=DMARC1; p=reject", "v=DMARC1; p=none"]
        )
        self.assertEqual(result["grade"], "FAIL")
        self.assertIn("Multiple DMARC", result["issues"][0])

    def test_dkim_version_tag_is_optional(self):
        with patch.object(mailsec, "txt_lookup", return_value=["k=rsa; p=QUJD"]):
            result = mailsec.analyse_dkim("example.com", ["known"])
        self.assertEqual(result["grade"], "PASS")
        self.assertEqual(result["found"][0][0], "known")

    def test_common_dkim_probe_is_inconclusive(self):
        with patch.object(mailsec, "txt_lookup", return_value=[]):
            result = mailsec.analyse_dkim("example.com")
        self.assertEqual(result["grade"], "WARN")
        self.assertIn("inconclusive", " ".join(result["issues"]))

    def test_known_missing_dkim_selector_fails(self):
        with patch.object(mailsec, "txt_lookup", return_value=[]):
            result = mailsec.analyse_dkim("example.com", ["known"])
        self.assertEqual(result["grade"], "FAIL")

    def test_revoked_old_selector_does_not_downgrade_active_key(self):
        def records(name):
            return ["v=DKIM1; p=QUJD"] if name.startswith("active.") else ["p="]

        with patch.object(mailsec, "txt_lookup", side_effect=records):
            result = mailsec.analyse_dkim("example.com", ["active", "old"])
        self.assertEqual(result["grade"], "PASS")
        self.assertEqual(len(result["revoked"]), 1)

    def test_dns_timeout_is_not_reported_as_absence(self):
        resolver = unittest.mock.Mock()
        resolver.resolve.side_effect = dns.exception.Timeout()
        with patch.object(mailsec, "_resolver", return_value=resolver):
            with self.assertRaises(mailsec.DNSLookupError):
                mailsec.txt_lookup("example.com")

    def test_domain_validation_rejects_shell_or_url_input(self):
        for value in ("example.com;id", "https://example.com", "user@example.com"):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    mailsec.normalize_domain(value)

    def test_untrusted_terminal_control_characters_are_rendered_inert(self):
        self.assertEqual(mailsec.safe_output("ok\x1b[2J"), "ok\\x1b[2J")


if __name__ == "__main__":
    unittest.main()
