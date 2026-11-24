import unittest

from tools.target_guard import (
    TargetRejected,
    validate_loopback_url,
)


class TargetGuardTests(unittest.TestCase):

    def test_localhost(self):
        self.assertTrue(
            validate_loopback_url("http://localhost:8080/")
        )

    def test_ipv4_loopback(self):
        self.assertTrue(
            validate_loopback_url("http://127.0.0.1:8080/")
        )

    def test_ipv6_loopback(self):
        self.assertTrue(
            validate_loopback_url("http://[::1]:8080/")
        )

    def test_public_ip_rejected(self):
        with self.assertRaises(TargetRejected):
            validate_loopback_url("http://8.8.8.8/")

    def test_external_hostname_rejected(self):
        with self.assertRaises(TargetRejected):
            validate_loopback_url("https://example.com/")

    def test_localhost_suffix_rejected(self):
        with self.assertRaises(TargetRejected):
            validate_loopback_url(
                "http://localhost.example.com/"
            )

    def test_credentials_rejected(self):
        with self.assertRaises(TargetRejected):
            validate_loopback_url(
                "http://user:pass@127.0.0.1/"
            )

    def test_file_scheme_rejected(self):
        with self.assertRaises(TargetRejected):
            validate_loopback_url("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
