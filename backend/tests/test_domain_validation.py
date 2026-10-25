import unittest

from services.domain_validation import normalize_domain


class DomainValidationTests(unittest.TestCase):
    def test_normalizes_url_and_case(self):
        self.assertEqual(
            normalize_domain("HTTPS://Example.COM/path?q=1"),
            "example.com",
        )

    def test_normalizes_international_domain_names(self):
        self.assertEqual(normalize_domain("BÜCHER.de"), "xn--bcher-kva.de")

    def test_rejects_invalid_hostnames(self):
        for value in ("", "localhost", "bad..example.com", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)

    def test_rejects_non_http_schemes_and_ip_addresses(self):
        for value in ("ftp://example.com", "192.0.2.4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_domain(value)


if __name__ == "__main__":
    unittest.main()