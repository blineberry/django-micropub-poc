from django.test import TestCase
from ..indieauthclient import Client, Request, InvalidProfileUrlException

class ClientTestCase(TestCase):
    client = None

    def setUp(self):
        self.client = Client()

    def test_canonicalize_url_adds_missing_scheme(self):
        self.assertEqual(self.client.canonicalize_url("www.example.com/"), "https://www.example.com/")

    def test_canonicalize_url_adds_missing_path(self):
        self.assertEqual(self.client.canonicalize_url("https://www.example.com"), "https://www.example.com/")

    def test_canonicalize_url_lowercases_domain(self):
        self.assertEqual(self.client.canonicalize_url("https://www.EXAMPLE.com/"), "https://www.example.com/")

    def test_canonicalize_url_preserves_userpassword(self):
        self.assertEqual(self.client.canonicalize_url("https://user:pass@www.example.com/"),"https://user:pass@www.example.com/")

    # Some examples of valid profile URLs are:

    #     https://example.com/
    #     https://example.com/username
    #     https://example.com/users?id=100

    # Some examples of invalid profile URLs are:

    #     example.com - missing scheme
    #     mailto:user@example.com - invalid scheme
    #     https://example.com/foo/../bar - contains a double-dot path segment
    #     https://example.com/#me - contains a fragment
    #     https://user:pass@example.com/ - contains a username and password
    #     https://example.com:8443/ - contains a port
    #     https://172.28.92.51/ - host is an IP address

    def test_validate_profile_url_validates(self):
        for u in ["https://example.com/","https://example.com/username","https://example.com/users?id=100"]:
            self.assertTrue(self.client.validate_profile_url(u, Request(u)))

    def test_validate_profile_url_is_true_actually_because_of_canonicalization(self):
        u = "example.com"
        self.assertTrue(self.client.validate_profile_url(u,Request(u)))

    def test_validate_profile_url_invalid_scheme(self):
        u = "mailto:user@example.com"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))

    def test_validate_profile_url_double_dot(self):
        u = "https://example.com/foo/../bar"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))

    def test_validate_profile_url_fragment(self):
        u = "https://example.com/#me"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))

    def test_validate_profile_url_username_password(self):
        u = "https://user:pass@example.com/"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))

    def test_validate_profile_url_port(self):
        u = "https://example.com:8443/"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))

    def test_validate_profile_url_ip_address(self):
        u = "https://172.28.92.51/"
        self.assertRaises(
            InvalidProfileUrlException,
            self.client.validate_profile_url,
            u, 
            Request(u))