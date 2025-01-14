from django.test import TestCase, Client
from django.test import Client
from oauthlib.common import Request
from indieauth.validator import Validator

# Create your tests here.
class ValidatorTestCase(TestCase):
    def test_authenticate_client_no_client_id_returns_false(self):
        request = Request("https://example.com")
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_not_uri_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "notauri"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_not_http_or_https_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "ftp://example.com/"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_no_path_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://example.com"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_dot_path_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://example.com/./"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_doubledot_path_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://example.com/../"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_user_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://user@example.com/"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_password_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://:password@example.com/"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_ipv4_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://127.0.0.2/"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_ipv6_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "[::2]"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertFalse(result)

    def test_authenticate_client_client_id_domain_returns_false(self):
        request = Request("https://example.com", body= {
            "client_id": "https://example.com/"
        })
        validator = Validator()

        result = validator.authenticate_client(request)

        self.assertTrue(result)

