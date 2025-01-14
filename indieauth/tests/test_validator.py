from django.test import TestCase, Client
from django.test import Client
from oauthlib.common import Request
from indieauth.validator import Validator
from unittest.mock import MagicMock, patch

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

    @patch('indieauth.validator.requests')
    def test_authenticate_client_clientidresponseisnotjson_returns_false(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value(side_effect=Exception('Boom!'))
        mock_requests.get.return_value = mock_response

        result = validator.authenticate_client(request)

        mock_requests.get.assert_called_with(client_id)
        self.assertFalse(result)

    @patch('indieauth.validator.requests')
    def test_authenticate_client_clientidresponsenoclientid_returns_false(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_requests.get.return_value = mock_response

        result = validator.authenticate_client(request)

        mock_requests.get.assert_called_with(client_id)
        self.assertFalse(result)

    @patch('indieauth.validator.requests')
    def test_authenticate_client_clientidresponseincludesclientsecretpost_returns_false(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id,
            "token_endpoint_auth_method": "client_secret_post"
        }
        mock_requests.get.return_value = mock_response

        result = validator.authenticate_client(request)

        mock_requests.get.assert_called_with(client_id)
        self.assertFalse(result)

    @patch('indieauth.validator.requests')
    def test_authenticate_client_clientidresponseincludesclientsecretpost_returns_false(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id,
            "token_endpoint_auth_method": "client_secret_basic"
        }
        mock_requests.get.return_value = mock_response

        result = validator.authenticate_client(request)

        mock_requests.get.assert_called_with(client_id)
        self.assertFalse(result)

    @patch('indieauth.validator.requests')
    def test_authenticate_client_clientidresponseincludesclientsecretpost_returns_false(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id
        }
        mock_requests.get.return_value = mock_response

        result = validator.authenticate_client(request)

        mock_requests.get.assert_called_with(client_id)
        self.assertTrue(result)

