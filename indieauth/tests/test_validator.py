from django.test import TestCase, Client
from oauthlib.common import Request
from indieauth.validator import Validator
from unittest.mock import MagicMock, patch
from oauthlib.oauth2 import FatalClientError

# Create your tests here.
class ValidatorTestCase(TestCase):
    def test_validate_client_id_noclientid_raises_FatalClientError(self):
        request = Request("https://example.com")
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, None, request)

    def test_validate_client_id_client_id_not_uri_raises_FatalClientError(self):
        client_id = "notauri"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_not_http_or_https_raises_FatalClientError(self):
        client_id ="ftp://example.com/"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_no_path_raises_FatalClientError(self):
        client_id = "https://example.com"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_dot_path_raises_FatalClientError(self):
        client_id = "https://example.com/./"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_doubledot_path_raises_FatalClientError(self):
        client_id = "https://example.com/../"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_user_raises_FatalClientError(self):
        client_id = "https://user@example.com/"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_password_raises_FatalClientError(self):
        client_id = "https://:password@example.com/"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_ipv4_raises_FatalClientError(self):
        client_id = "https://127.0.0.2/"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    def test_validate_client_id_client_id_ipv6_raises_FatalClientError(self):
        client_id = "[::2]"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponseisnotjson_raises_FatalClientError(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value(side_effect=Exception('Boom!'))
        mock_requests.get.return_value = mock_response

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponsenoclientid_raises_FatalClientError(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_requests.get.return_value = mock_response

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponseincludesclientsecretpost_raises_FatalClientError(self, mock_requests):
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

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponseincludesclientsecretpost_raises_FatalClientError(self, mock_requests):
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

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponseincludesclientsecret_raises_FatalClientError(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id,
            "client_secret": ""
        }
        mock_requests.get.return_value = mock_response

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponseincludesclientsecretexpiresat_raises_FatalClientError(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id,
            "client_secret_expires_at": ""
        }
        mock_requests.get.return_value = mock_response

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientidresponsedoesnotincludeclienturi_raises_FatalClientError(self, mock_requests):
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

        self.assertRaises(FatalClientError, validator.validate_client_id, client_id, request)

        mock_requests.get.assert_called_with(client_id)

    @patch('indieauth.validator.requests')
    def test_validate_client_id_clientmetadataconforms_returns_true(self, mock_requests):
        client_id = "https://example.com/client_id"
        request = Request("https://example.com", body= {
            "client_id": client_id
        })
        validator = Validator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "client_id": client_id,
            "client_uri": "https://example.com/client_uri"
        }
        mock_requests.get.return_value = mock_response

        response = validator.validate_client_id(client_id, request)

        self.assertTrue(response)

    def test_validateredirecturi_noredirecturi_raises_FatalClientError(self):
        validator = Validator()
        client_id = "https://example.com/clientid"
        redirect_uri = None
        
        self.assertRaises(FatalClientError, validator.validate_redirect_uri, client_id, redirect_uri, {})

    def test_validateredirecturi_nomatchclientidnomatchmetadata_returns_false(self):
        validator = Validator()
        client_id = "https://example.com/clientid"
        redirect_uri = "https://anotherwebsite.example.com"
        request = MagicMock()
        request.client.redirect_uris = []
        
        result = validator.validate_redirect_uri(client_id, redirect_uri, request)

        self.assertFalse(result)

    def test_validateredirecturi_nomatchclientidmatchmetadata_returns_true(self):
        validator = Validator()
        client_id = "https://example.com/clientid"
        redirect_uri = "https://anotherwebsite.example.com"
        request = MagicMock()
        request.client.redirect_uris = ["https://anotherwebsite.example.com"]
        
        result = validator.validate_redirect_uri(client_id, redirect_uri, request)

        self.assertTrue(result)

    def test_validateredirecturi_matchclientid_returns_true(self):
        validator = Validator()
        client_id = "https://example.com/clientid"
        redirect_uri = "https://example.com/callback"
        request = MagicMock()
        request.client.redirect_uris = ["https://anotherwebsite.example.com"]
        
        result = validator.validate_redirect_uri(client_id, redirect_uri, request)

        self.assertTrue(result)

