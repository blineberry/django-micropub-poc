from django.test import TestCase, Client
from django.test import Client
from django.contrib.auth.models import User

# Create your tests here.
class AuthorizationCodeGrantConformanceTestCase(TestCase):
    auth_request_data = {
        "response_type": "code",
        "client_id": "https://orangegnome.com"
    }
    c = None

    """
    Authorization is built on top of OAuth2 Authorization Code Grant. 
    https://www.rfc-editor.org/rfc/rfc6749#section-4.1
    """

    def setUp(self):
        self.user = User.objects.create_user(username="testUser", password="testPassword")
        self.c = Client()
        self.c.login(username="testUser",password="testPassword")

    def test_response_type_is_required(self):
        """https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1"""

        self.auth_request_data.update({"response_type": ""})

        response = self.c.get("/indieauth/authorization", self.auth_request_data)

        self.assertEqual(response.status_code, 400)

    def test_response_type_mustbe_code(self):
        """https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1"""

        self.auth_request_data.update({"response_type": "client_credentials"})
        
        response = self.c.get("/indieauth/authorization", self.auth_request_data)

        self.assertEqual(response.status_code, 400)

    def test_client_id_is_required(self):
        """https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1"""

        self.auth_request_data.update({"client_id": ""})
        
        response = self.c.get("/indieauth/authorization", self.auth_request_data)

        self.assertEqual(response.status_code, 400)