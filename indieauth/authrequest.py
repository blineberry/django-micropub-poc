from django.core.validators import URLValidator
import requests
from urllib.parse import urlparse

class AuthRequest:
    is_valid = False
    validation_error = "Not validated"

    def __init__(self, params):
        self.response_type = params.get('response_type')
        self.client_id = params.get('client_id')
        self.redirect_uri = params.get('redirect_uri')
        self.state = params.get('state')
        self.code_challenge = params.get('code_challenge')
        self.code_challenge_method = params.get('code_challenge_method')
        self.scope=params.get('scope')
        self.me = params.get('me')

    def validate(self):
        self.is_valid = False

        if self.response_type is None or self.response_type != 'code':
            self.validation_error = "response_type must be 'code'"
            return
        
        if self.validate_client_id() is False:
            self.validation_error = self.client_id_validation_error
            return

        if self.is_redirect_uri_valid() is False:
            self.validation_error = self.redirect_validation_error
            return
        
        self.is_valid = True
        self.validation_error = ""

    def validate_client_id(self):
        if self.client_id is None:
            self.client_id_validation_error = "client_id is missing"
            return False

        if self.__is_valid_URL(self.client_id) is False:
            self.client_id_validation_error = "client_id is not a valid URL"
            return False
        
        parsed_client_id = urlparse(self.client_id)

        if parsed_client_id.hostname == '127.0.0.1':
            self.client_id_validation_error = "client_id is localhost"
            return False        

        if parsed_client_id.hostname == '[::1]':
            self.client_id_validation_error = "client_id is localhost"
            return False

        self.client_response = requests.get(self.client_id)

    def is_redirect_uri_valid(self):
        parsed_redirect_uri = urlparse(self.redirect_uri)
        parsed_client_id = urlparse(self.client_id)

        pass

        # if parsed_redirect_uri.scheme != parsed_client_id.scheme:
                
        # if parsed_redirect_uri.scheme != parsed_client_id.scheme:
        #         and parsed_redirect_uri.scheme == parsed_client_id.scheme):
        #     return True

    def __is_valid_URL(self, url):
        validate = URLValidator()

        try:
            validate(url)
        except:
            return False
        
        return True