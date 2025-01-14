from oauthlib.oauth2 import RequestValidator
from .models import Client
from django.core.validators import URLValidator
from urllib.parse import urlparse
import ipaddress
import requests

class Validator(RequestValidator):
    def validate_client_id(self, client_id, request, *args, **kwargs):
        print("validate_client_id")

        if self.__is_client_id_valid(client_id) is False:
            print("client_id invalid")
            return False

        client_response = requests.get(client_id)

        try:
            client_response.raise_for_status()
            print("client_id request not successful")
        except:
            return False        
        
        if self.__is_client_response_valid(client_response, client_id) is False:
            return False
        
        request.client = client_response.json()

        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return super().confirm_redirect_uri(client_id, code, redirect_uri, client, request, *args, **kwargs)
    
    def client_authentication_required(self, request, *args, **kwargs):
        #IndieAuth clients are public
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        return super().authenticate_client_id(self, client_id, request, *args, **kwargs)
        if self.__is_client_id_valid(client_id) is False:
            return False        
        
        client_response = requests.get(client_id)

        try:
            client_response.raise_for_status()
        except:
            return False        
        
        if self.__is_client_response_valid(client_response, client_id) is False:
            return False
        
        request.client = client_response.json()

        return True

    def authenticate_client(self, request, *args, **kwargs):
        return super().authenticate_client(self, request, *args, **kwargs)
        """
        IndieAuth clients are not pre-registered. They have certain 
        requirements with their client_id and client metadata.
        """

        try:
            client_id = request.client_id
        except:
            return False

        return self.authenticate_client_id(client_id, request, *args, **kwargs)
    
    def __is_client_response_valid(self, client_response, client_id):
        """
        Validate client metadata against https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        """
        
        try:
            content = client_response.json()
        except Exception as e:
            print("client_id content not json")
            return False     

        # The client metadata document MUST contain a client_id property
        content_client_id = content.get("client_id")
        
        if content_client_id is None:
            print("client_id response does not have a client_id property")
            return False
        
        if content_client_id.lower() != client_id.lower():
            print("client_id response client_id does not match")
            return False

        # the token_endpoint_auth_method property MUST NOT include client_secret_post or client_secret_basic
        token_endpoint_auth_method = content.get("token_endpoint_auth_method")

        if token_endpoint_auth_method == "client_secret_post":
            print("client_id response has client_secret_post")
            return False
        
        if token_endpoint_auth_method == "client_secret_basic":
            print("client_id response has client_secret_basic")
            return False
        
        return True
        
    def __is_client_id_valid(self, client_id):
        print('__is_client_id_valid')
        if client_id is None:
            print('client_id is none')
            return False
        
        # Enforce conformance to https://indieauth.spec.indieweb.org/#client-identifier        
        validate = URLValidator()

        try:
            validate(client_id)
        except:
            print('client_id not a URL')
            return False
        
        # Clients are identified by a [URL].
        parsed_url = urlparse(client_id)

        # Client identifier URLs MUST have either an https or http scheme
        if (not (parsed_url.scheme == 'http' or parsed_url.scheme == 'https')):
            print('client_id scheme not http or https')
            return False
        
        # MUST contain a path component
        if parsed_url.path == "":
            print('client_id does not have path')
            return False
        
        # MUST NOT contain single-dot or double-dot path segments
        path_segments = parsed_url.path.split("/")
        if "." in path_segments:
            print('client_id has single dot segment')
            return False
        
        if ".." in path_segments:
            print('client_id has double-dot segment')
            return False
        
        # MUST NOT contain a fragment component
        if parsed_url.fragment != "":
            print('client_id has fragment')
            return False

        # MUST NOT contain a username or password component
        if parsed_url.username is not None:
            print('client_id has username')
            return False
        
        if parsed_url.password is not None:
            print('client_id has password')
            return False
        
        # host names MUST be domain names or a loopback interface and MUST NOT 
        # be IPv4 or IPv6 addresses except for IPv4 127.0.0.1 or IPv6 [::1].
        try:
            ipaddress.ip_address(parsed_url.hostname)
            print('client_id is ip_address')
            return False
        except ValueError:
            pass
        
        return True