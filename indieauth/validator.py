from oauthlib.oauth2 import RequestValidator, FatalClientError
from .models import Client
from django.core.validators import URLValidator
from urllib.parse import urlparse
import ipaddress
import requests
from django.conf import settings
from django.shortcuts import render


class Validator(RequestValidator):
    def validate_client_id(self, client_id, request, *args, **kwargs):
        if self.__is_client_id_valid(client_id) is False:
            raise FatalClientError("client_id invalid")

        client_response = requests.get(client_id)

        try:
            client_response.raise_for_status()
        except:
            raise FatalClientError("client_id request not successful")
        
        if self.__is_client_metadata_valid(client_response, client_id) is False:
            raise FatalClientError("client_id response invalid")
        
        request.client = dict(client_response.json())

        return True
    
    def client_authentication_required(self, request, *args, **kwargs):
        #IndieAuth clients are public
        return False
    
    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # IndieAuth clients do not have a default redirect_uri
        return request.redirect_uri
    
    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):        
        # If the URL scheme, host or port of the redirect_uri in the request do 
        # not match that of the client_id, then the authorization endpoint 
        # SHOULD verify that the requested redirect_uri matches one of the 
        # redirect URLs published by the client, and SHOULD block the request 
        # from proceeding if not.
        # https://indieauth.spec.indieweb.org/#authorization-request
        if redirect_uri is None:
            raise FatalClientError("redirect_uri is required.")
        
        parsed_redirect_uri = urlparse(redirect_uri)
        parsed_client_id = urlparse(client_id)

        if (parsed_redirect_uri.scheme == parsed_client_id.scheme 
                and parsed_redirect_uri.hostname == parsed_client_id.hostname
                and parsed_redirect_uri.port == parsed_client_id.port):
            return True
        
        if redirect_uri in request.client.redirect_uris:
            return True

        return False
    
    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return response_type == "code"
    
    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return []
    
    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # not sure about this one.
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        return super().authenticate_client_id(self, client_id, request, *args, **kwargs)
        if self.__is_client_id_valid(client_id) is False:
            return False        
        
        client_response = requests.get(client_id)

        try:
            client_response.raise_for_status()
        except:
            return False        
        
        if self.__is_client_metadata_valid(client_response, client_id) is False:
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
    
    def __is_client_metadata_valid(self, client_response, client_id):
        """
        Validate client metadata against https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        """
        
        # The client metadata document URL is a JSON document containing the 
        # metadata of the client. The client metadata values are the values 
        # defined in the OAuth Dynamic Client Registration Metadata OAuth 
        # Parameters registry https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata.
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        try:
            content = client_response.json()
        except Exception as e:
            raise FatalClientError("client_id metadata must be json")

        # The client metadata document MUST contain a client_id property…
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        content_client_id = content.get("client_id")
        
        if content_client_id is None:
            raise FatalClientError("client_id metadata must have a client_id property")
        
        # whose value MUST compare and match the URL of the document using 
        # simple string comparison as defined in [RFC3986] Section 6.2.1.
        # 
        # The client metadata document MAY define additional properties in the 
        # response. The client metadata document MAY also be served with more 
        # specific content types as long as the response is JSON and conforms to 
        # application/<AS-defined>+json.
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        if content_client_id.lower() != client_id.lower():
            raise FatalClientError("client_id metadata client_id must match")

        # As there is no way to establish a shared secret to be used with client
        # metadata documents, the following restrictions apply on the contents 
        # of the client metadata document:
        # 
        # the token_endpoint_auth_method property MUST NOT include 
        # client_secret_post or client_secret_basic
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        token_endpoint_auth_method = content.get("token_endpoint_auth_method")

        if token_endpoint_auth_method == "client_secret_post":
            raise FatalClientError("client_id metadata cannot have token_endpoint_auth_method=client_secret_post")
        
        if token_endpoint_auth_method == "client_secret_basic":
            raise FatalClientError("client_id metadata cannot have token_endpoint_auth_method=client_secret_basic")
        
        # the client_secret and client_secret_expires_at properties MUST NOT be 
        # used
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata
        if content.get("client_secret") is not None:
            raise FatalClientError("client_id metadata must not use client_secret")

        if content.get("client_secret_expires_at") is not None:
            raise FatalClientError("client_id metadata must not use client_secret_expires_at")
        
        # See Section 6.2 for more details. Other specifications MAY place 
        # additional restrictions on the contents of the client metadata 
        # document accepted by authorization servers implementing their 
        # specification, for instance, preventing the registration of 
        # confidential clients by requiring the token_endpoint_auth_method 
        # property be set to "none".
        # 
        # TBD: We may want a property such as 
        # client_id_expires_at for indicating that the client is ephemeral and 
        # not valid after a given timestamp, especially for documents issued by 
        # a service for development purposes.
        # https://datatracker.ietf.org/doc/html/draft-parecki-oauth-client-id-metadata-document#name-client-metadata


        # Clients SHOULD have a JSON [RFC7159] document at their client_id URL 
        # containing client metadata defined in [RFC7591], the minimum 
        # properties for an IndieAuth client defined below. 
        # …
        # client_uri - URL of a webpage providing information about the client
        # https://indieauth.spec.indieweb.org/#client-metadata

        if content.get("client_uri") is None:
            raise FatalClientError("client_id metadata must have client_uri")

        return True
        
    def __is_client_id_valid(self, client_id):
        if client_id is None:
            raise FatalClientError("client_id is absent")
        
        # Clients are identified by a [URL].
        # https://indieauth.spec.indieweb.org/#client-identifier        
        validate = URLValidator()

        try:
            validate(client_id)
        except:
            raise FatalClientError("client_id must be a URL")
        
        parsed_url = urlparse(client_id)

        # Client identifier URLs MUST have either an https or http scheme,…
        # https://indieauth.spec.indieweb.org/#client-identifier
        if (not (parsed_url.scheme == 'http' or parsed_url.scheme == 'https')):
            raise FatalClientError("client_id scheme must be http or https")
        
        # MUST contain a path component,…
        # https://indieauth.spec.indieweb.org/#client-identifier
        if parsed_url.path == "":
            raise FatalClientError("client_id must have path")
        
        # MUST NOT contain single-dot or double-dot path segments,…
        # https://indieauth.spec.indieweb.org/#client-identifier
        path_segments = parsed_url.path.split("/")
        if "." in path_segments:
            raise FatalClientError("client_id cannot have single dot segment")
        
        if ".." in path_segments:
            raise FatalClientError("client_id cannot have double dot segment")
        
        # MAY contain a query string component,…
        
        # MUST NOT contain a fragment component,…
        # https://indieauth.spec.indieweb.org/#client-identifier
        if parsed_url.fragment != "":
            raise FatalClientError("client_id cannot have a fragment")

        # MUST NOT contain a username or password component,…
        # https://indieauth.spec.indieweb.org/#client-identifier
        if parsed_url.username is not None:
            raise FatalClientError("client_id cannot have a username")
        
        if parsed_url.password is not None:
            raise FatalClientError("client_id cannot have a password")
        
        # and MAY contain a port.
        
        # Additionally, host names MUST be domain names or a loopback interface 
        # and MUST NOT be IPv4 or IPv6 addresses except for IPv4 127.0.0.1 or 
        # IPv6 [::1].
        # https://indieauth.spec.indieweb.org/#client-identifier
        try:
            ipaddress.ip_address(parsed_url.hostname)
            raise FatalClientError("client_id cannot be IPv4 or IPv6")
        except ValueError:
            pass
        
        return True