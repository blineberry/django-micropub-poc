from oauthlib.common import add_params_to_uri
from urllib.parse import urlparse, urlunparse
from django.core.validators import URLValidator
import ipaddress
import requests
from bs4 import BeautifulSoup


class Request:
    def __init__(self, profile_url=None):
        self.profile_url = profile_url
        pass

class Client:
    def create_login_response(self, request):
        if request.profile_url is None:
            raise InvalidProfileUrlException("Profile url is required.")
        
        if not self.validate_profile_url(request.profile_url, request):
            raise InvalidProfileUrlException("Profile url failed validation.")

        authorization_endpoint = self.get_authorization_endpoint(request.profile_url, request)

        headers = {
            "Location": add_params_to_uri(authorization_endpoint, [
                ("response_type", request.response_type),
                ("client_id" , request.client_id),
                ("redirect_uri" , request.redirect_uri),
                ("state", request.state),
                ("code_challenge", request.code_challenge),
                ("code_challenge_method", request.code_challenge_method),
                ("scope", "create update profile"),
                ("me", request.profile_url)
            ])
        }

        return (headers, None, 302)
        
    def validate_profile_url(self, profile_url ,request):
        # Users are identified by a [URL]. Profile URLs MUST have either an 
        # https or http scheme, MUST contain a path component (/ is a valid 
        # path), MUST NOT contain single-dot or double-dot path segments, MAY 
        # contain a query string component, MUST NOT contain a fragment 
        # component, MUST NOT contain a username or password component, and MUST
        # NOT contain a port. Additionally, host names MUST be domain names and 
        # MUST NOT be ipv4 or ipv6 addresses.
        #
        # https://indieauth.spec.indieweb.org/#user-profile-url
        request.profile_url = self.canonicalize_url(profile_url)

        validate = URLValidator()
        try:
            validate(request.profile_url)
        except:
            raise InvalidProfileUrlException("Profile url must be a valid url.")
            
        parsed = urlparse(request.profile_url)

        if parsed.scheme != "http" and parsed.scheme != "https":
            raise InvalidProfileUrlException("Profile url must be http or https.")
        
        if "." in parsed.path.split("/") or ".." in parsed.path.split("/"):
            raise InvalidProfileUrlException("Profile url must not have single-dot or double-dot path segments.")
        
        if parsed.fragment != "":
            raise InvalidProfileUrlException("Profile url must not contain a fragment.")
        
        if parsed.username is not None or parsed.password is not None:
            raise InvalidProfileUrlException("Profile url must not contain a username or password.")
        
        if parsed.port is not None:
            raise InvalidProfileUrlException("Profile url must not contain a port.")
        
        try:
            ipaddress.ip_address(parsed.hostname)
            raise InvalidProfileUrlException("Profile url must be a domain and must not be IPv4 or IPv6.")
        except ValueError:
            pass

        return True
        
    def canonicalize_url(self, profile_url):
        # Since IndieAuth uses https/http URLs which fall under what [URL] calls
        # "Special URLs", a string with no path component is not a valid [URL]. 
        # As such, if a URL with no path component is ever encountered, it MUST 
        # be treated as if it had the path /. For example, if a user provides 
        # https://example.com for Discovery, the client MUST transform it to 
        # https://example.com/ when using it and comparing it.
        # 
        # Since domain names are case insensitive, the host component of the URL
        # MUST be compared case insensitively. Implementations SHOULD convert 
        # the host to lowercase when storing and using URLs.
        # 
        # For ease of use, clients MAY allow users to enter just the host part 
        # of the URL, in which case the client MUST turn that into a valid URL 
        # before beginning the IndieAuth flow, by prepending either an http or 
        # https scheme and appending the path /. For example, if the user enters
        # example.com, the client transforms it into http://example.com/ before 
        # beginning discovery
        #
        # https://indieauth.spec.indieweb.org/#url-canonicalization
        parsed_url = urlparse(profile_url)

        if parsed_url.scheme == "":
            profile_url = "https://" + profile_url
            parsed_url = urlparse(profile_url)

        if parsed_url.path == "":
            profile_url = profile_url + "/"
            parsed_url = urlparse(profile_url)        

        return urlunparse((parsed_url.scheme, parsed_url.netloc.lower(), parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment))

    def get_authorization_endpoint(self, profile_url, request):
        response = requests.get(profile_url)

        try:
            response.raise_for_status()
        except:
            raise AuthorizationEndpointException("Non-successful response from profile url.")

        try:
            indieauth_metadata_endpoint = self.get_indieauth_metadata_endpoint(response)
        except:
            raise AuthorizationEndpointException("Error getting indieauth metadata endpoint.")
        
        # In the event there is no indieauth-metadata URL provided, for 
        # compatibility with previous revisions of IndieAuth, the client SHOULD 
        # look for an HTTP Link header and HTML <link> element with a rel value 
        # of authorization_endpoint (and optionally token_endpoint) following 
        # the same order of predence as described above.
        # 
        # https://indieauth.spec.indieweb.org/#discovery-by-clients       

        if indieauth_metadata_endpoint is None:
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('link'):
                if link.get('rel') == "authorization_endpoint":
                    return link.get('href')
            
            return None
        
        response = requests.get(indieauth_metadata_endpoint)

        try:
            response.raise_for_status()
        except:
            raise AuthorizationEndpointException("Non-successful response from metadata url.")

        content = response.json()

        return content.get("authorization_endpoint")


    def get_indieauth_metadata_endpoint(http_response):
        # Clients need to discover a few pieces of information when a user signs 
        # in. The client needs to discover the user's indieauth-metadata 
        # endpoint, which provides the location of the IndieAuth server's 
        # authorization endpoint and token endpoint, as well as other relevant 
        # information for the client. Clients MUST start by making a GET or HEAD 
        # request to [Fetch] the user provided URL to discover the necessary 
        # values. Clients MUST follow HTTP redirects (up to a self-imposed 
        # limit). When using the Authorization flow to obtain an access token 
        # for use at another endpoint, such as a [Micropub] endpoint, the client 
        # will also discover the micropub endpoint.
        #
        # Clients MUST check for an HTTP Link header [RFC8288] with a rel value 
        # of indieauth-metadata. If the content type of the document is HTML, 
        # then the client MUST check for an HTML <link> element with a rel value 
        # of indieauth-metadata. If more than one of these is present, the first 
        # HTTP Link header takes precedence, followed by the first <link> 
        # element in document order.
        #
        # The URLs discovered MAY be relative URLs, in which case the client 
        # MUST resolve them relative to the current document URL according to 
        # [URL].
        #
        # Clients MAY initially make an HTTP HEAD request [RFC7231] to follow 
        # redirects and check for the Link header before making a GET request.
        #
        # https://indieauth.spec.indieweb.org/#discovery-by-clients

        link_headers = http_response.headers['Link']

        for header in link_headers.split(","):
            pair = header.split(":")

            if pair[0].trim() == "rel" and pair[1].trim() == "indieauth-metadata":
                return pair[1]
        
        soup = BeautifulSoup(http_response.text, 'html.parser')

        for link in soup.find_all('link'):
            if link.get('rel') == "indieauth-metadata":
                return link.get('href')
        
        return None

class InvalidProfileUrlException(Exception):
    pass

class AuthorizationEndpointException(Exception):
    pass