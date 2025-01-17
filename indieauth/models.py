from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime


# Create your models here.
class Client(models.Model):
    client_id = models.URLField(max_length=2048, unique=True)
    client_name = models.TextField(null=True)
    client_uri = models.URLField(max_length=2048)
    logo_uri = models.URLField(max_length=2048, null=True)

    class Meta:
        abstract = True
    
class Client(dict):
    def __init__(
            self, 
            client_id, 
            client_uri, 
            client_name=None, 
            logo_uri=None, 
            redirect_uris=None):
        self.client_id = client_id
        self.client_uri = client_uri
        self.client_name = client_name
        self.logo_uri = logo_uri
        self.redirect_uris = redirect_uris

class RedirectUri(models.Model):
    uri = models.URLField(max_length=2048)
    # client = models.ForeignKey(
    #     Client, 
    #     on_delete=models.CASCADE, 
    #     related_name="redirect_uris",
    #     related_query_name="redirect_uri"
    # )

    class Meta:
        abstract = True

class BearerToken(models.Model):
    client_id = models.URLField(max_length=2048)    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scopes = models.TextField()
    access_token = models.CharField(max_length=100, unique=True)
    refresh_token = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()
    issued_at = models.DateTimeField(default = timezone.now)
    me = models.URLField(max_length=2048)

    def _get_exp(self):
        return int(round(self.expires_at.timestamp()))
    
    def _set_exp(self, timestamp):
        self.expires_at = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def _get_iat(self):
        return int(round(self.issued_at.timestamp()))
    
    def _set_iat(self, timestamp):
        self.issued_at = datetime.datetime.fromtimestamp(timestamp, tz=timezone.utc)

    def _get_is_expired(self):
        return self.expires_at < timezone.now()

    exp = property(_get_exp, _set_exp, doc="Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire")
    iat = property(_get_iat, _set_iat)
    is_expired = property(_get_is_expired)

class AuthorizationCode(models.Model):
    client_id = models.URLField(max_length=2048)   
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scopes = models.TextField()
    redirect_uri = models.TextField()
    code = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()
    challenge = models.CharField(max_length=128)
    challenge_method = models.CharField(max_length=6)