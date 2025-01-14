from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Client(models.Model):
    client_id = models.URLField(max_length=2048, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    grant_type = models.CharField(max_length=18, choices=[('authorization_code', 'Authorization code')])
    response_type = models.CharField(max_length=4,choices=[('code', 'Authorization code')])
    scopes = models.TextField()
    redirect_uris = models.TextField()

class BearerToken(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scopes = models.TextField()
    access_token = models.CharField(max_length=100, unique=True)
    refresh_token = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()

class AuthorizationCode(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scopes = models.TextField()
    redirect_uri = models.TextField()
    code = models.CharField(max_length=100, unique=True)
    expires_at = models.DateTimeField()
    challenge = models.CharField(max_length=128)
    challenge_method = models.CharField(max_length=6)