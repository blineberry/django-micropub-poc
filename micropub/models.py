from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class BearerToken():
    access_token = models.CharField(max_length=100, unique=True)
    scopes = models.TextField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class MicroformatModel():
    """
    Define the methods needed to work with models at the micropub endpoint.
    Models that can be CRUDed via micropub should implement this class.
    """
    def to_mf_mson(self, properties):
        raise NotImplementedError("This method should be implemented by inherited class.")