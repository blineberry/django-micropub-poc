from django.db import models
from django.utils import timezone
from micropub.models import MicroformatModel

class Tag(models.Model):
    text = models.TextField()
    slug = models.SlugField()

# Create your models here.
class Note(MicroformatModel, models.Model):
    content = models.TextField()
    tags = models.ManyToManyField(Tag)
    published = models.DateTimeField(null=True, default=timezone.now)

    def to_mf_mson(self, properties):
        mf_json = {
            "type": ["h-entry"],
            "properties": {
                "content": [self.content],
                "published": [self.published],
                "category": [t.text for t in self.tags.all()]
            }
        }

        if properties is None:
            return mf_json
        
        del mf_json["type"]

        for key in ["content", "published", "category"]:
            if key not in properties:
                del mf_json["properties"][key]
        
        return mf_json