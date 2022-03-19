from django.db import models
from django.contrib.auth.models import User

# Create your models here.
from event.models import EventRecord


class FeedBack(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    message = models.CharField(max_length=5000)
    status = models.BooleanField(default=False)
    id = models.IntegerField(primary_key=True)
    event_id = models.ForeignKey(EventRecord, on_delete=models.PROTECT, null=True)


class News(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    image = models.ImageField(upload_to='news')