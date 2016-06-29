from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.utils.translation import ugettext_lazy
from guardian.shortcuts import get_perms_for_model, assign_perm
from rest_framework.authtoken.models import Token
from jsonfield import JSONField
from onadata.libs.utils.country_field import COUNTRIES
from onadata.libs.utils.gravatar import get_gravatar_img_link, gravatar_exists
from onadata.apps.main.signals import set_api_permissions

class Approval(models.Model):    
    formid = models.CharField(max_length=200)
    subbmissionid = models.CharField(max_length=200)
    userid = models.CharField(max_length=200)
    status = models.CharField(max_length=200)
    label = models.IntegerField(default=0)
