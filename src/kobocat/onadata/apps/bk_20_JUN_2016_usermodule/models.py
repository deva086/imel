from django.db import models
from django.contrib.auth.models import User


# Create your models here.
from django.db.models import Count

from django.db import models

class UserModuleProfile(models.Model):
    user = models.OneToOneField(User)
    expired = models.DateTimeField()
    # designation = models.CharField(max_length=200)
    # The additional attributes we wish to include.
    admin = models.BooleanField(default=False)
    employee_id = models.CharField(max_length=50)
    organisation_name = models.ForeignKey('Organizations', on_delete=models.PROTECT)
    country = models.CharField(max_length=100)
    position = models.CharField(max_length=100)

    # Override the __unicode__() method to return out something meaningful!
    def __str__(self):
        return self.user

    class Meta:
       app_label = 'usermodule'    


class UserPasswordHistory(models.Model):
    user_id = models.IntegerField()
    password = models.CharField(max_length=150)
    # designation = models.CharField(max_length=200)
    date = models.DateTimeField()

    # Override the __unicode__() method to return out something meaningful!
    def __str__(self):
        return self.user


class UserFailedLogin(models.Model):
    user_id = models.IntegerField()
    login_attempt_time= models.DateTimeField(auto_now_add=True)


    def was_username(self):
        current_user= User.objects.get(id=self.user_id)
        return current_user;
    was_username.short_description = 'Username'


class OrganizationDataAccess(models.Model):
    # observer_oraganization = models.CharField(max_length=150)
    # observable_oraganization = models.CharField(max_length=150)
    observer_organization = models.ForeignKey('Organizations',related_name='user_observer_organization', on_delete=models.CASCADE)
    observable_organization = models.ForeignKey('Organizations',related_name='user_observable_organization', on_delete=models.CASCADE)
    

    class Meta:
        unique_together = ('observer_organization', 'observable_organization',)


class Organizations(models.Model):
    organization = models.CharField(max_length=150)
    # Override the __unicode__() method to return out something meaningful!
    def __str__(self):
        return self.organization

    class Meta:
       app_label = 'usermodule'


class MenuItem(models.Model):
    text = models.CharField(max_length=150)
    url = models.CharField(max_length=150)
    list_class = models.CharField(max_length=150)
    icon_class = models.CharField(max_length=150)
    parent_menu = models.CharField(max_length=150)
    
    def __str__(self):
        return self.text

    



