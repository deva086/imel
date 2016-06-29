from django.conf import settings
from django.contrib.sites.models import Site
from onadata.apps.usermodule.models import MenuItem, UserModuleProfile, OrganizationDataAccess
from onadata.apps.reports.project_data import OXFAM_BD_ORG_ID # oxfam bd report
from onadata.apps.usermodule.views_project import get_own_and_partner_orgs_usermodule_users

def site_name(request):
    site_id = getattr(settings, 'SITE_ID', None)
    try:
        site = Site.objects.get(pk=site_id)
    except Site.DoesNotExist:
        site_name = 'example.org'
    else:
        site_name = site.name
    return {'SITE_NAME': site_name}


def additional_menu_items(request):
    menu_items = MenuItem.objects.all()
    return {'menu_items': menu_items}


def is_admin(request):
    admin_menu = 0
    user = request.user._wrapped if hasattr(request.user,'_wrapped') else request.user
    if not request.user.id == None:
        current_user = UserModuleProfile.objects.filter(user=request.user)
        if current_user:
            current_user = current_user[0]
            if current_user.admin:
                admin_menu = 1
            else:
                admin_menu = 0
        else:
            admin_menu = 1   
    return {'admin_menu': admin_menu}


def is_oxfambd_user(request):
    oxfambd_user = 0
    org_list = OrganizationDataAccess.objects.filter(observer_organization=OXFAM_BD_ORG_ID)
    org_id_list = [org.observable_organization.id for org in org_list]
    user = request.user._wrapped if hasattr(request.user,'_wrapped') else request.user
    if not request.user.id == None:
        current_user = UserModuleProfile.objects.filter(user=request.user)
        if current_user:
            current_user = current_user[0]
            if current_user.organisation_name.id in org_id_list:
                oxfambd_user = 1
            else:
                oxfambd_user = 0
        else:
            oxfambd_user = 1   
    return {'oxfambd_user': oxfambd_user}