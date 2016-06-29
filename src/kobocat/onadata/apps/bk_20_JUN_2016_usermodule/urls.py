from django.conf.urls import patterns, include, url
from django.contrib import admin
from onadata.apps.usermodule import views,views_project

urlpatterns = patterns('',
    url(r'^$', views.index, name='index'),
    url(r'^register/$', views.register, name='register'),
    url(r'^add-organization/$', views.add_organization, name='add_organization'),
    url(r'^organizations/$', views.organization_index, name='organization_index'),
    url(r'^edit-organization/(?P<org_id>\d+)/$', views.edit_organization, name='edit_organization'),
    # url(r'^organization-mapping/$', views.organization_mapping, name='organization_mapping'),
    url(r'^organization-delete/(?P<org_id>\d+)/$', views.delete_organization, name='organization_delete'),
    url(r'^organization-delete-mapping/(?P<org_id>\d+)/$', views.delete_organization_mapping, name='delete_organization_mapping'),
    url(r'^edit/(?P<user_id>\d+)/$', views.edit_profile, name='edit_profile'),
    url(r'^delete/(?P<user_id>\d+)/$', views.delete_user, name='delete_user'),
    url(r'^reset-password/(?P<reset_user_id>\d+)/$', views.reset_password, name='reset_password'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^change-password/$', views.change_password, name='change_password'),
    url(r'^locked-users/$', views.locked_users, name='locked_users'),
    url(r'^unlock/$', views.unlock, name='unlock'),
    url(r'^organization-access-list/$', views.organization_access_list, name='organization_access_list'),
    # menu item urls 
    #url(r'^add-menu/$', views.add_menu, name='add_menu'),
    # url(r'^organizations/$', views.organization_index, name='organization_index'),
    # url(r'^edit-organization/(?P<org_id>\d+)/$', views.edit_organization, name='edit_organization'),

    # new project view url
    url(r'^(?P<username>\w+)/projects-views/(?P<id_string>[^/]+)/$', views_project.custom_project_window, name='custom_project_window'),
    url(r'^(?P<username>\w+)/test/(?P<id_string>[^/]+)/$', views_project.test, name='test'),
    
    # url(r"^(?P<username>\w+)/forms/(?P<id_string>[^/]+)/view-data",
    #     'onadata.apps.viewer.views.data_view'),
    url(r'^ajax-reponse/$', views_project.get_ajax_response, name='get_ajax_response'),
    )
