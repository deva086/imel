from django.conf.urls import patterns, include, url
from django.contrib import admin
from onadata.apps.reports import views

urlpatterns = patterns('',
    # url(r'^$', views.index, name='index'),
    url(r'^all/$', views.reports, name='reports'),
    url(r'^export/$', views.export_xls_report, name='export_xls_report'),
    url(r'^villege-list/$', views.get_villege_list, name='get_villege_list'),
    url(r'^question-list/$', views.get_question_list, name='get_question_list'),

    url(r'^monthly-accomplishment-report/$', views.moa_report, name='moa_report'),
    url(r'^export-moa-report/$', views.export_moa_report, name='export_moa_report'),
    url(r'^get-org-users/$', views.get_org_users, name='get_org_users'),
    )
