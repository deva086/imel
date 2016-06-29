from django.conf.urls import patterns, include, url
from django.contrib import admin
from onadata.apps.reports import views

urlpatterns = patterns('',
    # url(r'^$', views.index, name='index'),
    url(r'^all/$', views.reports, name='reports'),
    url(r'^export/$', views.export_xls_report, name='export_xls_report'),
    url(r'^villege-list/$', views.get_villege_list, name='get_villege_list'),
    url(r'^question-list/$', views.get_question_list, name='get_question_list'),
    )
