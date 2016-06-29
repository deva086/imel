from django.conf.urls import patterns, include, url
from django.contrib import admin
from onadata.apps.merge_report_gen import views

urlpatterns = patterns('',
   
	url(r"^view/(?P<username>\w+)/merge/",views.instance_merge, name='instance_merge'),
	url(r'^(?P<username>\w+)/forms/(?P<id_string>[^/]+)/get_json/(?P<instance_id>[\d+^/]+)',views.getInstance_json_merge, name='instance_json_merge'),
	url(r'^setvalue/$', views.setValueToDatabase, name='setValueToDatabase'),

	url(r'^get_merge_json/$', views.get_merge_data_with_filter, name='get_merge_data_with_filter'),
	url(r'^get_form_info/$', views.get_form_info, name='get_form_info'),
    )