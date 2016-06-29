from django.http import HttpResponse, HttpResponseBadRequest, \
      HttpResponseRedirect, HttpResponseForbidden, StreamingHttpResponse
from django.shortcuts import render_to_response,render,get_object_or_404
from django.template import RequestContext,loader
#from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
import json
import sys

from django.db import IntegrityError
from django.db.models import ProtectedError
from django.db import connection

from onadata.apps.logger.models import Instance, XForm

from onadata.libs.utils.user_auth import has_permission, get_xform_and_perms,\
    helper_auth_helper, has_edit_permission

import collections
from onadata.apps.reports.views import get_moa_data_list
# Create your views here.

@login_required
def getInstance_json_merge(request, username, id_string, instance_id):
    #print 'Entered------------------------------------------------------'
    #print data_id
    xform = get_object_or_404(
        XForm, user__username__iexact=username, id_string__exact=id_string)
    instance = get_object_or_404(Instance, id=instance_id)
    
    #print 'data ::-----------------'
   # print xform_instance
    response = HttpResponse()
    response.content = json.dumps(instance.json)
    return response

@login_required
def instance_merge(request, username):
    
    return render(request, 'merge_report_gen/merge_test.html', {
        'username': username,
    })


def setValueToDatabase(request):
    form_id = request.POST.get('form_id_string','monthly_accomplishment_form')
    instance_id = request.POST.get('instance_id',0)
    json_val = request.POST.get('json_val',{})
    # print 'setValueToDatabase------------------'
    # print form_id
    # print instance_id
    
    data = json.loads(json_val)
    cursor = connection.cursor()
    #print "##########"
    #print "" + str(form_id) + "--" + int(instance_id) + "--" + str(key)
    #print "##########"
    for key in data.keys():
        cursor.execute("BEGIN")
        cursor.callproc("set_value_question_log",(str(form_id),int(instance_id),str(key),json.dumps(data[key])))
        cursor.execute("COMMIT")
    update_is_new_query = "UPDATE public.specific_form_info SET is_new = FALSE WHERE form_instance_id = "+instance_id
    cursor.execute(update_is_new_query)
    cursor.close()
    response = HttpResponse()
    response.content = 'success'
    return response

def get_merge_data_with_filter(request):
    submitted_by = request.POST.get('submitted_by','%')
    fromdate = request.POST.get('fromdate','2016-03-01')
    todate = request.POST.get('todate','2016-03-02')
    outcome = request.POST.get('outcome','1')
    component = request.POST.get('component','%')
    sub_list = request.POST.getlist('submitted_by[]','[]')
    logger_xform_id = 296
    accomplishment_xform_id = 294   
    target_form_data = ''
    accomplishment_form_query = ''
    if submitted_by == '%' and sub_list != '[]':
        query = "SELECT instance_question_log.question,SUM(cast(instance_question_log.qvalue_json->>'question_value' as int)) as value FROM instance_question_log, "
        query += " logger_instance where instance_question_log.instance_id=logger_instance.id and question like 'activity\_%\_%' and logger_instance.json ->> 'date' between '"+fromdate+"' and '"+todate+"' and ("
        partial_accomplishment_form_query = "select activity,SUM(t.female::int) as female,SUM(t.male::int) as male,SUM(t.boys::int) as boys,SUM(t.girls::int) as girls, SUM(t.disable_male::int) as disable_male,SUM(t.disable_female::int) as disable_female,SUM(t.disable_girls::int) as disable_girls,SUM(t.disable_boys::int) as disable_boys from (select * from crosstab('select instance_id, question , answer from vsAccomp where formdate between ''"+fromdate+"'' and ''"+todate+"'' and ( "
        mid_query = ""
        for submitter in sub_list:
            mid_query += "logger_instance.json ->> '_submitted_by' like '"+submitter+"' OR "
            partial_accomplishment_form_query += " submittedby like ''"+submitter+"'' OR "
        last_index = mid_query.rfind('OR')
        last_index_paf = partial_accomplishment_form_query.rfind('OR')
        mid_query = mid_query[:last_index]

        # partial_accomplishment_form_query = partial_accomplishment_form_query[last_index_paf:].replace('OR', '')
        partial_accomplishment_form_query = partial_accomplishment_form_query[:last_index_paf]
        query += mid_query
        query += " ) and logger_instance.xform_id in ("+str(logger_xform_id)+") AND (instance_question_log.qvalue_json ->> 'question_value'::text) IS NOT NULL group by question order by question"
        target_form_data = query

        partial_accomplishment_form_query += " ) and component like ''"+component+"'' order by 1,2') as ct(\"instance_id\" integer, \"activity\" text, \"female\" text, \"male\" text, \"boys\" text,\"girls\" text,\"disable_male\" text,\"disable_female\" text,\"disable_girls\" text,\"disable_boys\" text))as t group by t.activity"
        accomplishment_form_query = partial_accomplishment_form_query
    else:
        target_form_data = "SELECT instance_question_log.question,SUM(cast(instance_question_log.qvalue_json->>'question_value' as int)) as value FROM instance_question_log, logger_instance where instance_question_log.instance_id=logger_instance.id and question like 'activity\_%\_%' and logger_instance.json ->> 'date' between '"+fromdate+"' and '"+todate+"' and logger_instance.json ->> '_submitted_by' like '"+submitted_by+"' and logger_instance.xform_id in ("+str(logger_xform_id)+") AND (instance_question_log.qvalue_json ->> 'question_value'::text) IS NOT NULL group by question order by question"
        accomplishment_form_query = "select activity,SUM(t.female::int) as female,SUM(t.male::int) as male,SUM(t.boys::int) as boys,SUM(t.girls::int) as girls, SUM(t.disable_male::int) as disable_male,SUM(t.disable_female::int) as disable_female,SUM(t.disable_girls::int) as disable_girls,SUM(t.disable_boys::int) as disable_boys from (select * from crosstab('select instance_id, question , answer from vsAccomp where formdate between ''"+fromdate+"'' and ''"+todate+"'' and submittedby like ''"+submitted_by+"'' and component like ''"+component+"'' order by 1,2' ) as ct(\"instance_id\" integer, \"activity\" text, \"female\" text, \"male\" text, \"boys\" text,\"girls\" text,\"disable_male\" text,\"disable_female\" text,\"disable_girls\" text,\"disable_boys\" text))as t group by t.activity"

    # print "************"
    # print sub_list
    # print partial_accomplishment_form_query
    # print target_form_data
    # print accomplishment_form_query
    # print "************"    
    # print accomplishment_form_query    
    # print "************"    
    response = HttpResponse()
    cursor = connection.cursor()
    target_form_activities = {}
    # target_form_data = {}
    # target_form_data = "SELECT instance_question_log.question,SUM(cast(instance_question_log.qvalue_json->>'question_value' as int)) as value FROM instance_question_log, logger_instance where instance_question_log.instance_id=logger_instance.id and question like 'activity\_%\_%' and logger_instance.json ->> 'date' between '"+fromdate+"' and '"+todate+"' and logger_instance.json ->> '_submitted_by' like '"+submitted_by+"' and logger_instance.xform_id in (45) AND (instance_question_log.qvalue_json ->> 'question_value'::text) IS NOT NULL group by question order by question"
    #print target_form_data
    cursor.execute(target_form_data)
    raw_datas = cursor.fetchall();
    for each in raw_datas:
        target_form_activities[str(each[0])]=int(each[1])
    #print target_form_activities

    # accomplishment_form_query = "select activity,SUM(t.female::int) as female,SUM(t.male::int) as male,SUM(t.boys::int) as boys,SUM(t.girls::int) as girls, SUM(t.disable_male::int) as disable_male,SUM(t.disable_female::int) as disable_female,SUM(t.disable_girls::int) as disable_girls,SUM(t.disable_boys::int) as disable_boys from (select * from crosstab('select instance_id, question , answer from vsAccomp where formdate between ''"+fromdate+"'' and ''"+todate+"'' and submittedby like ''"+submitted_by+"'' order by 1,2') as ct(\"instance_id\" integer, \"activity\" text, \"boys\" text, \"female\" text, \"girls\" text,\"male\" text,\"disable_male\" text,\"disable_female\" text,\"disable_boys\" text,\"disable_girls\" text))as t group by t.activity"
    cursor.execute(accomplishment_form_query)
    rows = cursor.fetchall()

    achievement_query = "select qvalue_json->>'question_value',count(qvalue_json->>'question_value') from instance_question_log,logger_instance where instance_question_log.instance_id=logger_instance.id and logger_instance.xform_id in ("+str(accomplishment_xform_id)+") and question like 'activity\_%' and logger_instance.json ->> '_submitted_by' like '"+submitted_by+"' and logger_instance.json ->> 'date' between '"+fromdate+"' and '"+todate+"' AND (instance_question_log.qvalue_json ->> 'question_value'::text) IS NOT NULL group by question,qvalue_json->>'question_value' order by question"
    cursor.execute(achievement_query)
    achievement_data = cursor.fetchall()
    
    achievement_data_dict = {}
    for row in achievement_data:
        achievement_data_dict['activity_'+str(row[0])]=str(row[1])
    
    achievement_query_cumulative = "select qvalue_json->>'question_value',count(qvalue_json->>'question_value') from instance_question_log,logger_instance where instance_question_log.instance_id=logger_instance.id and logger_instance.xform_id in ("+str(accomplishment_xform_id)+") and question like 'activity\_%' and logger_instance.json ->> '_submitted_by' like '"+submitted_by+"' and (instance_question_log.qvalue_json ->> 'question_value'::text) IS NOT NULL group by question,qvalue_json->>'question_value' order by question"
    cursor.execute(achievement_query_cumulative)
    achievement_cumulative_data = cursor.fetchall()
    
    achievement_cumulative_dict = {}
    for row in achievement_cumulative_data:
        achievement_cumulative_dict['activity_'+str(row[0])]=str(row[1])

    cursor.close()
    merge_form_Data = {}
    
    for row in rows:
        accomplisment_data = {}
        key = 'activity_'+str(row[0])
        female = int(row[1])
        male = int(row[2])
        boys = int(row[3])
        girls = int(row[4])
        disable_male = int(row[5])
        disable_female = int(row[6])
        disable_girls = int(row[7])
        disable_boys = int(row[8])
        accomplisment_data['female'] = female
        accomplisment_data['male'] = male
        accomplisment_data['boys'] = boys
        accomplisment_data['girls'] = girls
        accomplisment_data['disable_male'] = disable_male
        accomplisment_data['disable_female'] = disable_female
        accomplisment_data['disable_girls'] = disable_girls
        accomplisment_data['disable_boys'] = disable_boys
        accomplisment_data['total_disable'] = disable_male + disable_female +disable_boys + disable_girls
        accomplisment_data['total_notdisable'] = male + female + boys+ girls
        if achievement_data_dict.get(key) is not None:
            accomplisment_data['achievement'] = achievement_data_dict.get(key)
        if achievement_cumulative_dict.get(key) is not None:
            accomplisment_data['achievement_cumulative'] = achievement_cumulative_dict.get(key)
        if key in target_form_activities:
            target = target_form_activities[key]
            accomplisment_data['target'] = int(target)
            target_form_activities.pop(key, None)
        merge_form_Data[key] = accomplisment_data
    
    
    for each in target_form_activities:
        target_data = {}
        key = str(each)
        #print key, target_form_activities[key]
        target_data['target'] = int(target_form_activities[key])
        merge_form_Data[key] = target_data
    #print target_form_activities
    #print merge_form_Data
      ##------------Daily_accomplishment_form-----query---end      
    
    #print formData
    # response.content = json.dumps(merge_form_Data)
    # print "************"
    
    formatted_data = get_moa_data_list(json.dumps(merge_form_Data),outcome)
    # response.content = json.dumps(formatted_data) 
    #print json.dumps(merge_form_Data)
    # print "************"
    # return response
    return HttpResponse(json.dumps(formatted_data), content_type="application/json")

def get_form_info(request):
    response = HttpResponse()
    cursor = connection.cursor()

    query = "select specific_form_info.form_id_string,specific_form_info.form_instance_id,specific_form_info.form_id_int from specific_form_info where is_new = TRUE and form_instance_id in (select instance_id from approval_instanceapproval where status like 'Approved')"

    cursor.execute(query)
    form_informations = cursor.fetchall()
    rowcount = cursor.rowcount
    
    form_info_json = {}

    for info in form_informations:
        data={}
        form_id = int(info[2])
        if form_id == 296 or form_id == 294:
            # print form_id
            xform = get_object_or_404(XForm, pk=form_id)
            user_id = xform.user_id
            owner = get_object_or_404(User, pk=user_id)
            # print owner.username
            data['username'] = str(owner.username)
            data['xform_id_string'] = str(xform.id_string)
            form_info_json[str(info[1])] = data

    response.content = json.dumps(form_info_json)
    return response
