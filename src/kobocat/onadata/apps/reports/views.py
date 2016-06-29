from django.http import (
    HttpResponseRedirect, HttpResponse)
from django.shortcuts import render_to_response,render,get_object_or_404
from django.template import RequestContext,loader
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
import json
import sys
from onadata.apps.logger.models import Instance, XForm
from onadata.apps.usermodule.models import UserModuleProfile, Organizations, OrganizationDataAccess
from onadata.apps.reports.project_data import static_data, OXFAM_BD_ORG_ID
from django.db import IntegrityError
from django.db.models import ProtectedError
from django.db import connection
from onadata.apps.reports.helpers import dictfetchall, get_count, get_percentage, get_viewable_projects
from onadata.apps.logger.models import XForm
import xlwt
import time,datetime
import urllib, json


def get_select_key_choices(xjson):
    data = json.loads(xjson)
    response = []
    ques_json_array = data['children'] if 'children' in data else []
    for ques_json_obj in ques_json_array:
        response_obj = {}
        response_obj['type'] = ques_json_obj['type']
        bool_type_check =  ques_json_obj['type'] == 'select one' or ques_json_obj['type'] == 'select many' or ques_json_obj['type'] == 'select all that apply'
        if 'children' in ques_json_obj and bool_type_check:
            response_obj['ques_key'] = ques_json_obj['name'] if 'name' in ques_json_obj else 'N/A'
            response_obj['ques_label'] = ques_json_obj['label']['default'] if 'default' in ques_json_obj['label'] else ques_json_obj['label']
            ans_choices = []
            for choices in ques_json_obj['children']:
                label = choices['label']['default'] if 'default' in choices['label'] else choices['label']
                ans_dic = {}
                ans_dic['lable_key'] = choices['name']
                ans_dic['readable_label'] = label
                ans_choices.append(ans_dic)
            response_obj['ans_choices'] = ans_choices
            response.append(response_obj)
        elif 'children' in ques_json_obj and ques_json_obj['type'] == 'group':
            for grp_json_obj in ques_json_obj['children']:
                response_obj = {}
                response_obj['type'] = grp_json_obj['type']
                bool_type_check =  grp_json_obj['type'] == 'select one' or grp_json_obj['type'] == 'select many' or grp_json_obj['type'] == 'select all that apply'
                if 'children' in grp_json_obj and bool_type_check:
                    # response_obj['ques_key'] = grp_json_obj['name'] if 'name' in grp_json_obj else 'N/A'
                    response_obj['ques_key'] = ques_json_obj['name'] + "/"+ grp_json_obj['name'] if 'name' in grp_json_obj else 'N/A'
                    response_obj['ques_label'] = grp_json_obj['label']['default'] if 'default' in grp_json_obj['label'] else grp_json_obj['label']
                    ans_choices = []
                    for choices in grp_json_obj['children']:
                        label = choices['label']['default'] if 'default' in choices['label'] else choices['label']
                        ans_dic = {}
                        ans_dic['lable_key'] = choices['name']
                        ans_dic['readable_label'] = label
                        ans_choices.append(ans_dic)
                    response_obj['ans_choices'] = ans_choices
                    response.append(response_obj)    
    return response


@login_required
def reports(request):
    xforms_list = get_viewable_projects(request)
    context = RequestContext(request)
    current_from_date = "N/A"
    current_to_date = "N/A"
    previous_from_date = "N/A"
    previous_to_date = "N/A"
    
    if request.method == 'GET' and request.GET.get('id'):
        xform_id_string = request.GET.get('id')
        current_from_date = request.GET.get('current_from_date')
        current_to_date = request.GET.get('current_to_date')
        previous_from_date = request.GET.get('previous_from_date')
        previous_to_date = request.GET.get('previous_to_date')
        ajax_villege_array = request.GET.getlist('villege_array[]')
        ajax_question_selected = request.GET.get('question_select')
        ajax_response_type = request.GET.get('type')
        
        table_set = get_tableset(xforms_list, current_from_date, current_to_date,
         previous_from_date,previous_to_date, xform_id_string, ajax_villege_array, 
         ajax_question_selected, ajax_response_type)
        
        return HttpResponse(json.dumps(table_set), content_type="application/json")
    return render_to_response(
            'reports/list_reports.html',
            {'xforms_list':xforms_list},
            context)


def export_xls_report(request): #,table_set
    xforms_list = get_viewable_projects(request)
    wb = xlwt.Workbook()
    ws = wb.add_sheet('Report')

    xform_id_string = request.POST.get('id','xxx')
    current_from_date = request.POST.get('current_from_date','xxx')
    current_to_date = request.POST.get('current_to_date','xxx')
    previous_from_date = request.POST.get('previous_from_date','xxx')
    previous_to_date = request.POST.get('previous_to_date','xxx')
    ajax_villeges = request.POST.get('villege_array')
    ajax_question_selected = request.POST.get('question_select','xxx')
    ajax_response_type = request.POST.get('type','xxx')
    
    current_time = time.time()
    current_timestamp = str('_'+datetime.datetime.fromtimestamp(current_time).strftime('%Y_%m_%d_%H_%M_%S'))
    report_filename = 'report'+current_timestamp
    if xform_id_string != 'xxx':
        if len(xform_id_string) >= 4:
            report_filename = 'report' + '_' + xform_id_string[0:4] + current_timestamp
        else:
            report_filename = 'report' + '_' + xform_id_string + current_timestamp

    response = HttpResponse(mimetype='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename='+report_filename+'.xls'
    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet(report_filename)
    style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',
        num_format_str='#,##0.00')
    style1 = xlwt.easyxf(num_format_str='D-MMM-YY')
    style2 = xlwt.easyxf('font: name Times New Roman, color-index black, bold on',
        num_format_str='#,##0.00')

    ajax_villege_array = []
    if ajax_villeges:
        ajax_villege_array = ajax_villeges.split(",")
    print ajax_villege_array
    table_set = get_tableset(xforms_list, current_from_date, current_to_date,
         previous_from_date,previous_to_date, xform_id_string, ajax_villege_array, 
         ajax_question_selected, ajax_response_type)

    row = 0
    col = 0
    for table in table_set:
        villege_list = table['villege_list']
        ws.write_merge(row, row, col, (col+4) , 'Data Display Format Aggregate',style2)
        colspan = int(table['disaggregate_colspan'])
        if colspan > 1:
            ws.write_merge(row, row, (col+5) , (col+5+int(table['disaggregate_colspan'])), 'Data Display Format (disaggregate)',style2)

        col = 0
        row = row + 1 
        ws.write( (row), 0, table['question'],style2)
        ws.write( (row), 1, 'Current', style2)
        ws.write( (row), 2, 'Previous', style2)
        ws.write( (row), 3, 'Percentage Change', style2)
        ws.write( (row), 4, 'Total', style2)

        if colspan > 1:
            ws.write( (row), 5, table['question'],style2)
            col = 6
            for v in villege_list:
                ws.write_merge((row), (row), col, (col+1) , v['title'], style2)
                ws.write( (row), (col+2), 'Percentage Change',style2)
                col = col + 3   
        
        col = 0
        row = row + 1 
        if colspan > 1:    
            ws.write_merge((row), (row), col, (col+5) , '', style2)
            col = col + 6
        for v in villege_list:
            ws.write( (row), (col), 'Current',style2)
            ws.write( (row), (col+1), 'Previous',style2)
            ws.write( (row), (col+2), '',style2)
            col = col + 3

        row = row + 1 
        for data_collection in table['list']:
            col = 0    
            for data in data_collection:
                ws.write( (row), (col), data)
                col = col + 1
            row = row + 1

        col = 0
        for foot in table['footer']:
            ws.write( (row), (col), foot, style2)
            col = col + 1

        row = row + 1
        col = 0    
    wb.save(response)
    return response


def get_villege_list(request):
    if request.method == 'GET' and request.GET.get('project_id'):
        xform_id_string = request.GET.get('project_id')
        xform = get_object_or_404(XForm, id_string__exact=xform_id_string)
        formatted_json = get_select_key_choices(xform.json)
        villege_list = []
        for fd in formatted_json:
            if fd['ques_key'] == 'Villege_':
                villege = {}
                villege['villege_value'] = 'Villege ID'
                villege['villege_title'] = 'Villege Name'
                villege_list.append(villege)
                for choice in fd['ans_choices']:
                    villege = {}
                    villege['villege_value'] = choice['lable_key']
                    villege['villege_title'] = choice['readable_label']
                    villege_list.append(villege)
        return HttpResponse(json.dumps(villege_list), content_type="application/json")
    return HttpResponse('[]')


def get_question_list(request):
    if request.method == 'GET' and request.GET.get('project_id'):
        xform_id_string = request.GET.get('project_id')
        xform = get_object_or_404(XForm, id_string__exact=xform_id_string)
        formatted_json = get_select_key_choices(xform.json)
        question_list = []
        for fd in formatted_json:
            if fd['ques_key'] != 'Villege_':
                question = {}
                question['ques_key'] =fd['ques_key']
                question['ques_label'] = fd['ques_label']
                question_list.append(question)
        return HttpResponse(json.dumps(question_list), content_type="application/json")
    return HttpResponse('[]')


def get_tableset(xforms_list, current_from_date, current_to_date,
         previous_from_date,previous_to_date, xform_id_string, ajax_villege_array, 
         ajax_question_selected, ajax_response_type):
    coloumn = 'status'
    value = 'value'
    count = 'count'
    default_value = 'N/A'
    all_forms = []
    # oxfa, test5_form, birth_registration, complementary_feeding, maternal_diet, villege_form
    # xform_id_string = "oxfa"
    form_id_string = "'" + xform_id_string + "'"
    options_query = "SELECT id FROM public.logger_xform where id_string="+ form_id_string
    cursor = connection.cursor()
    cursor.execute(options_query)
    xform_id = str(dictfetchall(cursor)[0]['id'])

    xform = get_object_or_404(XForm, id_string__exact=xform_id_string)
    formatted_json = get_select_key_choices(xform.json)
    Villege_list = []
    for fd in formatted_json:
        if fd['ques_key'] == 'Villege_':
            if not ajax_villege_array:
                for choice in fd['ans_choices']:
                    villege = {}
                    villege['title'] = choice['readable_label']
                    villege['current'] = '1'
                    villege['previous'] = '0'
                    villege['percentage'] = '1%'
                    Villege_list.append(villege)
            else:
                for choice in fd['ans_choices']:
                    if choice['lable_key'] in ajax_villege_array:
                        villege = {}
                        villege['title'] = choice['readable_label']
                        villege['current'] = '1'
                        villege['previous'] = '0'
                        villege['percentage'] = '1%'
                        Villege_list.append(villege)
                        
    table_set = []
    for fd in formatted_json:
        if fd['ques_key'] == 'Villege_' or fd['ques_key'] != ajax_question_selected:
            continue    
        table = {}
        table['question'] = fd['ques_label']
        table['villege_list'] = Villege_list
        
        listy = []
        sum_previous = 0
        sum_current = 0
        sum_current_villege = 0
        sum_previous_villege = 0
        sum_total_data_point = 0
        for choice in fd['ans_choices']:
            dicty = []
            previous = get_count(connection,fd['type'],cursor,fd['ques_key'],choice['lable_key'],'','',xform_id, previous_from_date, previous_to_date)
            current = get_count(connection,fd['type'],cursor,fd['ques_key'],choice['lable_key'],'','',xform_id, current_from_date, current_to_date)
            percentage = get_percentage(previous,current)
            total_data_point = previous + current
            sum_previous += previous
            sum_current += current
            sum_total_data_point += total_data_point
            dicty.append(choice['readable_label'])
            dicty.append(current)
            dicty.append(previous)
            dicty.append(percentage)
            dicty.append(total_data_point)

            if Villege_list:
                dicty.append(choice['readable_label'])

            for v in Villege_list:
                villege_current = get_count(connection,fd['type'],cursor,fd['ques_key'],choice['lable_key'],'Villege_',v['title'],xform_id, current_from_date, current_to_date)
                villege_previous = get_count(connection,fd['type'],cursor,fd['ques_key'],choice['lable_key'],'Villege_',v['title'],xform_id, previous_from_date, previous_to_date)
                sum_current_villege += villege_current
                sum_previous_villege += villege_previous
                villege_percentage = get_percentage(villege_current, villege_previous)
                dicty.append(villege_current)
                dicty.append(villege_previous)
                dicty.append(villege_percentage)
            listy.append(dicty)
        table['disaggregate_colspan'] = (len(Villege_list)*3)+1
        table['list'] = listy

        footers = []
        footers.append('Total')
        footers.append(sum_current)
        footers.append(sum_previous)
        footers.append('')
        footers.append(sum_total_data_point)
        if Villege_list:
            footers.append('Total')
        for v in Villege_list:
            footers.append(sum_current_villege)
            footers.append(sum_previous_villege)
            footers.append('')
        
        table['footer'] = footers
        table_set.append(table)
    return table_set


@login_required
def moa_report(request):
    context = RequestContext(request)
    # url = "http://192.168.21.230:8001/audit/mainview/ratna/test_json/monthly_target_form2/322/json/daily_accomplishment_form/321"
    # data_array = get_moa_data_list(url)
    organization_list = OrganizationDataAccess.objects.filter(observer_organization=OXFAM_BD_ORG_ID).values('observable_organization')
    org_id_list = [org_id['observable_organization'] for org_id in organization_list]
    organizations = Organizations.objects.filter(id__in=org_id_list)
    userlist = UserModuleProfile.objects.filter(organisation_name__in=org_id_list)
    # organization = Organizations.objects.filter(observable_organization_in=OXFAM_BD_ORG_ID)
    # .filter(organisation_name__in=org_id_list)
    # print "#######"
    # print organization.pk, organization
    # print organizations
    # print "#######"
    return render_to_response(
            'reports/moa_reports.html',
            {'userlist':userlist,'organizations':organizations}, # 'data_array':data_array,
            context)

@require_GET
def get_org_users(request):
    org_id = str(OXFAM_BD_ORG_ID)
    if request.method == 'GET' and request.GET.get('org_id'):
        org_id = request.GET.get('org_id')
    if org_id == 'custom':
        organization_list = OrganizationDataAccess.objects.filter(observer_organization=OXFAM_BD_ORG_ID).values('observable_organization')
        org_id_list = [org_id['observable_organization'] for org_id in organization_list]
        users = UserModuleProfile.objects.filter(organisation_name__in=org_id_list).order_by("user__username")
    else:    
        users = UserModuleProfile.objects.filter(organisation_name=org_id).order_by("user__username")
    userlist = []
    for u in users:
        user_dict = {}
        user_dict['id'] = u.user.id
        user_dict['name'] = u.user.username
        userlist.append(user_dict)

    return HttpResponse(json.dumps(userlist), content_type="application/json")    
    

def get_moa_data_list(ajax_data, outcome):
    # static data contained in dict

    # print "#######"
    # print static_data['1.1']
    # print "#######"
    formatted_list = []
    # response = urllib.urlopen(url)
    # data = str(response.read())
    # {"activity_1_2": {"target": "8"}, "activity_2_48": {"disable_boys": "7", "disable_male": "10", "disable_female": "10", "girls": "7", "boys": "7", "female": "7", "disable_girls": "7", "male": "7"}, "activity_1_1": {"target": "8"}, "activity_2_1": {"target": "9"}, "activity_2_2": {"target": "9"}}
    # data = json.loads(response.read()) # <======== real one
    # data = {"activity_1_2": {"target": "8"}, "activity_2_48": {"disable_boys": "7", "disable_male": "10", "disable_female": "10", "girls": "7", "boys": "7", "female": "7", "disable_girls": "7", "male": "7"}, "activity_1_1": {"target": "8"}, "activity_2_1": {"target": "9"}, "activity_2_2": {"target": "9"}}
    data = data = json.loads(ajax_data)
    # data = '[' + data[1:-1] + ']'
    formatted_list_2 = []
    ranger = {}
    ranger[1] = 46
    ranger[2] = 48
    ranger[3] = 9
    ranger[4] = 26
    range_start = 1
    range_end = 5
    if outcome != 'custom':
        range_start = int(outcome)
        range_end = range_start + 1
    for report_type_count in range(range_start,range_end):
        for i in range(1,(ranger[report_type_count]+1) ): # report_type_count
            formatted_dict_2 = {}
            ki = str(report_type_count)+'.' + str(i)
            activity = 'activity_'+str(report_type_count)+'_' + str(i)
            value = 'XXX'
            if activity in data:
                # if 'target' in data[activity]:
                #     value = data[activity]['target']
                formatted_dict_2['result_type_row'] = '0'    
                formatted_dict_2['sn'] = ki
                formatted_dict_2['outcome_activities'] = static_data[str(ki)] if str(ki) in static_data else 'N/A'
                formatted_dict_2['trg_vs_ach_target'] = data[activity]['target'] if 'target' in data[activity] else ''
                formatted_dict_2['trg_vs_ach_achievement'] = data[activity]['achievement'] if 'achievement' in data[activity] else ''
                formatted_dict_2['trg_vs_ach_achievement_cumulative'] = data[activity]['achievement_cumulative'] if 'achievement_cumulative' in data[activity] else ''

                formatted_dict_2['prsn_w_dis_male'] = data[activity]['disable_male'] if 'disable_male' in data[activity] else ''
                formatted_dict_2['prsn_w_dis_female'] = data[activity]['disable_female'] if 'disable_female' in data[activity] else ''
                formatted_dict_2['prsn_w_dis_boy'] = data[activity]['disable_boys'] if 'disable_boys' in data[activity] else ''
                formatted_dict_2['prsn_w_dis_girl'] = data[activity]['disable_girls'] if 'disable_girls' in data[activity] else ''
                formatted_dict_2['prsn_w_dis_total'] = data[activity]['total_disable'] if 'total_disable' in data[activity] else ''

                formatted_dict_2['prsn_wo_dis_male'] = data[activity]['male'] if 'male' in data[activity] else ''
                formatted_dict_2['prsn_wo_dis_female'] = data[activity]['female'] if 'female' in data[activity] else ''
                formatted_dict_2['prsn_wo_dis_boy'] = data[activity]['boys'] if 'boys' in data[activity] else ''
                formatted_dict_2['prsn_wo_dis_girl'] = data[activity]['girls'] if 'girls' in data[activity] else ''
                formatted_dict_2['prsn_wo_dis_total'] = data[activity]['total_notdisable'] if 'total_notdisable' in data[activity] else ''

                formatted_dict_2['progress'] = ''
                formatted_dict_2['name_component'] = ''
                formatted_list_2.append(formatted_dict_2)    
            else:        
                formatted_dict_2['result_type_row'] = '0'    
                formatted_dict_2['sn'] = ki
                formatted_dict_2['outcome_activities'] = static_data[str(ki)] if str(ki) in static_data else 'N/A'
                formatted_dict_2['trg_vs_ach_target'] = value['target'] if 'target' in value else ''
                formatted_dict_2['trg_vs_ach_achievement'] = value['achievement'] if 'achievement' in value else ''
                formatted_dict_2['trg_vs_ach_achievement_cumulative'] = value['achievement_cumulative'] if 'achievement_cumulative' in value else ''

                formatted_dict_2['prsn_w_dis_male'] = value['disable_male'] if 'disable_male' in value else ''
                formatted_dict_2['prsn_w_dis_female'] = value['disable_female'] if 'disable_female' in value else ''
                formatted_dict_2['prsn_w_dis_boy'] = value['disable_boys'] if 'disable_boys' in value else ''
                formatted_dict_2['prsn_w_dis_girl'] = value['disable_girls'] if 'disable_girls' in value else ''
                formatted_dict_2['prsn_w_dis_total'] = value['total_disable'] if 'total_disable' in value else ''

                formatted_dict_2['prsn_wo_dis_male'] = value['male'] if 'male' in value else ''
                formatted_dict_2['prsn_wo_dis_female'] = value['female'] if 'female' in value else ''
                formatted_dict_2['prsn_wo_dis_boy'] = value['boys'] if 'boys' in value else ''
                formatted_dict_2['prsn_wo_dis_girl'] = value['girls'] if 'girls' in value else ''
                formatted_dict_2['prsn_wo_dis_total'] = value['total_notdisable'] if 'total_notdisable' in value else ''

                formatted_dict_2['progress'] = ''
                formatted_dict_2['name_component'] = ''
                formatted_list_2.append(formatted_dict_2)
        
    # formatted_dict = {}
    # formatted_dict['result_type_row'] = '1'
    # formatted_dict['result_type_val'] = 'Result-1: Community Based Organisations (CBOs) and local government institutions are able to anticipate possible impact of climate change, disaster and taking appropriate measures accordingly.'
    # formatted_list.append(formatted_dict)

    # formatted_dict = {}
    # formatted_dict['result_type_row'] = '0'
    # formatted_dict['sn'] = '1.1'
    # formatted_dict['outcome_activities'] = 'Community Based Organization-CBO formation and Review the existing plan'
    
    # formatted_dict['trg_vs_ach_target'] = 'N/A'
    # formatted_dict['trg_vs_ach_achievement'] = 'N/A'
    # formatted_dict['trg_vs_ach_achievement_cumulative'] = 'N/A'
    
    # formatted_dict['prsn_w_dis_male'] = 'N/A'
    # formatted_dict['prsn_w_dis_female'] = 'N/A'
    # formatted_dict['prsn_w_dis_boy'] = 'N/A'
    # formatted_dict['prsn_w_dis_girl'] = 'N/A'
    # formatted_dict['prsn_w_dis_total'] = 'N/A'

    # formatted_dict['prsn_wo_dis_male'] = 'N/A'
    # formatted_dict['prsn_wo_dis_female'] = 'N/A'
    # formatted_dict['prsn_wo_dis_boy'] = 'N/A'
    # formatted_dict['prsn_wo_dis_girl'] = 'N/A'
    # formatted_dict['prsn_wo_dis_total'] = 'N/A'

    # formatted_dict['progress'] = 'N/A'
    # formatted_dict['name_component'] = 'GEM'
    # formatted_list.append(formatted_dict)

    

    return formatted_list_2

def export_moa_report(request):
    # submitted_by = request.POST.get('submitted_by','%')
    # xforms_list = get_viewable_projects(request)
    wb = xlwt.Workbook()
    ws = wb.add_sheet('Monthly Accomplishment Report')

    export_data = request.POST.get('export','xxx')
    re_format = json.loads(export_data)
    current_time = time.time()
    current_timestamp = str('_'+datetime.datetime.fromtimestamp(current_time).strftime('%Y_%m_%d_%H_%M_%S'))
    report_filename = 'report'+current_timestamp
    if export_data != 'xxx':
        report_filename = 'report_moa_' + current_timestamp

    response = HttpResponse(mimetype='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename='+report_filename+'.xls'
    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet(report_filename)
    style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',
        num_format_str='#,##0.00')
    style1 = xlwt.easyxf(num_format_str='D-MMM-YY')
    style2 = xlwt.easyxf('font: name Times New Roman, color-index black, bold on',
        num_format_str='#,##0.00')
    # S/N   Outcome/Activities  Target vs. Achievement  Person with disabilities    Person without disabilities Progress    Name of Component
    row = 0
    # ws.write_merge((row), (row), col, (col+5) , '', style2)
    ws.write( (row), 0, "S/N",style2)
    ws.write( (row), 1, "Outcome/Activities",style2)
    ws.write_merge( (row),(row), 2, 4 ,"Target vs. Achievement",style2)
    ws.write_merge( (row),(row), 5, 9 ,"Person with disabilities",style2)
    ws.write_merge( (row),(row), 10, 14, "Person without disabilities",style2)
    # ws.write( (row), 3, "Person with disabilities",style2)
    # ws.write( (row), 4, "Person without disabilities",style2)
    # ws.write( (row), 15, "Progress",style2)
    # ws.write( (row), 16, "Name of Component",style2)

    row += 1
    ws.write( (row), 0, "",style2)
    ws.write( (row), 1, "",style2)
    ws.write( (row), 2, "Target",style2)
    ws.write( (row), 3, "Achievement",style2)
    ws.write( (row), 4, "Achievement Cumulative",style2)
    ws.write( (row), 5, "Male",style2)
    ws.write( (row), 6, "Female",style2)
    ws.write( (row), 7, "Boy",style2)
    ws.write( (row), 8, "Girl",style2)
    ws.write( (row), 9, "Total",style2)
    ws.write( (row), 10, "Male",style2)
    ws.write( (row), 11, "Female",style2)
    ws.write( (row), 12, "Boy",style2)
    ws.write( (row), 13, "Girl",style2)
    ws.write( (row), 14, "Total",style2)
    ws.write( (row), 15, "",style2)
    ws.write( (row), 16, "",style2)

    row += 1
    # print "********"
    for i in re_format:
        col = 0
        print i
        ws.write( (row), col, i['sn'],style2)
        ws.write( (row), col+1, i['outcome_activities'],style2)
        ws.write( (row), col+2, i['trg_vs_ach_target'],style2)
        ws.write( (row), col+3, i['trg_vs_ach_achievement'],style2)
        ws.write( (row), col+4, i['trg_vs_ach_achievement_cumulative'],style2)
        ws.write( (row), col+5, i['prsn_w_dis_male'],style2)
        ws.write( (row), col+6, i['prsn_w_dis_female'],style2)
        ws.write( (row), col+7, i['prsn_w_dis_boy'],style2)
        ws.write( (row), col+8, i['prsn_w_dis_girl'],style2)
        ws.write( (row), col+9, i['prsn_w_dis_total'],style2)
        ws.write( (row), col+10, i['prsn_wo_dis_male'],style2)
        ws.write( (row), col+11, i['prsn_wo_dis_female'],style2)
        ws.write( (row), col+12, i['prsn_wo_dis_boy'],style2)
        ws.write( (row), col+13, i['prsn_wo_dis_girl'],style2)
        ws.write( (row), col+14, i['prsn_wo_dis_total'],style2)
        # ws.write( (row), col+15, i['progress'],style2)
        # ws.write( (row), col+16, i['name_component'],style2)
        
        row += 1
    # print "********"
    # ajax_villege_array = []
    # if ajax_villeges:
    #     ajax_villege_array = ajax_villeges.split(",")
    # print ajax_villege_array
    # table_set = get_tableset(xforms_list, current_from_date, current_to_date,
    #      previous_from_date,previous_to_date, xform_id_string, ajax_villege_array, 
    #      ajax_question_selected, ajax_response_type)

    # row = 0
    # col = 0
    # for table in table_set:
    #     villege_list = table['villege_list']
    #     ws.write_merge(row, row, col, (col+4) , 'Data Display Format Aggregate',style2)
    #     colspan = int(table['disaggregate_colspan'])
    #     if colspan > 1:
    #         ws.write_merge(row, row, (col+5) , (col+5+int(table['disaggregate_colspan'])), 'Data Display Format (disaggregate)',style2)

    #     col = 0
    #     row = row + 1 
    #     ws.write( (row), 0, table['question'],style2)
    #     ws.write( (row), 1, 'Current', style2)
    #     ws.write( (row), 2, 'Previous', style2)
    #     ws.write( (row), 3, 'Percentage Change', style2)
    #     ws.write( (row), 4, 'Total', style2)

    #     if colspan > 1:
    #         ws.write( (row), 5, table['question'],style2)
    #         col = 6
    #         for v in villege_list:
    #             ws.write_merge((row), (row), col, (col+1) , v['title'], style2)
    #             ws.write( (row), (col+2), 'Percentage Change',style2)
    #             col = col + 3   
        
    #     col = 0
    #     row = row + 1 
    #     if colspan > 1:    
    #         ws.write_merge((row), (row), col, (col+5) , '', style2)
    #         col = col + 6
    #     for v in villege_list:
    #         ws.write( (row), (col), 'Current',style2)
    #         ws.write( (row), (col+1), 'Previous',style2)
    #         ws.write( (row), (col+2), '',style2)
    #         col = col + 3

    #     row = row + 1 
    #     for data_collection in table['list']:
    #         col = 0    
    #         for data in data_collection:
    #             ws.write( (row), (col), data)
    #             col = col + 1
    #         row = row + 1

    #     col = 0
    #     for foot in table['footer']:
    #         ws.write( (row), (col), foot, style2)
    #         col = col + 1

    #     row = row + 1
    #     col = 0    
    wb.save(response)
    return response

