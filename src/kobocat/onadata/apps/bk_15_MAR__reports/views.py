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
from django.db import IntegrityError
from django.db.models import ProtectedError
from django.db import connection
from onadata.apps.reports.helpers import dictfetchall, get_count, get_percentage, get_viewable_projects
from onadata.apps.logger.models import XForm
import xlwt

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
                    response_obj['ques_key'] = grp_json_obj['name'] if 'name' in grp_json_obj else 'N/A'
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
    response = HttpResponse(mimetype='application/vnd.ms-excel')
    response['Content-Disposition'] = 'attachment; filename=mymodel.xls'
    wb = xlwt.Workbook(encoding='utf-8')
    ws = wb.add_sheet("MyModel")
    style0 = xlwt.easyxf('font: name Times New Roman, color-index red, bold on',
        num_format_str='#,##0.00')
    style1 = xlwt.easyxf(num_format_str='D-MMM-YY')
    style2 = xlwt.easyxf('font: name Times New Roman, color-index black, bold on',
        num_format_str='#,##0.00')


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