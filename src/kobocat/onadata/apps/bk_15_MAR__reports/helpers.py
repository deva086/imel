from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from onadata.apps.logger.models import Instance, XForm 
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext as _
from onadata.apps.main.forms import QuickConverter,QuickConverterFile,QuickConverterURL

def dictfetchall(cursor):
    "Returns all rows from a cursor as a dict"
    desc = cursor.description
    return [
        dict(zip([col[0] for col in desc], row))
        for row in cursor.fetchall()
    ]


def get_count(connection, query_type, cursor, key, value, key2, value2, xform_id,from_date, to_date ):
    """
    Returns count of specified key where its equal to 
    the passed on value.
    """
    count = 'count'
    extra_cond = ''
    from_bool = from_date == "N/A" or from_date == ''
    to_bool =  to_date == "N/A" or to_date == ''
    
    second_condition = ''
    if len(key2) > 0 and len(value2) > 0:
        second_condition = " AND json->>'"+key2+"' = '" + value2 + "'"
        
    if (not from_bool) and (not to_bool):
        extra_cond = "AND ( json->>'_submission_time' >= '" + from_date + "' AND json->>'_submission_time' <= '" + to_date + "')"
    elif not from_bool:
        extra_cond = "AND json->>'_submission_time' >= '" + from_date + "'"
    elif not to_bool:
        extra_cond = "AND json->>'_submission_time' <= '" + to_date + "'"
    if query_type == 'select all that apply' or query_type == 'select many':
        options_query = "SELECT count(json::json->'" + key + "') as " + count + " FROM public.logger_instance where json->>'"+ key +"' LIKE '%"+ value +"%' " +second_condition+ " and xform_id='"+xform_id+"' " + extra_cond
    elif query_type == 'select one':
        options_query = "SELECT count(json::json->'" + key + "') as " + count + " FROM public.logger_instance where json->>'"+ key +"' = '"+ value +"' " +second_condition+ " and xform_id='"+xform_id+"' " + extra_cond
    cursor = connection.cursor()
    cursor.execute(options_query)
    counter = dictfetchall(cursor)[0][count]
    return counter


def get_percentage(previous, current):
    """
    retruns ( (previous - current) / previous ) * 100 = xx %
    or N/A if arithmetic error occurs.
    """
    if previous == 0 or (type(previous) != long or type(current) != long):
        return 'N/A'
    else:
        percentage = ((current - previous) / (previous * 1.0)) * 100
        percentage = str(percentage) + "%"
    return percentage


def get_viewable_projects(request):
    """
    Returns the list of projects/forms 
    which are created or shared to the currently
    logged in user.
    """
    content_user = get_object_or_404(User, username__iexact=request.user.username)
    form = QuickConverter()
    data = {'form': form}
    content_user = request.user
    all_forms = content_user.xforms.count()
    xforms = XForm.objects.filter(user=content_user)\
        .select_related('user', 'instances')
    user_xforms = xforms
    xfct = ContentType.objects.get(app_label='logger', model='xform')
    xfs = content_user.userobjectpermission_set.filter(content_type=xfct)
    shared_forms_pks = list(set([xf.object_pk for xf in xfs]))
    forms_shared_with = XForm.objects.filter(
        pk__in=shared_forms_pks).exclude(user=content_user)\
        .select_related('user')
    published_or_shared = XForm.objects.filter(
        pk__in=shared_forms_pks).select_related('user')
    xforms_list = [
        {
            'id': 'published',
            'xforms': user_xforms,
            'title': _(u"Published Forms"),
            'small': _("Export, map, and view submissions.")
        },
        {
            'id': 'shared',
            'xforms': forms_shared_with,
            'title': _(u"Shared Forms"),
            'small': _("List of forms shared with you.")
        },
        {
            'id': 'published_or_shared',
            'xforms': published_or_shared,
            'title': _(u"Published Forms"),
            'small': _("Export, map, and view submissions.")
        }
    ]
    
    new_list = []
    for xform_list in xforms_list:
        if xform_list['xforms'] not in new_list:
            new_list.extend(xform_list['xforms'])
    xforms_list = list(set(new_list))
    return xforms_list