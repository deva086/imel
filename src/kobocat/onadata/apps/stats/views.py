from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext
from django.shortcuts import render
from onadata.apps.main.models import Approveline,Approval
from onadata.apps.logger.models import XForm
from onadata.apps.stats.utils import get_form_submissions_per_day
from django.http import HttpResponse
import logging
import json

@login_required
def stats(request, username=None, id_string=None):
    if id_string:
        xform = get_object_or_404(
            XForm, user=request.user, id_string__exact=id_string)
        data = {
            'xform': xform,
            'context.submission_stats': get_form_submissions_per_day(xform)
        }
    else:
        data = {'xforms': XForm.objects.filter(user=request.user)}
    return render(request, 'form-stats.html', data)


@staff_member_required
def submissions(request):
    stats = {}
    stats['submission_count'] = {}
    stats['submission_count']['total_submission_count'] = 0
    logging.basicConfig(filename='ex.log',level=logging.DEBUG) 
    users = User.objects.all()

    logging.info(users)
    for user in users:
        stats['submission_count'][user.username] = 0
        stats['submission_count'][user.username] += user.instances.count()
        logging.info(user.instances.count())
        stats['submission_count'][
            'total_submission_count'] += user.instances.count()

    return render(request, "submissions.html", {'stats': stats})


#@staff_member_required
@login_required
def pending_approval(request):
    context = RequestContext(request)
    logging.basicConfig(filename='ex.log',level=logging.DEBUG)
    approvals = Approval.objects.filter(userid=request.user.username,status='Pending')
    logging.info("get:")
    logging.info(approvals)
    context.approvals = approvals
    #return render_to_response("pending-approval.html", context_instance=context)
    return render(request, "pending-approval.html", {'approvals': approvals})

def data_approval_list(request):
    form_id = request.POST.get('formid');
    xform = get_object_or_404(XForm, id_string__exact=form_id)
    response_data = {'submission_id': request.POST.get('submissionid'), 'form_id': request.POST.get('formid'),
                     'form_owner': xform.user.username}
    return HttpResponse(json.dumps(response_data), content_type="application/json")
