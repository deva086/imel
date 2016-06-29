from datetime import datetime,date
from django.contrib.contenttypes.models import ContentType
from django.views.decorators.csrf import csrf_exempt
import os
import json
import pytz
from bson import json_util

from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.files.storage import default_storage
from django.core.files.storage import get_storage_class
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import IntegrityError, connection
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
from rest_framework.decorators import action
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import HttpResponseNotFound
from django.http import HttpResponseRedirect
from django.http import HttpResponseServerError
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from django.shortcuts import render
from django.template import loader, RequestContext
from django.utils.translation import ugettext as _
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
from django.views.decorators.http import require_http_methods
from guardian.shortcuts import assign_perm, remove_perm, get_users_with_perms
from django.db import connection

from onadata.apps.main.forms import UserProfileForm, FormLicenseForm,\
    DataLicenseForm, SupportDocForm, QuickConverterFile, QuickConverterURL,\
    QuickConverter, SourceForm, PermissionForm, MediaForm, MapboxLayerForm,\
    ActivateSMSSupportFom, ExternalExportForm
from onadata.apps.main.models import AuditLog, UserProfile, MetaData, Approveline,Approval
from onadata.apps.logger.models import Instance, XForm
from onadata.apps.logger.views import enter_data
from onadata.apps.viewer.models.data_dictionary import DataDictionary,\
    upload_to
from onadata.apps.viewer.models.parsed_instance import\
    DATETIME_FORMAT, ParsedInstance
from onadata.apps.viewer.views import attachment_url
from onadata.apps.sms_support.tools import check_form_sms_compatibility,\
    is_sms_related
from onadata.apps.sms_support.autodoc import get_autodoc_for
from onadata.apps.sms_support.providers import providers_doc
from onadata.libs.utils.bamboo import get_new_bamboo_dataset,\
    delete_bamboo_dataset, ensure_rest_service
from onadata.libs.utils.decorators import is_owner
from onadata.libs.utils.logger_tools import response_with_mimetype_and_name,\
    publish_form
from onadata.libs.utils.user_auth import add_cors_headers
from onadata.libs.utils.user_auth import check_and_set_user_and_form
from onadata.libs.utils.user_auth import check_and_set_user
from onadata.libs.utils.user_auth import get_xform_and_perms
from onadata.libs.utils.user_auth import has_permission
from onadata.libs.utils.user_auth import has_edit_permission
from onadata.libs.utils.user_auth import helper_auth_helper
from onadata.libs.utils.user_auth import set_profile_data
from onadata.libs.utils.log import audit_log, Actions
from onadata.libs.utils.qrcode import generate_qrcode
from onadata.libs.utils.viewer_tools import enketo_url
from onadata.libs.utils.export_tools import upload_template_for_external_export
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions
from onadata.apps.approval.models.approval import ApprovalDef
from onadata.apps.approval.forms import ApprovalForm
import json
import logging
DEFAULT_CONTENT_LENGTH = getattr(settings, 'DEFAULT_CONTENT_LENGTH', 10000000)


# this is Mongo Collection where we will store the parsed submissions
xform_instances = settings.MONGO_DB.instances
key_whitelist = ['$or', '$and', '$exists', '$in', '$gt', '$gte',
                 '$lt', '$lte', '$regex', '$options', '$all']
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


class ExampleAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        username = request.META.get('X_USERNAME')
        if not username:
            return None
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')
        return (user, None)


def home(request):
    if request.user.username:
        return HttpResponseRedirect(
            reverse(profile, kwargs={'username': request.user.username}))

    return render(request, 'home.html')


@login_required
def login_redirect(request):
    return HttpResponseRedirect(reverse(profile,
                                kwargs={'username': request.user.username}))

# @login_required
# @api_view(['GET'])
# def mobile_login(request, *args, **kwargs):
#     logging.basicConfig(filename='ex.log',level=logging.DEBUG)
#
#     user = authenticate(username=request.user.username, password=request.user.password)
#     if(user is not None):
#       if request.user.is_active:
#         username = request.user.username
#         return HttpResponse('User is valid, active and authenticated', content_type="application/json", status = 200)
#       else:
#         return HttpResponse('The password is valid, but the account has been disabled!', content_type="application/json", status = 402)
#     else:
#         return HttpResponse('The username and password were incorrect' + request.user.password, content_type="application/json", status = 401)
#
#     #logging.info('(main/view.py) User is authenticated..')
#     response_data = {}
#     response_data['result'] = 'error'
#     response_data['message'] = 'Some error message'
#     """
#     response = HttpResponse('Authenticate', mimetype='application/json')
#     add_cors_headers(response)
#     return response
#     """
#
#     #return HttpResponse(json.dumps(response_data), content_type="application/json", headers=get_openrosa_headers())
#     return Response('authenticate', headers=get_openrosa_headers())
#     #values_for_template = {}
#     #return render(request,'404.html',values_for_template,status=404)


@csrf_exempt
def mobile_login(request, *args, **kwargs):
    username = kwargs.get('username')
    password = request.GET.get('password', '')

    user = authenticate(username=username, password=password)
    if user is not None:
        if request.user.is_active:
            return HttpResponse('User is valid, active and authenticated', content_type="application/json", status=200)
        else:
            return HttpResponse('The password is valid, but the account has been disabled!',
                                content_type="application/json", status=200)
    else:
        return HttpResponse('The username and password were incorrect',
                            content_type="application/json", status=401)

    return Response('authenticate', headers=get_openrosa_headers())


def get_openrosa_headers():
      logging.debug('test log-0')
      tz = pytz.timezone(settings.TIME_ZONE)
      dt = datetime.now(tz).strftime('%a, %d %b %Y %H:%M:%S %Z')

      return {
          'Date': dt,
          'X-OpenRosa-Version': '1.0',
          'X-OpenRosa-Accept-Content-Length': DEFAULT_CONTENT_LENGTH
      }

@require_POST
@login_required
def clone_xlsform(request, username):
    """
    Copy a public/Shared form to a users list of forms.
    Eliminates the need to download Excel File and upload again.
    """
    to_username = request.user.username
    message = {'type': None, 'text': '....'}
    message_list = []

    def set_form():
        form_owner = request.POST.get('username')
        id_string = request.POST.get('id_string')
        xform = XForm.objects.get(user__username__iexact=form_owner,
                                  id_string__exact=id_string)
        if len(id_string) > 0 and id_string[0].isdigit():
            id_string = '_' + id_string
        path = xform.xls.name
        if default_storage.exists(path):
            xls_file = upload_to(None, '%s%s.xls' % (
                                 id_string, XForm.CLONED_SUFFIX), to_username)
            xls_data = default_storage.open(path)
            xls_file = default_storage.save(xls_file, xls_data)
            survey = DataDictionary.objects.create(
                user=request.user,
                xls=xls_file
            ).survey
            # log to cloner's account
            audit = {}
            audit_log(
                Actions.FORM_CLONED, request.user, request.user,
                _("Cloned form '%(id_string)s'.") %
                {
                    'id_string': survey.id_string,
                }, audit, request)
            clone_form_url = reverse(
                show, kwargs={
                    'username': to_username,
                    'id_string': xform.id_string + XForm.CLONED_SUFFIX})
            return {
                'type': 'alert-success',
                'text': _(u'Successfully cloned to %(form_url)s into your '
                          u'%(profile_url)s') %
                {'form_url': u'<a href="%(url)s">%(id_string)s</a> ' % {
                 'id_string': survey.id_string,
                 'url': clone_form_url
                 },
                    'profile_url': u'<a href="%s">profile</a>.' %
                    reverse(profile, kwargs={'username': to_username})}
            }

    form_result = publish_form(set_form)
    if form_result['type'] == 'alert-success':
        # comment the following condition (and else)
        # when we want to enable sms check for all.
        # until then, it checks if form barely related to sms
        if is_sms_related(form_result.get('form_o')):
            form_result_sms = check_form_sms_compatibility(form_result)
            message_list = [form_result, form_result_sms]
        else:
            message = form_result
    else:
        message = form_result

    context = RequestContext(request, {
        'message': message, 'message_list': message_list})

    if request.is_ajax():
        res = loader.render_to_string(
            'message.html',
            context_instance=context
        ).replace("'", r"\'").replace('\n', '')

        return HttpResponse(
            "$('#mfeedback').html('%s').show();" % res)
    else:
        return HttpResponse(message['text'])


def profile(request, username):
    content_user = get_object_or_404(User, username__iexact=username)
    form = QuickConverter()
    data = {'form': form}

    # xlsform submission...
    if request.method == 'POST' and request.user.is_authenticated():
        def set_form():
            form = QuickConverter(request.POST, request.FILES)
            survey = form.publish(request.user).survey
            audit = {}
            audit_log(
                Actions.FORM_PUBLISHED, request.user, content_user,
                _("Published form '%(id_string)s'.") %
                {
                    'id_string': survey.id_string,
                }, audit, request)
            enketo_webform_url = reverse(
                enter_data,
                kwargs={'username': username, 'id_string': survey.id_string}
            )
            return {
                'type': 'alert-success',
                'preview_url': reverse(enketo_preview, kwargs={
                    'username': username,
                    'id_string': survey.id_string
                }),
                'text': _(u'Successfully published %(form_id)s.'
                          u' <a href="%(form_url)s">Enter Web Form</a>'
                          u' or <a href="#preview-modal" data-toggle="modal">'
                          u'Preview Web Form</a>')
                % {'form_id': survey.id_string,
                    'form_url': enketo_webform_url},
                'form_o': survey
            }

        form_result = publish_form(set_form)
        if form_result['type'] == 'alert-success':
            # comment the following condition (and else)
            # when we want to enable sms check for all.
            # until then, it checks if form barely related to sms
            if is_sms_related(form_result.get('form_o')):
                form_result_sms = check_form_sms_compatibility(form_result)
                data['message_list'] = [form_result, form_result_sms]
            else:
                data['message'] = form_result
        else:
            data['message'] = form_result

    # profile view...
    # for the same user -> dashboard
    if content_user == request.user:
        show_dashboard = True
        all_forms = content_user.xforms.count()
        form = QuickConverterFile()
        form_url = QuickConverterURL()

        request_url = request.build_absolute_uri(
            "/%s" % request.user.username)
        url = request_url.replace('http://', 'https://')
        xforms = XForm.objects.filter(user=content_user)\
            .select_related('user', 'instances')
        user_xforms = xforms
        # forms shared with user
        xfct = ContentType.objects.get(app_label='logger', model='xform')
        xfs = content_user.userobjectpermission_set.filter(content_type=xfct)
        shared_forms_pks = list(set([xf.object_pk for xf in xfs]))
        forms_shared_with = XForm.objects.filter(
            pk__in=shared_forms_pks).exclude(user=content_user)\
            .select_related('user')
        # all forms to which the user has access
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
        data.update({
            'all_forms': all_forms,
            'show_dashboard': show_dashboard,
            'form': form,
            'form_url': form_url,
            'url': url,
            'user_xforms': user_xforms,
            'xforms_list': xforms_list,
            'forms_shared_with': forms_shared_with
        })
    # for any other user -> profile
    set_profile_data(data, content_user)

    return render(request, "profile.html", data)


def members_list(request):
    if not request.user.is_staff and not request.user.is_superuser:
        return HttpResponseForbidden(_(u'Forbidden.'))
    users = User.objects.all()
    template = 'people.html'

    return render(request, template, {'template': template, 'users': users})


@login_required
def profile_settings(request, username):
    logging.basicConfig(filename='ex.log',level=logging.DEBUG)
    content_user = check_and_set_user(request, username)
    profile, created = UserProfile.objects.get_or_create(user=content_user)
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            logging.basicConfig(filename='ex.log',level=logging.DEBUG)
            logging.info("user : ")
            # get user
            # user.email = cleaned_email
            form.instance.user.email = form.cleaned_data['email']
            form.instance.user.save()
            form.save()
            # todo: add string rep. of settings to see what changed
            audit = {}
            audit_log(
                Actions.PROFILE_SETTINGS_UPDATED, request.user, content_user,
                _("Profile settings updated."), audit, request)
            return HttpResponseRedirect(reverse(
                public_profile, kwargs={'username': request.user.username}
            ))
    else:
        form = UserProfileForm(
            instance=profile, initial={"email": content_user.email})

    return render(request, "settings.html",
                  {'content_user': content_user, 'form': form})


@require_GET
def public_profile(request, username):
    content_user = check_and_set_user(request, username)
    if isinstance(content_user, HttpResponseRedirect):
        return content_user
    data = {}
    set_profile_data(data, content_user)
    data['is_owner'] = request.user == content_user
    audit = {}
    audit_log(
        Actions.PUBLIC_PROFILE_ACCESSED, request.user, content_user,
        _("Public profile accessed."), audit, request)

    return render(request, "profile.html", data)


@login_required
def dashboard(request):
    content_user = request.user
    data = {
        'form': QuickConverter(),
        'content_user': content_user,
        'url': request.build_absolute_uri("/%s" % request.user.username)
    }
    set_profile_data(data, content_user)

    return render(request, "dashboard.html", data)


def redirect_to_public_link(request, uuid):
    xform = get_object_or_404(XForm, uuid=uuid)
    request.session['public_link'] = \
        xform.uuid if MetaData.public_link(xform) else False

    return HttpResponseRedirect(reverse(show, kwargs={
        'username': xform.user.username,
        'id_string': xform.id_string
    }))


def set_xform_owner_data(data, xform, request, username, id_string):
    data['sms_support_form'] = ActivateSMSSupportFom(
        initial={'enable_sms_support': xform.allows_sms,
                 'sms_id_string': xform.sms_id_string})
    if not xform.allows_sms:
        data['sms_compatible'] = check_form_sms_compatibility(
            None, json_survey=json.loads(xform.json))
    else:
        url_root = request.build_absolute_uri('/')[:-1]
        data['sms_providers_doc'] = providers_doc(
            url_root=url_root,
            username=username,
            id_string=id_string)
        data['url_root'] = url_root

    data['form_license_form'] = FormLicenseForm(
        initial={'value': data['form_license']})
    data['data_license_form'] = DataLicenseForm(
        initial={'value': data['data_license']})
    data['doc_form'] = SupportDocForm()
    data['source_form'] = SourceForm()
    data['media_form'] = MediaForm()
    data['mapbox_layer_form'] = MapboxLayerForm()
    data['external_export_form'] = ExternalExportForm()
    users_with_perms = []

    for perm in get_users_with_perms(xform, attach_perms=True).items():
        has_perm = []
        if 'change_xform' in perm[1]:
            has_perm.append(_(u"Can Edit"))
        if 'view_xform' in perm[1]:
            has_perm.append(_(u"Can View"))
        if 'report_xform' in perm[1]:
            has_perm.append(_(u"Can submit to"))
        users_with_perms.append((perm[0], u" | ".join(has_perm)))
    data['users_with_perms'] = users_with_perms
    data['permission_form'] = PermissionForm(username)
    data['users_with_perms'] = users_with_perms
    data['permission_form'] = PermissionForm(username)
    approval_list = ApprovalDef.objects.filter(formid=id_string).order_by('-id')
    data['approve_form'] = ApprovalForm(username)
    data['approval_list'] = approval_list


@require_GET
def show(request, username=None, id_string=None, uuid=None):
    if uuid:
        return redirect_to_public_link(request, uuid)

    xform, is_owner, can_edit, can_view = get_xform_and_perms(
        username, id_string, request)
    # no access
    if not (xform.shared or can_view or request.session.get('public_link')):
        return HttpResponseRedirect(reverse(home))

    data = {}
    data['cloned'] = len(
        XForm.objects.filter(user__username__iexact=request.user.username,
                             id_string__exact=id_string + XForm.CLONED_SUFFIX)
    ) > 0
    data['public_link'] = MetaData.public_link(xform)
    data['is_owner'] = is_owner
    data['can_edit'] = can_edit
    data['can_view'] = can_view or request.session.get('public_link')
    data['xform'] = xform
    data['content_user'] = xform.user
    data['base_url'] = "https://%s" % request.get_host()
    data['source'] = MetaData.source(xform)
    data['form_license'] = MetaData.form_license(xform).data_value
    data['data_license'] = MetaData.data_license(xform).data_value
    data['supporting_docs'] = MetaData.supporting_docs(xform)
    data['media_upload'] = MetaData.media_upload(xform)
    data['mapbox_layer'] = MetaData.mapbox_layer_upload(xform)
    data['external_export'] = MetaData.external_export(xform)

    if is_owner:
        set_xform_owner_data(data, xform, request, username, id_string)

    if xform.allows_sms:
        data['sms_support_doc'] = get_autodoc_for(xform)

    return render(request, "show.html", data)


@require_GET
def api_token(request, username=None):
    user = get_object_or_404(User, username=username)
    data = {}
    data['token_key'], created = Token.objects.get_or_create(user=user)

    return render(request, "api_token.html", data)


@require_http_methods(["GET", "OPTIONS"])
def api(request, username=None, id_string=None):
    """
    Returns all results as JSON.  If a parameter string is passed,
    it takes the 'query' parameter, converts this string to a dictionary, an
    that is then used as a MongoDB query string.

    NOTE: only a specific set of operators are allow, currently $or and $and.
    Please send a request if you'd like another operator to be enabled.

    NOTE: Your query must be valid JSON, double check it here,
    http://json.parser.online.fr/

    E.g. api?query='{"last_name": "Smith"}'
    """
    if request.method == "OPTIONS":
        response = HttpResponse()
        add_cors_headers(response)

        return response
    helper_auth_helper(request)
    helper_auth_helper(request)
    xform, owner = check_and_set_user_and_form(username, id_string, request)

    if not xform:
        return HttpResponseForbidden(_(u'Not shared.'))

    try:
        args = {
            'username': username,
            'id_string': id_string,
            'query': request.GET.get('query'),
            'fields': request.GET.get('fields'),
            'sort': request.GET.get('sort')
        }
        if 'start' in request.GET:
            args["start"] = int(request.GET.get('start'))
        if 'limit' in request.GET:
            args["limit"] = int(request.GET.get('limit'))
        if 'count' in request.GET:
            args["count"] = True if int(request.GET.get('count')) > 0\
                else False
        cursor = ParsedInstance.query_mongo(**args)
    except ValueError as e:
        return HttpResponseBadRequest(e.__str__())

    records = list(record for record in cursor)
    response_text = json_util.dumps(records)

    if 'callback' in request.GET and request.GET.get('callback') != '':
        callback = request.GET.get('callback')
        response_text = ("%s(%s)" % (callback, response_text))

    response = HttpResponse(response_text, content_type='application/json')
    add_cors_headers(response)

    return response


@require_GET
def public_api(request, username, id_string):
    """
    Returns public information about the form as JSON
    """

    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)

    _DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'
    exports = {'username': xform.user.username,
               'id_string': xform.id_string,
               'bamboo_dataset': xform.bamboo_dataset,
               'shared': xform.shared,
               'shared_data': xform.shared_data,
               'downloadable': xform.downloadable,
               'title': xform.title,
               'date_created': xform.date_created.strftime(_DATETIME_FORMAT),
               'date_modified': xform.date_modified.strftime(_DATETIME_FORMAT),
               'uuid': xform.uuid,
               }
    response_text = json.dumps(exports)

    return HttpResponse(response_text, content_type='application/json')


@login_required
def edit(request, username, id_string):
    xform = XForm.objects.get(user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user

    if username == request.user.username or\
            request.user.has_perm('logger.change_xform', xform):
        if request.POST.get('description'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Description for '%(id_string)s' updated from "
                    "'%(old_description)s' to '%(new_description)s'.") %
                {
                    'id_string': xform.id_string,
                    'old_description': xform.description,
                    'new_description': request.POST['description']
                }, audit, request)
            xform.description = request.POST['description']
        elif request.POST.get('title'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Title for '%(id_string)s' updated from "
                    "'%(old_title)s' to '%(new_title)s'.") %
                {
                    'id_string': xform.id_string,
                    'old_title': xform.title,
                    'new_title': request.POST.get('title')
                }, audit, request)
            xform.title = request.POST['title']
        elif request.POST.get('toggle_shared'):
            if request.POST['toggle_shared'] == 'data':
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Data sharing updated for '%(id_string)s' from "
                        "'%(old_shared)s' to '%(new_shared)s'.") %
                    {
                        'id_string': xform.id_string,
                        'old_shared': _("shared")
                        if xform.shared_data else _("not shared"),
                        'new_shared': _("shared")
                        if not xform.shared_data else _("not shared")
                    }, audit, request)
                xform.shared_data = not xform.shared_data
            elif request.POST['toggle_shared'] == 'form':
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Form sharing for '%(id_string)s' updated "
                        "from '%(old_shared)s' to '%(new_shared)s'.") %
                    {
                        'id_string': xform.id_string,
                        'old_shared': _("shared")
                        if xform.shared else _("not shared"),
                        'new_shared': _("shared")
                        if not xform.shared else _("not shared")
                    }, audit, request)
                xform.shared = not xform.shared
            elif request.POST['toggle_shared'] == 'active':
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Active status for '%(id_string)s' updated from "
                        "'%(old_shared)s' to '%(new_shared)s'.") %
                    {
                        'id_string': xform.id_string,
                        'old_shared': _("shared")
                        if xform.downloadable else _("not shared"),
                        'new_shared': _("shared")
                        if not xform.downloadable else _("not shared")
                    }, audit, request)
                xform.downloadable = not xform.downloadable
        elif request.POST.get('form-license'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Form License for '%(id_string)s' updated to "
                    "'%(form_license)s'.") %
                {
                    'id_string': xform.id_string,
                    'form_license': request.POST['form-license'],
                }, audit, request)
            MetaData.form_license(xform, request.POST['form-license'])
        elif request.POST.get('data-license'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Data license for '%(id_string)s' updated to "
                    "'%(data_license)s'.") %
                {
                    'id_string': xform.id_string,
                    'data_license': request.POST['data-license'],
                }, audit, request)
            MetaData.data_license(xform, request.POST['data-license'])
        elif request.POST.get('source') or request.FILES.get('source'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Source for '%(id_string)s' updated to '%(source)s'.") %
                {
                    'id_string': xform.id_string,
                    'source': request.POST.get('source'),
                }, audit, request)
            MetaData.source(xform, request.POST.get('source'),
                            request.FILES.get('source'))
        elif request.POST.get('enable_sms_support_trigger') is not None:
            sms_support_form = ActivateSMSSupportFom(request.POST)
            if sms_support_form.is_valid():
                audit = {
                    'xform': xform.id_string
                }
                enabled = \
                    sms_support_form.cleaned_data.get('enable_sms_support')
                if enabled:
                    audit_action = Actions.SMS_SUPPORT_ACTIVATED
                    audit_message = _(u"SMS Support Activated on")
                else:
                    audit_action = Actions.SMS_SUPPORT_DEACTIVATED
                    audit_message = _(u"SMS Support Deactivated on")
                audit_log(
                    audit_action, request.user, owner,
                    audit_message
                    % {'id_string': xform.id_string}, audit, request)
                # stored previous states to be able to rollback form status
                # in case we can't save.
                pe = xform.allows_sms
                pid = xform.sms_id_string
                xform.allows_sms = enabled
                xform.sms_id_string = \
                    sms_support_form.cleaned_data.get('sms_id_string')
                compat = check_form_sms_compatibility(None,
                                                      json.loads(xform.json))
                if compat['type'] == 'alert-error':
                    xform.allows_sms = False
                    xform.sms_id_string = pid
                try:
                    xform.save()
                except IntegrityError:
                    # unfortunately, there's no feedback mechanism here
                    xform.allows_sms = pe
                    xform.sms_id_string = pid

        elif request.POST.get('media_url'):
            uri = request.POST.get('media_url')
            MetaData.media_add_uri(xform, uri)
        elif request.FILES.get('media'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Media added to '%(id_string)s'.") %
                {
                    'id_string': xform.id_string
                }, audit, request)
            for aFile in request.FILES.getlist("media"):
                MetaData.media_upload(xform, aFile)
        elif request.POST.get('map_name'):
            mapbox_layer = MapboxLayerForm(request.POST)
            if mapbox_layer.is_valid():
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Map layer added to '%(id_string)s'.") %
                    {
                        'id_string': xform.id_string
                    }, audit, request)
                MetaData.mapbox_layer_upload(xform, mapbox_layer.cleaned_data)
        elif request.FILES.get('doc'):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Supporting document added to '%(id_string)s'.") %
                {
                    'id_string': xform.id_string
                }, audit, request)
            MetaData.supporting_docs(xform, request.FILES.get('doc'))
        elif request.POST.get("template_token") \
                and request.POST.get("template_token"):
            template_name = request.POST.get("template_name")
            template_token = request.POST.get("template_token")
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("External export added to '%(id_string)s'.") %
                {
                    'id_string': xform.id_string
                }, audit, request)
            merged = template_name + '|' + template_token
            MetaData.external_export(xform, merged)
        elif request.POST.get("external_url") \
                and request.FILES.get("xls_template"):
            template_upload_name = request.POST.get("template_upload_name")
            external_url = request.POST.get("external_url")
            xls_template = request.FILES.get("xls_template")

            result = upload_template_for_external_export(external_url,
                                                         xls_template)
            status_code = result.split('|')[0]
            token = result.split('|')[1]
            if status_code == '201':
                data_value =\
                    template_upload_name + '|' + external_url + '/xls/' + token
                MetaData.external_export(xform, data_value=data_value)

        xform.update()

        if request.is_ajax():
            return HttpResponse(_(u'Updated succeeded.'))
        else:
            return HttpResponseRedirect(reverse(show, kwargs={
                'username': username,
                'id_string': id_string
            }))

    return HttpResponseForbidden(_(u'Update failed.'))


def getting_started(request):
    template = 'getting_started.html'

    return render(request, 'base.html', {'template': template})


def support(request):
    template = 'support.html'

    return render(request, 'base.html', {'template': template})


def faq(request):
    template = 'faq.html'

    return render(request, 'base.html', {'template': template})


def xls2xform(request):
    template = 'xls2xform.html'

    return render(request, 'base.html', {'template': template})


def tutorial(request):
    template = 'tutorial.html'
    username = request.user.username if request.user.username else \
        'your-user-name'
    url = request.build_absolute_uri("/%s" % username)

    return render(request, 'base.html', {'template': template, 'url': url})


def resources(request):
    if 'fr' in request.LANGUAGE_CODE.lower():
        deck_id = 'a351f6b0a3730130c98b12e3c5740641'
    else:
        deck_id = '1a33a070416b01307b8022000a1de118'

    return render(request, 'resources.html', {'deck_id': deck_id})


def about_us(request):
    a_flatpage = '/about-us/'
    username = request.user.username if request.user.username else \
        'your-user-name'
    url = request.build_absolute_uri("/%s" % username)

    return render(request, 'base.html', {'a_flatpage': a_flatpage, 'url': url})


def privacy(request):
    template = 'privacy.html'

    return render(request, 'base.html', {'template': template})


def tos(request):
    template = 'tos.html'

    return render(request, 'base.html', {'template': template})


def syntax(request):
    template = 'syntax.html'

    return render(request, 'base.html', {'template': template})


def form_gallery(request):
    """
    Return a list of urls for all the shared xls files. This could be
    made a lot prettier.
    """
    data = {}
    if request.user.is_authenticated():
        data['loggedin_user'] = request.user
    data['shared_forms'] = XForm.objects.filter(shared=True)
    # build list of shared forms with cloned suffix
    id_strings_with_cloned_suffix = [
        x.id_string + XForm.CLONED_SUFFIX for x in data['shared_forms']
    ]
    # build list of id_strings for forms this user has cloned
    data['cloned'] = [
        x.id_string.split(XForm.CLONED_SUFFIX)[0]
        for x in XForm.objects.filter(
            user__username__iexact=request.user.username,
            id_string__in=id_strings_with_cloned_suffix
        )
    ]

    return render(request, 'form_gallery.html', data)


def download_metadata(request, username, id_string, data_id):
    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user
    if username == request.user.username or xform.shared:
        data = get_object_or_404(MetaData, pk=data_id)
        file_path = data.data_file.name
        filename, extension = os.path.splitext(file_path.split('/')[-1])
        extension = extension.strip('.')
        dfs = get_storage_class()()
        if dfs.exists(file_path):
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Document '%(filename)s' for '%(id_string)s' downloaded.") %
                {
                    'id_string': xform.id_string,
                    'filename': "%s.%s" % (filename, extension)
                }, audit, request)
            response = response_with_mimetype_and_name(
                data.data_file_type,
                filename, extension=extension, show_date=False,
                file_path=file_path)
            return response
        else:
            return HttpResponseNotFound()

    return HttpResponseForbidden(_(u'Permission denied.'))


@login_required()
def delete_metadata(request, username, id_string, data_id):
    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user
    data = get_object_or_404(MetaData, pk=data_id)
    dfs = get_storage_class()()
    req_username = request.user.username
    if request.GET.get('del', False) and username == req_username:
        try:
            dfs.delete(data.data_file.name)
            data.delete()
            audit = {
                'xform': xform.id_string
            }
            audit_log(
                Actions.FORM_UPDATED, request.user, owner,
                _("Document '%(filename)s' deleted from '%(id_string)s'.") %
                {
                    'id_string': xform.id_string,
                    'filename': os.path.basename(data.data_file.name)
                }, audit, request)
            return HttpResponseRedirect(reverse(show, kwargs={
                'username': username,
                'id_string': id_string
            }))
        except Exception:
            return HttpResponseServerError()
    elif (request.GET.get('map_name_del', False) or
          request.GET.get('external_del', False)) and username == req_username:
        data.delete()
        audit = {
            'xform': xform.id_string
        }
        audit_log(
            Actions.FORM_UPDATED, request.user, owner,
            _("Map layer deleted from '%(id_string)s'.") %
            {
                'id_string': xform.id_string,
            }, audit, request)
        return HttpResponseRedirect(reverse(show, kwargs={
            'username': username,
            'id_string': id_string
        }))

    return HttpResponseForbidden(_(u'Permission denied.'))


def download_media_data(request, username, id_string, data_id):
    xform = get_object_or_404(
        XForm, user__username__iexact=username,
        id_string__exact=id_string)
    owner = xform.user
    data = get_object_or_404(MetaData, id=data_id)
    dfs = get_storage_class()()
    if request.GET.get('del', False):
        if username == request.user.username:
            try:
                # ensure filename is not an empty string
                if data.data_file.name != '':
                    dfs.delete(data.data_file.name)

                data.delete()
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Media download '%(filename)s' deleted from "
                        "'%(id_string)s'.") %
                    {
                        'id_string': xform.id_string,
                        'filename': os.path.basename(data.data_file.name)
                    }, audit, request)
                return HttpResponseRedirect(reverse(show, kwargs={
                    'username': username,
                    'id_string': id_string
                }))
            except Exception as e:
                return HttpResponseServerError(e)
    else:
        if username:  # == request.user.username or xform.shared:
            if data.data_file.name == '' and data.data_value is not None:
                return HttpResponseRedirect(data.data_value)

            file_path = data.data_file.name
            filename, extension = os.path.splitext(file_path.split('/')[-1])
            extension = extension.strip('.')
            if dfs.exists(file_path):
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_UPDATED, request.user, owner,
                    _("Media '%(filename)s' downloaded from "
                        "'%(id_string)s'.") %
                    {
                        'id_string': xform.id_string,
                        'filename': os.path.basename(file_path)
                    }, audit, request)
                response = response_with_mimetype_and_name(
                    data.data_file_type,
                    filename, extension=extension, show_date=False,
                    file_path=file_path)
                return response
            else:
                return HttpResponseNotFound()

    return HttpResponseForbidden(_(u'Permission denied.'))


def form_photos(request, username, id_string):
    xform, owner = check_and_set_user_and_form(username, id_string, request)

    if not xform:
        return HttpResponseForbidden(_(u'Not shared.'))

    data = {}
    data['form_view'] = True
    data['content_user'] = owner
    data['xform'] = xform
    image_urls = []

    for instance in xform.instances.all():
        for attachment in instance.attachments.all():
            # skip if not image e.g video or file
            if not attachment.mimetype.startswith('image'):
                continue

            data = {}

            for i in ['small', 'medium', 'large', 'original']:
                url = reverse(attachment_url, kwargs={'size': i})
                url = '%s?media_file=%s' % (url, attachment.media_file.name)
                data[i] = url

            image_urls.append(data)

    data['images'] = image_urls
    data['profilei'], created = UserProfile.objects.get_or_create(user=owner)

    return render(request, 'form_photos.html', data)


@require_POST
def set_approval(request, username, id_string):
    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user
    if username != request.user.username\
            and not has_permission(xform, username, request):
        return HttpResponseForbidden(_(u'Permission denied.'))
    try:
        approval = Approveline()
        approval.userid = request.POST['approver']
        approval.label = request.POST['label_type']
        approval.formid = id_string
        approval_type = request.POST['approval_type']
    except KeyError:
        return HttpResponseBadRequest()

    if approval_type == 'add' and has_no_approval(request, approval, obj=None):
        approval.save()
    elif approval_type == 'remove':
        approval_list = Approveline.objects.filter(userid=approval.userid)
        for approve in approval_list:
            approve.delete()

    return HttpResponseRedirect(reverse(show, kwargs={
        'username': username,
        'id_string': id_string
    }))


def has_no_approval(self, approval, obj=None):
    logging.basicConfig(filename='my.log',level=logging.DEBUG)
    #approvalline = Approveline.objects.raw('SELECT COUNT(*) FROM models_approveline WHERE userid = %s and formid = %s', [approval.userid, approval.formid])
    approvalline = Approveline.objects.filter(userid=approval.userid, formid=approval.formid)
    if approvalline is not None and approvalline.count() > 0:
        #logging.info('approvalSize : '+approvalline.count() + ' where userid :' + approval.userid + ' formid : ' + approval.formid)
        return False
    else:
        return True


@require_POST
def set_perm(request, username, id_string):
    logging.basicConfig(filename='ex.log',level=logging.DEBUG)

    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user
    if username != request.user.username\
            and not has_permission(xform, username, request):
        return HttpResponseForbidden(_(u'Permission denied.'))

    try:
        perm_type = request.POST['perm_type']
        for_user = request.POST['for_user']

    except KeyError:
        return HttpResponseBadRequest()
    logging.info('(apps/main/views.py) permtype: ' + perm_type)

    if perm_type in ['edit', 'view', 'report', 'remove']:
        try:
            user = User.objects.get(username=for_user)
            if user.has_perm('view_xform', xform):
                logging.info('(apps/main/views.py) _User_already has permission')
        except User.DoesNotExist:
            messages.add_message(
                request, messages.INFO,
                _(u"Wrong username <b>%s</b>." % for_user),
                extra_tags='alert-error')
        else:
            if perm_type == 'edit' and\
                    not user.has_perm('change_xform', xform):
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_PERMISSIONS_UPDATED, request.user, owner,
                    _("Edit permissions on '%(id_string)s' assigned to "
                        "'%(for_user)s'.") %
                    {
                        'id_string': xform.id_string,
                        'for_user': for_user
                    }, audit, request)
                assign_perm('change_xform', user, xform)
            elif perm_type == 'view' and\
                    not user.has_perm('view_xform', xform):
                logging.info('(apps/main/views.py) Setting perms...')
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_PERMISSIONS_UPDATED, request.user, owner,
                    _("View permissions on '%(id_string)s' "
                        "assigned to '%(for_user)s'.") %
                    {
                        'id_string': xform.id_string,
                        'for_user': for_user
                    }, audit, request)
                logging.info('(apps/main/views.py) setting perms, where id = ' + xform.id_string)
                assign_perm('view_xform', user, xform)
            elif perm_type == 'report' and\
                    not user.has_perm('report_xform', xform):
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_PERMISSIONS_UPDATED, request.user, owner,
                    _("Report permissions on '%(id_string)s' "
                        "assigned to '%(for_user)s'.") %
                    {
                        'id_string': xform.id_string,
                        'for_user': for_user
                    }, audit, request)
                assign_perm('report_xform', user, xform)
            elif perm_type == 'remove':
                audit = {
                    'xform': xform.id_string
                }
                audit_log(
                    Actions.FORM_PERMISSIONS_UPDATED, request.user, owner,
                    _("All permissions on '%(id_string)s' "
                        "removed from '%(for_user)s'.") %
                    {
                        'id_string': xform.id_string,
                        'for_user': for_user
                    }, audit, request)
                remove_perm('change_xform', user, xform)
                remove_perm('view_xform', user, xform)
                remove_perm('report_xform', user, xform)
    elif perm_type == 'link':
        current = MetaData.public_link(xform)
        if for_user == 'all':
            MetaData.public_link(xform, True)
        elif for_user == 'none':
            MetaData.public_link(xform, False)
        elif for_user == 'toggle':
            MetaData.public_link(xform, not current)
        audit = {
            'xform': xform.id_string
        }
        audit_log(
            Actions.FORM_PERMISSIONS_UPDATED, request.user, owner,
            _("Public link on '%(id_string)s' %(action)s.") %
            {
                'id_string': xform.id_string,
                'action': "created"
                if for_user == "all" or
                (for_user == "toggle" and not current) else "removed"
            }, audit, request)

    if request.is_ajax():
        return HttpResponse(
            json.dumps(
                {'status': 'success'}), content_type='application/json')

    return HttpResponseRedirect(reverse(show, kwargs={
        'username': username,
        'id_string': id_string
    }))


@require_POST
@login_required
def delete_data(request, username=None, id_string=None):
    xform, owner = check_and_set_user_and_form(username, id_string, request)
    response_text = u''
    if not xform or not has_edit_permission(
        xform, owner, request, xform.shared
    ):
        return HttpResponseForbidden(_(u'Not shared.'))

    data_id = request.POST.get('id')
    if not data_id:
        return HttpResponseBadRequest(_(u"id must be specified"))

    Instance.set_deleted_at(data_id)

    logging.info('mPower:formid = ' + id_string + ' userid = ' + username + ' subbmissionid = ' + data_id)
    approval = Approval.objects.filter(formid=id_string,userid= username,subbmissionid=data_id,status="Pending")[0]
    approval.status = "Deleted"
    approval.save(update_fields=['status'])
    audit = {
        'xform': xform.id_string
    }
    audit_log(
        Actions.SUBMISSION_DELETED, request.user, owner,
        _("Deleted submission with id '%(record_id)s' "
            "on '%(id_string)s'.") %
        {
            'id_string': xform.id_string,
            'record_id': data_id
        }, audit, request)
    response_text = json.dumps({"success": "Deleted data %s" % data_id})
    if 'callback' in request.GET and request.GET.get('callback') != '':
        callback = request.GET.get('callback')
        response_text = ("%s(%s)" % (callback, response_text))

    return HttpResponse(response_text, content_type='application/json')


@require_POST
@is_owner
def link_to_bamboo(request, username, id_string):
    xform = get_object_or_404(XForm,
                              user__username__iexact=username,
                              id_string__exact=id_string)
    owner = xform.user
    audit = {
        'xform': xform.id_string
    }

    # try to delete the dataset first (in case it exists)
    if xform.bamboo_dataset and delete_bamboo_dataset(xform):
        xform.bamboo_dataset = u''
        xform.save()
        audit_log(
            Actions.BAMBOO_LINK_DELETED, request.user, owner,
            _("Bamboo link deleted on '%(id_string)s'.")
            % {'id_string': xform.id_string}, audit, request)

    # create a new one from all the data
    dataset_id = get_new_bamboo_dataset(xform)

    # update XForm
    xform.bamboo_dataset = dataset_id
    xform.save()
    ensure_rest_service(xform)

    audit_log(
        Actions.BAMBOO_LINK_CREATED, request.user, owner,
        _("Bamboo link created on '%(id_string)s'.") %
        {
            'id_string': xform.id_string,
        }, audit, request)

    return HttpResponseRedirect(reverse(show, kwargs={
        'username': username,
        'id_string': id_string
    }))


@require_POST
@is_owner
def update_xform(request, username, id_string):
    xform = get_object_or_404(
        XForm, user__username__iexact=username, id_string__exact=id_string)
    owner = xform.user

    def set_form():
        form = QuickConverter(request.POST, request.FILES)
        survey = form.publish(request.user, id_string).survey
        enketo_webform_url = reverse(
            enter_data,
            kwargs={'username': username, 'id_string': survey.id_string}
        )
        audit = {
            'xform': xform.id_string
        }
        audit_log(
            Actions.FORM_XLS_UPDATED, request.user, owner,
            _("XLS for '%(id_string)s' updated.") %
            {
                'id_string': xform.id_string,
            }, audit, request)
        return {
            'type': 'alert-success',
            'text': _(u'Successfully published %(form_id)s.'
                      u' <a href="%(form_url)s">Enter Web Form</a>'
                      u' or <a href="#preview-modal" data-toggle="modal">'
                      u'Preview Web Form</a>')
                    % {'form_id': survey.id_string,
                       'form_url': enketo_webform_url}
        }
    message = publish_form(set_form)
    messages.add_message(
        request, messages.INFO, message['text'], extra_tags=message['type'])

    return HttpResponseRedirect(reverse(show, kwargs={
        'username': username,
        'id_string': id_string
    }))


@is_owner
def activity(request, username):
    owner = get_object_or_404(User, username=username)

    return render(request, 'activity.html', {'user': owner})


def activity_fields(request):
    fields = [
        {
            'id': 'created_on',
            'label': _('Performed On'),
            'type': 'datetime',
            'searchable': False
        },
        {
            'id': 'action',
            'label': _('Action'),
            'type': 'string',
            'searchable': True,
            'options': sorted([Actions[e] for e in Actions.enums])
        },
        {
            'id': 'user',
            'label': 'Performed By',
            'type': 'string',
            'searchable': True
        },
        {
            'id': 'msg',
            'label': 'Description',
            'type': 'string',
            'searchable': True
        },
    ]
    response_text = json.dumps(fields)

    return HttpResponse(response_text, content_type='application/json')


@is_owner
def activity_api(request, username):
    from bson.objectid import ObjectId

    def stringify_unknowns(obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.strftime(DATETIME_FORMAT)
        return None

    try:
        query_args = {
            'username': username,
            'query': json.loads(request.GET.get('query'))
            if request.GET.get('query') else {},
            'fields': json.loads(request.GET.get('fields'))
            if request.GET.get('fields') else [],
            'sort': json.loads(request.GET.get('sort'))
            if request.GET.get('sort') else {}
        }
        if 'start' in request.GET:
            query_args["start"] = int(request.GET.get('start'))
        if 'limit' in request.GET:
            query_args["limit"] = int(request.GET.get('limit'))
        if 'count' in request.GET:
            query_args["count"] = True \
                if int(request.GET.get('count')) > 0 else False
        cursor = AuditLog.query_mongo(**query_args)
    except ValueError as e:
        return HttpResponseBadRequest(e.__str__())

    records = list(record for record in cursor)
    response_text = json.dumps(records, default=stringify_unknowns)
    if 'callback' in request.GET and request.GET.get('callback') != '':
        callback = request.GET.get('callback')
        response_text = ("%s(%s)" % (callback, response_text))

    return HttpResponse(response_text, content_type='application/json')


def qrcode(request, username, id_string):
    try:
        formhub_url = "http://%s/" % request.META['HTTP_HOST']
    except:
        formhub_url = "http://formhub.org/"
    formhub_url = formhub_url + username

    if settings.TESTING_MODE:
        formhub_url = "https://{}/{}".format(settings.TEST_HTTP_HOST,
                                             settings.TEST_USERNAME)

    results = _(u"Unexpected Error occured: No QRCODE generated")
    status = 200
    try:
        url = enketo_url(formhub_url, id_string)
    except Exception as e:
        error_msg = _(u"Error Generating QRCODE: %s" % e)
        results = """<div class="alert alert-error">%s</div>""" % error_msg
        status = 400
    else:
        if url:
            image = generate_qrcode(''.join((url, '#qr')))
            results = """<img class="qrcode" src="%s" alt="%s" />
                    </br><a href="%s" target="_blank">%s</a>""" \
                % (image, url, url, url)
        else:
            status = 400

    return HttpResponse(results, content_type='text/html', status=status)


def enketo_preview(request, username, id_string):
    xform = get_object_or_404(
        XForm, user__username__iexact=username, id_string__exact=id_string)
    owner = xform.user
    if not has_permission(xform, owner, request, xform.shared):
        return HttpResponseForbidden(_(u'Not shared.'))
    enekto_preview_url = \
        "%(enketo_url)s?server=%(profile_url)s&id=%(id_string)s" % {
            'enketo_url': settings.ENKETO_PREVIEW_URL,
            'profile_url': request.build_absolute_uri(
                reverse(profile, kwargs={'username': owner.username})),
            'id_string': xform.id_string
        }
    return HttpResponseRedirect(enekto_preview_url)


@require_GET
@login_required
def username_list(request):
    data = []
    query = request.GET.get('query', None)
    if query:
        users = User.objects.values('username')\
            .filter(username__startswith=query, is_active=True, pk__gte=0)
        data = [user['username'] for user in users]

    return HttpResponse(json.dumps(data), content_type='application/json')


@login_required
def data_list(request,username):
    template = 'data.html'
    coloumn = 'status'
    value = 'value'
    count = 'count'
    default_value = 'N/A'
    all_forms = []
    # KOBOCAT_REPORT_FORM_ID gets the form id set from environment variable 
    # environment variable script location: scripts/01_environment_vars.sh
    # KOBOCAT_REPORT_FORM_ID variable used in mongo queries
    KOBOCAT_REPORT_FORM_ID = os.environ.get('KOBOCAT_REPORT_FORM_ID')
    # form_id_string is used in postges queries
    form_id_string = "'" + KOBOCAT_REPORT_FORM_ID + "'"
    # First Form
    cursor = connection.cursor()

    
    from_date = "2010-01-01"
    to_date = "2115-09-08T08:15:10"
    if request.method == 'POST':
        from_date = request.POST['start_date']
        to_date = request.POST['end_date']
    # Gets list of approved data 
    approved_data_query = "SELECT subbmissionid FROM models_approval where formid="+ form_id_string +" and status='Approved'"
    cursor.execute(approved_data_query)
    approved_data_id_dictionary = dictfetchall(cursor)
    approved_data_id_list = []
    for approved_data_id in approved_data_id_dictionary:
        approved_data_id_list.append(int(approved_data_id["subbmissionid"]))
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Are_there_changes_in_the_clima",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Are_there_changes_in_the_clima",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->1->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->1->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are there changes in the climate that you observed since 2012?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->2->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->2->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think the cold months are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_the_cold_months_a_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_the_cold_months_a_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->3->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->3->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think the hot months are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_rainfall_is",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_rainfall_is",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->4->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->4->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think rainfall is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->5->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->5->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think intensity of rain is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->6->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->6->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think the rainy season is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->7->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->7->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think the dry season is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->8->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->8->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Change in season is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->9->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->9->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Supply of potable water is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->10->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->10->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Supply of water for irrigation is"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->11->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->11->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you feel floods are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->12->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->12->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you feel floods are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->13->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->13->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you feel landslides are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->14->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->14->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you feel dry spells are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_intensity_of_rain_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->15->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->15->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you feel dry spells are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Where_do_you_source_info_about",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Where_do_you_source_info_about",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->16->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->16->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Where do you source info about the weather?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Are_you_aware_of_climate_chang",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Are_you_aware_of_climate_chang",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->18->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->18->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are you aware of climate change?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Which_one_of_the_following_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Which_one_of_the_following_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->20->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->20->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Which one of the following has the most impact on the climate?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Does_climate_change_have_any_e",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Does_climate_change_have_any_e",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->22->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->22->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Does climate change have any effect on your livelihood?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$My_harvest_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$My_harvest_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->24->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->24->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "My harvest has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Was_this_change_due_to",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Was_this_change_due_to",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->25->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->25->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Was this change due to"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$The_number_of_cropping_per_yea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$The_number_of_cropping_per_yea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->27->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->27->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "The number of cropping per year has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_did_you_do_to_adapt_your_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_did_you_do_to_adapt_your_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->28->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->28->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What did you do to adapt your farm management to these changes?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Does_climate_change_have_effec",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Does_climate_change_have_effec",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->30->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->30->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Does climate change have effect on your household?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Exposure_to_risk_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Exposure_to_risk_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->32->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->32->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Exposure to risk has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Water_collection_has_become",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Water_collection_has_become",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->33->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->33->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Water collection has become"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Children_s_access_to_school_ha",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Children_s_access_to_school_ha",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->34->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->34->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Children's access to school has become"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_did_you_do_to_ensure_safe",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_did_you_do_to_ensure_safe",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->36->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->36->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What did you do to ensure safety for these changes?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Which_one_of_the_following_has_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Which_one_of_the_following_has_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->39->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->39->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Which one of the following has the most impact on the community adaptation?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_participate_in_any_of_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_participate_in_any_of_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->41->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->41->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you participate in any of the PCVAs?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_role_or_roles_did_you_hav",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_role_or_roles_did_you_hav",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->42->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->42->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What role or roles did you have in the PCVAs?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_that_the_output_o",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_that_the_output_o",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->43->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->43->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think that the output of the PCVA was useful to you and your community?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_was_the_most_recent_natur",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_was_the_most_recent_natur",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->45->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->45->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What was the most recent natural disaster you experienced?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Was_your_livelihood_affected_b",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Was_your_livelihood_affected_b",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->46->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->46->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Was your livelihood affected by this disaster?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$How_long_before_you_were_able_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$How_long_before_you_were_able_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->47->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->47->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "How long before you were able to recover from its effects ?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_think_that_it_took_you_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_think_that_it_took_you_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->49->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->49->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you think that it took you a long time to recover from its effects?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_do_you_think_were_the_rea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_do_you_think_were_the_rea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->50->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->50->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What do you think were the reasons why it took you a long time to recover?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Were_you_able_to_attend_the_fi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Were_you_able_to_attend_the_fi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->51->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->51->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Were you able to attend the field school?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Were_you_able_to_complete_it",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Were_you_able_to_complete_it",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->52->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->52->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Were you able to complete it?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_training_have_you_partici",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_training_have_you_partici",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->53->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->53->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What training have you participated in?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_training_have_you_partici_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_training_have_you_partici_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->55->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->55->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What technology have you applied in your farm?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->57->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->57->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on upland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->61->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->61->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->62->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->62->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->63->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->63->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on irrigated lowland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->67->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->67->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->68->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->68->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->69->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->69->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on rainfed lowland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->73->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->73->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->74->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->74->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->75->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->75->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on fruit trees?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->79->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->79->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->80->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->80->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->81->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->81->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on coconut?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->85->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->85->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->86->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->86->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->87->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->87->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on cassava?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->91->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->91->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_0",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_0",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->92->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->92->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->93->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->93->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on vegetables?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->97->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->97->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->98->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->98->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->99->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->99->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on banana?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->103->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->103->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->104->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->104->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->105->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->105->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on coffee?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->109->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->109->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->110->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->110->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_015",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_015",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->111->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->111->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on rubber?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->115->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->115->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_001_001_001_0_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->116->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->116->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->117->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->117->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you apply it on other crops?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_cost_of_production_00_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_cost_of_production_00_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->122->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->122->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_your_harvest_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_your_harvest_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->123->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->123->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_have_a_farm_plan",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_have_a_farm_plan",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->124->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->124->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you have a farm plan"    
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->126->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->126->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is upland rice in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->127->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->127->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->129->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->129->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->131->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->131->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is irrigated low land rice in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->132->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->132->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->134->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->134->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->136->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->136->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is corn in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->137->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->137->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->139->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->139->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->141->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->141->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is banana in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->142->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->142->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->144->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->144->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->146->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->146->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are vegetables in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->147->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->147->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->149->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->149->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->151->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->151->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are rootcrops in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->152->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->152->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->154->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->154->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->156->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->156->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is coconut in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->157->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->157->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->159->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->159->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_016",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_016",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->161->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->161->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are fruits in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_015",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_015",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->162->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->162->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->164->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->164->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->166->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->166->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is coffee in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->167->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->167->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->169->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->169->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->171->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->171->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is rubber in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->172->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->172->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->174->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->174->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->176->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->176->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are there other crops in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->178->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->178->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->180->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->180->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->182->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->182->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are hogs in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->183->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->183->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->185->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->185->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_011",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_011",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->187->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->187->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is cattle in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_011",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_011",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->188->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->188->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->190->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->190->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_012",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_012",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->192->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->192->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are ducks in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_012",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_012",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->193->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->193->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->195->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->195->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->197->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->197->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are fish in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->198->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->198->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->200->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->200->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_upland_rice_in_your_farmpla_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->201->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->201->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are there other animals in your farmplan?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Is_this_a_new_source_of_income_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Is_this_a_new_source_of_income_014",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->203->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->203->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Is this a new source of income?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_you_make_a_profit_001_001__009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_you_make_a_profit_001_001__009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->205->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->205->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did you make a profit?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_were_the_challenges_in_pl",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_were_the_challenges_in_pl",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->207->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->207->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What were the challenges in planting a new crop or raising animals?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Would_you_say_that_these_measu",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Would_you_say_that_these_measu",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->210->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->210->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Would you say that these measures are"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Are_you_a_member_of_any_organi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Are_you_a_member_of_any_organi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->211->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->211->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are you a member of any organization?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->212->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->212->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to a neighborhood association?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->215->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->215->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->216->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->216->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to a farmer's association?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->219->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->219->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->220->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->220->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to a faith based association?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->223->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->223->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->224->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->224->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to a co-operative?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->227->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->227->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->228->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->228->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to a political organization?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->231->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->231->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_belong_to_a_neighborhoo_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->232->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->232->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you belong to any other type of organization?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_position_do_you_currently_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_position_do_you_currently_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->235->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->235->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What position do you currently hold?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$As_a_result_of_being_a_member_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$As_a_result_of_being_a_member_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->237->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->237->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "As a result of being a member of an organisation, do you feel"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_sell_to_the_local_marke",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_sell_to_the_local_marke",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->238->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->238->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you sell to the local market?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_get_your_desired_price",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_get_your_desired_price",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->239->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->239->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you get your desired price?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_sell_to_the_traders",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_sell_to_the_traders",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->240->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->240->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you sell to the traders?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_get_your_desired_price_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_get_your_desired_price_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->241->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->241->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you get your desired price there?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_sell_directly_to_consum",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_sell_directly_to_consum",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->242->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->242->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you sell directly to consumers?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_get_your_desired_price__001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_get_your_desired_price__001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->243->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->243->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you get your desired price there?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_sell_to_associations_or",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_sell_to_associations_or",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->244->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->244->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you sell to associations or cooperatives?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_get_your_desired_price__002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_get_your_desired_price__002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->245->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->245->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you get your desired price there?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_have_access_to_price_in",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_have_access_to_price_in",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->246->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->246->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you have access to price information of goods sold at the local market?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$How_would_you_rate_your_satisf",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$How_would_you_rate_your_satisf",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->247->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->247->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "How would you rate your satisfaction with access to market for your produce?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_you_or_the_group_you_belong",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_you_or_the_group_you_belong",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->248->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->248->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do you or the group you belong to have access to the following business or enterprise development services:"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Did_female_members_of_your_hou",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Did_female_members_of_your_hou",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->250->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->250->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Did female members of your household engage in livelihood activities 12 months ago?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Please_identify_the_livelihood",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Please_identify_the_livelihood",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->251->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->251->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Please identify the livelihood activities"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_factors_lead_to_female_co",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_factors_lead_to_female_co",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->254->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->254->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What factors lead to female contribution to productive livelihood activities?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Do_female_adults_in_the_family",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Do_female_adults_in_the_family",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->256->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->256->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Do female adults in the family have time for leisure and rest?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Are_you_satisfied_with_the_tim",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Are_you_satisfied_with_the_tim",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->259->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->259->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are you satisfied with the time female adults in your household spend for leisure and rest?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$In_your_household_who_is_the_p",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$In_your_household_who_is_the_p",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->260->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->260->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "In your household who is the primary caregiver?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Has_the_role_of_the_primary_ca",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Has_the_role_of_the_primary_ca",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->262->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->262->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Has the role of the primary caregiver changed since we last spoke?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$What_has_your_organization_don",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$What_has_your_organization_don",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->266->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->266->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "What has your organization done to ensure Local Government Units support care work innovation?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_xform_id_string": KOBOCAT_REPORT_FORM_ID} },{"$group": {"_id": "$Are_you_confident_that_the_loc",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":KOBOCAT_REPORT_FORM_ID } },{"$group": {"_id": "$Are_you_confident_that_the_loc",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->267->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->267->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id_string="+ form_id_string
    question = "Are you confident that the local government unit will invest more on basic social services?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    
    dict_landsize = {}
    dict_landsize["Upland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo")
    dict_landsize["Irrigated Lowland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_001")
    dict_landsize["Rainfed Lowland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_002")
    dict_landsize["Fruit Trees"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_003")
    dict_landsize["Coconut"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_004")
    dict_landsize["Cassava"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_005")
    dict_landsize["Vegetables"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_006")
    dict_landsize["Banana"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_007")
    dict_landsize["Coffee"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_008")
    dict_landsize["Rubber"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_009")
    dict_landsize["Other Crops"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_the_size_of_land_devo_010")

    dict_production_cost = {}
    dict_production_cost["Upland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti")
    dict_production_cost["Irrigated Lowland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_001")
    dict_production_cost["Rainfed Lowland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_002")
    dict_production_cost["Fruit Trees"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_003")
    dict_production_cost["Coconut"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_004")
    dict_production_cost["Cassava"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_005")
    dict_production_cost["Vegetables"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_006")
    dict_production_cost["Banana"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_007")
    dict_production_cost["Coffee"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_008")
    dict_production_cost["Rubber"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_009")
    dict_production_cost["Other Crops"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"What_was_your_cost_of_producti_010")

    dict_avg_net_income = {}
    dict_avg_net_income["Upland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question")
    dict_avg_net_income["Irrigated Lowland Rice"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001")
    dict_avg_net_income["Corn"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001")
    dict_avg_net_income["Banana"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001")
    dict_avg_net_income["Vegetables"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001")
    dict_avg_net_income["rootcrops"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_001")
    dict_avg_net_income["Coconut"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0")
    dict_avg_net_income["Fruits"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_010")
    dict_avg_net_income["Coffee"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_001")
    dict_avg_net_income["Rubber"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_002")
    dict_avg_net_income["Other Crops"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_003")
    dict_avg_net_income["Hogs"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_004")
    dict_avg_net_income["Cattle"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_005")
    dict_avg_net_income["Ducks"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_006")
    # missing in current form
    # dict_production_cost["Fish"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_007")
    dict_avg_net_income["Other Animals"] = get_average(KOBOCAT_REPORT_FORM_ID,approved_data_id_list,from_date,to_date,"New_Question_001_001_001_001_0_008")
    #====================================================================================================
    survey = Survey(all_forms)

    return render(request, template, {'template': template,'survey':survey,"dict_landsize":dict_landsize,"dict_production_cost":dict_production_cost,"dict_avg_net_income":dict_avg_net_income})

def get_average(form_id,approved_data_id_list,from_date,to_date,key):
    land_size = xform_instances.find({"_id":{ "$in": approved_data_id_list },"_submission_time": { "$gte": from_date, "$lte": to_date },"_xform_id_string":form_id, key : { "$ne" : "null" }},{ key:1 })
    avg_counter = 0 
    sum_of_values = 0
    list__ = []
    for d in land_size:
        list__.append(d)
    for a in list__:
        try:
            sum_of_values += float(a[key])
            avg_counter += 1   
        except KeyError:    
            pass

    if avg_counter == 0:
        average = "N/A"
    else:
        average = "{0:.2f}".format( (sum_of_values/ (avg_counter*1.0)))
    return average


def response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value):
    cursor = connection.cursor()
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    cursor.execute(options_query)
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    options_list = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list.append(options)
    form = Form(question,options_list)
    all_forms.append(form)


def get_dictionary(results,labels,coloumn,value,count,default_value):
    dictionary = {}
    total = 0 ;
    for label in labels:
        for result in results:
            if label[coloumn] == result.status:
                dictionary[label[value]] = result.count
                total += result.count

    for label in labels:
        if label[value] not in dictionary:
            dictionary[label[value]] = default_value
        else:
            dictionary[label[value]] = "{0:.2f}".format( (dictionary[label[value]]/ (total*1.0))*100 ) + "%"
    return dictionary


def dictfetchall(cursor):
    "Returns all rows from a cursor as a dict"
    desc = cursor.description
    return [
        dict(zip([col[0] for col in desc], row))
        for row in cursor.fetchall()
    ]

def dictmongo(cursor):
    "Returns all rows from a cursor as a dict"
    value_list = []
    for key in cursor['result']:
        value_list.append(keyVal(key['_id'],key['count']))
    return value_list



class Survey(object):
    def __init__(self,datalist):
        self.datalist = datalist


class Form(object):
    def __init__(self,question,options_list):
        self.question = question
        self.options_list= options_list


class Options(object):
    def __init__(self,property,quarterly_value = "N/A",lifetime_value = "N/A"):
        self.property = property
        self.quarterly_value = quarterly_value
        self.lifetime_value = lifetime_value

class keyVal(object):
    def __init__(self,status = "status",count="N/A"):
        self.status = status
        self.count = count


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
