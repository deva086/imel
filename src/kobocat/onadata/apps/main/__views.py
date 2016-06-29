from datetime import datetime
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
    ActivateSMSSupportFom, ExternalExportForm,ApprovalForm
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
    approval_list = Approveline.objects.order_by('-id')[:5]
    data['users_with_perms'] = users_with_perms
    data['permission_form'] = PermissionForm(username)
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
        approval.userid = request.POST['for_user']
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
    form_id = "5"
    # First Form
    cursor = connection.cursor()

    
    from_date = "2010-01-01"
    to_date = "2115-09-08T08:15:10"
    if request.method == 'POST':
        from_date = request.POST['start_date']
        to_date = request.POST['end_date']
    # gets values for climate change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Are_there_changes_in_the_clima",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Are_there_changes_in_the_clima",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for climate change
    # cursor.execute("SELECT json_array_elements(json::json->'children'->0->'children')->'name' AS  " + coloumn + " FROM public.logger_xform where id = 4")
    cursor.execute("SELECT json_array_elements(json::json->'children'->1->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->1->'children')->'label' AS "+ value + " FROM public.logger_xform where id = 4")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question3 = "Are there changes in the climate that you observed since 2012?"
    options_list3 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list3.append(options)

    form3 = Form(question3,options_list3)
    # all_forms.append(form3)


    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->2->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->2->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question5 = "Do you think the cold months are"
    options_list5 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list5.append(options)

    form5 = Form(question5,options_list5)
    all_forms.append(form5)

    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_the_cold_months_a_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->3->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->3->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question6 = "Do you think the hot months are"
    options_list6 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list6.append(options)

    form6 = Form(question6,options_list6)
    all_forms.append(form6)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_rainfall_is",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_rainfall_is",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->4->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->4->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question7 = "Do you think rainfall is"
    options_list7 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list7.append(options)

    form7 = Form(question7,options_list7)
    all_forms.append(form7)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->5->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->5->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question8 = "Do you think intensity of rain is"
    options_list8 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list8.append(options)

    form8 = Form(question8,options_list8)
    all_forms.append(form8)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->6->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->6->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question9 = "Do you think the rainy season is"
    options_list9 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list9.append(options)

    form9 = Form(question9,options_list9)
    all_forms.append(form9)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->7->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->7->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question10 = "Do you think the dry season is"
    options_list10 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list10.append(options)

    form10 = Form(question10,options_list10)
    all_forms.append(form10)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->8->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->8->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question11 = "Change in season is"
    options_list11 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list11.append(options)

    form11 = Form(question11,options_list11)
    all_forms.append(form11)
    #====================================================================================================
    # gets values for soil change
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
                           # db.instances.aggregate([{"$group": {"_id": "$Do_you_think_the_cold_months_a",count: { "$sum": 1 }}},,{"$sort" :  { "_id" : 1 }}] )
    # from_date = "2015-09-08"
    # to_date = "2015-09-08T08:15:10" # Y-M-D-T-H-M-S
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels for soil change
    cursor.execute("SELECT json_array_elements(json::json->'children'->9->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->9->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
                    
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question12 = "Supply of potable water is"
    options_list12 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list12.append(options)

    form12 = Form(question12,options_list12)
    all_forms.append(form12)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_005",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->10->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->10->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question13 = "Supply of water for irrigation is"
    options_list13 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list13.append(options)

    form13 = Form(question13,options_list13)
    all_forms.append(form13)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_006",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->11->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->11->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question14 = "Do you feel floods are"
    options_list14 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list14.append(options)

    form14 = Form(question14,options_list14)
    all_forms.append(form14)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_007",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->12->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->12->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question15 = "Do you feel floods are"
    options_list15 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list15.append(options)

    form15 = Form(question15,options_list15)
    all_forms.append(form15)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_008",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->13->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->13->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question16 = "Do you feel landslides are"
    options_list16 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list16.append(options)

    form16 = Form(question16,options_list16)
    all_forms.append(form16)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_009",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->14->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->14->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question17 = "Do you feel dry spells are"
    options_list17 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list17.append(options)

    form17 = Form(question17,options_list17)
    all_forms.append(form17)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_intensity_of_rain_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_intensity_of_rain_010",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    mongo_data_all = dictmongo(mongo_results_all)
    mongo_data_quarterly = dictmongo(mongo_results_quarterly)
    # gets labels
    cursor.execute("SELECT json_array_elements(json::json->'children'->15->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->15->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = 5")
    labels = dictfetchall(cursor)

    dictionaryA = get_dictionary(mongo_data_all,labels,coloumn,value,count,default_value)
    dictionaryQ = get_dictionary(mongo_data_quarterly,labels,coloumn,value,count,default_value)
    question18 = "Do you feel dry spells are"
    options_list18 = []
    for key,values in dictionaryA.iteritems():
        quarterly_value = dictionaryQ.get(key,"XX")
        options = Options(key,quarterly_value,values)
        options_list18.append(options)

    form18 = Form(question18,options_list18)
    all_forms.append(form18)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Where_do_you_source_info_about",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Where_do_you_source_info_about",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->16->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->16->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Where do you source info about the weather?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Are_you_aware_of_climate_chang",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Are_you_aware_of_climate_chang",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->18->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->18->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Are you aware of climate change?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Which_one_of_the_following_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Which_one_of_the_following_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->20->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->20->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Which one of the following has the most impact on the climate?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Does_climate_change_have_any_e",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Does_climate_change_have_any_e",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->22->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->22->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Does climate change have any effect on your livelihood?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$My_harvest_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$My_harvest_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->24->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->24->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "My harvest has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Was_this_change_due_to",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Was_this_change_due_to",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->25->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->25->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Was this change due to"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$The_number_of_cropping_per_yea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$The_number_of_cropping_per_yea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->27->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->27->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "The number of cropping per year has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_did_you_do_to_adapt_your_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_did_you_do_to_adapt_your_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->28->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->28->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What did you do to adapt your farm management to these changes?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Does_climate_change_have_effec",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Does_climate_change_have_effec",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->30->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->30->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Does climate change have effect on your household?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Exposure_to_risk_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Exposure_to_risk_has",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->32->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->32->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Exposure to risk has"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Water_collection_has_become",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Water_collection_has_become",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->33->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->33->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Water collection has become"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Children_s_access_to_school_ha",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Children_s_access_to_school_ha",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->34->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->34->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Children's access to school has become"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_did_you_do_to_ensure_safe",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_did_you_do_to_ensure_safe",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->36->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->36->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What did you do to ensure safety for these changes?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Which_one_of_the_following_has_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Which_one_of_the_following_has_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->39->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->39->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Which one of the following has the most impact on the community adaptation?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_participate_in_any_of_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_participate_in_any_of_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->41->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->41->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you participate in any of the PCVAs?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_role_or_roles_did_you_hav",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_role_or_roles_did_you_hav",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->42->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->42->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What role or roles did you have in the PCVAs?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_that_the_output_o",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_that_the_output_o",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->43->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->43->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Do you think that the output of the PCVA was useful to you and your community?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_was_the_most_recent_natur",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_was_the_most_recent_natur",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->45->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->45->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What was the most recent natural disaster you experienced?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Was_your_livelihood_affected_b",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Was_your_livelihood_affected_b",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->46->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->46->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Was your livelihood affected by this disaster?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$How_long_before_you_were_able_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$How_long_before_you_were_able_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->47->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->47->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "How long before you were able to recover from its effects ?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Do_you_think_that_it_took_you_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Do_you_think_that_it_took_you_",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->49->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->49->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Do you think that it took you a long time to recover from its effects?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_do_you_think_were_the_rea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_do_you_think_were_the_rea",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->50->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->50->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What do you think were the reasons why it took you a long time to recover?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Were_you_able_to_attend_the_fi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Were_you_able_to_attend_the_fi",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->51->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->51->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Were you able to attend the field school?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Were_you_able_to_complete_it",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Were_you_able_to_complete_it",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->52->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->52->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Were you able to complete it?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_training_have_you_partici",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_training_have_you_partici",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->53->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->53->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What training have you participated in?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$What_training_have_you_partici_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$What_training_have_you_partici_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->55->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->55->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "What technology have you applied in your farm?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->57->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->57->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on upland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_cost_of_production",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_cost_of_production",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->61->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->61->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_harvest",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_harvest",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->62->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->62->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_013",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->63->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->63->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on irrigated lowland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_cost_of_production_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_cost_of_production_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->67->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->67->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_harvest_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_harvest_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->68->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->68->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->69->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->69->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on rainfed lowland rice?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_cost_of_production_00",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_cost_of_production_00",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->73->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->73->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_harvest_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_harvest_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->74->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->74->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->75->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->75->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on fruit trees?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_cost_of_production_00_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_cost_of_production_00_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->79->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->79->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_harvest_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_harvest_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->80->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->80->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_003",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->81->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->81->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on coconut?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_cost_of_production_00_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_cost_of_production_00_002",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->85->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->85->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your cost of production"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Has_your_harvest_001_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Has_your_harvest_001_001_001_001",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->86->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->86->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Has your harvest"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    #====================================================================================================
    mongo_results_all = xform_instances.aggregate([{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}] )
    mongo_results_quarterly = xform_instances.aggregate([{ "$match": { "_submission_time": { "$gt": from_date, "$lt": to_date } } },{"$group": {"_id": "$Did_you_apply_it_on_upland_ric_004",count: { "$sum": 1 }}},{"$sort" :  { "_id" : 1 }}])
    options_query = "SELECT json_array_elements(json::json->'children'->87->'children')->'name' AS " + coloumn + ",json_array_elements(json::json->'children'->87->'children')->'label'->'default' AS "+ value + " FROM public.logger_xform where id = "+form_id
    question = "Did you apply it on cassava?"
    response_percentage_structure(all_forms, mongo_results_all,mongo_results_quarterly,options_query,question,coloumn,value,count,default_value)
    

    #====================================================================================================
    survey = Survey(all_forms)

    return render(request, template, {'template': template,'survey':survey,'mongo_data':mongo_data_all, 'labels':labels  })


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
