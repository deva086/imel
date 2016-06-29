import pytz
import logging
from django.contrib.contenttypes.models import ContentType
from datetime import datetime

from django.conf import settings
from django.http import Http404
from django.shortcuts import get_object_or_404

from rest_framework import viewsets
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth import authenticate


from onadata.apps.api.tools import get_media_file_response
from onadata.apps.logger.models.xform import XForm
from onadata.apps.main.models.meta_data import MetaData
from onadata.apps.main.models.user_profile import UserProfile
from django.contrib.auth.models import User
from onadata.libs import filters
from onadata.libs.authentication import DigestAuthentication
from onadata.libs.renderers.renderers import MediaFileContentNegotiation
from onadata.libs.renderers.renderers import XFormListRenderer
from onadata.libs.renderers.renderers import XFormManifestRenderer
from onadata.libs.serializers.xform_serializer import XFormListSerializer
from onadata.libs.serializers.xform_serializer import XFormManifestSerializer


# 10,000,000 bytes
DEFAULT_CONTENT_LENGTH = getattr(settings, 'DEFAULT_CONTENT_LENGTH', 10000000)


class XFormListApi(viewsets.ReadOnlyModelViewSet):
    #logging.debug('test log')
    authentication_classes = (DigestAuthentication,)
    content_negotiation_class = MediaFileContentNegotiation
    filter_backends = (filters.XFormListObjectPermissionFilter,)
    queryset = XForm.objects.filter(downloadable=True)
    permission_classes = (permissions.AllowAny,)
    renderer_classes = (XFormListRenderer,)
    serializer_class = XFormListSerializer
    template_name = 'api/xformsList.xml'

    def get_openrosa_headers(self):
        logging.debug('test log-0')
        tz = pytz.timezone(settings.TIME_ZONE)
        dt = datetime.now(tz).strftime('%a, %d %b %Y %H:%M:%S %Z')

        return {
            'Date': dt,
            'X-OpenRosa-Version': '1.0',
            'X-OpenRosa-Accept-Content-Length': DEFAULT_CONTENT_LENGTH
        }

    def get_renderers(self):
        logging.debug('test log-1')
        if self.action and self.action == 'manifest':
            logging.debug('test log-2')
            return [XFormManifestRenderer()]

        return super(XFormListApi, self).get_renderers()

    def filter_queryset(self, queryset):
        username = self.kwargs.get('username')
	password = self.request.GET.get('password')
        if username is None and password is None and self.request.user.is_anonymous():
            # raises a permission denied exception, forces authentication
            self.permission_denied(self.request)

        if username is not None:
            profile = get_object_or_404(
                UserProfile, user__username=username.lower())

            if profile.require_auth and self.request.user.is_anonymous():
                # raises a permission denied exception, forces authentication
                self.permission_denied(self.request)
            else:
                queryset = queryset.filter(user=profile.user)

        if not self.request.user.is_anonymous():
            queryset = super(XFormListApi, self).filter_queryset(queryset)
        return queryset
	
    def old_list(self, request, *args, **kwargs):
        logging.basicConfig(filename='ex.log', level=logging.DEBUG)
        username = self.kwargs.get('username')
        password = request.GET.get('password', '')
        logging.info('mpower:password = ' + password)
        mobileuser = authenticate(username=username, password=password)
        #logging.info('mpower:username = ' + mobileuser.username)
        if self.request.user.is_anonymous():
            if username is None or mobileuser is None:
                # raises a permission denied exception, forces authentication
                self.permission_denied(self.request)
            else:
                user = get_object_or_404(User, username=username.lower())

                profile, created = UserProfile.objects.get_or_create(user=user)

                if profile.require_auth:
                    # raises a permission denied exception,
                    # forces authentication
                    self.permission_denied(self.request)
        elif mobileuser is None:
            self.permission_denied(self.request)
        elif not username:
            # get the username from the user if not set
            username = (request.user and request.user.username)

        self.object_list = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(self.object_list, many=True)
        return Response(serializer.data, headers=self.get_openrosa_headers())

    def list(self, request, *args, **kwargs):
        logging.basicConfig(filename='test.log',level=logging.DEBUG)
        self.object_list = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(self.object_list, many=True)
        return Response(serializer.data)

    def form_list(self, request, *args, **kwargs):
        logging.basicConfig(filename='test.log',level=logging.DEBUG)
        session = self.request.COOKIES.get('sessionid')
        logging.debug(session)
        self.object_list = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(self.object_list, many=True)
        return Response(serializer.data, headers=self.get_openrosa_headers())

    def mobile_login(self, request, *args, **kwargs):
        username = self.kwargs.get('username')
        password = request.GET.get('password', '')
        users = authenticate(username=username, password=password)
        if users is not None:	    
            return Response('Logged in successfully', headers=self.get_openrosa_headers(), status=200)
        else:
            return Response(password, headers=self.get_openrosa_headers(), status=401)

    def retrieve(self, request, *args, **kwargs):
        logging.debug('test log-11')
        self.object = self.get_object()

        return Response(self.object.xml, headers=self.get_openrosa_headers())

    @action(methods=['GET'])
    def manifest(self, request, *args, **kwargs):
        logging.debug('test log-12')
        self.object = self.get_object()
        object_list = MetaData.objects.filter(data_type='media',
                                              xform=self.object)
        context = self.get_serializer_context()
        serializer = XFormManifestSerializer(object_list, many=True,
                                             context=context)

        return Response(serializer.data, headers=self.get_openrosa_headers())

    @action(methods=['GET'])
    def media(self, request, *args, **kwargs):
        logging.debug('test log-13')
        self.object = self.get_object()
        pk = kwargs.get('metadata')

        if not pk:
            raise Http404()

        meta_obj = get_object_or_404(
            MetaData, data_type='media', xform=self.object, pk=pk)

        return get_media_file_response(meta_obj)
