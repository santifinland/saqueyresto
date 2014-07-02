from django.http import Http404
from django.contrib.auth import login, logout
from django.utils.http import base36_to_int
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from rest_framework import generics
from rest_framework import exceptions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated

from .mixins import ListSerializerMixin, CustomDataMixin

from .models import Profile
from .serializers import *
from .permissions import *


# ------ User Profile ------ #


class ProfileList(generics.ListCreateAPIView):
    """
    Return profile of current authenticated user or return 401.

    ### POST

    Create a new user account.
    Sends a confirmation mail if if PROFILE_EMAL_CONFIRMATION setting is True.

    **Required Fields**:

     * username
     * email
     * password
     * password_confirmation

    ** Optional Fields **

     * first_name
     * last_name
     * about
     * gender
     * birth_date
     * address
     * city
     * country
    """
    authentication_classes = (BasicAuthentication, TokenAuthentication, SessionAuthentication)
    model = Profile
    serializer_class = ProfileCreateSerializer

    # custom
    serializer_reader_class = ProfileSerializer

    def get(self, request, *args, **kwargs):
        """ return profile of current user if authenticated otherwise 401 """
        serializer = self.serializer_reader_class

        if request.user.is_authenticated():
            return Response(serializer(request.user, context=self.get_serializer_context()).data)
        else:
            return Response({ 'detail': _('XXXXXXAuthentication credentials were not provided') }, status=401)

    def post_save(self, obj, created):
        """
        Send email confirmation according to configuration
        """
        super(ProfileList, self).post_save(obj)

        if created:
            obj.add_email()

profile_list = ProfileList.as_view()


class ProfileDetail(generics.RetrieveUpdateAPIView):
    """
    Retrieve specified profile.

    ### PUT & PATCH

    Update profile.

    **Permissions**: only profile owner can edit.

    **Editable fields**

     * first_name
     * last_name
     * about
     * gender
     * birth_date
     * address
     * city
     * country
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticatedOrReadOnly, IsProfileOwner)
    model = Profile
    serializer_class = ProfileSerializer
    lookup_field = 'username'

profile_detail = ProfileDetail.as_view()

# ------ Account ------ #


class AccountLogin(generics.GenericAPIView):
    """
    Log in

    **Parameters**:

     * username
     * password
     * remember
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsNotAuthenticated, )
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        """ authenticate """
        serializer = self.serializer_class(data=request.DATA)

        if serializer.is_valid():
            login(request, serializer.instance)

            if request.DATA.get('remember'):
                # TODO: remember configurable
                request.session.set_expiry(60 * 60 * 24 * 7 * 3)
            else:
                request.session.set_expiry(0)

            return Response({
                'detail': _(u'Logged in successfully'),
                'user': ProfileRelationSerializer(
                    serializer.instance,
                    context={ 'request': request }
                ).data
            })

        return Response(serializer.errors, status=400)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied(_("You are already authenticated"))

account_login = AccountLogin.as_view()


class AccountLogout(APIView):
    """
    Log out
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )

    def post(self, request, format=None):
        """ clear session """
        logout(request)
        return Response({ 'detail': _(u'Logged out successfully') })

account_logout = AccountLogout.as_view()


class AccountDetail(generics.GenericAPIView):
    """
    Retrieve profile of current user or return 401 if not authenticated.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated, )
    serializer_class = AccountSerializer

    def get(self, request, format=None):
        """ Retrieve profile of current user or return 401 if not authenticated. """
        serializer = self.serializer_class(request.user, context=self.get_serializer_context())
        return Response(serializer.data)

account_detail = AccountDetail.as_view()


# ------ Account Password ------ #


class AccountPassword(generics.GenericAPIView):
    """
    Change password of the current user.

    **Accepted parameters:**

     * current_password
     * password1
     * password2
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    def post(self, request, format=None):
        """ validate password change operation and return result """
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.DATA, instance=request.user)

        if serializer.is_valid():
            serializer.save()
            return Response({ 'detail': _(u'Password successfully changed') })

        return Response(serializer.errors, status=400)

account_password_change = AccountPassword.as_view()


class PasswordResetRequestKey(generics.GenericAPIView):
    """
    Sends an email to the user email address with a link to reset his password.

    **TODO:** the key should be sent via push notification too.

    **Accepted parameters:**

     * email
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsNotAuthenticated, )
    serializer_class = ResetPasswordSerializer

    def post(self, request, format=None):
        # init form with POST data
        serializer = self.serializer_class(data=request.DATA)
        # validate
        if serializer.is_valid():
            serializer.save()
            return Response({
                'detail': _(u'We just sent you the link with which you will able to reset your password at %s') % request.DATA.get('email')
            })
        # in case of errors
        return Response(serializer.errors, status=400)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied(_("You can't reset your password if you are already authenticated"))

account_password_reset = PasswordResetRequestKey.as_view()


class PasswordResetFromKey(generics.GenericAPIView):
    """
    Reset password from key.

    **The key must be part of the URL**!

    **Accepted parameters:**

     * password1
     * password2
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsNotAuthenticated, )
    serializer_class = ResetPasswordKeySerializer

    def post(self, request, uidb36, key, format=None):
        # pull out user
        try:
            uid_int = base36_to_int(uidb36)
            password_reset_key = PasswordReset.objects.get(user_id=uid_int, temp_key=key, reset=False)
        except (ValueError, PasswordReset.DoesNotExist, AttributeError):
            return Response({ 'errors': _(u'Key Not Found') }, status=404)

        serializer = ResetPasswordKeySerializer(
            data=request.DATA,
            instance=password_reset_key
        )

        # validate
        if serializer.is_valid():
            serializer.save()
            return Response({ 'detail': _(u'Password successfully changed.') })
        # in case of errors
        return Response(serializer.errors, status=400)

    def permission_denied(self, request):
        raise exceptions.PermissionDenied(_("You can't reset your password if you are already authenticated"))

account_password_reset_key = PasswordResetFromKey.as_view()


# ------ Account Email ------ #



from emailconfirmation.models import EmailAddress, EmailConfirmation

class AccountEmailList(CustomDataMixin, generics.ListCreateAPIView):
    """
    Get email addresses of current authenticated user.

    ### POST

    Add new email address.
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailSerializer
    serializer_custom_class = EmailAddSerializer
    model = EmailAddress

    def get_queryset(self):
        return self.model.objects.filter(user=self.request.user)

    def get_custom_data(self):
        """ additional request.DATA """
        return {
            'user': self.request.user.id
        }

    def post_save(self, obj, created):
        """
        Send email confirmation
        """
        super(AccountEmailList, self).post_save(obj)

        if created:
            EmailConfirmation.objects.send_confirmation(obj)

account_email_list = AccountEmailList.as_view()


class AccountEmailDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Get specified email object.

    ### PUT & PATCH

    Make primary.

    ### DELETE

    Delete email address
    """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailEditSerializer
    model = EmailAddress

    def get_queryset(self):
        return self.model.objects.filter(user=self.request.user)

    def pre_save(self, obj):
        """
        make_primary
        """
        if obj.primary:
            obj.set_as_primary()

        super(AccountEmailDetail, self).pre_save(obj)

    def delete(self, request, *args, **kwargs):
        """ can't delete if only 1 email address """
        if self.get_object().primary:
            return Response({ 'error': _("You can't delete your primary address")}, status=400)
        elif EmailAddress.objects.filter(user=request.user).count() <= 1:
            return Response({ 'error': _("You can't delete your only email address")}, status=400)

        return self.destroy(request, *args, **kwargs)

account_email_detail = AccountEmailDetail.as_view()


class ResendEmailConfirmation(APIView):
    """ Resend email confirmation """
    authentication_classes = (TokenAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        """
        Resend email confirmation
        """
        try:
            email_address = EmailAddress.objects.get(user=request.user, pk=kwargs.get('pk', None))
        except EmailAddress.DoesNotExist:
            return Response({ 'detail': _('Not Found') }, status=404)

        if email_address.verified:
            return Response({ 'error': _('Email address %s already verified' % email_address.email )}, status=400)

        EmailConfirmation.objects.send_confirmation(email_address)

        return Response({ 'detail': _('Email confirmation sent to %s' % email_address.email )})

account_email_resend_confirmation = ResendEmailConfirmation.as_view()
