import hashlib

from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate
from django.conf import settings
from django.core.urlresolvers import NoReverseMatch

from rest_framework import serializers
from rest_framework.fields import Field
from rest_framework.reverse import reverse

from .models import Profile as User
from .models import PasswordReset


PROFILE_EMAIL_CONFIRMATION = True
PASSWORD_MAX_LENGTH = User._meta.get_field('password').max_length
NOTIFICATIONS_INSTALLED = 'nodeshot.community.notifications' in settings.INSTALLED_APPS

if PROFILE_EMAIL_CONFIRMATION:
    from emailconfirmation.models import EmailAddress


__all__ = [
    'LoginSerializer',
    'ProfileSerializer',
    'ProfileCreateSerializer',
    'AccountSerializer',
    'ChangePasswordSerializer',
    'ResetPasswordSerializer',
    'ResetPasswordKeySerializer',
]


class HyperlinkedField(Field):
    """
    Represents the instance, or a property on the instance, using hyperlinking.
    """
    read_only = True

    def __init__(self, *args, **kwargs):
        self.view_name = kwargs.pop('view_name', None)
        # Optionally the format of the target hyperlink may be specified
        self.format = kwargs.pop('format', None)
        # Optionally specify arguments
        self.view_args = kwargs.pop('view_args', None)

        super(HyperlinkedField, self).__init__(*args, **kwargs)

    def field_to_native(self, obj, field_name):
        request = self.context.get('request', None)
        format = self.context.get('format', None)
        view_name = self.view_name

        # By default use whatever format is given for the current context
        # unless the target is a different type to the source.
        if format and self.format and self.format != format:
            format = self.format

        try:
            return reverse(view_name, args=self.view_args, request=request, format=format)
        except NoReverseMatch:
            pass

        raise Exception('Could not resolve URL for field using view name "%s"' % view_name)


class ExtraFieldSerializerOptions(serializers.ModelSerializerOptions):
    """
    Meta class options for ExtraFieldSerializerOptions
    """
    def __init__(self, meta):
        super(ExtraFieldSerializerOptions, self).__init__(meta)
        self.non_native_fields = getattr(meta, 'non_native_fields', ())


class ExtraFieldSerializer(serializers.ModelSerializer):
    """
    ModelSerializer in which non native extra fields can be specified.
    """

    _options_class = ExtraFieldSerializerOptions

    def restore_object(self, attrs, instance=None):
        """
        Deserialize a dictionary of attributes into an object instance.
        You should override this method to control how deserialized objects
        are instantiated.
        """
        for field in self.opts.non_native_fields:
            attrs.pop(field)

        return super(ExtraFieldSerializer, self).restore_object(attrs, instance)

    def to_native(self, obj):
        """
        Serialize objects -> primitives.
        """
        ret = self._dict_class()
        ret.fields = self._dict_class()

        for field_name, field in self.fields.items():
            if field.read_only and obj is None:
                continue
            field.initialize(parent=self, field_name=field_name)
            key = self.get_field_key(field_name)

            # skips to next iteration but permits to show the field in API browser
            try:
                value = field.field_to_native(obj, field_name)
            except AttributeError as e:
                if field_name in self.opts.non_native_fields:
                    continue
                else:
                    raise AttributeError(e.message)

            method = getattr(self, 'transform_%s' % field_name, None)
            if callable(method):
                value = method(obj, value)
            if not getattr(field, 'write_only', False):
                ret[key] = value
            ret.fields[key] = self.augment_field(field, field_name, key, value)

        return ret


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=User._meta.get_field('username').max_length)
    password = serializers.CharField(max_length=PASSWORD_MAX_LENGTH)
    remember = serializers.BooleanField(default=True, help_text = _("If checked you will stay logged in for 3 weeks"))

    def user_credentials(self, attrs):
        """
        Provides the credentials required to authenticate the user for login.
        """
        credentials = {}
        credentials["username"] = attrs["username"]
        credentials["password"] = attrs["password"]
        return credentials

    def validate(self, attrs):
        """ checks if login credentials are correct """
        user = authenticate(**self.user_credentials(attrs))

        if user:
            if user.is_active:
                self.instance = user
            else:
                raise serializers.ValidationError(_("This account is currently inactive."))
        else:
            error = _("Ivalid login credentials.")
            raise serializers.ValidationError(error)
        return attrs


class ProfileSerializer(serializers.ModelSerializer):
    """ Profile Serializer for visualization """
    details = serializers.HyperlinkedIdentityField(lookup_field='username', view_name='api_profile_detail')
    avatar = serializers.SerializerMethodField('get_avatar')
    full_name = serializers.SerializerMethodField('get_full_name')
    location = serializers.SerializerMethodField('get_location')

    def get_avatar(self, obj):
        """ avatar from gravatar.com """
        return 'https://www.gravatar.com/avatar/%s' % hashlib.md5(obj.email).hexdigest()

    def get_full_name(self, obj):
        """ user's full name """
        return obj.get_full_name()

    def get_location(self, obj):
        """ return user's location """
        if not obj.city:
            return None
        else:
            return obj.city

    class Meta:
        model = User
        fields = [
            'details', 'id',
            'username', 'full_name', 'first_name', 'last_name',
            'about', 'gender', 'birth_date', 'address', 'city',
            'location',
            'date_joined', 'last_login', 'avatar',
            ]

        read_only_fields = (
            'username',
            'date_joined',
            'last_login'
        )


class ProfileRelationSerializer(ProfileSerializer):
    """ Profile Serializer used for linking """
    class Meta:
        model = User
        fields = ('id', 'username', 'full_name', 'city', 'country', 'avatar', 'details')


class ProfileCreateSerializer(ExtraFieldSerializer):
    """ Profile Serializer for User Creation """
    password_confirmation = serializers.CharField(label=_('password_confirmation'),
                                                  max_length=PASSWORD_MAX_LENGTH)
    email = serializers.CharField(source='email', required='email' in User.REQUIRED_FIELDS)

    def validate_password_confirmation(self, attrs, source):
        """
        password_confirmation check
        """
        password_confirmation = attrs[source]
        password = attrs['password']

        if password_confirmation != password:
            raise serializers.ValidationError(_('Password confirmation mismatch'))

        return attrs

    class Meta:
        model = User
        fields = (
            'id',
            # required
            'username', 'email', 'password', 'password_confirmation',
            # optional
            'first_name', 'last_name', 'about', 'gender',
            'birth_date', 'address', 'city'
        )
        non_native_fields = ('password_confirmation', )


class AccountSerializer(serializers.ModelSerializer):
    """ Account serializer """
    profile = serializers.HyperlinkedIdentityField(
        lookup_field='username',
        view_name='api_profile_detail'
    )
    change_password = HyperlinkedField(
        view_name='api_account_password_change'
    )
    logout = HyperlinkedField(view_name='api_account_logout')

    if PROFILE_EMAIL_CONFIRMATION:
        email_addresses = HyperlinkedField(view_name='api_account_email_list')

    if NOTIFICATIONS_INSTALLED:
        web_notification_settings = HyperlinkedField(
            view_name='api_notification_web_settings'
        )
        email_notification_settings = HyperlinkedField(
            view_name='api_notification_email_settings'
        )

    class Meta:
        model = User
        fields = ['profile', 'change_password', 'logout']

        if PROFILE_EMAIL_CONFIRMATION:
            fields += ['email_addresses']

        if NOTIFICATIONS_INSTALLED:
            fields += ['web_notification_settings', 'email_notification_settings']


class ChangePasswordSerializer(serializers.Serializer):
    """
    Change password serializer
    """
    current_password = serializers.CharField(
        help_text=_('Current Password'),
        max_length=PASSWORD_MAX_LENGTH,
        required=False  # optional because users subscribed from social network won't have a password set
    )
    password1 = serializers.CharField(
        help_text = _('New Password'),
        max_length=PASSWORD_MAX_LENGTH
    )
    password2 = serializers.CharField(
        help_text = _('New Password (confirmation)'),
        max_length=PASSWORD_MAX_LENGTH
    )

    def validate_current_password(self, attrs, source):
        """
        current password check
        """
        if self.object.has_usable_password() and not self.object.check_password(attrs.get("current_password")):
            raise serializers.ValidationError(_('Current password is not correct'))

        return attrs

    def validate_password2(self, attrs, source):
        """
        password_confirmation check
        """
        password_confirmation = attrs[source]
        password = attrs['password1']

        if password_confirmation != password:
            raise serializers.ValidationError(_('Password confirmation mismatch'))

        return attrs

    def restore_object(self, attrs, instance=None):
        """ change password """
        if instance is not None:
            instance.change_password(attrs.get('password2'))
            return instance

        return User(**attrs)


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required = True)

    def validate_email(self, attrs, source):
        """ ensure email is in the database """
        if PROFILE_EMAIL_CONFIRMATION:
            condition = EmailAddress.objects.filter(email__iexact=attrs["email"], verified=True).count() == 0
        else:
            condition = User.objects.get(email__iexact=attrs["email"], is_active=True).count() == 0

        if condition is True:
            raise serializers.ValidationError(_("Email address not verified for any user account"))

        return attrs

    def restore_object(self, attrs, instance=None):
        """ create password reset for user """
        password_reset = PasswordReset.objects.create_for_user(attrs["email"])

        return password_reset


class ResetPasswordKeySerializer(serializers.Serializer):
    password1 = serializers.CharField(
        help_text = _('New Password'),
        max_length=PASSWORD_MAX_LENGTH
    )
    password2 = serializers.CharField(
        help_text = _('New Password (confirmation)'),
        max_length=PASSWORD_MAX_LENGTH
    )

    def validate_password2(self, attrs, source):
        """
        password2 check
        """
        password_confirmation = attrs[source]
        password = attrs['password1']

        if password_confirmation != password:
            raise serializers.ValidationError(_('Password confirmation mismatch'))

        return attrs

    def restore_object(self, attrs, instance):
        """ change password """
        user = instance.user
        user.set_password(attrs["password1"])
        user.save()
        # mark password reset object as reset
        instance.reset = True
        instance.save()

        return instance


# email addresses
if PROFILE_EMAIL_CONFIRMATION:

    __all__ += [
        'EmailSerializer',
        'EmailAddSerializer',
        'EmailEditSerializer'
    ]

    class EmailSerializer(serializers.ModelSerializer):
        details = serializers.HyperlinkedIdentityField(lookup_field='pk', view_name='api_account_email_detail')
        resend_confirmation = serializers.SerializerMethodField('get_resend_confirmation')

        def get_resend_confirmation(self, obj):
            """ return resend_confirmation url """
            if obj.verified:
                return False
            request = self.context.get('request', None)
            format = self.context.get('format', None)
            return reverse('api_account_email_resend_confirmation',
                           args=[obj.pk], request=request, format=format)

        class Meta:
            model = EmailAddress
            fields = ('id', 'email', 'verified', 'primary', 'details', 'resend_confirmation')
            read_only_fields = ('verified', 'primary')


    class EmailAddSerializer(serializers.ModelSerializer):
        class Meta:
            model = EmailAddress
            read_only_fields = ('verified', 'primary')


    class EmailEditSerializer(EmailSerializer):
        def validate_primary(self, attrs, source):
            """
            primary field validation
            """
            primary = attrs[source]
            verified = self.object.verified

            if primary is True and verified is False:
                raise serializers.ValidationError(_('Email address cannot be made primary if it is not verified first'))

            if primary is False and verified is True:
                primary_addresses = EmailAddress.objects.filter(user=self.object.user, primary=True)

                if primary_addresses.count() == 1 and primary_addresses[0].pk == self.object.pk:
                    raise serializers.ValidationError(_('You must have at least one primary address.'))

            return attrs

        class Meta:
            model = EmailAddress
            fields = ('id', 'email', 'verified', 'primary', 'resend_confirmation')
            read_only_fields = ('verified', 'email')


