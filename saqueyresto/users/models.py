from django.db import models
from django.core import validators
from django.core.mail import send_mail
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, UserManager
from django.utils.timezone import utc
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.utils.http import int_to_base36
from django.contrib.sites.models import Site
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator as token_generator

from datetime import datetime
from signals import password_changed

import re


SEX_CHOICES = (
    ('M', _('male')),
    ('F', _('female'))
)


class Profile(AbstractBaseUser, PermissionsMixin):
    """
    User Profile Model
    Contains personal info of a user
    """
    # 254 maximum character for username makes it possible
    username = models.CharField(
        _('username'),
        max_length=254,
        unique=True,
        db_index=True,
        help_text=_('Required. 30 characters or fewer.\
                    Letters, numbers and @/./+/-/_ characters'),
        validators=[
            validators.RegexValidator(
                re.compile('^[\w.@+-]+$'),
                _('Enter a valid username.'),
                'invalid'
            )
        ]
    )
    email = models.EmailField(_('primary email address'), blank=True, unique=True, db_index=True)
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)

    # added fields
    about = models.TextField(_('about me'), blank=True)
    gender = models.CharField(_('gender'), max_length=1, choices=SEX_CHOICES, blank=True)
    birth_date = models.DateField(_('birth date'), blank=True, null=True)
    address = models.CharField(_('address'), max_length=150, blank=True)
    city = models.CharField(_('city'), max_length=30, blank=True)

    is_active   = models.BooleanField(default=True)
    is_staff = models.BooleanField(_('staff status'), default=False,
                                   help_text=_('Designates whether the user can log into this admin site.'))
    date_joined = models.DateTimeField(_('date joined'), default=datetime.utcnow().replace(tzinfo=utc))

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        app_label = 'users'

    def __unicode__(self):
        return self.username

    def save(self, *args, **kwargs):
        """ ensure instance has usable password when created """
        if not self.pk and self.has_usable_password() is False:
            self.set_password(self.password)

        super(Profile, self).save(*args, **kwargs)

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email])

    def add_email(self):
        """
        Add email to DB and sends a confirmation mail if PROFILE_EMAL_CONFIRMATION is True
        """
        from emailconfirmation.models import EmailAddress
        self.is_active = False
        self.save()
        EmailAddress.objects.add_email(self, self.email)
        return True

    def change_password(self, new_password):
        """
        Changes password and sends a signal
        """
        self.set_password(new_password)
        self.save()
        password_changed.send(sender=self.__class__, user=self)

    if 'grappelli' in settings.INSTALLED_APPS:
        @staticmethod
        def autocomplete_search_fields():
            return (
                'username__icontains',
                'first_name__icontains',
                'last_name__icontains',
                'email__icontains'
            )




from .models import Profile as User


class PasswordResetManager(models.Manager):
    """ Password Reset Manager """

    def create_for_user(self, user):
        """ create password reset for specified user """
        # support passing email address too
        if type(user) is unicode:
            user = User.objects.get(email=user)

        temp_key = token_generator.make_token(user)

        # save it to the password reset model
        password_reset = PasswordReset(user=user, temp_key=temp_key)
        password_reset.save()

        current_site = Site.objects.get_current()
        domain = unicode(current_site.domain)

        # send the password reset email
        subject = _("Password reset email sent")
        message = render_to_string("profiles/email_messages/password_reset_key_message.txt", {
            "user": user,
            "uid": int_to_base36(user.id),
            "temp_key": temp_key,
            "domain": domain,
            })
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

        return password_reset


class PasswordReset(models.Model):
    """
    Password reset Key
    """
    user = models.ForeignKey(User, verbose_name=_("user"))

    temp_key = models.CharField(_("temp_key"), max_length=100)
    timestamp = models.DateTimeField(_("timestamp"), default=datetime.utcnow().replace(tzinfo=utc))
    reset = models.BooleanField(_("reset yet?"), default=False)

    objects = PasswordResetManager()

    class Meta:
        verbose_name = _('password reset')
        verbose_name_plural = _('password resets')
        app_label = 'profiles'

    def __unicode__(self):
        return "%s (key=%s, reset=%r)" % (
            self.user.username,
            self.temp_key,
            self.reset
        )