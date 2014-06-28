from django.conf.urls import include, patterns, url

urlpatterns = patterns('users.views',
    url(r'^profiles/$', 'profile_list', name='api_profile_list'),
    url(r'^profiles/(?P<username>[-.\w]+)/$', 'profile_detail', name='api_profile_detail'),

    url(r'^account/$', 'account_detail', name='api_account_detail'),
    url(r'^account/login/$', 'account_login', name='api_account_login'),
    url(r'^account/logout/$', 'account_logout', name='api_account_logout'),

    url(r'^account/password/$', 'account_password_change', name='api_account_password_change'),
    url(r'^account/password/reset/$', 'account_password_reset', name='api_account_password_reset'),
    url(r'^account/password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', 'account_password_reset_key', name='api_account_password_reset_key'),

    url(r'^account/email/$', 'account_email_list', name='api_account_email_list'),
    url(r'^account/email/(?P<pk>[0-9]+)/$', 'account_email_detail', name='api_account_email_detail'),
    url(r'^account/email/(?P<pk>[0-9]+)/resend-confirmation/$', 'account_email_resend_confirmation', name='api_account_email_resend_confirmation'),
)

urlpatterns += patterns('',
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
)

