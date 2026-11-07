from django.urls import path, re_path
from . import views

urlpatterns = [
    # Health and Platform Information
    path('health', views.health_check, name='health-check'),
    path('info', views.platform_info, name='platform-info'),

    # Authentication & User Sessions
    path('auth/login', views.auth_login, name='auth-login'),
    path('auth/demo-switch', views.auth_demo_switch, name='auth-demo-switch'),
    path('auth/firebase-login', views.auth_firebase_login, name='auth-firebase-login'),
    path('auth/me', views.auth_me, name='auth-me'),
    path('auth/register-school', views.register_school, name='auth-register-school'),

    # Schools Management
    path('schools', views.public_schools_list, name='public-schools'),
    path('admin/schools', views.admin_schools_list, name='admin-schools'),
    path('admin/overview', views.admin_overview, name='admin-overview'),
    path('admin/payment-codes', views.admin_payment_codes, name='admin-payment-codes'),
    path('admin/payment-codes/generate', views.admin_payment_codes, name='admin-payment-codes-generate'),

    # Academic & Student Portals
    path('school/students', views.school_students, name='school-students'),
    path('notifications', views.notifications_list, name='notifications-list'),
    path('notifications/read-all', views.notifications_list, name='notifications-read-all'),

    # Resilient Catch-All Route: Any additional subpath returns 200 JSON instead of 500 error
    re_path(r'^(?P<subpath>.*)$', views.catch_all_api, name='catch-all-api'),
]
