from django.urls import path
from .views import (
    home,
    register,
    login_view,
    dashboard,
    submit_form,
    save_drawing,
    logout_view,
    admin_dashboard,
    edit_submission,
    delete_submission,
    export_submissions,
    activate,
    about,
    report,
    all_time_report,
    weekly_report,  # New weekly report view
    monthly_report,  # New monthly report view
    export_report_csv,
    privacy_policy,
    terms_of_service
)
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth import views as auth_views
from django.contrib.admin.views.decorators import staff_member_required
from .views import approve_password_reset_request, create_password_reset_request

urlpatterns = [
    # Publicly accessible homepage
    path('', home, name='home'),

    # User registration, login, logout, and password reset
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('password-reset/', PasswordResetView.as_view(template_name='shegarland/password_reset.html'), name='password_reset'),
    path('about/', about, name='about'),

    # User dashboard and form submission (login required)
    path('dashboard/', dashboard, name='dashboard'),
    path('submit-form/', submit_form, name='submit_form'),
    path('save_drawing/', save_drawing, name='save_drawing'),

    # Admin-only dashboard (restricted to superuser/admin)
    path('admindashboard/', staff_member_required(admin_dashboard), name='admin_dashboard'),

    # Submission management: edit, delete, export
    path('submission/edit/<int:submission_id>/', edit_submission, name='edit_submission'),
    path('submission/delete/<int:submission_id>/', delete_submission, name='delete_submission'),
    path('submissions/export/', export_submissions, name='export_submissions'),

    # Password reset views
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='shegarland/password_reset_done.html'), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='shegarland/password_reset_confirm.html'), name='password_reset_confirm'),
    path('password-reset-complete/', auth_views.PasswordResetCompleteView.as_view(template_name='shegarland/password_reset_complete.html'), name='password_reset_complete'),
    path('password-reset-request/', create_password_reset_request, name='create_password_reset_request'),
    path('approve-password-reset/<int:request_id>/', approve_password_reset_request, name='approve_password_reset_request'),
    path('activate/<uidb64>/<token>/', activate, name='activate'),

    # Admin-only report view (restricted to staff/admin users)
 
    path('admin/report/', staff_member_required(report), name='report'),
    path('all-time-report/', all_time_report, name='all_time_report'),
    path('admin/report/weekly/', staff_member_required(weekly_report), name='weekly_report'),
    path('admin/report/monthly/', staff_member_required(monthly_report), name='monthly_report'),

    path('export/report/csv/', export_report_csv, name='export_report_csv'),
    path('privacy-policy/', privacy_policy, name='privacy_policy'),
    path('terms-of-service/', terms_of_service, name='terms_of_service'),
]