from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .forms import CustomUserCreationForm, ShegarLandFormForm
from django.views.decorators.csrf import csrf_exempt
import json 
from django.http import JsonResponse
from django.core.mail import send_mail
from .models import ShegarLandForm, PasswordResetRequest
from django.conf import settings
import os
import geopandas as gpd
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from .utils import account_activation_token
import csv
from django.http import HttpResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Sum
import datetime
from django.http import HttpResponse
from datetime import datetime, timedelta
from django.db.models import Sum, Count
from django.db.models.functions import ExtractWeek, ExtractYear
import csv
from django.utils import timezone
from datetime import datetime, timedelta

# Get the custom user model
User = get_user_model()

# Home view
def home(request):
    return render(request, 'home.html')

def privacy_policy(request):
    return render(request, 'shegarland/privacy_policy.html')

def terms_of_service(request):
    return render(request, 'shegarland/terms_of_service.html')

# Register view
def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            # Get cleaned data
            first_name = form.cleaned_data.get('first_name')
            last_name = form.cleaned_data.get('last_name')
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')

            # Create a new user but keep it inactive
            user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            user.is_active = False  # Set as inactive until email confirmation
            user.save()

            # Send the activation email
            current_site = get_current_site(request)
            subject = 'Activate Your Account'
            message = render_to_string('shegarland/activation_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })

            # Send email with your system's email configurations
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

            messages.success(request, 'Registration successful! Please check your email for an activation link.')
            return redirect('login')  # Redirect to login page
        else:
            messages.error(request, 'Please correct the errors below.')
    
    else:
        form = CustomUserCreationForm()

    return render(request, 'shegarland/register.html', {'form': form})

# Account activation view
def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Your account has been activated successfully!')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid!')
        return render(request, 'shegarland/activation_invalid.html')

# About view
def about(request):
    return render(request, 'shegarland/about.html')

# Login view
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Your account is inactive. Please check your email to activate your account.')
            else:
                messages.error(request, 'Invalid credentials.')
    else:
        form = AuthenticationForm()
    return render(request, 'shegarland/login.html', {'form': form})

# Logout view
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')

# Dashboard view (protected)
@login_required
def dashboard(request):
    submissions = ShegarLandForm.objects.filter(user=request.user)  # Get submissions for the logged-in user
    return render(request, 'shegarland/dashboard.html', {'submissions': submissions})

# Admin dashboard view
@login_required
def admin_dashboard(request):
    if request.user.is_superuser:
        submissions = ShegarLandForm.objects.all()  # Get all form submissions

        # Calculate 'balina_lafa_hafe' for each submission
        for submission in submissions:
            if submission.bal_lafa_bahi_tae:  # Ensure the field is not None
                submission.bal_lafa_hafe = submission.balina_lafa - submission.bal_lafa_bahi_tae
            else:
                submission.bal_lafa_hafe = None  # Set to None if 'bal_lafa_bahi_tae' is not provided
        
        return render(request, 'shegarland/admin_dashboard.html', {'submissions': submissions})
    else:
        messages.error(request, 'Access denied: Only administrators can access this page.')
        return redirect('dashboard')

# Submit form view (protected)
@login_required
def submit_form(request):
    admin_only_fields = ['bal_lafa_bahi_tae', 'bal_lafa_hafe', 'qaama_bahi_tahef','tajajila_bahi_tahef', 'kan_bahi_taasise','ragaittin_bahi_tae', 'guyyaa_bahi_tae'] 
    if request.method == 'POST':
        form = ShegarLandFormForm(request.POST, request.FILES)
        if form.is_valid():
            form.instance.user = request.user
            form.save()
            messages.success(request, 'Your submission was successful!')
            return redirect('dashboard')
        else:
            messages.error(request, 'There were errors in your submission. Please correct them.')
    else:
        form = ShegarLandFormForm()

    return render(request, 'shegarland/form.html', {'form': form, 'admin_only_fields': admin_only_fields})

# Handle map drawing saving via GeoJSON
@csrf_exempt
def save_drawing(request):
    if request.method == 'POST':
        try:
            geojson_data = json.loads(request.body.decode('utf-8'))
            # You can process the geojson_data as needed here
            return JsonResponse({'status': 'success'}, status=200)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

    return JsonResponse({'status': 'invalid request'}, status=400)

# Password reset request creation
@login_required
def create_password_reset_request(request):
    if request.method == 'POST':
        user = request.user
        if user.is_authenticated:
            PasswordResetRequest.objects.create(user=user)
            messages.success(request, 'Password reset request submitted. Please wait for approval.')
            return redirect('dashboard')

# Admin view to approve and send password reset link
@login_required
def approve_password_reset_request(request, request_id):
    password_reset_request = PasswordResetRequest.objects.get(id=request_id)
    
    if password_reset_request and not password_reset_request.approved:
        password_reset_request.approved = True
        password_reset_request.save()

        # Send the password reset email
        subject = 'Password Reset Request Approved'
        token = default_token_generator.make_token(password_reset_request.user)
        uid = urlsafe_base64_encode(force_bytes(password_reset_request.user.pk))
        reset_link = request.build_absolute_uri(
            reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        )
        
        message = render_to_string('registration/password_reset_email.html', {
            'user': password_reset_request.user,
            'reset_link': reset_link
        })
        send_mail(subject, message, 'shegarlaofficials@gmail.com', [password_reset_request.user.email])

        messages.success(request, f'Password reset email has been sent to {password_reset_request.user.email}.')
    return redirect('admin_dashboard')

# Edit submission view
@login_required
def edit_submission(request, submission_id):
    submission = get_object_or_404(ShegarLandForm, id=submission_id)
    admin_only_fields = ['field1', 'field2', 'field3']  # Replace with the actual field names

    if request.method == 'POST':
        # Include request.FILES to handle file uploads
        form = ShegarLandFormForm(request.POST, request.FILES, instance=submission)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your submission has been updated!')
            return redirect('admin_dashboard')  # Adjust the redirect as needed
    else:
        form = ShegarLandFormForm(instance=submission)

    return render(request, 'shegarland/edit_submission.html', {
        'form': form,
        'submission': submission,
        'admin_only_fields': admin_only_fields
    })

# Delete submission view
@login_required
def delete_submission(request, submission_id):
    submission = get_object_or_404(ShegarLandForm, id=submission_id)
    if request.method == 'POST':
        submission.delete()
        messages.success(request, 'Submission deleted successfully!')
        return redirect('admin_dashboard')  # Redirect to admin dashboard after deleting
    return render(request, 'shegarland/delete_submission.html', {'submission': submission})

# Export submissions view
@login_required
def export_submissions(request):
    submissions = ShegarLandForm.objects.all()  # Get all submissions to export
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=submissions.csv'
    
    writer = csv.writer(response)
    writer.writerow(['id','username','Kutaamagaalaa', 'Aanaa', 'iddo_adda',  'lakk_adda', 'gosa_tajajila','madda_lafa','tajajila_iddo','haala_beenya', 'qamaa_qophaef',
                  'tajajila_qophaef', 'balina_lafa', 'kan_qophesse', 'guyya_qophae','guyya_galmae','bal_lafa_bahi_tae', 'bal_lafa_hafe',
            'qaama_bahi_tahef', 'tajajila_bahi_tahef',
            'kan_bahi_taasise','ragaittin_bahi_tae', 'guyyaa_bahi_tae'])  # Customize the header based on your model fields

    for submission in submissions:
        writer.writerow([submission.id, submission.user.username, submission.Kutaamagaalaa, submission.Aanaa, submission.iddo_adda, submission.lakk_adda,submission.gosa_tajajila,submission.madda_lafa,submission.tajajila_iddo,submission.haala_beenya,submission.qamaa_qophaef,submission.tajajila_qophaef,submission.balina_lafa,submission.kan_qophesse,submission.guyya_qophae,submission.guyya_galmae,submission.bal_lafa_bahi_tae,submission.bal_lafa_hafe,submission.qaama_bahi_tahef,submission.tajajila_bahi_tahef,submission.kan_bahi_taasise,submission.ragaittin_bahi_tae,submission.guyyaa_bahi_tae])  # Customize the fields as needed

    return response

from django.db.models import Sum
from django.shortcuts import render
from .models import ShegarLandForm

def report(request):
    # Fetch all-time data
    all_time_aggregate = ShegarLandForm.objects.values('Kutaamagaalaa').annotate(
        total_balina_lafa=Sum('balina_lafa'),
        bal_lafa_bahi_tae=Sum('bal_lafa_bahi_tae'),
        total_bal_lafa_hafe=Sum('bal_lafa_hafe')
    )
    
    # Add separate context lists for each dataset
    all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae = [
        {"Kutaamagaalaa": item["Kutaamagaalaa"], "total_bal_bahi_tae": item["bal_lafa_bahi_tae"]}
        for item in all_time_aggregate if item["bal_lafa_bahi_tae"] is not None
    ]
    
    all_time_Kutaamagaalaa_vs_bal_lafa_hafee = [
        {"Kutaamagaalaa": item["Kutaamagaalaa"], "total_bal_hafe": item["total_bal_lafa_hafe"]}
        for item in all_time_aggregate if item["total_bal_lafa_hafe"] is not None
    ]
    
    all_time_total_balina_lafa = all_time_aggregate.aggregate(Sum('total_balina_lafa'))['total_balina_lafa__sum']
    all_time_bal_bahi_tae = all_time_aggregate.aggregate(Sum('bal_lafa_bahi_tae'))['bal_lafa_bahi_tae__sum']
    all_time_total_lafa_hafe = all_time_aggregate.aggregate(Sum('total_bal_lafa_hafe'))['total_bal_lafa_hafe__sum']

    context = {
        'all_time_aggregate': all_time_aggregate,
        'all_time_total_balina_lafa': all_time_total_balina_lafa,
        'all_time_bal_bahi_tae': all_time_bal_bahi_tae,
        'all_time_total_lafa_hafe': all_time_total_lafa_hafe,
        'all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae': all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae,
        'all_time_Kutaamagaalaa_vs_bal_lafa_hafee': all_time_Kutaamagaalaa_vs_bal_lafa_hafee,
    }
    
    return render(request, 'shegarland/report.html', context)
from datetime import datetime
from django.shortcuts import render
from django.db.models import Sum
from django.contrib.admin.views.decorators import staff_member_required
from .models import ShegarLandForm  # Ensure you import your model

@staff_member_required  # Ensure that only admin users can access this view
def monthly_report(request):
    # Retrieve today's date and calculate the start of the current month
    today = datetime.today().date()
    start_of_month = today.replace(day=1)

    # Retrieve submissions for the current month based on 'guyya_qophae'
    submissions = ShegarLandForm.objects.filter(guyya_qophae__gte=start_of_month)

    # Prepare data for the charts
    Kutaamagaalaa_vs_balina_lafa = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_balina=Sum('balina_lafa'))
    )
    Kutaamagaalaa_vs_bal_lafa_bahi_tae = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_bal_bahi_tae=Sum('bal_lafa_bahi_tae'))
    )
    Kutaamagaalaa_vs_bal_lafa_hafee = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_bal_hafe=Sum('bal_lafa_hafe'))
    )

    # Prepare total sums for each aggregate
    monthly_total_balina_lafa = submissions.aggregate(total=Sum('balina_lafa'))['total'] or 0
    monthly_total_bal_bahi_tae = submissions.aggregate(total=Sum('bal_lafa_bahi_tae'))['total'] or 0
    monthly_total_bal_hafe = submissions.aggregate(total=Sum('bal_lafa_hafe'))['total'] or 0

    # Calculate the net (adjusted) value
    monthly_adjusted_total_balina_lafa = monthly_total_balina_lafa - monthly_total_bal_bahi_tae

    # Debug information (optional)
    print("Monthly Total Balina Lafa:", monthly_total_balina_lafa)
    print("Monthly Total Balina Lafa Bahi Tae:", monthly_total_bal_bahi_tae)
    print("Monthly Total Balina Lafa Hafe:", monthly_total_bal_hafe)
    print("Monthly Adjusted Total Balina Lafa:", monthly_adjusted_total_balina_lafa)

    # Prepare context for rendering
    context = {
        'submissions': submissions,
        'Kutaamagaalaa_vs_balina_lafa': Kutaamagaalaa_vs_balina_lafa,
        'Kutaamagaalaa_vs_bal_lafa_bahi_tae': Kutaamagaalaa_vs_bal_lafa_bahi_tae,
        'Kutaamagaalaa_vs_bal_lafa_hafee': Kutaamagaalaa_vs_bal_lafa_hafee,
        'monthly_total_balina_lafa': monthly_total_balina_lafa,
        'monthly_total_bal_bahi_tae': monthly_total_bal_bahi_tae,
        'monthly_total_bal_hafe': monthly_total_bal_hafe,
        'monthly_adjusted_total_balina_lafa': monthly_adjusted_total_balina_lafa,
        'aggregate_data': (
            submissions.values('Kutaamagaalaa')
            .annotate(
                total_balina_lafa=Sum('balina_lafa'),
                total_balina_lafa_bahi_tae=Sum('bal_lafa_bahi_tae'),
                total_balina_lafa_hafe=Sum('bal_lafa_hafe'),
                net_bal_lafa_hafe=Sum('balina_lafa') - Sum('bal_lafa_bahi_tae')
            )
        ),
        'tajajila_qophaef_vs_balina_lafa': submissions.values('tajajila_qophaef').annotate(total_balina=Sum('balina_lafa')),
        'madda_lafa_vs_balina_lafa': submissions.values('madda_lafa').annotate(total_balina=Sum('balina_lafa')),
        'gosa_tajajila_vs_balina_lafa': submissions.values('gosa_tajajila').annotate(total_balina=Sum('balina_lafa')),
        'tajajila_iddo_vs_balina_lafa': submissions.values('tajajila_iddo').annotate(total_balina=Sum('balina_lafa')),
    }

    return render(request, 'shegarland/monthly_report.html', context)  # Update the path if needed

from django.db.models import Sum
from django.shortcuts import render
from .models import ShegarLandForm

def all_time_report(request):
    # Fetch all-time data
    all_time_aggregate = ShegarLandForm.objects.values('Kutaamagaalaa').annotate(
        total_balina_lafa=Sum('balina_lafa'),
        bal_lafa_bahi_tae=Sum('bal_lafa_bahi_tae'),
        total_bal_lafa_hafe=Sum('bal_lafa_hafe')
    )
    
    # Add separate context lists for each dataset
    all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae = [
        {"Kutaamagaalaa": item["Kutaamagaalaa"], "total_bal_bahi_tae": item["bal_lafa_bahi_tae"]}
        for item in all_time_aggregate if item["bal_lafa_bahi_tae"] is not None
    ]
    
    all_time_Kutaamagaalaa_vs_bal_lafa_hafee = [
        {"Kutaamagaalaa": item["Kutaamagaalaa"], "total_bal_hafe": item["total_bal_lafa_hafe"]}
        for item in all_time_aggregate if item["total_bal_lafa_hafe"] is not None
    ]
    
    all_time_total_balina_lafa = all_time_aggregate.aggregate(Sum('total_balina_lafa'))['total_balina_lafa__sum']
    all_time_bal_bahi_tae = all_time_aggregate.aggregate(Sum('bal_lafa_bahi_tae'))['bal_lafa_bahi_tae__sum']
    all_time_total_lafa_hafe = all_time_aggregate.aggregate(Sum('total_bal_lafa_hafe'))['total_bal_lafa_hafe__sum']

    context = {
        'all_time_aggregate': all_time_aggregate,
        'all_time_total_balina_lafa': all_time_total_balina_lafa,
        'all_time_bal_bahi_tae': all_time_bal_bahi_tae,
        'all_time_total_lafa_hafe': all_time_total_lafa_hafe,
        'all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae': all_time_Kutaamagaalaa_vs_bal_lafa_bahi_tae,
        'all_time_Kutaamagaalaa_vs_bal_lafa_hafee': all_time_Kutaamagaalaa_vs_bal_lafa_hafee,
    }
    
    return render(request, 'shegarland/all_time_report.html', context)
from datetime import datetime, timedelta
from django.shortcuts import render
from django.db.models import Sum, F
from django.contrib.admin.views.decorators import staff_member_required
from .models import ShegarLandForm  # Ensure you import your model

@staff_member_required  # Ensure that only admin users can access this view
def weekly_report(request):
    # Retrieve today's date and calculate the start of the current week
    today = datetime.today().date()
    start_of_week = today - timedelta(days=today.weekday())

    # Retrieve submissions for the current week based on 'guyya_qophae'
    submissions = ShegarLandForm.objects.filter(guyya_qophae__gte=start_of_week)

    # Prepare data for the charts
    Kutaamagaalaa_vs_balina_lafa = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_balina=Sum('balina_lafa'))
    )

    # Aggregate for balina lafa bahi tae within the same magaalaa
    Kutaamagaalaa_vs_bal_lafa_bahi_tae = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_bal_bahi_tae=Sum('bal_lafa_bahi_tae'))
    )

    # Aggregate for balina lafa hafe within the same magaalaa
    Kutaamagaalaa_vs_bal_lafa_hafee = (
        submissions.values('Kutaamagaalaa')
        .annotate(total_bal_hafe=Sum('bal_lafa_hafe'))
    )

    # Prepare total sums for each aggregate
    total_balina_lafa = submissions.aggregate(total=Sum('balina_lafa'))['total'] or 0
    total_bal_bahi_tae = submissions.aggregate(total=Sum('bal_lafa_bahi_tae'))['total'] or 0
    total_bal_hafe = submissions.aggregate(total=Sum('bal_lafa_hafe'))['total'] or 0

    # Net Bal Lafa Hafe calculation for the entire dataset
    net_bal_lafa_hafe = total_balina_lafa - total_bal_bahi_tae

    # Prepare aggregate data for each magaalaa, including net calculation per magaalaa
    aggregate_data = (
        submissions.values('Kutaamagaalaa')
        .annotate(
            total_balina_lafa=Sum('balina_lafa'),
            total_balina_lafa_bahi_tae=Sum('bal_lafa_bahi_tae'),
            total_balina_lafa_hafe=Sum('bal_lafa_hafe'),
            net_bal_lafa_hafe=Sum('balina_lafa') - Sum('bal_lafa_bahi_tae')
        )
    )

    # Prepare context for rendering
    context = {
        'submissions': submissions,
        'Kutaamagaalaa_vs_balina_lafa': Kutaamagaalaa_vs_balina_lafa,
        'Kutaamagaalaa_vs_bal_lafa_bahi_tae': Kutaamagaalaa_vs_bal_lafa_bahi_tae,
        'Kutaamagaalaa_vs_bal_lafa_hafee': Kutaamagaalaa_vs_bal_lafa_hafee,
        'total_balina_lafa': total_balina_lafa,
        'total_bal_bahi_tae': total_bal_bahi_tae,
        'total_bal_hafe': total_bal_hafe,
        'net_bal_lafa_hafe': net_bal_lafa_hafe,  # Added for the entire summary
        'aggregate_data': aggregate_data,
        'tajajila_qophaef_vs_balina_lafa': submissions.values('tajajila_qophaef').annotate(total_balina=Sum('balina_lafa')),
        'madda_lafa_vs_balina_lafa': submissions.values('madda_lafa').annotate(total_balina=Sum('balina_lafa')),
        'gosa_tajajila_vs_balina_lafa': submissions.values('gosa_tajajila').annotate(total_balina=Sum('balina_lafa')),
        'tajajila_iddo_vs_balina_lafa': submissions.values('tajajila_iddo').annotate(total_balina=Sum('balina_lafa')),
    }

    return render(request, 'shegarland/weekly_report.html', context)  # Update the path if needed

@staff_member_required
def export_report_csv(request):
    today = datetime.now().date()
    start_of_week = today - timedelta(days=today.weekday())  # Calculate start of the week

    # Filter submissions from the current week
    submissions = ShegarLandForm.objects.filter(guyya_qophae__gte=start_of_week)

    # Create the HttpResponse object with the appropriate CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="weekly_report.csv"'

    # Create a CSV writer
    writer = csv.writer(response)

    # Write the header row
    writer.writerow(['User', 'Kutaamagaalaa', 'Tajajila Qophaef', 'Madda Lafa', 'Gosa Tajajila', 'Balina Lafa', 'bal_lafa_bahi_tae', 'bal_lafa_hafe'])

    # Write data rows
    for submission in submissions:
        writer.writerow([
            submission.user.username,
            submission.Kutaamagaalaa,
            submission.tajajila_qophaef,
            submission.madda_lafa,
            submission.gosa_tajajila,
            submission.balina_lafa,
            submission.bal_lafa_bahi_tae,
            submission.bal_lafa_hafe,
        ])

    return response