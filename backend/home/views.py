from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.admin.views.decorators import staff_member_required
from django.conf import settings
from django.db.models import Avg, Count
from django.http import JsonResponse
from django.db.models.functions import TruncDay
from django.contrib.auth import get_user_model

from .models import SecurityEvent, SecurityAlert
from .helpers import create_security_event

User = get_user_model()

# ===========================
# PUBLIC USER VIEWS
# ===========================

def home(request):
    return render(request, 'home.html')


def register(request):
    if request.method == 'GET':
        return render(request, 'register.html')
    elif request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )
        messages.success(request, "Registration Successful. Please log in.")
        return redirect('/login/')


def loginuser(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            create_security_event(
                request=request,
                user=user,
                event_type="LOGIN_SUCCESS"
            )
            messages.success(request, "Login Successful")
            return redirect("/welcome/")
        else:
            # Try fetching user for logging context
            failed_user = User.objects.filter(username=username).first()
            create_security_event(
                request=request,
                user=failed_user,
                event_type="LOGIN_FAILED"
            )
            messages.error(request, "Invalid username or password.")
            return redirect("/login/")

    return render(request, "login.html")


def welcome(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Please login first")
        return redirect('/login/')
    return render(request, 'welcome.html')


def logoutuser(request):
    if request.user.is_authenticated:
        create_security_event(
            request=request,
            user=request.user,
            event_type="LOGOUT"
        )
    logout(request)
    return redirect('/login/')


# ===========================
# SOC ADMIN DEDICATED VIEWS
# ===========================

def soc_login(request):
    """
    Dedicated SOC Admin Authentication View.
    Requires Superuser credentials AND a Secret SOC Passkey.
    """
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('/soc/dashboard/')

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        passkey = request.POST.get("passkey")

        # 1. Verify SOC Passkey
        expected_passkey = getattr(settings, 'SOC_PASSKEY', 'admin@123')
        if passkey != expected_passkey:
            messages.error(request, "Invalid Security Passkey. Access Denied.")
            return redirect('/soc/login/')

        # 2. Authenticate User
        user = authenticate(username=username, password=password)

        # 3. Verify Superuser Privileges
        if user and user.is_superuser:
            login(request, user)
            create_security_event(
                request=request,
                user=user,
                event_type="LOGIN_SUCCESS"
            )
            messages.success(request, "SOC Admin Authentication Successful.")
            return redirect('/soc/dashboard/')
        else:
            create_security_event(
                request=request,
                user=user,
                event_type="LOGIN_FAILED"
            )
            messages.error(request, "Unauthorized. Superuser privileges required for SOC access.")
            return redirect('/soc/login/')

    return render(request, "soc_login.html")


@staff_member_required(login_url='/soc/login/')
def soc_dashboard(request):
    """
    Main SOC Operations Dashboard. Accessible only by authenticated SOC staff/superusers.
    """
    events = SecurityEvent.objects.all().order_by('-created_at')
    total_users = User.objects.count()
    total_events = SecurityEvent.objects.count()
    failed_logins = SecurityEvent.objects.filter(event_type="LOGIN_FAILED").count()
    active_alerts = SecurityAlert.objects.filter(status__in=['OPEN', 'INVESTIGATING']).count()
    high_risk_events = SecurityEvent.objects.filter(risk_level__in=['HIGH', 'CRITICAL']).count()
    high_risk_alerts = events.filter(risk_level__in=['HIGH', 'CRITICAL'])[:5]
    avg_risk_query = SecurityEvent.objects.aggregate(avg_score=Avg('risk_score'))
    avg_risk_score = round(avg_risk_query['avg_score'] or 0, 1)

    vpn_users_count = SecurityEvent.objects.filter(is_vpn=True).values('user').distinct().count()
    tor_users_count = SecurityEvent.objects.filter(is_tor=True).values('user').distinct().count()

    recent_alerts = SecurityAlert.objects.select_related('user', 'event').order_by('-created_at')[:5]

    context = {
        "metrics": {
            "total_users": total_users,
            "total_events": total_events,
            "failed_logins": failed_logins,
            "active_alerts": active_alerts,
            "high_risk_events": high_risk_events,
            "avg_risk_score": avg_risk_score,
            "vpn_users_count": vpn_users_count,
            "tor_users_count": tor_users_count,
        },
        "recent_alerts": recent_alerts,
        "live_events": events[:10],
        "alerts": high_risk_alerts,
        "total_users": events.values('user').distinct().count(),
        "total_events": events.count(),
        "auth_failures": events.filter(event_type='LOGIN_FAILED').count(),
        "active_alerts_count": high_risk_alerts.count(),
    }

    return render(request, "soc_dashboard.html", context)


@staff_member_required(login_url='/soc/login/')
def soc_analytics_data(request):
    """
    JSON API providing aggregated metrics for Chart.js rendering.
    """
    daily_volume = list(
        SecurityEvent.objects.annotate(day=TruncDay('created_at'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )
    daily_labels = [d['day'].strftime('%Y-%m-%d') for d in daily_volume]
    daily_counts = [d['count'] for d in daily_volume]

    # Risk Severity Breakdown
    risk_counts = SecurityEvent.objects.values('risk_level').annotate(count=Count('id'))
    risk_dict = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for item in risk_counts:
        if item['risk_level'] in risk_dict:
            risk_dict[item['risk_level']] = item['count']

    # Client Agent / OS Distribution
    agent_counts = list(
        SecurityEvent.objects.values('operating_system')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    # Top Origin Geographic Regions
    geo_counts = list(
        SecurityEvent.objects.values('country')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    return JsonResponse({
        "daily_volume": {"labels": daily_labels, "data": daily_counts},
        "risk_breakdown": list(risk_dict.values()),  # Order: LOW, MEDIUM, HIGH, CRITICAL
        "agent_distribution": {
            "labels": [a['operating_system'] or 'Unknown' for a in agent_counts],
            "data": [a['count'] for a in agent_counts]
        },
        "geo_regions": {
            "labels": [g['country'] or 'Localhost / Dev' for g in geo_counts],
            "data": [g['count'] for g in geo_counts]
        }
    })


@staff_member_required(login_url='/soc/login/')
def threat_map_page(request):
    """Renders the Leaflet.js Interactive Threat Map Page."""
    return render(request, "soc_map.html")


@staff_member_required(login_url='/soc/login/')
def threat_map_data(request):
    """Excludes main superusers/admins from the global threat map."""
    events = (
        SecurityEvent.objects.filter(user__is_superuser=False)
        .exclude(latitude__isnull=True)
        .exclude(longitude__isnull=True)
        .order_by('-created_at')[:300]
    )

    locations = []
    for ev in events:
        locations.append({
            "id": ev.id,
            "username": ev.user.username if ev.user else "Non-Registered User",
            "ip": ev.ip_address,
            "country": ev.country or "Unknown",
            "city": ev.city or "Unknown",
            "lat": ev.latitude,
            "lng": ev.longitude,
            "risk_score": ev.risk_score,
            "risk_level": ev.risk_level,
            "event_type": ev.event_type,
            "time": ev.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        })

    return JsonResponse({"locations": locations})


@staff_member_required(login_url='/soc/login/')
def user_directory_view(request):
    """User Dashboard listing all monitored users (excluding superusers)."""
    users = User.objects.filter(is_superuser=False)
    user_list = []
    
    for u in users:
        events = SecurityEvent.objects.filter(user=u)
        last_event = events.order_by('-created_at').first()
        user_list.append({
            "user": u,
            "total_events": events.count(),
            "last_login": last_event.created_at if last_event else None,
            "last_ip": last_event.ip_address if last_event else "N/A",
            "last_country": last_event.country if last_event else "N/A",
        })

    return render(request, "soc_user_list.html", {"user_list": user_list})


@staff_member_required(login_url='/soc/login/')
def user_detail_view(request, username):
    """Detailed profile & complete extracted telemetry for a single user."""
    target_user = get_object_or_404(User, username=username)
    user_events = SecurityEvent.objects.filter(user=target_user).order_by('-created_at')

    # Extract distinct locations for individual map
    location_history = list(
        user_events.exclude(latitude__isnull=True)
        .values('latitude', 'longitude', 'city', 'country', 'created_at', 'ip_address')
    )
    for loc in location_history:
        loc['created_at'] = loc['created_at'].strftime('%Y-%m-%d %H:%M:%S')

    context = {
        "target_user": target_user,
        "events": user_events,
        "total_logins": user_events.filter(event_type='LOGIN_SUCCESS').count(),
        "failed_logins": user_events.filter(event_type='LOGIN_FAILED').count(),
        "location_history": location_history,
    }
    return render(request, "soc_user_detail.html", context)


@staff_member_required(login_url='/soc/login/')
def soc_analytics_page(request):
    """Renders the Chart.js Analytics Dashboard page."""
    return render(request, "soc_analytics.html")