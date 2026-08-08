# backend/home/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.admin.views.decorators import staff_member_required
from django.conf import settings
from django.db.models import Avg, Count
from django.http import JsonResponse, HttpResponse
from django.db.models.functions import TruncDay
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.template.loader import render_to_string

# ✅ ADD THESE IMPORTS FOR TIMEZONE CONVERSION
from zoneinfo import ZoneInfo
from datetime import timedelta

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO

from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import SecurityEvent, SecurityAlert
from .helpers import create_security_event
from .ai_assistant import get_ai_response

User = get_user_model()

# ✅ DEFINE IST TIMEZONE OBJECT
IST = ZoneInfo("Asia/Kolkata")

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

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken. Please choose another.")
            return redirect('/register/')

        if email and User.objects.filter(email=email).exists():
            messages.error(request, "An account with this email already exists.")
            return redirect('/register/')

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


from django.contrib.messages import get_messages

def logoutuser(request):
    """Fixed logout view"""
    if request.user.is_authenticated:
        # Create security event before logout
        create_security_event(
            request=request,
            user=request.user,
            event_type="LOGOUT"
        )

        username = request.user.username
        is_admin = request.user.is_staff or request.user.is_superuser
    else:
        is_admin = False
        username = None

    # Actually logout the user
    logout(request)

    # Clear session completely
    request.session.flush()

    # Flush any stale/unread messages (e.g. leftover login-success message
    # that never got displayed because a previous page didn't render {% messages %})
    list(get_messages(request))

    # Redirect based on user type
    if is_admin:
        messages.info(request, f"Goodbye, {username}. SOC session terminated.")
        return redirect('/soc/login/')

    messages.info(request, f"Goodbye, {username}. See you soon!")
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
    """Main SOC Operations Dashboard."""
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
def risk_detail_view(request, event_id):
    """Shows detailed risk breakdown for a specific event."""
    event = get_object_or_404(SecurityEvent, id=event_id)
    
    context = {
        "event": event,
    }
    return render(request, "soc_risk_detail.html", context)


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

@staff_member_required(login_url='/soc/login/')
def user_detail_view(request, username):
    """Detailed profile & complete extracted telemetry for a single user."""
    target_user = get_object_or_404(User, username=username)
    user_events = SecurityEvent.objects.filter(user=target_user).order_by('-created_at')

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

#AI
# backend/home/views.py

@api_view(['POST'])
@staff_member_required(login_url='/soc/login/')
def chat_with_ai(request):
    """
    Handles chat requests from the frontend.
    Passes session context for "this/it" resolution.
    """
    user_message = request.data.get('message', '')
    
    if not user_message:
        return Response({"error": "No message provided"}, status=400)

    # Pass session for context tracking
    ai_reply = get_ai_response(user_message, request_session=request.session)
    
    return Response({
        "user_message": user_message,
        "ai_response": ai_reply
    })


@staff_member_required(login_url='/soc/login/')
def ai_chat_view(request):
    """Dedicated AI Security Analyst Chat Page"""
    return render(request, "soc_ai_chat.html")


#PDF Report Generation
@staff_member_required(login_url='/soc/login/')
def generate_pdf_report(request, username):
    """Generates PDF report for a user's login history."""
    target_user = get_object_or_404(User, username=username)
    events = SecurityEvent.objects.filter(user=target_user).order_by('-created_at')
    alerts = SecurityAlert.objects.filter(user=target_user).order_by('-created_at')
    
    # Calculate stats
    total_events = events.count()
    successful_logins = events.filter(event_type='LOGIN_SUCCESS').count()
    failed_logins = events.filter(event_type='LOGIN_FAILED').count()
    high_risk_count = events.filter(risk_level__in=['HIGH', 'CRITICAL']).count()
    last_login = events.filter(event_type='LOGIN_SUCCESS').order_by('-created_at').first()
    
    # ✅ Get current time in IST
    now_ist = timezone.now().astimezone(IST)
    
    # Render HTML template (if you still use it)
    html_string = render_to_string('report_template.html', {
        'target_user': target_user,
        'events': events,
        'alerts': alerts,
        'total_events': total_events,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'high_risk_count': high_risk_count,
        'last_login': last_login.created_at.astimezone(IST) if last_login else None,  # ✅ Fixed
        'generated_at': now_ist,
    })
    
    # Create PDF
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="SentinelX_Report_{username}_{now_ist.strftime("%Y%m%d")}.pdf"'
    
    # Convert HTML to PDF using ReportLab
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph("🛡️ SentinelX SOC - Security Report", styles['Heading1']))
    story.append(Paragraph(f"User: {target_user.username} | Generated: {now_ist.strftime('%Y-%m-%d %H:%M:%S')} IST", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Summary
    story.append(Paragraph("📊 Summary", styles['Heading2']))
    summary_data = [
        ['Total Events', str(total_events)],
        ['Successful Logins', str(successful_logins)],
        ['Failed Logins', str(failed_logins)],
        ['High Risk Events', str(high_risk_count)],
    ]
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Events Table
    story.append(Paragraph("📋 Login History", styles['Heading2']))
    events_data = [['Date/Time', 'Event', 'IP', 'Location', 'Risk']]
    for ev in events[:50]:  # Limit to 50 events
        location = f"{ev.city or 'Unknown'}, {ev.country or 'Unknown'}"
        # ✅ FIXED: Call astimezone on created_at field, not on ev object
        event_time_ist = ev.created_at.astimezone(IST)
        events_data.append([
            event_time_ist.strftime('%Y-%m-%d %H:%M'),
            ev.event_type,
            ev.ip_address,
            location[:30],
            ev.risk_level
        ])
    
    events_table = Table(events_data, colWidths=[120, 80, 100, 150, 60])
    events_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))
    story.append(events_table)
    
    # Alerts Table (if any)
    if alerts:
        story.append(Spacer(1, 20))
        story.append(Paragraph("⚠️ Security Alerts", styles['Heading2']))
        alerts_data = [['Date/Time', 'Severity', 'Title', 'Status']]
        for alert in alerts[:20]:
            # ✅ FIXED: Call astimezone on created_at field
            alert_time_ist = alert.created_at.astimezone(IST)
            alerts_data.append([
                alert_time_ist.strftime('%Y-%m-%d %H:%M'),
                alert.severity,
                alert.title[:40],
                alert.status
            ])
        
        alerts_table = Table(alerts_data, colWidths=[120, 60, 250, 80])
        alerts_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        story.append(alerts_table)
    
    # Footer
    story.append(Spacer(1, 30))
    story.append(Paragraph(f"<i>Report generated in IST (UTC+5:30) | SentinelX SOC Platform</i>", styles['Normal']))
    
    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()
    
    response.write(pdf)
    return response

