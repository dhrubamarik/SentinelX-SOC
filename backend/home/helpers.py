import hashlib
import json
import requests

from django.conf import settings

from .models import SecurityEvent
from .threat_engine import analyze_security_event
from .risk_engine import calculate_risk
from .alert_engine import evaluate_and_generate_alerts


# ===========================
# CLIENT IP
# ===========================

def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")

    return ip


# ===========================
# GEO LOCATION
# ===========================

def get_location(ip):
    # Development mode / Localhost override
    if ip in ["127.0.0.1", "::1"]:
        return {
            "country": "Development / Localhost",
            "city": "Localhost",
            "lat": 22.5726,
            "lon": 88.3639,
        }

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
            }
    except Exception:
        pass

    return {
        "country": "",
        "city": "",
        "lat": None,
        "lon": None,
    }


# ===========================
# DEVICE INFO
# ===========================

def get_device_info(request):
    ua = getattr(request, 'user_agent', None)
    if ua:
        return {
            "browser": ua.browser.family,
            "browser_version": ua.browser.version_string,
            "os": ua.os.family,
            "device": ua.device.family,
        }
    return {
        "browser": "Unknown",
        "browser_version": "",
        "os": "Unknown",
        "device": "Unknown",
    }


# ===========================
# CYBERWATCH PIPELINE
# ===========================

def create_security_event(request, user, event_type):
    # --------------------------
    # Network & Device Details
    # --------------------------
    ip = get_client_ip(request)
    location = get_location(ip)
    device = get_device_info(request)

    # --------------------------
    # Browser Fingerprint
    # --------------------------
    fingerprint_data = request.POST.get("fingerprint_data")
    fingerprint_hash = ""
    fingerprint_details = {}

    if fingerprint_data:
        try:
            fingerprint_details = json.loads(fingerprint_data)
            fingerprint_hash = hashlib.sha256(
                json.dumps(
                    fingerprint_details,
                    sort_keys=True
                ).encode()
            ).hexdigest()
        except (json.JSONDecodeError, TypeError):
            fingerprint_hash = ""
            fingerprint_details = {}

    # --------------------------
    # Step 1: Initial Event Creation
    # --------------------------
    event = SecurityEvent.objects.create(
        user=user,
        event_type=event_type,
        ip_address=ip,
        country=location.get("country", ""),
        city=location.get("city", ""),
        latitude=location.get("lat"),
        longitude=location.get("lon"),
        browser=device.get("browser", ""),
        browser_version=device.get("browser_version", ""),
        operating_system=device.get("os", ""),
        device_type=device.get("device", ""),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        language=request.META.get("HTTP_ACCEPT_LANGUAGE", ""),
        timezone=fingerprint_details.get("timezone", ""),
        session_key=request.session.session_key or "",
        device_fingerprint=fingerprint_hash,
        device_details=fingerprint_details,
        risk_score=0,
        risk_level="LOW",
    )

    # --------------------------
    # Step 2: Threat Analysis (Passes event object for exclude support)
    # --------------------------
    analysis = analyze_security_event(event)

    # --------------------------
    # Step 3: Risk Engine Calculation
    # --------------------------
    risk = calculate_risk(analysis)

    # --------------------------
    # Step 4: Update Detection Flags & Risk Metrics
    # --------------------------
    event.is_new_device = analysis.get("is_new_device", False)
    event.is_new_browser = analysis.get("is_new_browser", False)
    event.is_new_location = analysis.get("is_new_country", False)
    event.is_vpn = analysis.get("is_vpn", False)
    event.is_tor = analysis.get("is_tor", False)
    
    event.risk_score = risk.get("score", 0)
    event.risk_level = risk.get("level", "LOW")
    event.risk_reasons = risk.get("reasons", [])

    event.save()

    # --------------------------
    # Step 5: Trigger Security Alerts
    # --------------------------
    evaluate_and_generate_alerts(event)

    return event