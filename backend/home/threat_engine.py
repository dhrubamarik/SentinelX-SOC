from datetime import timedelta
from django.utils import timezone
from .models import SecurityEvent

def check_new_device(user, device_fingerprint, current_event_id=None):
    """Returns True if this device fingerprint has never been seen for this user prior to this event."""
    if not device_fingerprint:
        return False
    
    query = SecurityEvent.objects.filter(user=user, device_fingerprint=device_fingerprint)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_new_browser(user, browser, current_event_id=None):
    """Returns True if this browser has never been seen for this user prior to this event."""
    if not browser or browser == "Unknown":
        return False
        
    query = SecurityEvent.objects.filter(user=user, browser=browser)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_new_country(user, country, current_event_id=None):
    """Returns True if this country has never been seen for this user prior to this event."""
    if not country or country in ["Unknown", "Development / Localhost"]:
        return False
        
    query = SecurityEvent.objects.filter(user=user, country=country)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_failed_logins(user, minutes=10):
    """Counts failed logins for the user within the last X minutes."""
    if not user:
        return 0
    time_threshold = timezone.now() - timedelta(minutes=minutes)
    return SecurityEvent.objects.filter(
        user=user, 
        event_type="LOGIN_FAILED", 
        created_at__gte=time_threshold
    ).count()


def check_unusual_login_time(event_time=None):
    """Flags login attempts between 11 PM and 6 AM local/server time."""
    now = event_time or timezone.now()
    hour = now.hour
    return hour >= 23 or hour < 6


def check_vpn(ip_address):
    """Placeholder for VPN detection service integration."""
    return False


def check_tor(ip_address):
    """Placeholder for TOR node detection integration."""
    return False


# threat_engine.py

def analyze_security_event(event):
    """
    Main Threat Engine Entry Point.
    Accepts a saved SecurityEvent instance, evaluates threat rules, and returns results.
    """
    # Safe user handling for anonymous events
    user = getattr(event, 'user', None)

    return {
        "new_device": check_new_device(user, getattr(event, 'device_fingerprint', None), event.id) if user else False,
        "new_browser": check_new_browser(user, getattr(event, 'browser', None), event.id) if user else False,
        "new_country": check_new_country(user, getattr(event, 'country', None), event.id) if user else False,
        "failed_logins": check_failed_logins(user) if user else 0,
        "unusual_time": check_unusual_login_time(event.created_at),
        "vpn": check_vpn(event.ip_address) if hasattr(event, 'is_vpn') is False else event.is_vpn,
        "tor": check_tor(event.ip_address) if hasattr(event, 'is_tor') is False else event.is_tor,
        "event_type": event.event_type  # Pass event_type so the LOGIN_FAILED check triggers!
    }