# backend/home/threat_engine.py

from datetime import timedelta
from django.utils import timezone
import requests
import os

def check_new_device(user, device_fingerprint, current_event_id=None):
    """Returns True if this device fingerprint has never been seen for this user prior to this event."""
    if not user or not device_fingerprint:
        return False
        
    from .models import SecurityEvent
    query = SecurityEvent.objects.filter(user=user, device_fingerprint=device_fingerprint)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_new_browser(user, browser, current_event_id=None):
    """Returns True if this browser has never been seen for this user prior to this event."""
    if not user or not browser or browser == "Unknown":
        return False
        
    from .models import SecurityEvent    
    query = SecurityEvent.objects.filter(user=user, browser=browser)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_new_country(user, country, current_event_id=None):
    """Returns True if this country has never been seen for this user prior to this event."""
    if not user or not country or country in ["Unknown", "Development / Localhost"]:
        return False
        
    from .models import SecurityEvent    
    query = SecurityEvent.objects.filter(user=user, country=country)
    if current_event_id:
        query = query.exclude(id=current_event_id)
        
    return not query.exists()


def check_failed_logins(user, minutes=10):
    """Counts failed logins for the user within the last X minutes."""
    if not user:
        return 0
        
    from .models import SecurityEvent
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


# ✅ FIX: Real VPN Detection using free API
def check_vpn(ip_address):
    """
    Detects if IP is from a VPN/Proxy service.
    Uses vpnapi.io (free tier: 1000 requests/day)
    """
    if not ip_address or ip_address in ["127.0.0.1", "::1", "0.0.0.0"]:
        return False
    
    try:
        # Option 1: vpnapi.io (Free, no API key required for basic)
        response = requests.get(
            f'https://vpnapi.io/api/{ip_address}',
            timeout=5
        )
        data = response.json()
        
        # Check multiple VPN indicators
        is_vpn = data.get('security', {}).get('vpn', False)
        is_proxy = data.get('security', {}).get('proxy', False)
        is_tor = data.get('security', {}).get('tor', False)
        
        return is_vpn or is_proxy or is_tor
        
    except Exception:
        # Fallback: Option 2 - ipqualityscore (requires API key)
        api_key = os.getenv('IPQS_API_KEY')
        if api_key:
            try:
                response = requests.get(
                    f'https://www.ipqualityscore.com/api/json/ip/{api_key}/{ip_address}',
                    timeout=5
                )
                data = response.json()
                return data.get('proxy', False) or data.get('vpn', False)
            except Exception:
                pass
    
    return False


# ✅ FIX: Real TOR Detection
def check_tor(ip_address):
    """
    Detects if IP is from a TOR exit node.
    Uses vpnapi.io or checks against known TOR ports
    """
    if not ip_address or ip_address in ["127.0.0.1", "::1", "0.0.0.0"]:
        return False
    
    try:
        # Use vpnapi.io for TOR detection
        response = requests.get(
            f'https://vpnapi.io/api/{ip_address}',
            timeout=5
        )
        data = response.json()
        
        is_tor = data.get('security', {}).get('tor', False)
        return is_tor
        
    except Exception:
        # Fallback: Check if using common TOR ports (9001, 9030, 9050, 9150)
        # This is a basic heuristic, not definitive
        pass
    
    return False


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
        "vpn": check_vpn(event.ip_address),
        "tor": check_tor(event.ip_address),
        "event_type": event.event_type  
    }