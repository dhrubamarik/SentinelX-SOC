from .models import SecurityAlert

def create_alert(event, title, description, severity):
    """Helper to create and return a SecurityAlert instance."""
    return SecurityAlert.objects.create(
        user=event.user,
        event=event,
        title=title,
        description=description,
        severity=severity,
        status='OPEN'
    )

def evaluate_and_generate_alerts(event):
    """
    Evaluates a post-analyzed SecurityEvent and generates corresponding SecurityAlerts.
    """
    alerts_created = []

    # Safely extract rule names out of the reasons list of dicts
    # Handles both flat string lists and dictionary structures cleanly
    reason_strings = []
    if event.risk_reasons:
        for r in event.risk_reasons:
            if isinstance(r, dict):
                reason_strings.append(r.get("rule", "UNKNOWN"))
            else:
                reason_strings.append(str(r))

    # Rule 1: High / Critical Risk Score Alert
    if event.risk_level in ['HIGH', 'CRITICAL']:
        alert = create_alert(
            event=event,
            title=f"High Risk Authentication Detected ({event.risk_score}/100)",
            description=f"User {event.user} logged in with risk score {event.risk_score}. Reasons: {', '.join(reason_strings)}",
            severity=event.risk_level
        )
        alerts_created.append(alert)

    # Rule 2: Brute Force / Repeated Failures
    if event.event_type == 'LOGIN_FAILED':
        failed_reasons = [r for r in reason_strings if 'FAILED' in r or 'BRUTE' in r]
        if failed_reasons or event.risk_score >= 30:
            alert = create_alert(
                event=event,
                title="Failed Login Attempt Spike",
                description=f"Multiple failed login attempts recorded for IP {event.ip_address}.",
                severity="HIGH" if event.risk_score > 50 else "MEDIUM"
            )
            alerts_created.append(alert)

    # Rule 3: TOR / VPN Access
    if event.is_tor or event.is_vpn:
        alert = create_alert(
            event=event,
            title="Anonymized Network Login (TOR/VPN)",
            description=f"Authentication originated from an anonymized node (IP: {event.ip_address}).",
            severity="HIGH"
        )
        alerts_created.append(alert)

    # Rule 4: New Device Access
    if event.is_new_device and event.risk_level != 'LOW':
        alert = create_alert(
            event=event,
            title="Unrecognized Device Login",
            description=f"Login attempt from a new fingerprint on OS {event.operating_system} / {event.browser}.",
            severity="MEDIUM"
        )
        alerts_created.append(alert)

    return alerts_created