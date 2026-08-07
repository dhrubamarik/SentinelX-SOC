# home/risk_engine.py

# Updated keys to align exactly with threat_engine.py outputs
RISK_RULES = {
    "is_new_device": {"name": "NEW_DEVICE", "score": 15},
    "is_new_browser": {"name": "NEW_BROWSER", "score": 15},
    "is_new_location": {"name": "NEW_COUNTRY", "score": 20},
    "failed_logins": {"name": "FAILED_LOGINS", "score": 25},
    "is_vpn": {"name": "VPN", "score": 20},
    "is_tor": {"name": "TOR", "score": 30},
    "unusual_time": {"name": "UNUSUAL_LOGIN_TIME", "score": 10},
}

def calculate_risk(analysis: dict) -> dict:
    score = 0
    reasons = []

    event_type = analysis.get("event_type")
    
    for key, rule in RISK_RULES.items():
        val = analysis.get(key)
        
        if val:
            if isinstance(val, (int, float)) and val <= 0:
                continue
            
            # Suppress novel device/browser noise on standard LOGIN_SUCCESS if no threats exist
            if key in ["is_new_device", "is_new_browser"] and event_type == "LOGIN_SUCCESS":
                if not analysis.get("failed_logins") and not analysis.get("is_vpn") and not analysis.get("is_tor"):
                    continue

            score += rule["score"]
            reasons.append({"rule": rule["name"], "score": rule["score"]})

    # Base risk increment for explicit LOGIN_FAILED events
    if event_type == "LOGIN_FAILED" and not analysis.get("failed_logins"):
        score += 25
        reasons.append({"rule": "LOGIN_FAILED", "score": 25})

    # Ensure clean LOGOUT or normal LOGIN_SUCCESS stays LOW
    if event_type == "LOGOUT":
        score = 0
        reasons = []

    if score <= 20:
        level = "LOW"
    elif score <= 50:
        level = "MEDIUM"
    elif score <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {"score": score, "level": level, "reasons": reasons}