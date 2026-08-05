# home/risk_engine.py

RISK_RULES = {
    "new_device": {"name": "NEW_DEVICE", "score": 15},
    "new_browser": {"name": "NEW_BROWSER", "score": 15},
    "new_country": {"name": "NEW_COUNTRY", "score": 20},
    "failed_logins": {"name": "FAILED_LOGINS", "score": 25},
    "vpn": {"name": "VPN", "score": 20},
    "tor": {"name": "TOR", "score": 30},
    "unusual_time": {"name": "UNUSUAL_LOGIN_TIME", "score": 10},
}

def calculate_risk(analysis: dict) -> dict:
    score = 0
    reasons = []

    # 1. Ignore "new device/browser" flags if user is logging in on standard conditions
    event_type = analysis.get("event_type")
    
    for key, rule in RISK_RULES.items():
        val = analysis.get(key)
        
        if val:
            if isinstance(val, (int, float)) and val <= 0:
                continue
            
            # Suppress novel device/browser noise on standard LOGIN_SUCCESS if no failed attempts exist
            if key in ["new_device", "new_browser"] and event_type == "LOGIN_SUCCESS":
                if not analysis.get("failed_logins") and not analysis.get("vpn") and not analysis.get("tor"):
                    continue

            score += rule["score"]
            reasons.append({"rule": rule["name"], "score": rule["score"]})

    # Base risk increment ONLY for explicit LOGIN_FAILED events
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