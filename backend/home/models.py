from django.db import models
from django.contrib.auth.models import User


class SecurityEvent(models.Model):

    EVENT_TYPES = [
        ("LOGIN_SUCCESS", "Login Success"),
        ("LOGIN_FAILED", "Login Failed"),
        ("LOGOUT", "Logout"),
    ]

    RISK_LEVELS = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    # ==========================
    # User Information
    # ==========================

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    event_type = models.CharField(
        max_length=30,
        choices=EVENT_TYPES
    )

    # ==========================
    # Network Information
    # ==========================

    ip_address = models.GenericIPAddressField()

    country = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )

    city = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )

    latitude = models.FloatField(
        blank=True,
        null=True
    )

    longitude = models.FloatField(
        blank=True,
        null=True
    )

    # ==========================
    # Device Information
    # ==========================

    browser = models.CharField(
        max_length=100,
        blank=True
    )

    browser_version = models.CharField(
        max_length=50,
        blank=True
    )

    operating_system = models.CharField(
        max_length=100,
        blank=True
    )

    device_type = models.CharField(
        max_length=50,
        blank=True
    )

    user_agent = models.TextField(
        blank=True
    )

    language = models.CharField(
        max_length=50,
        blank=True
    )

    timezone = models.CharField(
        max_length=100,
        blank=True
    )

    device_fingerprint = models.CharField(
        max_length=64,
        blank=True
    )

    # Stores browser fingerprint details
    device_details = models.JSONField(
        default=dict,
        blank=True
    )

    # ==========================
    # Session Information
    # ==========================

    session_key = models.CharField(
        max_length=100,
        blank=True
    )

    login_time = models.DateTimeField(
        auto_now_add=True
    )

    logout_time = models.DateTimeField(
        blank=True,
        null=True
    )

    # ==========================
    # Detection Flags
    # ==========================

    is_new_device = models.BooleanField(
        default=False
    )

    is_new_browser = models.BooleanField(
        default=False
    )

    is_new_location = models.BooleanField(
        default=False
    )

    is_vpn = models.BooleanField(
        default=False
    )

    is_tor = models.BooleanField(
        default=False
    )

    # ==========================
    # Risk
    # ==========================

    risk_score = models.IntegerField(
        default=0
    )

    risk_reasons = models.JSONField(
        default=list, 
        blank=True
    )

    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVELS,
        default="LOW"
    )

    # ==========================
    # Timestamp
    # ==========================

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    def save(self, *args, **kwargs):
        is_new = self.pk is None

        # 1. Save initially to establish primary key (PK) & timestamp
        super().save(*args, **kwargs)

        # 2. Lazy imports to break circular dependencies on module load
        if is_new or self.risk_score == 0:
            from .threat_engine import analyze_security_event
            from .risk_engine import calculate_risk

            analysis = analyze_security_event(self)
            risk_res = calculate_risk(analysis)

            # Map threat engine outputs to flags
            self.is_new_device = analysis.get("new_device", False)
            self.is_new_browser = analysis.get("new_browser", False)
            self.is_new_location = analysis.get("new_country", False)
            self.is_vpn = analysis.get("vpn", False)
            self.is_tor = analysis.get("tor", False)

            # Map risk calculations
            self.risk_score = risk_res["score"]
            self.risk_level = risk_res["level"]
            self.risk_reasons = risk_res["reasons"]

            # 3. Direct DB update to prevent infinite save loops
            SecurityEvent.objects.filter(pk=self.pk).update(
                is_new_device=self.is_new_device,
                is_new_browser=self.is_new_browser,
                is_new_location=self.is_new_location,
                is_vpn=self.is_vpn,
                is_tor=self.is_tor,
                risk_score=self.risk_score,
                risk_level=self.risk_level,
                risk_reasons=self.risk_reasons,
            )

    def __str__(self):
        username = self.user.username if self.user else "Unknown User"
        return f"{username} | {self.event_type} | Risk: {self.risk_score} ({self.risk_level})"

class SecurityAlert(models.Model):
    """
    Generated by Alert Engine when threats exceed threshold scores or match specific rules.
    Used in SOC Dashboard, Incident Investigation, and Reports.
    """
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('DISMISSED', 'Dismissed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    event = models.ForeignKey(SecurityEvent, on_delete=models.CASCADE, related_name='alerts')
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    resolution_notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        username = self.user.username if self.user else "System/Unknown"
        return f"[{self.severity}] {self.title} - {username}"