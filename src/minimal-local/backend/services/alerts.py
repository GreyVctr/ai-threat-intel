"""
Alert notification service for AI Shield Intelligence.

Provides email and webhook notifications for high-severity threats.

Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List, Dict, Any
from datetime import datetime

import httpx

from config import settings

logger = logging.getLogger(__name__)


class AlertService:
    """Service for sending alert notifications"""
    
    def __init__(self):
        """Initialize alert service"""
        self.alert_enabled = getattr(settings, 'alert_enabled', False)
        self.alert_email_enabled = getattr(settings, 'alert_email_enabled', False)
        self.alert_webhook_enabled = getattr(settings, 'alert_webhook_enabled', False)
        self.smtp_host = getattr(settings, 'smtp_host', 'localhost')
        self.smtp_port = getattr(settings, 'smtp_port', 587)
        self.smtp_user = getattr(settings, 'smtp_user', None)
        self.smtp_password = getattr(settings, 'smtp_password', None)
        self.smtp_from = getattr(settings, 'smtp_from', 'alerts@aishield.local')
        self.alert_email_to = getattr(settings, 'alert_email_to', [])
        self.alert_webhook_url = getattr(settings, 'alert_webhook_url', '')
        self.severity_threshold = getattr(settings, 'alert_severity_threshold', 8)
    
    def should_trigger_alert(self, threat: Dict[str, Any]) -> bool:
        """
        Check if a threat should trigger an alert.
        
        Args:
            threat: Threat data dictionary
        
        Returns:
            True if alert should be triggered
        
        Requirements: 14.3, 14.6
        """
        # Check if alerts are globally enabled
        if not self.alert_enabled:
            return False
        
        severity = threat.get('severity')
        threat_type = threat.get('threat_type')
        
        # Check severity threshold
        if severity is None or severity < self.severity_threshold:
            return False
        
        # Could add threat type filters here if configured
        # For now, trigger on any high-severity threat
        
        return True
    
    async def send_email_notification(
        self,
        threat: Dict[str, Any],
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send email notification for a threat.
        
        Args:
            threat: Threat data dictionary
            recipients: List of email addresses (uses config default if None)
        
        Returns:
            True if email sent successfully
        
        Requirements: 14.1, 14.5, 14.7
        """
        # Check if email alerts are enabled
        if not self.alert_email_enabled:
            logger.info("Email alerts are disabled")
            return False
        
        if recipients is None:
            recipients = self.alert_email_to
        
        if not recipients:
            logger.warning("No email recipients configured for alerts")
            return False
        
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[AI Shield Alert] High Severity Threat: {threat.get('title', 'Unknown')}"
            msg['From'] = self.smtp_from
            msg['To'] = ', '.join(recipients)
            
            # Create email body
            text_body = self._create_email_text(threat)
            html_body = self._create_email_html(threat)
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user and self.smtp_password:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                
                server.send_message(msg)
            
            logger.info(f"Email alert sent for threat {threat.get('id')} to {len(recipients)} recipients")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}", exc_info=True)
            return False
    
    async def send_webhook_notification(
        self,
        threat: Dict[str, Any],
        webhook_url: Optional[str] = None
    ) -> bool:
        """
        Send webhook notification for a threat.
        
        Args:
            threat: Threat data dictionary
            webhook_url: Webhook URL (uses config default if None)
        
        Returns:
            True if webhook sent successfully
        
        Requirements: 14.2, 14.5, 14.7
        """
        # Check if webhook alerts are enabled
        if not self.alert_webhook_enabled:
            logger.info("Webhook alerts are disabled")
            return False
        
        if webhook_url is None:
            webhook_url = self.alert_webhook_url
        
        if not webhook_url:
            logger.warning("No webhook URL configured for alerts")
            return False
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Create webhook payload
                payload = {
                    'event': 'high_severity_threat',
                    'timestamp': datetime.utcnow().isoformat(),
                    'threat': {
                        'id': threat.get('id'),
                        'title': threat.get('title'),
                        'description': threat.get('description'),
                        'severity': threat.get('severity'),
                        'threat_type': threat.get('threat_type'),
                        'source': threat.get('source'),
                        'source_url': threat.get('source_url'),
                        'ingested_at': threat.get('ingested_at')
                    }
                }
                
                # Send webhook
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
                
                logger.info(f"Webhook alert sent for threat {threat.get('id')} to {webhook_url}")
                return True
        
        except Exception as e:
            logger.error(f"Failed to send webhook alert to {webhook_url}: {e}")
            return False
    
    async def send_alert(
        self,
        threat: Dict[str, Any],
        channels: Optional[List[str]] = None
    ) -> Dict[str, bool]:
        """
        Send alert through configured channels.
        
        Args:
            threat: Threat data dictionary
            channels: List of channels ('email', 'webhook') or None for all
        
        Returns:
            Dictionary with channel results
        
        Requirements: 14.4, 14.5
        """
        if channels is None:
            channels = ['email', 'webhook']
        
        results = {}
        
        # Send email alerts
        if 'email' in channels:
            results['email'] = await self.send_email_notification(threat)
        
        # Send webhook alerts
        if 'webhook' in channels:
            results['webhook'] = await self.send_webhook_notification(threat)
        
        return results
    
    def _create_email_text(self, threat: Dict[str, Any]) -> str:
        """Create plain text email body"""
        return f"""
AI Shield Intelligence - High Severity Threat Alert

Threat ID: {threat.get('id', 'Unknown')}
Title: {threat.get('title', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}/10
Type: {threat.get('threat_type', 'Unknown')}
Source: {threat.get('source', 'Unknown')}

Description:
{threat.get('description', 'No description available')}

Source URL: {threat.get('source_url', 'N/A')}

Ingested: {threat.get('ingested_at', 'Unknown')}

---
This is an automated alert from AI Shield Intelligence.
"""
    
    def _create_email_html(self, threat: Dict[str, Any]) -> str:
        """Create HTML email body"""
        severity = threat.get('severity', 0)
        severity_color = '#dc2626' if severity >= 9 else '#ea580c' if severity >= 7 else '#f59e0b'
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #1f2937; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background-color: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; }}
        .severity {{ display: inline-block; padding: 4px 12px; border-radius: 4px; 
                     background-color: {severity_color}; color: white; font-weight: bold; }}
        .field {{ margin: 10px 0; }}
        .label {{ font-weight: bold; color: #6b7280; }}
        .footer {{ background-color: #f3f4f6; padding: 15px; border-radius: 0 0 8px 8px; 
                   text-align: center; font-size: 12px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🚨 High Severity Threat Alert</h2>
        </div>
        <div class="content">
            <div class="field">
                <span class="label">Threat ID:</span> {threat.get('id', 'Unknown')}
            </div>
            <div class="field">
                <span class="label">Title:</span> {threat.get('title', 'Unknown')}
            </div>
            <div class="field">
                <span class="label">Severity:</span> 
                <span class="severity">{threat.get('severity', 'Unknown')}/10</span>
            </div>
            <div class="field">
                <span class="label">Type:</span> {threat.get('threat_type', 'Unknown')}
            </div>
            <div class="field">
                <span class="label">Source:</span> {threat.get('source', 'Unknown')}
            </div>
            <div class="field">
                <span class="label">Description:</span><br>
                {threat.get('description', 'No description available')}
            </div>
            <div class="field">
                <span class="label">Source URL:</span> 
                <a href="{threat.get('source_url', '#')}">{threat.get('source_url', 'N/A')}</a>
            </div>
            <div class="field">
                <span class="label">Ingested:</span> {threat.get('ingested_at', 'Unknown')}
            </div>
        </div>
        <div class="footer">
            This is an automated alert from AI Shield Intelligence
        </div>
    </div>
</body>
</html>
"""


# Singleton instance
_alert_service: Optional[AlertService] = None


def get_alert_service() -> AlertService:
    """Get or create alert service instance"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService()
    return _alert_service
