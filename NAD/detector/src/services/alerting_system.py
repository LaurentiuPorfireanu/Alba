import asyncio
import smtplib
import json
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
from typing import Dict, List, Any, Optional
from datetime import datetime
import os
from dataclasses import dataclass

@dataclass
class AlertConfig:
    """Configuratie pentru alerting"""
    email_enabled: bool = True
    slack_enabled: bool = True
    webhook_enabled: bool = True
    sms_enabled: bool = False
    
    # Email settings
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: List[str] = None
    
    # Slack settings
    slack_webhook_url: str = ""
    slack_channel: str = "#security-alerts"
    
    # Webhook settings
    webhook_urls: List[str] = None
    
    # Alert thresholds
    min_severity: str = "MEDIUM"
    rate_limit_minutes: int = 5
    max_alerts_per_hour: int = 20

class AlertingSystem:
    """
    Sistem de alerting pentru anomalii de securitate
    Suporta email, Slack, webhook si SMS
    """
    
    def __init__(self, config: AlertConfig = None):
        self.config = config or AlertConfig()
        self.alert_history = []
        self.rate_limiter = {}
        
        # Alert templates
        self.templates = {
            'email': self._get_email_template(),
            'slack': self._get_slack_template(),
            'webhook': self._get_webhook_template()
        }
        
        logger.info("AlertingSystem initialized")
    
    async def send_alert(self, anomaly_info: Dict[str, Any]):
        """Trimite alerta prin toate canalele configurate"""
        try:
            # Check rate limiting
            if not self._should_send_alert(anomaly_info):
                logger.debug("Alert rate limited, skipping")
                return
            
            # Add to history
            alert_data = {
                'timestamp': datetime.now().isoformat(),
                'anomaly_info': anomaly_info,
                'channels_sent': []
            }
            
            # Send through configured channels
            tasks = []
            
            if self.config.email_enabled:
                tasks.append(self._send_email_alert(anomaly_info, alert_data))
            
            if self.config.slack_enabled:
                tasks.append(self._send_slack_alert(anomaly_info, alert_data))
            
            if self.config.webhook_enabled:
                tasks.append(self._send_webhook_alert(anomaly_info, alert_data))
            
            if self.config.sms_enabled:
                tasks.append(self._send_sms_alert(anomaly_info, alert_data))
            
            # Execute all tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Add to history
            self.alert_history.append(alert_data)
            
            # Cleanup old history
            self._cleanup_history()
            
            logger.info(f"Alert sent for anomaly with severity {anomaly_info.get('severity', 'UNKNOWN')}")
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
    
    def _should_send_alert(self, anomaly_info: Dict[str, Any]) -> bool:
        """Verifica daca alerta trebuie trimisa (rate limiting + severity)"""
        severity = anomaly_info.get('severity', 'LOW')
        
        # Check severity threshold
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_levels.get(self.config.min_severity, 2)
        current_level = severity_levels.get(severity, 1)
        
        if current_level < min_level:
            return False
        
        # Check rate limiting
        now = datetime.now()
        rate_key = f"{severity}_{anomaly_info.get('type', 'unknown')}"
        
        if rate_key in self.rate_limiter:
            last_sent = self.rate_limiter[rate_key]
            minutes_passed = (now - last_sent).total_seconds() / 60
            
            if minutes_passed < self.config.rate_limit_minutes:
                return False
        
        # Check hourly limit
        recent_alerts = [
            a for a in self.alert_history 
            if (now - datetime.fromisoformat(a['timestamp'])).total_seconds() < 3600
        ]
        
        if len(recent_alerts) >= self.config.max_alerts_per_hour:
            logger.warning("Hourly alert limit reached")
            return False
        
        # Update rate limiter
        self.rate_limiter[rate_key] = now
        
        return True
    
    async def _send_email_alert(self, anomaly_info: Dict[str, Any], alert_data: Dict[str, Any]):
        """Trimite alerta prin email"""
        try:
            if not self.config.email_recipients:
                logger.warning("No email recipients configured")
                return
            
            # Create email content
            subject = f"🚨 Security Alert: {anomaly_info.get('type', 'Network Anomaly')} Detected"
            html_content = self._format_email_content(anomaly_info)
            
            # Setup email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config.email_username
            msg['To'] = ', '.join(self.config.email_recipients)
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                server.starttls()
                server.login(self.config.email_username, self.config.email_password)
                server.send_message(msg)
            
            alert_data['channels_sent'].append('email')
            logger.info("Email alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    async def _send_slack_alert(self, anomaly_info: Dict[str, Any], alert_data: Dict[str, Any]):
        """Trimite alerta prin Slack"""
        try:
            if not self.config.slack_webhook_url:
                logger.warning("No Slack webhook URL configured")
                return
            
            # Create Slack message
            slack_payload = self._format_slack_content(anomaly_info)
            
            # Send to Slack
            async with asyncio.timeout(10):
                response = requests.post(
                    self.config.slack_webhook_url,
                    json=slack_payload,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()
            
            alert_data['channels_sent'].append('slack')
            logger.info("Slack alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    async def _send_webhook_alert(self, anomaly_info: Dict[str, Any], alert_data: Dict[str, Any]):
        """Trimite alerta prin webhook"""
        try:
            if not self.config.webhook_urls:
                logger.warning("No webhook URLs configured")
                return
            
            # Create webhook payload
            webhook_payload = self._format_webhook_content(anomaly_info)
            
            # Send to all webhooks
            for webhook_url in self.config.webhook_urls:
                try:
                    async with asyncio.timeout(10):
                        response = requests.post(
                            webhook_url,
                            json=webhook_payload,
                            headers={'Content-Type': 'application/json'}
                        )
                        response.raise_for_status()
                except Exception as e:
                    logger.error(f"Failed to send webhook to {webhook_url}: {e}")
            
            alert_data['channels_sent'].append('webhook')
            logger.info("Webhook alerts sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send webhook alerts: {e}")
    
    async def _send_sms_alert(self, anomaly_info: Dict[str, Any], alert_data: Dict[str, Any]):
        """Trimite alerta prin SMS (implementare mock)"""
        try:
            # Mock SMS implementation
            # În producție, aici ar fi integrarea cu Twilio, AWS SNS, etc.
            
            sms_content = self._format_sms_content(anomaly_info)
            logger.info(f"SMS Alert (Mock): {sms_content}")
            
            alert_data['channels_sent'].append('sms')
            
        except Exception as e:
            logger.error(f"Failed to send SMS alert: {e}")
    
    def _format_email_content(self, anomaly_info: Dict[str, Any]) -> str:
        """Formateaza continutul email-ului"""
        timestamp = anomaly_info.get('timestamp', 'Unknown')
        severity = anomaly_info.get('severity', 'UNKNOWN')
        confidence = anomaly_info.get('confidence', 0)
        
        flow_data = anomaly_info.get('flow_data', {})
        packet_info = flow_data.get('packet_info', {})
        
        # Severity color mapping
        severity_colors = {
            'LOW': '#36a64f',
            'MEDIUM': '#ff9500',
            'HIGH': '#ff0000',
            'CRITICAL': '#8b0000'
        }
        
        color = severity_colors.get(severity, '#808080')
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                .alert-container {{ border-left: 4px solid {color}; padding: 20px; background-color: #f9f9f9; }}
                .severity-{severity.lower()} {{ color: {color}; font-weight: bold; }}
                .details {{ background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .footer {{ font-size: 12px; color: #666; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="alert-container">
                <h2>🚨 Network Security Alert</h2>
                
                <div class="details">
                    <h3>Alert Details</h3>
                    <p><strong>Severity:</strong> <span class="severity-{severity.lower()}">{severity}</span></p>
                    <p><strong>Confidence:</strong> {confidence:.2%}</p>
                    <p><strong>Timestamp:</strong> {timestamp}</p>
                    <p><strong>Type:</strong> {anomaly_info.get('type', 'Network Anomaly')}</p>
                </div>
                
                <div class="details">
                    <h3>Network Flow Information</h3>
                    <p><strong>Source IP:</strong> {packet_info.get('src_ip', 'Unknown')}</p>
                    <p><strong>Destination IP:</strong> {packet_info.get('dst_ip', 'Unknown')}</p>
                    <p><strong>Source Port:</strong> {packet_info.get('src_port', 'Unknown')}</p>
                    <p><strong>Destination Port:</strong> {packet_info.get('dst_port', 'Unknown')}</p>
                    <p><strong>Protocol:</strong> {packet_info.get('protocol', 'Unknown')}</p>
                    <p><strong>Packet Size:</strong> {packet_info.get('packet_length', 'Unknown')} bytes</p>
                </div>
                
                <div class="details">
                    <h3>Recommended Actions</h3>
                    <ul>
                        <li>Investigate the source IP address</li>
                        <li>Check firewall logs for related activity</li>
                        <li>Monitor for additional anomalous traffic</li>
                        <li>Consider blocking suspicious IPs if confirmed malicious</li>
                    </ul>
                </div>
                
                <div class="footer">
                    <p>This alert was generated by the Network Anomaly Detection System</p>
                    <p>For more information, check the monitoring dashboard</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _format_slack_content(self, anomaly_info: Dict[str, Any]) -> Dict[str, Any]:
        """Formateaza continutul pentru Slack"""
        severity = anomaly_info.get('severity', 'UNKNOWN')
        confidence = anomaly_info.get('confidence', 0)
        
        flow_data = anomaly_info.get('flow_data', {})
        packet_info = flow_data.get('packet_info', {})
        
        # Severity emojis and colors
        severity_config = {
            'LOW': {'emoji': '🟡', 'color': 'warning'},
            'MEDIUM': {'emoji': '🟠', 'color': 'warning'},
            'HIGH': {'emoji': '🔴', 'color': 'danger'},
            'CRITICAL': {'emoji': '🚨', 'color': 'danger'}
        }
        
        config = severity_config.get(severity, {'emoji': '⚪', 'color': 'good'})
        
        slack_payload = {
            "channel": self.config.slack_channel,
            "username": "Security Bot",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": config['color'],
                    "title": f"{config['emoji']} Network Security Alert - {severity}",
                    "fields": [
                        {
                            "title": "Confidence",
                            "value": f"{confidence:.1%}",
                            "short": True
                        },
                        {
                            "title": "Type",
                            "value": anomaly_info.get('type', 'Network Anomaly'),
                            "short": True
                        },
                        {
                            "title": "Source",
                            "value": f"{packet_info.get('src_ip', 'Unknown')}:{packet_info.get('src_port', '?')}",
                            "short": True
                        },
                        {
                            "title": "Destination",
                            "value": f"{packet_info.get('dst_ip', 'Unknown')}:{packet_info.get('dst_port', '?')}",
                            "short": True
                        }
                    ],
                    "footer": "Network Anomaly Detection System",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        return slack_payload
    
    def _format_webhook_content(self, anomaly_info: Dict[str, Any]) -> Dict[str, Any]:
        """Formateaza continutul pentru webhook"""
        return {
            "alert_type": "network_anomaly",
            "severity": anomaly_info.get('severity', 'UNKNOWN'),
            "confidence": anomaly_info.get('confidence', 0),
            "timestamp": anomaly_info.get('timestamp'),
            "source_system": "network_anomaly_detection",
            "details": anomaly_info
        }
    
    def _format_sms_content(self, anomaly_info: Dict[str, Any]) -> str:
        """Formateaza continutul pentru SMS"""
        severity = anomaly_info.get('severity', 'UNKNOWN')
        flow_data = anomaly_info.get('flow_data', {})
        packet_info = flow_data.get('packet_info', {})
        
        return f"SECURITY ALERT [{severity}]: Anomaly detected from {packet_info.get('src_ip', 'Unknown')} to {packet_info.get('dst_ip', 'Unknown')}. Check monitoring dashboard."
    
    def _cleanup_history(self):
        """Curata istoricul vechi de alerte"""
        cutoff_time = datetime.now().timestamp() - (24 * 3600)  # 24 hours
        
        self.alert_history = [
            alert for alert in self.alert_history
            if datetime.fromisoformat(alert['timestamp']).timestamp() > cutoff_time
        ]
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Returneaza statistici despre alerte"""
        now = datetime.now()
        
        # Last 24 hours
        recent_alerts = [
            alert for alert in self.alert_history
            if (now - datetime.fromisoformat(alert['timestamp'])).total_seconds() < 86400
        ]
        
        # Group by severity
        severity_counts = {}
        for alert in recent_alerts:
            severity = alert['anomaly_info'].get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_alerts_24h': len(recent_alerts),
            'severity_breakdown': severity_counts,
            'channels_used': list(set([
                channel for alert in recent_alerts 
                for channel in alert.get('channels_sent', [])
            ])),
            'rate_limits_active': len(self.rate_limiter),
            'last_alert': self.alert_history[-1]['timestamp'] if self.alert_history else None
        }
    
    def _get_email_template(self) -> str:
        """Template pentru email"""
        return "email_template"
    
    def _get_slack_template(self) -> str:
        """Template pentru Slack"""
        return "slack_template"
    
    def _get_webhook_template(self) -> str:
        """Template pentru webhook"""
        return "webhook_template"

# Configuration helper
def create_alert_config_from_env() -> AlertConfig:
    """Creaza configuratie din environment variables"""
    return AlertConfig(
        email_enabled=os.getenv('ALERT_EMAIL_ENABLED', 'true').lower() == 'true',
        slack_enabled=os.getenv('ALERT_SLACK_ENABLED', 'true').lower() == 'true',
        webhook_enabled=os.getenv('ALERT_WEBHOOK_ENABLED', 'true').lower() == 'true',
        
        smtp_server=os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
        smtp_port=int(os.getenv('SMTP_PORT', '587')),
        email_username=os.getenv('EMAIL_USERNAME', ''),
        email_password=os.getenv('EMAIL_PASSWORD', ''),
        email_recipients=os.getenv('EMAIL_RECIPIENTS', '').split(',') if os.getenv('EMAIL_RECIPIENTS') else [],
        
        slack_webhook_url=os.getenv('SLACK_WEBHOOK_URL', ''),
        slack_channel=os.getenv('SLACK_CHANNEL', '#security-alerts'),
        
        webhook_urls=os.getenv('WEBHOOK_URLS', '').split(',') if os.getenv('WEBHOOK_URLS') else [],
        
        min_severity=os.getenv('MIN_ALERT_SEVERITY', 'MEDIUM'),
        rate_limit_minutes=int(os.getenv('RATE_LIMIT_MINUTES', '5')),
        max_alerts_per_hour=int(os.getenv('MAX_ALERTS_PER_HOUR', '20'))
    )