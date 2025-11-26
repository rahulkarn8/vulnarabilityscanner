"""
Support email functionality for sending customer support emails to support@daifend.com
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Email configuration from environment variables
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SUPPORT_EMAIL = os.getenv('SUPPORT_EMAIL', 'support@daifend.com')
FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USERNAME)  # Email address to send from

def send_support_email(customer_email: str, issue: str) -> tuple[bool, Optional[str]]:
    """
    Send a support email to support@daifend.com from a customer.
    
    Args:
        customer_email: The email address of the customer
        issue: The issue or question description
        
    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    # Validate required configuration
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        return False, "Email server configuration is missing. Please configure SMTP_USERNAME and SMTP_PASSWORD environment variables."
    
    if not FROM_EMAIL:
        return False, "FROM_EMAIL environment variable is not set."
    
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = SUPPORT_EMAIL
        msg['Reply-To'] = customer_email  # Set reply-to to customer email
        msg['Subject'] = f"Support Request from {customer_email}"
        
        # Create email body
        body = f"""
New support request received from Daifend Platform

Customer Email: {customer_email}
Issue/Question:
{issue}

---
This email was sent from the Daifend Support Page.
Please reply directly to this email to respond to the customer.
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Enable encryption
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        return True, None
        
    except smtplib.SMTPAuthenticationError:
        return False, "Email authentication failed. Please check SMTP_USERNAME and SMTP_PASSWORD."
    except smtplib.SMTPException as e:
        return False, f"SMTP error occurred: {str(e)}"
    except Exception as e:
        return False, f"Failed to send email: {str(e)}"

