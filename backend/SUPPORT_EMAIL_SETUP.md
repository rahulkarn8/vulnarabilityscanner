# Support Email Setup

This document explains how to configure the support email functionality to send customer support emails to `support@daifend.com`.

## Environment Variables

Add the following environment variables to your `.env` file in the `backend` directory:

```env
# SMTP Server Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=your-email@gmail.com

# Support Email Recipient
SUPPORT_EMAIL=support@daifend.com
```

## Gmail Setup (Example)

If using Gmail, you'll need to:

1. **Enable 2-Factor Authentication** on your Google account
2. **Generate an App Password**:
   - Go to [Google Account Settings](https://myaccount.google.com/)
   - Navigate to Security → 2-Step Verification → App passwords
   - Generate a new app password for "Mail"
   - Use this app password as `SMTP_PASSWORD` (not your regular Gmail password)

## Other Email Providers

### Outlook/Office 365
```env
SMTP_SERVER=smtp.office365.com
SMTP_PORT=587
```

### SendGrid
```env
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=your-sendgrid-api-key
```

### AWS SES
```env
SMTP_SERVER=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
```

## Testing

After configuration, test the support email functionality by:

1. Navigate to the Support page in the application
2. Fill in your email address and issue description
3. Click "Send Message"
4. Check that the email arrives at `support@daifend.com`

## Troubleshooting

- **Authentication Failed**: Verify `SMTP_USERNAME` and `SMTP_PASSWORD` are correct
- **Connection Timeout**: Check firewall settings and SMTP server/port
- **Email Not Received**: Check spam folder and verify `SUPPORT_EMAIL` is correct
- **TLS Error**: Ensure `SMTP_PORT` is 587 (TLS) or 465 (SSL)

