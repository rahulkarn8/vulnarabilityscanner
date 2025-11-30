# Security Measures

This document outlines the security measures implemented to protect the application from brute force attacks and other security threats.

## Implemented Security Features

### 1. Rate Limiting
- **Global Rate Limiting**: 60 requests per minute per IP address
- **Login Rate Limiting**: Maximum 5 login attempts per 15 minutes per IP/email combination
- **Registration Rate Limiting**: Maximum 5 registration attempts per hour per IP
- **Automatic Blocking**: IPs are temporarily blocked after exceeding limits

### 2. Brute Force Protection
- **Login Attempt Tracking**: All login attempts are tracked by IP address and email
- **Progressive Lockout**: After 5 failed login attempts, the account is locked for 15 minutes
- **Automatic Reset**: Lockouts automatically expire after the timeout period
- **Failed Attempt Counter**: Tracks consecutive failed attempts per IP/email

### 3. Security Headers
The following security headers are automatically added to all responses:
- `X-Content-Type-Options: nosniff` - Prevents MIME type sniffing
- `X-Frame-Options: DENY` - Prevents clickjacking attacks
- `X-XSS-Protection: 1; mode=block` - Enables XSS filtering
- `Strict-Transport-Security` - Forces HTTPS connections
- `Content-Security-Policy` - Restricts resource loading
- `Referrer-Policy` - Controls referrer information
- `Permissions-Policy` - Restricts browser features

### 4. Database-Level Protection
- **Login Attempts Table**: Tracks all login attempts with timestamps and blocking status
- **Registration Attempts Table**: Tracks registration attempts to prevent spam
- **Indexed Queries**: Fast lookups for rate limiting checks

## Google Cloud Run Security Recommendations

### 1. Cloud Armor (Recommended)
For additional protection, enable Google Cloud Armor:

```bash
# Create a security policy
gcloud compute security-policies create stratum-security-policy \
    --description "Security policy for Stratum API"

# Add rate limiting rule (100 requests per minute per IP)
gcloud compute security-policies rules create 1000 \
    --security-policy stratum-security-policy \
    --expression "true" \
    --action rate-based-ban \
    --rate-limit-threshold-count 100 \
    --rate-limit-threshold-interval-sec 60 \
    --ban-duration-sec 300 \
    --conform-action allow \
    --exceed-action deny-429 \
    --enforce-on-key IP

# Attach to Cloud Run service (requires Load Balancer)
# Note: Cloud Run services need to be behind a Load Balancer to use Cloud Armor
```

### 2. Cloud Run Service Configuration
- **Min Instances**: Set to 0 to prevent constant resource usage
- **Max Instances**: Limit to prevent resource exhaustion
- **Timeout**: Set appropriate timeout values
- **Memory/CPU**: Allocate sufficient resources to handle legitimate traffic

### 3. IP Allowlisting (Optional)
For additional security, you can restrict access to specific IPs:

```bash
# Update Cloud Run service to only allow specific IPs
# This requires setting up a Load Balancer with Cloud Armor
```

### 4. Monitoring and Alerting
Set up monitoring for:
- High rate of 429 (Too Many Requests) responses
- Unusual traffic patterns
- Failed login attempts
- Blocked IP addresses

```bash
# Create alert for high error rate
gcloud alpha monitoring policies create \
    --notification-channels=CHANNEL_ID \
    --display-name="High 429 Rate" \
    --condition-display-name="429 rate > 10/min" \
    --condition-threshold-value=10 \
    --condition-threshold-duration=60s
```

## Configuration

### Environment Variables
- `FREE_SCAN_LIMIT`: Number of free scans allowed (default: 5)
- Rate limiting thresholds are configurable in `security_middleware.py`

### Adjusting Rate Limits
To adjust rate limits, modify:
1. **Global Rate Limit**: `RateLimitMiddleware` in `security_middleware.py`
2. **Login Rate Limit**: `check_login_brute_force` function in `auth.py`
3. **Registration Rate Limit**: `register` function in `auth.py`

## Testing Security Measures

### Test Rate Limiting
```bash
# Test global rate limit (should fail after 60 requests)
for i in {1..65}; do
  curl -X GET https://your-api-url/health
done
```

### Test Login Brute Force Protection
```bash
# Test login rate limit (should block after 5 attempts)
for i in {1..6}; do
  curl -X POST https://your-api-url/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong"}'
done
```

## Best Practices

1. **Monitor Logs**: Regularly review logs for suspicious activity
2. **Update Dependencies**: Keep all dependencies up to date
3. **Use HTTPS**: Always use HTTPS in production
4. **Strong Passwords**: Enforce strong password requirements
5. **Regular Audits**: Conduct regular security audits
6. **Backup Data**: Regularly backup user data and logs

## Additional Recommendations

1. **WAF (Web Application Firewall)**: Consider using Cloud Armor or similar WAF
2. **DDoS Protection**: Use Google Cloud's DDoS protection
3. **IP Reputation**: Consider integrating IP reputation services
4. **CAPTCHA**: Add CAPTCHA for sensitive operations
5. **Two-Factor Authentication**: Consider adding 2FA for user accounts
6. **Session Management**: Implement proper session timeout and rotation

## Incident Response

If you detect a brute force attack:
1. Check Cloud Run logs for the attacking IP
2. Review blocked IPs in the `login_attempts` table
3. Consider manually blocking IPs in Cloud Armor
4. Monitor for any successful unauthorized access
5. Review and rotate any potentially compromised credentials

