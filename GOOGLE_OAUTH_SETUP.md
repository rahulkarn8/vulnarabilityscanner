# Google OAuth Setup Guide

## Current Backend URL
Your backend is deployed at:
```
https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app
```

## Required Redirect URI
The redirect URI that must be registered in your Google OAuth app is:
```
https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback
```

## Steps to Fix "redirect_uri_mismatch" Error

### 1. Update Google OAuth App Settings

1. Go to Google Cloud Console → APIs & Services → Credentials
   - Direct link: https://console.cloud.google.com/apis/credentials

2. Find your OAuth 2.0 Client ID (or create a new one if you don't have one)

3. Click on the OAuth 2.0 Client ID to edit it

4. Under "Authorized redirect URIs", click "ADD URI"

5. Add this exact URL:
   ```
   https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback
   ```

6. You can also add for local development:
   ```
   http://localhost:8000/auth/google/callback
   ```

7. Click "SAVE"

### 2. Verify Environment Variables

Make sure your backend has the correct environment variables set:

1. Go to: https://console.cloud.google.com/run/detail/europe-west1/vulnerability-scanner-backend
2. Click "Edit & Deploy New Revision"
3. Go to "Variables & Secrets" tab
4. Verify these are set:
   - `GOOGLE_CLIENT_ID` - Your Google OAuth Client ID
   - `GOOGLE_CLIENT_SECRET` - Your Google OAuth Client Secret
   - `GOOGLE_REDIRECT_URI` - `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback`

### 3. Create Google OAuth App (if you don't have one)

If you don't have a Google OAuth app yet:

1. Go to: https://console.cloud.google.com/apis/credentials
2. Click "CREATE CREDENTIALS" → "OAuth client ID"
3. If prompted, configure the OAuth consent screen first:
   - User Type: External (or Internal if using Google Workspace)
   - App name: "Stratum Security Scanner"
   - User support email: Your email
   - Developer contact: Your email
   - Click "SAVE AND CONTINUE"
   - Add scopes: `email`, `profile`, `openid`
   - Click "SAVE AND CONTINUE"
   - Add test users if needed
   - Click "SAVE AND CONTINUE"
   - Review and submit

4. Create OAuth Client ID:
   - Application type: "Web application"
   - Name: "Stratum Backend"
   - Authorized redirect URIs: 
     ```
     https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback
     ```
   - Click "CREATE"

5. Copy the Client ID and Client Secret

6. Add them to Cloud Run environment variables:
   - `GOOGLE_CLIENT_ID` = Your Client ID
   - `GOOGLE_CLIENT_SECRET` = Your Client Secret

### 4. Test the OAuth Flow

After updating:
1. Try logging in with Google again
2. You should be redirected to Google for authorization
3. After authorizing, you should be redirected back to your backend
4. The backend will then redirect you to the frontend with a token

## Troubleshooting

### Error: "redirect_uri_mismatch"
- **Cause**: The redirect URI in your Google OAuth app doesn't match what the backend is sending
- **Fix**: Make sure the exact URL `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback` is in your Google OAuth app's authorized redirect URIs
- **Important**: The URL must match **exactly** (including https, no trailing slash)

### Error: "Invalid client_id"
- **Cause**: The `GOOGLE_CLIENT_ID` environment variable is not set or incorrect
- **Fix**: Check the environment variables in Cloud Run and make sure `GOOGLE_CLIENT_ID` matches your Google OAuth Client ID

### Error: "Invalid client_secret"
- **Cause**: The `GOOGLE_CLIENT_SECRET` environment variable is not set or incorrect
- **Fix**: Check the environment variables in Cloud Run. You may need to regenerate the client secret in Google Cloud Console and update it

### Error: "Access blocked: This app's request is invalid"
- **Cause**: OAuth consent screen is not configured or app is in testing mode
- **Fix**: 
  1. Go to OAuth consent screen: https://console.cloud.google.com/apis/credentials/consent
  2. Make sure the app is published (or add test users if in testing mode)
  3. Ensure required scopes are added

## Notes

- The redirect URI must match **exactly** (including https, no trailing slash)
- Google allows multiple redirect URIs, so you can add both localhost and production URLs
- After updating the Google OAuth app, changes take effect immediately
- If your app is in "Testing" mode, you need to add test users in the OAuth consent screen

## Quick Checklist

- [ ] Google OAuth Client ID created
- [ ] Redirect URI added: `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/google/callback`
- [ ] `GOOGLE_CLIENT_ID` set in Cloud Run environment variables
- [ ] `GOOGLE_CLIENT_SECRET` set in Cloud Run environment variables
- [ ] `GOOGLE_REDIRECT_URI` set in Cloud Run environment variables (optional, will use default if not set)
- [ ] OAuth consent screen configured
- [ ] App published or test users added (if in testing mode)

