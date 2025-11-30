# GitHub OAuth Setup Guide

## Current Backend URL
Your backend is deployed at:
```
https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app
```

## Required Redirect URI
The redirect URI that must be registered in your GitHub OAuth app is:
```
https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/github/callback
```

## Steps to Fix

### 1. Update GitHub OAuth App Settings

1. Go to GitHub Settings → Developer settings → OAuth Apps
   - Direct link: https://github.com/settings/developers

2. Click on your OAuth App (or create a new one if you don't have one)

3. In the "Authorization callback URL" field, add:
   ```
   https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/github/callback
   ```

4. You can have multiple callback URLs. Make sure to include:
   - For local development: `http://localhost:8000/auth/github/callback`
   - For production: `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/github/callback`
   - (Optional) If you have a custom domain: `https://stratum.daifend.ai/auth/github/callback`

5. Click "Update application"

### 2. Verify Environment Variables

Make sure your backend has the correct environment variables set:

1. Go to: https://console.cloud.google.com/run/detail/europe-west1/vulnerability-scanner-backend
2. Click "Edit & Deploy New Revision"
3. Go to "Variables & Secrets" tab
4. Verify these are set:
   - `GITHUB_CLIENT_ID` - Your GitHub OAuth App Client ID
   - `GITHUB_CLIENT_SECRET` - Your GitHub OAuth App Client Secret
   - `GITHUB_REDIRECT_URI` - `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/github/callback`

### 3. Test the OAuth Flow

After updating:
1. Try logging in with GitHub again
2. You should be redirected to GitHub for authorization
3. After authorizing, you should be redirected back to your backend
4. The backend will then redirect you to the frontend with a token

## Troubleshooting

### Error: "redirect_uri is not associated with this application"
- **Cause**: The redirect URI in your GitHub OAuth app doesn't match what the backend is sending
- **Fix**: Make sure the exact URL `https://vulnerability-scanner-backend-oi4goiciua-ew.a.run.app/auth/github/callback` is in your GitHub OAuth app's callback URLs

### Error: "Invalid client_id"
- **Cause**: The `GITHUB_CLIENT_ID` environment variable is not set or incorrect
- **Fix**: Check the environment variables in Cloud Run and make sure `GITHUB_CLIENT_ID` matches your GitHub OAuth App's Client ID

### Error: "Invalid client_secret"
- **Cause**: The `GITHUB_CLIENT_SECRET` environment variable is not set or incorrect
- **Fix**: Check the environment variables in Cloud Run. You may need to regenerate the client secret in GitHub and update it

## Notes

- The redirect URI must match **exactly** (including https, no trailing slash)
- GitHub allows multiple callback URLs, so you can add both localhost and production URLs
- After updating the GitHub OAuth app, changes take effect immediately (no need to wait)

