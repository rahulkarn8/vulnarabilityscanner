# Install Google Cloud CLI (gcloud)

## macOS Installation

### Option 1: Using Homebrew (Recommended - Easiest)

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install gcloud CLI
brew install --cask google-cloud-sdk
```

### Option 2: Direct Download

1. Download the installer from: https://cloud.google.com/sdk/docs/install
2. Run the downloaded `.pkg` file
3. Follow the installation wizard

### Option 3: Using the Interactive Installer

```bash
# Download and run the interactive installer
curl https://sdk.cloud.google.com | bash

# Restart your shell or run:
exec -l $SHELL
```

## After Installation

### 1. Initialize gcloud

```bash
gcloud init
```

This will:
- Prompt you to log in
- Ask you to select or create a project
- Set default compute region/zone

### 2. Authenticate

```bash
gcloud auth login
```

This will open a browser window for you to authenticate with your Google account.

### 3. Set Your Project

```bash
gcloud config set project avian-bricolage-475907-f8
```

### 4. Verify Installation

```bash
gcloud --version
```

You should see output like:
```
Google Cloud SDK 450.0.0
```

## Quick Setup for Deployment

After installing, run these commands to set up for deployment:

```bash
# Authenticate
gcloud auth login

# Set project
gcloud config set project avian-bricolage-475907-f8

# Enable required APIs
gcloud services enable run.googleapis.com artifactregistry.googleapis.com

# Verify
gcloud config list
```

## Troubleshooting

### Command not found after installation

If `gcloud` command is not found:

```bash
# Add to your shell profile (~/.zshrc or ~/.bash_profile)
echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.zshrc
source ~/.zshrc

# Or for bash:
echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bash_profile
source ~/.bash_profile
```

### Check if gcloud is in PATH

```bash
which gcloud
```

If it returns nothing, you need to add it to your PATH.

## Next Steps

Once gcloud is installed:

1. Run the deployment script:
   ```bash
   ./build-and-deploy-containers.sh
   ```

2. Or follow the manual deployment steps in `CONTAINER_DEPLOYMENT.md`

