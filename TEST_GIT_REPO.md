# Testing Git Repository Feature

## Quick Test Options

### Option 1: Test with Local Repository Path
The Git repository analyzer supports local Git repositories. However, the current implementation primarily supports remote URLs. For full testing, use Option 2 or 3.

### Option 2: Test with GitHub Repository
1. Create a new repository on GitHub
2. Push the test files from `test_repo/` directory
3. Use the repository URL in the web interface

### Option 3: Use Existing Test Repository
You can test with any public GitHub repository that contains Python or C++ code.

## Test Repository Created

A local test repository has been created at:
```
/Users/personalrk/Downloads/vulnerabilityscanner/test_repo/
```

This repository contains:
- `test_vulnerable.py` - 10+ Python vulnerabilities
- `test_vulnerable.cpp` - 10+ C++ vulnerabilities  
- `test_safer.py` - Secure Python examples
- `test_safer.cpp` - Secure C++ examples

## How to Test

### Method 1: Push to GitHub (Recommended)

1. **Create a GitHub repository:**
   ```bash
   cd /Users/personalrk/Downloads/vulnerabilityscanner/test_repo
   # Create a new repo on GitHub, then:
   git remote add origin https://github.com/YOUR_USERNAME/test-vulnerable-repo.git
   git branch -M main
   git push -u origin main
   ```

2. **Test in the web interface:**
   - Go to http://localhost:3000
   - Enter: `https://github.com/YOUR_USERNAME/test-vulnerable-repo`
   - Click "Analyze Git Repo"
   - Review the results!

### Method 2: Test with Public Repository

Test with any existing public repository:
- `https://github.com/python/cpython` (Python examples)
- `https://github.com/facebook/folly` (C++ examples)
- Any repository with `.py` or `.cpp` files

### Method 3: Quick Test Repository

I can create a minimal test repository for you. Just let me know!

## Expected Results

When you analyze the test repository, you should see:

1. **Multiple files detected** (test_vulnerable.py, test_vulnerable.cpp, etc.)
2. **Vulnerabilities found:**
   - SQL Injection
   - Command Injection
   - Hardcoded Passwords
   - Buffer Overflows
   - Memory Leaks
   - And more...

3. **AI-powered suggestions** for each vulnerability
4. **File tree navigation** to browse all files
5. **Code viewer** to see vulnerable code snippets

## Troubleshooting

### Backend Not Running
```bash
cd backend
source venv/bin/activate
python main.py
```

### Git Clone Issues
- Make sure Git is installed: `git --version`
- Check repository URL is valid
- Ensure repository is public or you have access

### No Files Found
- Repository might not have Python/C++ files
- Check repository URL is correct
- Verify the repository exists

