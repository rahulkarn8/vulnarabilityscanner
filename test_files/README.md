# Test Files for Vulnerability Scanner

This directory contains test files with intentional security vulnerabilities to test the vulnerability scanner.

## Test Files

### Python Files

1. **`test_vulnerable.py`** - Contains multiple intentional vulnerabilities:
   - SQL Injection (string concatenation)
   - Command Injection (os.system, subprocess)
   - Hardcoded Passwords
   - Weak Cryptography (MD5, SHA1)
   - Insecure Random
   - Eval Usage
   - Pickle Unsafe Deserialization
   - Path Traversal
   - Assert in Code
   - Exec Usage

2. **`test_safer.py`** - Shows safer alternatives:
   - Parameterized SQL queries
   - Safe subprocess usage
   - Secure random generation
   - Strong cryptography (SHA-256, bcrypt)
   - Safe alternatives to eval/pickle
   - Proper path validation

### C++ Files

1. **`test_vulnerable.cpp`** - Contains multiple intentional vulnerabilities:
   - Buffer Overflow (strcpy, strcat, sprintf)
   - Use After Free
   - Memory Leaks
   - Format String Vulnerabilities
   - Integer Overflow
   - Uninitialized Variables
   - Null Pointer Dereference
   - Double Free
   - Array Index Out of Bounds
   - Race Conditions

2. **`test_safer.cpp`** - Shows safer alternatives:
   - std::string usage
   - Safe string functions (strncpy with bounds)
   - Smart pointers (unique_ptr, shared_ptr)
   - Format string safety
   - Bounds checking
   - Thread safety (mutex)

## How to Test

### Option 1: Upload Files
1. Go to the web application
2. Click "Upload Files"
3. Select both `test_vulnerable.py` and `test_vulnerable.cpp`
4. View the detected vulnerabilities

### Option 2: Analyze Directory
1. Go to the web application
2. Enter the path to this `test_files` directory
3. Click "Analyze Directory"
4. Review all detected vulnerabilities

### Option 3: Git Repository (if you push these to a repo)
1. Push these files to a GitHub repository
2. Enter the repository URL in the web app
3. Click "Analyze Git Repo"
4. Review the analysis results

## Expected Results

### test_vulnerable.py
Should detect:
- Multiple SQL Injection vulnerabilities
- Command Injection (os.system, subprocess)
- Hardcoded credentials
- Weak cryptography (MD5, SHA1)
- Insecure random usage
- Eval/Exec usage
- Pickle unsafe deserialization
- Path traversal
- Assert statements

### test_vulnerable.cpp
Should detect:
- Buffer overflow vulnerabilities (strcpy, strcat, sprintf)
- Use after free
- Memory leaks
- Format string vulnerabilities
- Integer overflow potential
- Uninitialized variables
- Potential null pointer dereference
- Double free
- Array bounds issues
- Race condition potential

### test_safer.py and test_safer.cpp
Should have significantly fewer or no vulnerabilities detected, as they use secure coding practices.

## Notes

- These files contain intentional vulnerabilities for testing purposes
- **DO NOT** use these patterns in production code
- The safer versions show recommended secure coding practices
- Bandit and cppcheck should catch most of these automatically

