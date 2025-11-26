# Code Vulnerability Dashboard

A comprehensive web application for analyzing Python and C++ code to identify security vulnerabilities and suggest secure, efficient replacement code. Supports analyzing individual files, directories, and entire Git repositories.

## Features

- **Git Repository Support**: Clone and analyze entire Git repositories
- **Multi-language Support**: Analyze Python and C++ code
- **Advanced Vulnerability Detection**: 
  - Pattern-based detection for common vulnerabilities
  - **Bandit** integration for Python security scanning
  - **cppcheck** integration for C++ static analysis
- **Intelligent Code Suggestions**: 
  - AI-powered suggestions using OpenAI (optional)
  - Rule-based suggestions with detailed explanations
  - Secure code examples and best practices
- **Interactive Dashboard**: Modern web interface for exploring code and vulnerabilities
- **File Tree Navigation**: Easy navigation through analyzed files
- **Multiple Input Methods**: 
  - Upload files directly
  - Analyze local directories
  - Clone and analyze Git repositories (GitHub, GitLab, etc.)

## Project Structure

```
.
├── backend/                    # FastAPI backend
│   ├── main.py                # API endpoints
│   ├── code_analyzer.py       # Code parsing and structure analysis
│   ├── vulnerability_detector.py # Pattern-based vulnerability detection
│   ├── vulnerability_scanner.py # Integration with Bandit and cppcheck
│   ├── git_handler.py         # Git repository cloning and management
│   ├── model_integration.py   # Legacy model integration
│   ├── enhanced_suggestions.py # AI-powered code suggestions
│   └── requirements.txt
├── frontend/            # React + TypeScript frontend
│   ├── src/
│   │   ├── components/  # React components
│   │   ├── App.tsx      # Main app component
│   │   └── main.tsx     # Entry point
│   ├── package.json
│   └── vite.config.ts
└── README.md
```

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Install external scanning tools (optional but recommended):
```bash
# Bandit is already installed via pip (for Python scanning)
# For cppcheck (C++ scanning):
# On macOS:
brew install cppcheck

# On Ubuntu/Debian:
sudo apt-get install cppcheck

# On Windows:
# Download from: https://github.com/danmar/cppcheck/releases
```

5. (Optional) Set up OpenAI API key for enhanced AI suggestions:
```bash
export OPENAI_API_KEY="your-api-key-here"
```

6. Run the backend server:
```bash
python main.py
```

The API will be available at `http://localhost:8000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The dashboard will be available at `http://localhost:3000`

## Usage

### Analyzing Code

1. **Git Repository Analysis** (Recommended):
   - Enter a Git repository URL (e.g., `https://github.com/user/repo`)
   - Optionally specify a branch name
   - Click "Analyze Git Repo"
   - The platform will clone the repository, scan all Python and C++ files, and display results

2. **Upload Files**:
   - Click "Upload Files" and select Python (.py) or C++ (.cpp, .hpp, etc.) files
   - Files are analyzed immediately upon upload

3. **Analyze Directory**:
   - Enter a local directory path
   - Click "Analyze Directory" to scan all code files in that directory

### Viewing Results

- **File Tree**: Click on files in the sidebar to view their code
- **Vulnerabilities**: View detected vulnerabilities with severity levels
- **Code Suggestions**: Click on any vulnerability to see:
  - Detailed explanation of the vulnerability
  - Secure replacement code
  - Best practices and recommendations

## AI-Powered Suggestions

The system provides intelligent code suggestions through multiple methods:

1. **OpenAI Integration** (Optional):
   - Set `OPENAI_API_KEY` environment variable
   - Uses GPT-4 for comprehensive vulnerability explanations and secure code suggestions
   - Falls back to rule-based suggestions if unavailable

2. **Rule-Based Suggestions**:
   - Comprehensive database of vulnerability patterns
   - Secure code examples for each vulnerability type
   - Best practices and recommendations
   - Always available as fallback

The enhanced suggestion system is configured in `backend/enhanced_suggestions.py`.

## Detected Vulnerabilities

### Python
The system uses both pattern-based detection and **Bandit** for comprehensive Python security scanning:

- SQL Injection
- Command Injection
- Hardcoded Passwords/Credentials
- Weak Cryptography (MD5, SHA1)
- Insecure Random Number Generation
- Eval/Exec Usage (Code Injection)
- Pickle Unsafe Deserialization
- Path Traversal
- XSS (Cross-Site Scripting)
- Insecure Temporary Files
- And 50+ more vulnerability types detected by Bandit

### C++
The system uses both pattern-based detection and **cppcheck** for comprehensive C++ static analysis:

- Buffer Overflow (unsafe string functions)
- Use After Free
- Memory Leaks
- Integer Overflow
- Uninitialized Variables
- Format String Vulnerabilities
- Race Conditions
- Null Pointer Dereferences
- Array Index Out of Bounds
- And 100+ more issues detected by cppcheck

## API Endpoints

- `POST /analyze` - Analyze a single code snippet
- `POST /analyze-directory` - Analyze all files in a directory
- `POST /upload-files` - Upload and analyze multiple files
- `POST /analyze-git-repo` - Clone and analyze a Git repository
  ```json
  {
    "repo_url": "https://github.com/user/repo",
    "branch": "main",  // optional
    "languages": ["python", "cpp"]  // optional, defaults to both
  }
  ```
- `GET /read-file` - Read file content from a cloned repository
- `DELETE /cleanup-repo/{repo_path}` - Clean up a cloned repository

## Quick Start

The easiest way to get started is using the provided startup script:

```bash
chmod +x start.sh
./start.sh
```

This will:
1. Set up the backend virtual environment
2. Install all Python dependencies
3. Start the backend server (port 8000)
4. Install frontend dependencies
5. Start the frontend development server (port 3000)

Then open your browser to `http://localhost:3000`

## Development

### Adding New Vulnerability Patterns

Edit `backend/vulnerability_detector.py` to add new detection patterns:

```python
{
    "name": "Vulnerability Name",
    "pattern": r"regex_pattern",
    "severity": "high|medium|low|critical",
    "description": "Description of the vulnerability"
}
```

### Customizing Model Integration

Modify `backend/model_integration.py` to integrate with your specific model API or local model implementation.

## License

MIT

