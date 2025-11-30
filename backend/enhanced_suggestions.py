import os
from typing import Dict, Any, Optional

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


class EnhancedSuggestions:
    """
    Enhanced code suggestions using AI models, with a safe fallback to
    rule-based templates when the OpenAI API is unavailable.
    """

    def __init__(self) -> None:
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        self.openai_client: Optional[OpenAI] = None

        if self.openai_api_key:
            try:
                self.openai_client = OpenAI(api_key=self.openai_api_key)
            except Exception as e:
                # Non-fatal, we just fall back to rule-based suggestions
                print(f"Warning: Could not initialize OpenAI client: {e}")

    # ---------------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------------- #

    async def get_suggestion(
        self,
        code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> str:
        """
        Get an enhanced suggestion for a vulnerability.

        Args:
            code: Full source code of the file.
            language: "python" or "cpp".
            vulnerability: Dict with info: type, severity, description, line_number, code_snippet.

        Returns:
            A human-readable suggestion string including explanation,
            secure code, and best practices where possible.
        """
        # Try OpenAI first if configured
        if self.openai_client:
            try:
                suggestion = await self._get_openai_suggestion(
                    code=code,
                    language=language,
                    vulnerability=vulnerability,
                )
                if suggestion:
                    return suggestion
            except Exception as e:
                print(f"OpenAI suggestion failed, falling back to rules: {e}")

        # Fallback to rule-based suggestions
        return self._get_rule_based_suggestion(code, language, vulnerability)

    # ---------------------------------------------------------------------- #
    # OpenAI-backed suggestions
    # ---------------------------------------------------------------------- #

    async def _get_openai_suggestion(
        self,
        code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> Optional[str]:
        """
        Get suggestion from OpenAI API with timeout to prevent slow responses.

        Returns:
            The full text suggestion or None if something goes wrong.
        """
        if not self.openai_client:
            return None
        
        # Add timeout to prevent API from hanging
        import asyncio

        vuln_type = vulnerability.get("type", "Unknown")
        severity = vulnerability.get("severity", "medium")
        description = vulnerability.get("description", "")
        line_number = vulnerability.get("line_number", 0)
        code_snippet = vulnerability.get("code_snippet", "")

        # Limit context size to avoid oversized prompts
        context_prefix = code[:2000]

        prompt = f"""
You are an expert secure coding reviewer and application security engineer.

Analyze the following {language} code vulnerability and propose a secure fix.

VULNERABILITY:
- Type: {vuln_type}
- Severity: {severity}
- Description: {description}
- Line Number: {line_number}

VULNERABLE SNIPPET:
```{language}
{code_snippet}
```

CONTEXT (First 2000 chars):
```{language}
{context_prefix}
```

Please provide:
1. A brief explanation of why this is vulnerable
2. Secure replacement code
3. Best practices to follow

Format your response as:
EXPLANATION: [brief explanation]
SECURE_CODE: [replacement code]
BEST_PRACTICES: [key points]
"""

        try:
            # Add timeout to prevent API from hanging (5 seconds max)
            import asyncio
            loop = asyncio.get_event_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self.openai_client.chat.completions.create(
                        model="gpt-4-turbo-preview",
                        messages=[
                            {
                                "role": "system",
                                "content": "You are an expert cybersecurity and code security specialist. Provide clear, secure, and efficient code replacements."
                            },
                            {
                                "role": "user",
                                "content": prompt
                            }
                        ],
                        max_tokens=1000,
                        temperature=0.3
                    )
                ),
                timeout=5.0  # 5 second timeout
            )
            
            suggestion_text = response.choices[0].message.content
            
            # Extract the secure code section if available
            if "SECURE_CODE:" in suggestion_text:
                parts = suggestion_text.split("SECURE_CODE:")
                if len(parts) > 1:
                    code_part = parts[1].split("BEST_PRACTICES:")[0].strip()
                    return f"{suggestion_text}\n\n{code_part}"
            
            return suggestion_text
        
        except Exception as e:
            print(f"Error getting OpenAI suggestion: {e}")
            return None

    # ---------------------------------------------------------------------- #
    # Rule-based suggestions (fallback)
    # ---------------------------------------------------------------------- #

    def _get_rule_based_suggestion(self, code: str, language: str, vulnerability: Dict[str, Any]) -> str:
        """Fallback rule-based suggestions"""
        vuln_type = vulnerability.get('type', '')
        code_snippet = vulnerability.get('code_snippet', '')
        line_num = vulnerability.get('line_number', 0)
        description = vulnerability.get('description', '')
        
        if language == "python":
            return self._python_suggestions(vuln_type, code_snippet, description)
        else:
            return self._cpp_suggestions(vuln_type, code_snippet, description)
    
    def _python_suggestions(self, vuln_type: str, snippet: str, description: str) -> str:
        """Python-specific rule-based suggestions"""
        suggestions = {
            "SQL Injection": """
EXPLANATION: Using string concatenation in SQL queries allows attackers to inject malicious SQL code.

SECURE_CODE:
# Use parameterized queries with the database connector
# Example with sqlite3:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Example with psycopg2 (PostgreSQL):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Example with MySQL:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Example with SQLAlchemy:
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE id = :user_id"), {"user_id": user_id})

BEST_PRACTICES:
- Always use parameterized queries
- Validate and sanitize user input
- Use ORMs when possible (SQLAlchemy, Django ORM)
- Implement proper error handling
- Use least privilege database accounts
""",
            "Command Injection": """
EXPLANATION: Using os.system() or subprocess with shell=True allows command injection if user input is not properly sanitized.

SECURE_CODE:
# Use subprocess.run() with a list of arguments (avoid shell=True)
import subprocess

# Instead of: os.system(f"ls {user_input}")
result = subprocess.run(['ls', user_input], capture_output=True, text=True, check=True)

# For commands that need shell features, use shlex.quote()
import shlex
safe_input = shlex.quote(user_input)
result = subprocess.run(['bash', '-c', f'command {safe_input}'], capture_output=True, text=True)

# Alternative: Use specific Python libraries instead of shell commands
# Example: Use pathlib instead of shell commands for file operations

BEST_PRACTICES:
- Never use os.system() with user input
- Use subprocess.run() with argument lists
- Validate and sanitize all user inputs
- Use shlex.quote() if shell is unavoidable
- Prefer Python libraries over shell commands
""",
            "Hardcoded Password": """
EXPLANATION: Hardcoded credentials in source code are a critical security risk as they can be exposed in version control.

SECURE_CODE:
# Use environment variables
import os
password = os.getenv('DB_PASSWORD')
if not password:
    raise ValueError("DB_PASSWORD environment variable not set")

# Use a configuration file (not in version control)
# config.py (in .gitignore)
# PASSWORD = "secret"

# Use secrets management systems
# Example with python-decouple:
from decouple import config
password = config('DB_PASSWORD')

# For production, use secret managers like:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault

BEST_PRACTICES:
- Never commit credentials to version control
- Use environment variables for configuration
- Use secret management services in production
- Rotate credentials regularly
- Use .env files (and add to .gitignore)
- Implement proper access controls
""",
            "Weak Cryptography": """
EXPLANATION: MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks.

SECURE_CODE:
# For general hashing (SHA-256)
import hashlib
hash_value = hashlib.sha256(data.encode()).hexdigest()

# For password hashing (use bcrypt, argon2, or scrypt)
import bcrypt
# Hashing
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode(), salt)

# Verification
if bcrypt.checkpw(password.encode(), hashed):
    print("Password matches")

# Alternative: Use argon2 (more modern)
# pip install argon2-cffi
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)

BEST_PRACTICES:
- Use SHA-256 or SHA-3 for general hashing
- Use bcrypt, argon2, or scrypt for password hashing
- Use proper salt generation
- Use cryptographically secure random number generators
- Never use MD5 or SHA1 for security purposes
""",
            "Eval Usage": """
EXPLANATION: eval() and exec() can execute arbitrary Python code, leading to code injection attacks.

SECURE_CODE:
# For evaluating literals only:
import ast
try:
    result = ast.literal_eval(user_input)  # Only evaluates literals
except (ValueError, SyntaxError):
    print("Invalid input")

# For JSON data:
import json
result = json.loads(user_input)

# For mathematical expressions, use a safe evaluator:
import operator
import ast

# Safe operators only
safe_operators = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def safe_eval(expr):
    node = ast.parse(expr, mode='eval')
    if all(isinstance(n, (ast.Constant, ast.BinOp, ast.UnaryOp)) 
           for n in ast.walk(node)):
        return eval(compile(node, '<string>', 'eval'))
    raise ValueError("Unsafe expression")

BEST_PRACTICES:
- Avoid eval() and exec() with user input
- Use ast.literal_eval() for literals
- Use JSON parsing for structured data
- Implement a safe expression evaluator if needed
- Validate and sanitize all inputs
- Use whitelisting instead of blacklisting
""",
        }
        
        # AI-powered attack specific suggestions
        ai_attack_suggestions = {
            "Prompt Injection": """
EXPLANATION: User input is directly passed to LLM without validation, allowing prompt injection attacks.

SECURE_CODE:
# Use prompt templates with input escaping
from langchain.prompts import PromptTemplate

# Define a secure prompt template
template = PromptTemplate(
    input_variables=["user_input"],
    template="You are a helpful assistant. User question: {user_input}"
)

# Sanitize user input before passing to LLM
def sanitize_input(user_input: str) -> str:
    # Remove or escape special prompt characters
    sanitized = user_input.replace("{", "{{").replace("}", "}}")
    # Limit input length
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000]
    return sanitized

# Use the template with sanitized input
user_input = sanitize_input(request.json.get("user_input", ""))
prompt = template.format(user_input=user_input)
response = llm.generate(prompt)

# Alternative: Use structured inputs with role separation
messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": sanitize_input(user_input)}
]
response = openai.ChatCompletion.create(model="gpt-4", messages=messages)

BEST_PRACTICES:
- Always sanitize and validate user inputs before passing to LLM
- Use prompt templates instead of string concatenation
- Implement input length limits
- Separate system prompts from user content
- Use role-based message structures
- Implement output validation
- Monitor for suspicious prompt patterns
""",
            "AI Model: Hardcoded API Keys": """
EXPLANATION: API keys hardcoded in source code can be stolen and abused.

SECURE_CODE:
# Use environment variables
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set")

# Use secure key management (AWS Secrets Manager example)
import boto3
client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='openai-api-key')
api_key = response['SecretString']

BEST_PRACTICES:
- Never commit API keys to version control
- Use environment variables or secret management services
- Rotate API keys regularly
- Use different keys for different environments
- Implement key access logging
""",
            "AI Model: Missing Rate Limiting": """
EXPLANATION: AI API calls without rate limiting are vulnerable to abuse and cost attacks.

SECURE_CODE:
# Implement rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"]
)

@app.route("/chat", methods=["POST"])
@limiter.limit("5 per minute")
def chat():
    # Your AI API call here
    pass

# Implement cost controls
class AICostController:
    def __init__(self, max_cost_per_day=100):
        self.max_cost_per_day = max_cost_per_day
        self.daily_cost = 0
    
    def check_cost(self, estimated_cost):
        if self.daily_cost + estimated_cost > self.max_cost_per_day:
            raise ValueError("Daily cost limit exceeded")
        self.daily_cost += estimated_cost

BEST_PRACTICES:
- Implement rate limiting per user/IP
- Set cost budgets and alerts
- Monitor API usage
- Set maximum token limits
""",
            "AI Model: Unvalidated Model Output": """
EXPLANATION: AI model outputs used without validation can contain malicious content.

SECURE_CODE:
# Validate and sanitize AI outputs
import re
from html import escape

def validate_ai_output(output: str) -> str:
    # Check for code injection attempts
    dangerous_patterns = [
        re.compile(r"<script.*?>", re.IGNORECASE),
        re.compile(r"eval\\s*\\(", re.IGNORECASE),
        re.compile(r"exec\\s*\\(", re.IGNORECASE),
        re.compile(r"__import__", re.IGNORECASE),
        re.compile(r"subprocess\\.", re.IGNORECASE),
    ]
    
    for pattern in dangerous_patterns:
        if pattern.search(output):
            raise ValueError("Potentially malicious output detected")
    
    # Sanitize HTML if displaying in web
    sanitized = escape(output)
    
    # Limit output length
    if len(sanitized) > 10000:
        sanitized = sanitized[:10000]
    
    return sanitized

# Use output validation
response = llm.generate(prompt)
validated_output = validate_ai_output(response.text)

BEST_PRACTICES:
- Always validate AI outputs before use
- Sanitize outputs for display
- Use content filtering
- Implement output length limits
- Check for malicious patterns
""",
            "AI Code Generation: Unsafe Code Execution": """
EXPLANATION: Executing AI-generated code without validation is extremely dangerous.

SECURE_CODE:
# NEVER execute AI-generated code directly
# Instead, use code review and sandboxing

import ast
import subprocess
import tempfile
import os

def safe_code_review(code: str) -> bool:
    \"\"\"Review AI-generated code for safety\"\"\"
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    
    # Check for dangerous operations
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ['eval', 'exec', 'compile', '__import__']:
                    return False
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ['system', 'popen', 'call']:
                    return False
    
    return True

def execute_in_sandbox(code: str) -> str:
    \"\"\"Execute code in isolated sandbox\"\"\"
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        temp_file = f.name
    
    try:
        result = subprocess.run(
            ['python', temp_file],
            capture_output=True,
            text=True,
            timeout=5,
            env={'PATH': '/usr/bin'}
        )
        return result.stdout
    finally:
        os.unlink(temp_file)

# Usage
if safe_code_review(ai_generated_code):
    output = execute_in_sandbox(ai_generated_code)
else:
    raise ValueError("Code failed safety review")

BEST_PRACTICES:
- Never execute AI-generated code directly
- Always review code before execution
- Use static analysis tools
- Execute in sandboxed environments
- Implement timeouts and resource limits
""",
        }
        
        # Check for AI attack vulnerabilities first
        for key, suggestion in ai_attack_suggestions.items():
            if key.lower() in vuln_type.lower() or "ai" in vuln_type.lower() or "prompt" in vuln_type.lower():
                return suggestion
        
        # Try to match vulnerability type
        for key, suggestion in suggestions.items():
            if key.lower() in vuln_type.lower():
                return suggestion
        
        return f"""EXPLANATION: {description}

RECOMMENDATION:
Review the vulnerable code and apply security best practices:
1. Validate and sanitize all user inputs
2. Use secure alternatives to dangerous functions
3. Follow language-specific security guidelines
4. Keep dependencies updated
5. Perform regular security audits

VULNERABLE_CODE:
{snippet}

Please consult security documentation for {vuln_type} vulnerabilities."""
    
    def _cpp_suggestions(self, vuln_type: str, snippet: str, description: str) -> str:
        """C++-specific rule-based suggestions"""
        suggestions = {
            "Buffer Overflow": """
EXPLANATION: Unsafe string functions like strcpy, strcat, sprintf can cause buffer overflows if the destination buffer is not large enough.

SECURE_CODE:
// Use safe string functions with bounds checking
#include <cstring>

// Instead of: strcpy(dest, src);
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\\0';

// Better: Use C++ std::string
#include <string>
std::string dest = src;  // Safe and automatic memory management

// Or use std::array or std::vector
#include <array>
std::array<char, 256> buffer;
// Safe operations...

BEST_PRACTICES:
- Prefer C++ std::string over C-style strings
- Use strncpy with explicit size limits
- Always null-terminate strings
- Use std::array or std::vector for fixed-size buffers
- Enable compiler warnings (-Wall, -Wextra)
- Use static analysis tools
""",
            "Use After Free": """
EXPLANATION: Accessing memory after it has been freed can lead to undefined behavior and security vulnerabilities.

SECURE_CODE:
// Set pointer to nullptr after deletion
delete ptr;
ptr = nullptr;  // Prevent use after free

// Better: Use smart pointers
#include <memory>

// Instead of: int* ptr = new int(42);
std::unique_ptr<int> ptr = std::make_unique<int>(42);
// Automatically freed when out of scope

// For shared ownership:
std::shared_ptr<int> shared_ptr = std::make_shared<int>(42);

BEST_PRACTICES:
- Use smart pointers (std::unique_ptr, std::shared_ptr) instead of raw pointers
- Set pointers to nullptr after delete/free
- Use RAII (Resource Acquisition Is Initialization)
- Avoid manual memory management when possible
- Use modern C++ features (C++11 and later)
""",
            "Memory Leak": """
EXPLANATION: Memory allocated with new must be deallocated with delete. Forgetting to delete leads to memory leaks.

SECURE_CODE:
// Use smart pointers for automatic memory management
#include <memory>

// Instead of: int* arr = new int[100];
std::unique_ptr<int[]> arr(new int[100]);
// Automatically deleted when out of scope

// Or use std::vector (even better)
#include <vector>
std::vector<int> arr(100);  // Automatic memory management

// For custom classes, use RAII
class Resource {
    int* data;
public:
    Resource() : data(new int[100]) {}
    ~Resource() { delete[] data; }  // RAII: automatic cleanup
    // Delete copy constructor and assignment operator if needed
    Resource(const Resource&) = delete;
    Resource& operator=(const Resource&) = delete;
};

BEST_PRACTICES:
- Prefer std::vector over new[]/delete[]
- Use smart pointers (std::unique_ptr, std::shared_ptr)
- Implement RAII pattern
- Use containers from standard library
- Use static analysis tools to detect leaks
""",
            "Format String": """
EXPLANATION: Format string vulnerabilities occur when user input is passed directly to printf-like functions, allowing attackers to read or write memory.

SECURE_CODE:
// Always use format specifiers
char user_input[100];
// Instead of: printf(user_input);
printf("%s", user_input);

// Better: Use C++ streams
#include <iostream>
std::cout << user_input;

// Or use std::format (C++20)
#include <format>
std::cout << std::format("{}", user_input);

// For formatted output:
std::cout << std::format("Value: {}", value);

BEST_PRACTICES:
- Always use format specifiers in printf-like functions
- Prefer C++ streams (std::cout, std::cerr) over printf
- Use std::format in C++20
- Validate and sanitize user input
- Use const char* for format strings
""",
        }
        
        # Try to match vulnerability type
        for key, suggestion in suggestions.items():
            if key.lower() in vuln_type.lower():
                return suggestion
        
        return f"""EXPLANATION: {description}

RECOMMENDATION:
Review the vulnerable code and apply security best practices:
1. Use modern C++ features (C++11 and later)
2. Prefer smart pointers over raw pointers
3. Use standard library containers
4. Enable compiler warnings and static analysis
5. Follow C++ Core Guidelines

VULNERABLE_CODE:
{snippet}

Please consult security documentation for {vuln_type} vulnerabilities."""
