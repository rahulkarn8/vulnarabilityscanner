import os
import requests
from typing import Dict, Any, Optional, List
import json


class ModelIntegration:
    """Integration with trained model for code replacement suggestions"""
    
    def __init__(self):
        # Configuration for model API
        self.model_api_url = os.getenv("MODEL_API_URL", "http://localhost:5000/api/suggest")
        self.use_local_model = os.getenv("USE_LOCAL_MODEL", "false").lower() == "true"
        self.model_path = os.getenv("MODEL_PATH", "./models/vulnerability_fixer")
    
    async def get_suggestion(self, code: str, language: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """
        Get code replacement suggestion from trained model
        
        Args:
            code: Full source code
            language: Programming language (python or cpp)
            vulnerability: Vulnerability information dict
        
        Returns:
            Suggested replacement code or None
        """
        try:
            if self.use_local_model:
                return self._get_local_suggestion(code, language, vulnerability)
            else:
                return await self._get_api_suggestion(code, language, vulnerability)
        except Exception as e:
            print(f"Error getting model suggestion: {e}")
            return self._get_rule_based_suggestion(code, language, vulnerability)
    
    async def _get_api_suggestion(self, code: str, language: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Get suggestion from model API"""
        try:
            payload = {
                "code": code,
                "language": language,
                "vulnerability": vulnerability,
                "line_number": vulnerability.get("line_number"),
                "vulnerability_type": vulnerability.get("type")
            }
            
            response = requests.post(
                self.model_api_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("suggested_code")
            else:
                return None
        except Exception as e:
            print(f"API request failed: {e}")
            return None
    
    def _get_local_suggestion(self, code: str, language: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Get suggestion from local model (placeholder for actual model loading)"""
        # This would load and run a local model (e.g., transformers, onnx, etc.)
        # For now, return rule-based suggestion
        return self._get_rule_based_suggestion(code, language, vulnerability)
    
    def _get_rule_based_suggestion(self, code: str, language: str, vulnerability: Dict[str, Any]) -> str:
        """Fallback rule-based suggestions"""
        vuln_type = vulnerability.get("type", "")
        code_snippet = vulnerability.get("code_snippet", "")
        line_num = vulnerability.get("line_number", 0)
        lines = code.split('\n')
        
        if language == "python":
            return self._python_suggestions(vuln_type, code_snippet, lines, line_num)
        else:
            return self._cpp_suggestions(vuln_type, code_snippet, lines, line_num)
    
    def _python_suggestions(self, vuln_type: str, snippet: str, lines: List[str], line_num: int) -> str:
        """Python-specific rule-based suggestions"""
        suggestions = {
            "SQL Injection": """
# Use parameterized queries instead:
# OLD: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
# NEW: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# Or with psycopg2: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
""",
            "Command Injection": """
# Use subprocess with explicit arguments instead:
# OLD: os.system(user_input)
# NEW: subprocess.run(['command', 'arg1', 'arg2'], check=True)
# Or use shlex.quote() for shell commands
""",
            "Hardcoded Password": """
# Use environment variables or secure configuration:
# OLD: password = "mypassword123"
# NEW: password = os.getenv('DB_PASSWORD')
# Or use a secrets management system
""",
            "Weak Cryptography": """
# Use secure hash functions:
# OLD: hashlib.md5(data).hexdigest()
# NEW: hashlib.sha256(data).hexdigest()
# Or use hashlib.pbkdf2_hmac for password hashing
""",
            "Eval Usage": """
# Avoid eval(), use safer alternatives:
# OLD: result = eval(user_input)
# NEW: Use ast.literal_eval() for literals, or proper parsing
# Or use a safe expression evaluator library
""",
            "Pickle Unsafe": """
# Use safer serialization:
# OLD: data = pickle.loads(user_data)
# NEW: Use json.loads() or a safe serialization library
# Or validate and sanitize data before deserialization
"""
        }
        
        return suggestions.get(vuln_type, "Review the code and apply security best practices.")
    
    def _cpp_suggestions(self, vuln_type: str, snippet: str, lines: List[str], line_num: int) -> str:
        """C++-specific rule-based suggestions"""
        suggestions = {
            "Buffer Overflow": """
// Use safe string functions:
// OLD: strcpy(dest, src);
// NEW: strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest) - 1] = '\\0';
// Or better: use std::string or std::array
""",
            "Use After Free": """
// Ensure proper memory management:
// OLD: delete ptr; use(ptr);
// NEW: ptr = nullptr; after delete
// Or use smart pointers: std::unique_ptr, std::shared_ptr
""",
            "Memory Leak": """
// Use smart pointers or ensure proper cleanup:
// OLD: int* arr = new int[100];
// NEW: std::unique_ptr<int[]> arr(new int[100]);
// Or: std::vector<int> arr(100);
""",
            "Format String": """
// Use safe formatting:
// OLD: printf(user_input);
// NEW: printf("%s", user_input);
// Or use std::cout or std::format (C++20)
"""
        }
        
        return suggestions.get(vuln_type, "Review the code and apply security best practices.")
    
    def load_model(self):
        """Load the trained model (placeholder)"""
        # This would load the actual model
        # Example:
        # from transformers import AutoModel, AutoTokenizer
        # self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        # self.model = AutoModel.from_pretrained(self.model_path)
        pass

