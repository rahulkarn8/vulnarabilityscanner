"""
AI-Powered Attack Vulnerability Scanner (V2)
Detects vulnerabilities that make code susceptible to AI-powered attacks.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class AIAttackScanner:
    """
    Production-grade AI attack scanner:
    - Rule IDs & CWE IDs
    - Precompiled regex patterns
    - Category tagging (prompt/model/data/codegen/api)
    - De-duplication across same file/rule/line/match
    """

    SCANNER_NAME = "ai_attack"
    SCANNER_VERSION = "2.0.0"

    # ------------------------------------------------------------------ #
    # Init & pattern registration
    # ------------------------------------------------------------------ #

    def __init__(self) -> None:
        # Prompt Injection Patterns
        prompt_injection_patterns = [
            {
                "category": "prompt_injection",
                "rule_id": "PROMPT-001",
                "cwe_id": "CWE-74",
                "name": "Prompt Injection: Unvalidated User Input to LLM",
                "pattern": r"(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run).*\([^)]*user.*input|(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run).*\([^)]*request\.(?:body|json|form|args|params)",
                "severity": "critical",
                "description": (
                    "User input is directly passed to LLM without validation or sanitization. "
                    "This allows prompt injection attacks where attackers can manipulate AI behavior, "
                    "extract training data, or bypass security controls. Always validate, sanitize, "
                    "and use prompt templates with input escaping."
                ),
            },
            {
                "category": "prompt_injection",
                "rule_id": "PROMPT-002",
                "cwe_id": "CWE-20",
                "name": "Prompt Injection: Missing Input Sanitization",
                "pattern": r"(?:messages|prompt|input|query|text).*=\s*(?:request|input|user_input|body|json|form|args)",
                "severity": "high",
                "description": (
                    "User input is assigned to prompt variables without sanitization. "
                    "Implement input validation, length limits, and escape special prompt characters "
                    "to prevent prompt injection attacks."
                ),
            },
            {
                "category": "prompt_injection",
                "rule_id": "PROMPT-003",
                "cwe_id": "CWE-74",
                "name": "Prompt Injection: Direct String Concatenation in Prompt",
                "pattern": r"(?:f\"|f'|\"|\').*(?:{.*user|{.*input|{.*request|{.*body|{.*json|{.*form).*\"|'",
                "severity": "critical",
                "description": (
                    "User input is directly concatenated into prompt strings using f-strings or string formatting. "
                    "This is highly vulnerable to prompt injection. Use parameterized prompts or prompt templates "
                    "with proper escaping instead."
                ),
            },
            {
                "category": "prompt_injection",
                "rule_id": "PROMPT-004",
                "cwe_id": "CWE-285",
                "name": "Prompt Injection: Missing System Prompt Protection",
                "pattern": r"(?:system|role).*[:=].*[\"']user|(?:system|role).*[:=].*[\"']assistant.*[\"']user",
                "severity": "high",
                "description": (
                    "System prompts may be overwritten by user input. Separate system prompts from user content "
                    "and use role-based message structures that prevent system prompt manipulation."
                ),
            },
        ]

        # AI Model Security Patterns
        model_security_patterns = [
            {
                "category": "model_security",
                "rule_id": "MODEL-001",
                "cwe_id": "CWE-798",
                "name": "AI Model: Hardcoded API Keys",
                "pattern": r"(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|HUGGINGFACE_API_KEY|API_KEY|SECRET_KEY)\s*=\s*['\"][^'\"]+['\"]",
                "severity": "critical",
                "description": (
                    "AI API keys are hardcoded in source code. This allows attackers to steal credentials "
                    "and abuse your AI services. Store API keys in environment variables or secure key management systems."
                ),
            },
            {
                "category": "model_security",
                "rule_id": "MODEL-002",
                "cwe_id": "CWE-770",
                "name": "AI Model: Missing Rate Limiting",
                "pattern": r"(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run)",
                "severity": "high",
                "description": (
                    "AI API calls lack rate limiting. This makes the application vulnerable to abuse, "
                    "cost attacks, and denial of service. Implement rate limiting per user/IP and cost controls."
                ),
            },
            {
                "category": "model_security",
                "rule_id": "MODEL-003",
                "cwe_id": "CWE-116",
                "name": "AI Model: Unvalidated Model Output",
                "pattern": r"(?:response|result|output|completion|message).*\[.*content.*\]|(?:response|result|output|completion|message).*\.(?:content|text|message)",
                "severity": "high",
                "description": (
                    "AI model output is used without validation. Malicious or manipulated AI responses "
                    "can lead to code injection, XSS, or other attacks. Always validate and sanitize AI outputs "
                    "before using them in your application."
                ),
            },
            {
                "category": "model_security",
                "rule_id": "MODEL-004",
                "cwe_id": "CWE-94",
                "name": "AI Model: Missing Output Filtering",
                "pattern": r"(?:eval|exec|compile|__import__|subprocess|os\.system).*\(.*(?:response|result|output|completion|message)",
                "severity": "critical",
                "description": (
                    "AI model output is directly executed as code. This is extremely dangerous as AI models "
                    "can be manipulated to generate malicious code. Never execute AI outputs as code without "
                    "strict validation and sandboxing."
                ),
            },
            {
                "category": "model_security",
                "rule_id": "MODEL-005",
                "cwe_id": "CWE-494",
                "name": "AI Model: Insecure Model Loading",
                "pattern": r"(?:load_model|from_pretrained|load|pickle\.load).*\([^)]*http://|(?:load_model|from_pretrained|load|pickle\.load).*\([^)]*user.*input",
                "severity": "critical",
                "description": (
                    "AI models are loaded from untrusted sources or user input. This allows model poisoning attacks "
                    "where malicious models can be injected. Only load models from trusted sources with signature verification."
                ),
            },
            {
                "category": "model_security",
                "rule_id": "MODEL-006",
                "cwe_id": "CWE-770",
                "name": "AI Model: Missing Input Length Limits",
                "pattern": r"(?:max_tokens|max_length|truncate).*[:=].*None|(?:max_tokens|max_length|truncate).*[:=].*\d{5,}",
                "severity": "medium",
                "description": (
                    "AI input length limits are missing or too high. This allows resource exhaustion attacks "
                    "and increases prompt injection risk. Set reasonable max_tokens and input length limits."
                ),
            },
        ]

        # Adversarial Attack Patterns
        adversarial_patterns = [
            {
                "category": "adversarial",
                "rule_id": "ADV-001",
                "cwe_id": "CWE-20",
                "name": "Adversarial Attack: Missing Input Validation",
                "pattern": r"(?:model|predict|classify|inference|forward).*\([^)]*input|(?:model|predict|classify|inference|forward).*\([^)]*data",
                "severity": "high",
                "description": (
                    "Model inputs lack validation. Adversarial inputs can cause misclassification, "
                    "model evasion, or system failures. Implement input validation, normalization, "
                    "and adversarial detection mechanisms."
                ),
            },
            {
                "category": "adversarial",
                "rule_id": "ADV-002",
                "cwe_id": "CWE-20",
                "name": "Adversarial Attack: Missing Input Preprocessing",
                "pattern": r"(?:model|predict|classify|inference|forward).*\([^)]*\.(?:raw|original|unprocessed)",
                "severity": "medium",
                "description": (
                    "Raw, unprocessed inputs are fed to models. Adversarial examples can exploit this. "
                    "Always preprocess inputs (normalize, validate ranges, detect anomalies) before model inference."
                ),
            },
            {
                "category": "adversarial",
                "rule_id": "ADV-003",
                "cwe_id": "CWE-682",
                "name": "Adversarial Attack: Missing Confidence Thresholds",
                "pattern": r"(?:predict|classify|inference).*\([^)]*\)(?!.*(?:confidence|probability|threshold|score))",
                "severity": "medium",
                "description": (
                    "Model predictions lack confidence checking. Low-confidence predictions may indicate "
                    "adversarial inputs. Implement confidence thresholds and reject low-confidence predictions."
                ),
            },
        ]

        # Data Poisoning Patterns
        data_poisoning_patterns = [
            {
                "category": "data_poisoning",
                "rule_id": "DATA-001",
                "cwe_id": "CWE-20",
                "name": "Data Poisoning: Unvalidated Training Data",
                "pattern": r"(?:fit|train|train_on_batch|fit_generator).*\([^)]*user.*data|(?:fit|train|train_on_batch|fit_generator).*\([^)]*request|(?:fit|train|train_on_batch|fit_generator).*\([^)]*\.csv|(?:fit|train|train_on_batch|fit_generator).*\([^)]*\.json",
                "severity": "critical",
                "description": (
                    "Training data comes from untrusted sources without validation. This allows data poisoning "
                    "attacks where malicious data corrupts the model. Validate, sanitize, and audit all training data."
                ),
            },
            {
                "category": "data_poisoning",
                "rule_id": "DATA-002",
                "cwe_id": "CWE-20",
                "name": "Data Poisoning: Missing Data Validation",
                "pattern": r"(?:load_data|read_csv|read_json|load_dataset).*\([^)]*http://|(?:load_data|read_csv|read_json|load_dataset).*\([^)]*user",
                "severity": "high",
                "description": (
                    "Training data is loaded from untrusted sources. Implement data validation, anomaly detection, "
                    "and data provenance tracking to prevent poisoning attacks."
                ),
            },
        ]

        # AI Code Generation Security Patterns
        code_generation_patterns = [
            {
                "category": "code_generation",
                "rule_id": "CODEGEN-001",
                "cwe_id": "CWE-94",
                "name": "AI Code Generation: Unsafe Code Execution",
                "pattern": r"(?:eval|exec|compile|__import__|subprocess|os\.system).*\(.*(?:ai|model|llm|gpt|claude|gemini).*\.(?:generate|complete|chat)",
                "severity": "critical",
                "description": (
                    "AI-generated code is executed without validation. AI models can be manipulated to generate "
                    "malicious code. Never execute AI-generated code directly. Use code review, static analysis, "
                    "and sandboxing before execution."
                ),
            },
            {
                "category": "code_generation",
                "rule_id": "CODEGEN-002",
                "cwe_id": "CWE-710",
                "name": "AI Code Generation: Missing Code Review",
                "pattern": r"(?:code|script|function).*=\s*(?:ai|model|llm|gpt|claude|gemini).*\.(?:generate|complete|chat).*\([^)]*\)|(?:code|script|function).*=\s*(?:response|result|output).*\[.*content",
                "severity": "high",
                "description": (
                    "AI-generated code is used without review or validation. Implement automated code analysis, "
                    "security scanning, and human review before deploying AI-generated code."
                ),
            },
            {
                "category": "code_generation",
                "rule_id": "CODEGEN-003",
                "cwe_id": "CWE-265",
                "name": "AI Code Generation: Missing Sandboxing",
                "pattern": r"(?:exec|eval|compile|subprocess|os\.system).*\(.*(?:ai|model|llm|gpt|claude|gemini)",
                "severity": "critical",
                "description": (
                    "AI-generated code is executed without sandboxing. Execute in isolated environments with "
                    "restricted permissions, resource limits, and network isolation."
                ),
            },
        ]

        # AI API Security Patterns
        api_security_patterns = [
            {
                "category": "api_security",
                "rule_id": "API-001",
                "cwe_id": "CWE-306",
                "name": "AI API: Missing Authentication",
                "pattern": r"(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run).*\([^)]*\)(?!.*(?:api_key|token|auth|headers))",
                "severity": "critical",
                "description": (
                    "AI API calls lack authentication. Implement proper API key management and authentication "
                    "to prevent unauthorized access and abuse."
                ),
            },
            {
                "category": "api_security",
                "rule_id": "API-002",
                "cwe_id": "CWE-522",
                "name": "AI API: Insecure API Key Storage",
                "pattern": r"(?:api_key|token|secret).*=\s*(?:os\.getenv|os\.environ).*\([^)]*\)(?!.*(?:default|fallback))",
                "severity": "high",
                "description": (
                    "API keys are retrieved from environment variables without fallback validation. "
                    "Ensure API keys are properly configured and not exposed in logs or error messages."
                ),
            },
            {
                "category": "api_security",
                "rule_id": "API-003",
                "cwe_id": "CWE-391",
                "name": "AI API: Missing Error Handling",
                "pattern": r"(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run).*\([^)]*\)(?!.*(?:try|except|catch|error))",
                "severity": "medium",
                "description": (
                    "AI API calls lack error handling. Implement proper error handling to prevent information "
                    "leakage and handle API failures gracefully."
                ),
            },
            {
                "category": "api_security",
                "rule_id": "API-004",
                "cwe_id": "CWE-770",
                "name": "AI API: Missing Cost Controls",
                "pattern": r"(?:openai|anthropic|cohere|huggingface|transformers|langchain|llama|gpt|claude|gemini).*\.(?:chat|complete|generate|prompt|run)",
                "severity": "high",
                "description": (
                    "AI API calls lack cost controls. Implement usage limits, cost monitoring, and budget alerts "
                    "to prevent cost-based attacks and unexpected charges."
                ),
            },
        ]

        # Precompile everything once
        self._all_patterns: List[Dict[str, Any]] = []
        for group in (
            prompt_injection_patterns,
            model_security_patterns,
            adversarial_patterns,
            data_poisoning_patterns,
            code_generation_patterns,
            api_security_patterns,
        ):
            self._all_patterns.extend(self._compile_patterns(group))

    def _compile_patterns(self, raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        compiled: List[Dict[str, Any]] = []
        for p in raw:
            rule = dict(p)  # shallow copy
            rule["compiled"] = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
            compiled.append(rule)
        return compiled

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan code for AI-powered attack vulnerabilities.

        Returns a list of normalized vulnerability dicts:
        {
          type, rule_id, cwe_id, category, severity, description,
          line_number, code_snippet, match, scanner, scanner_version, file_path
        }
        """
        if not code:
            return []

        # Quick filter: skip if this file doesn't look AI/ML-related
        if not self._is_ai_related(code, file_path, language):
            return []

        lines = code.splitlines()
        findings: List[Dict[str, Any]] = []

        for pattern_info in self._all_patterns:
            regex = pattern_info["compiled"]
            for match in regex.finditer(code):
                line_number = code[: match.start()].count("\n") + 1
                finding = {
                    "type": pattern_info["name"],
                    "rule_id": pattern_info["rule_id"],
                    "cwe_id": pattern_info["cwe_id"],
                    "category": pattern_info.get("category"),
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "line_number": line_number,
                    "code_snippet": self._get_code_snippet(lines, line_number),
                    "match": match.group(0),
                    "scanner": self.SCANNER_NAME,
                    "scanner_version": self.SCANNER_VERSION,
                    "file_path": file_path,
                }
                findings.append(finding)

        return self._dedupe(findings)

    # ------------------------------------------------------------------ #
    # Heuristics & helpers
    # ------------------------------------------------------------------ #

    def _is_ai_related(
        self,
        code: str,
        file_path: Optional[str],
        language: Optional[str],
    ) -> bool:
        """Heuristic filter to avoid scanning non-AI code."""
        path = (file_path or "").lower()
        code_lower = code.lower()

        ai_indicators = [
            "openai",
            "anthropic",
            "cohere",
            "huggingface",
            "transformers",
            "langchain",
            "llama",
            "gpt",
            "claude",
            "gemini",
            "palm",
            "tensorflow",
            "pytorch",
            "torch",
            "keras",
            "sklearn",
            "scikit-learn",
            "neural",
            "neural network",
            "machine learning",
            "ml",
            "deep learning",
            "llm",
            "large language model",
            "prompt",
            "chat completion",
            "text generation",
            "inference",
            "predict",
            "classify",
            "embedding",
            "fine-tune",
            "train model",
        ]

        if any(ind in code_lower for ind in ai_indicators):
            return True

        if any(token in path for token in ["ai", "ml", "model", "llm", "prompt", "chatbot", "assistant"]):
            return True

        return False

    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 3) -> str:
        """Get code snippet around a line number."""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])

    def _dedupe(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        De-duplicate findings by (rule_id, line_number, match, file_path).
        This keeps the first occurrence and drops duplicates from overlapping regexes.
        """
        unique: Dict[Tuple[str, int, str, Optional[str]], Dict[str, Any]] = {}
        for f in findings:
            key = (
                f.get("rule_id") or "",
                f.get("line_number") or 0,
                f.get("match") or "",
                f.get("file_path"),
            )
            if key not in unique:
                unique[key] = f
        return list(unique.values())
