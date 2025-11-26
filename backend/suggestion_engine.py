"""
Suggestion Orchestrator

Priority:
1) Trained model (API or local) via ModelIntegration
2) EnhancedSuggestions (OpenAI-backed)
3) Rule-based fallback

Output format (always):
EXPLANATION:
SECURE_CODE:
BEST_PRACTICES:
"""

from typing import Dict, Any, Optional

from model_integration import ModelIntegration
from enhanced_suggestions import EnhancedSuggestions


class SuggestionEngine:
    """
    Unified suggestion engine that orchestrates multiple sources:

    1. Trained model (remote API or local model) via ModelIntegration
       - We call _get_api_suggestion / _get_local_suggestion directly to avoid
         its internal rule-based fallback.
    2. EnhancedSuggestions (OpenAI)
    3. If everything fails, a simple rule-based generic message.

    This keeps the public API async and returns a single string response
    formatted as:

    EXPLANATION: ...
    SECURE_CODE:
    ...
    BEST_PRACTICES:
    ...
    """

    def __init__(self) -> None:
        self.model_integration = ModelIntegration()
        self.enhanced = EnhancedSuggestions()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_suggestion(
        self,
        code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> str:
        """
        Get a unified, production-grade suggestion for a vulnerability.

        Args:
            code: Full file source code.
            language: "python" or "cpp".
            vulnerability: Dict with keys like:
                - type
                - severity
                - description
                - line_number
                - code_snippet
                - (optional) cwe_id, rule_id

        Returns:
            A string in the format:

            EXPLANATION: ...
            SECURE_CODE:
            ...
            BEST_PRACTICES:
            ...
        """
        # 1) Trained model (API/local) via ModelIntegration
        suggestion = await self._try_model(code, language, vulnerability)
        if suggestion:
            return suggestion

        # 2) EnhancedSuggestions (OpenAI + rule-based fallback)
        try:
            enhanced_text = await self.enhanced.get_suggestion(
                code=code,
                language=language,
                vulnerability=vulnerability,
            )
            if enhanced_text and enhanced_text.strip():
                return enhanced_text
        except Exception as e:
            print(f"[SuggestionEngine] EnhancedSuggestions failed: {e}")

        # 3) Last-resort generic rule-based fallback
        return self._generic_fallback(code, language, vulnerability)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _try_model(
        self,
        code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> Optional[str]:
        """
        Try to get a suggestion from the trained model only.

        We deliberately bypass ModelIntegration.get_suggestion() because that
        method already includes a rule-based fallback. We want:

        model-only  -> EnhancedSuggestions -> generic fallback
        """
        try:
            if self.model_integration.use_local_model:
                model_code = self.model_integration._get_local_suggestion(
                    code=code,
                    language=language,
                    vulnerability=vulnerability,
                )
            else:
                # Remote API path. We call the internal API method directly.
                # In your improved ModelIntegration this is async.
                model_code = await self.model_integration._get_api_suggestion(
                    code=code,
                    language=language,
                    vulnerability=vulnerability,
                )

        except Exception as e:
            print(f"[SuggestionEngine] ModelIntegration failed: {e}")
            return None

        if not model_code or not isinstance(model_code, str) or not model_code.strip():
            return None

        # Wrap raw model code into the standard EXPLANATION / SECURE_CODE / BEST_PRACTICES format
        return self._wrap_model_suggestion(model_code, language, vulnerability)

    def _wrap_model_suggestion(
        self,
        secure_code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> str:
        """
        Wrap a raw code snippet from the trained model into the common format:

        EXPLANATION:
        SECURE_CODE:
        BEST_PRACTICES:
        """
        vuln_type = vulnerability.get("type", "Unknown vulnerability")
        severity = vulnerability.get("severity", "medium")
        description = vulnerability.get("description", "").strip()
        cwe_id = vulnerability.get("cwe_id")
        rule_id = vulnerability.get("rule_id")

        explanation_lines = [
            f"This code was automatically refactored to mitigate: {vuln_type} (severity: {severity})."
        ]
        if description:
            explanation_lines.append(description)
        if cwe_id:
            explanation_lines.append(f"Mapped CWE: {cwe_id}")
        if rule_id:
            explanation_lines.append(f"Rule ID: {rule_id}")

        explanation = " ".join(explanation_lines)

        best_practices = self._best_practices_for(language, vuln_type)

        return (
            f"EXPLANATION: {explanation}\n\n"
            f"SECURE_CODE:\n{secure_code.strip()}\n\n"
            f"BEST_PRACTICES:\n{best_practices.strip()}\n"
        )

    def _best_practices_for(self, language: str, vuln_type: str) -> str:
        """Simple language + vuln-type based best practices."""
        lang = language.lower()

        generic = [
            "- Validate and sanitize all external inputs.",
            "- Avoid dangerous APIs or functions when safer alternatives exist.",
            "- Use least privilege for any external resources (DB, filesystem, network).",
            "- Add logging and monitoring around security-sensitive paths.",
        ]

        extra: list[str] = []

        if lang == "python":
            extra.extend(
                [
                    "- Prefer parameterized queries for database access.",
                    "- Avoid eval()/exec() on dynamic data.",
                    "- Use secure random (secrets, os.urandom) for security tokens.",
                ]
            )

        if lang == "cpp":
            extra.extend(
                [
                    "- Prefer std::string/std::vector over raw pointers and C arrays.",
                    "- Use RAII and smart pointers to manage resources safely.",
                    "- Enable compiler warnings (-Wall -Wextra) and static analysis.",
                ]
            )

        if "sql" in vuln_type.lower():
            extra.append("- Parameterize SQL queries; never concatenate user input into SQL strings.")

        if "command" in vuln_type.lower():
            extra.append("- Avoid shell calls with untrusted input; use subprocess with argument lists.")

        if "buffer overflow" in vuln_type.lower():
            extra.append("- Always perform bounds checking on buffers and use safer string functions.")

        return "\n".join(generic + extra)

    def _generic_fallback(
        self,
        code: str,
        language: str,
        vulnerability: Dict[str, Any],
    ) -> str:
        """Last fallback if both model and EnhancedSuggestions are unavailable."""
        vuln_type = vulnerability.get("type", "Unknown vulnerability")
        description = vulnerability.get("description", "")

        explanation = (
            f"No AI-based fix could be generated automatically for: {vuln_type}. "
            f"Description: {description or 'No additional description provided.'}"
        )

        best_practices = self._best_practices_for(language, vuln_type)

        return (
            f"EXPLANATION: {explanation}\n\n"
            "SECURE_CODE:\n"
            "# Please manually refactor this code following the BEST_PRACTICES below.\n\n"
            f"BEST_PRACTICES:\n{best_practices.strip()}\n"
        )
