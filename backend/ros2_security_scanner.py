"""
ros2_security_scanner.py

ROS 2 security configuration & hardening scanner.

Covers:
- Python / C++ nodes
- Launch files (.launch.py/.launch.xml/.launch.yaml/.launch.yml)
- Parameter / config YAMLs
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class ROS2SecurityScanner:
    """
    Detects ROS 2 specific security misconfigurations in:
    - Python / C++ nodes
    - launch files (.launch.py/.xml/.yaml/.yml)
    - parameter / config YAMLs
    """

    SCANNER_NAME = "ros2"
    SCANNER_VERSION = "1.1.0"

    def __init__(self) -> None:
        # --- Python ROS2 node patterns ---
        python_node_patterns = [
            {
                "name": "ROS2 Undeclared Parameters Enabled",
                "rule_id": "ROS2-001",
                "cwe_id": "CWE-20",  # Improper Input Validation
                "pattern": r"allow_undeclared_parameters\s*=\s*True",
                "severity": "high",
                "description": (
                    "allow_undeclared_parameters=True disables ROS 2 parameter validation and can lead to "
                    "unexpected runtime behavior. Prefer explicit parameter declarations."
                ),
            },
            {
                "name": "ROS2 Automatic Parameter Declaration",
                "rule_id": "ROS2-002",
                "cwe_id": "CWE-20",
                "pattern": r"automatically_declare_parameters_from_overrides\s*=\s*True",
                "severity": "medium",
                "description": (
                    "automatically_declare_parameters_from_overrides=True implicitly accepts external overrides. "
                    "This may allow adversaries to inject unexpected parameters at runtime."
                ),
            },
            {
                "name": "ROS2 Parameter Descriptor Dynamic Typing",
                "rule_id": "ROS2-003",
                "cwe_id": "CWE-20",
                "pattern": r"ParameterDescriptor\([^)]*dynamic_typing\s*=\s*True",
                "severity": "medium",
                "description": (
                    "dynamic_typing=True on ParameterDescriptor bypasses ROS 2 parameter type safety. "
                    "Prefer static typing to avoid unexpected parameter injection."
                ),
            },
            {
                "name": "ROS2 Security Env Disabled in Python",
                "rule_id": "ROS2-004",
                "cwe_id": "CWE-284",  # Improper Access Control
                # e.g. os.environ['ROS_SECURITY_ENABLE'] = 'false'
                "pattern": r"ROS_SECURITY_ENABLE[^\n=]*=\s*['\"]?(false|0)['\"]?",
                "severity": "high",
                "description": (
                    "ROS_SECURITY_ENABLE is set to false in Python code. Only disable security in isolated lab environments. "
                    "Use SROS2 enclaves in any realistic deployment."
                ),
            },
            {
                "name": "ROS2 Permissive Strategy in Python",
                "rule_id": "ROS2-005",
                "cwe_id": "CWE-284",
                # e.g. os.environ['ROS_SECURITY_STRATEGY'] = 'permissive'
                "pattern": r"ROS_SECURITY_STRATEGY[^\n=]*=\s*['\"]?permissive['\"]?",
                "severity": "medium",
                "description": (
                    "ROS_SECURITY_STRATEGY is set to 'permissive', which accepts unsigned/unauthenticated participants. "
                    "Use 'Enforce' for production systems."
                ),
            },
        ]

        # --- C++ ROS2 node patterns ---
        cpp_node_patterns = [
            {
                "name": "ROS2 Undeclared Parameters Enabled",
                "rule_id": "ROS2-001",
                "cwe_id": "CWE-20",
                "pattern": r"\.allow_undeclared_parameters\s*\(\s*true\s*\)",
                "severity": "high",
                "description": (
                    "NodeOptions.allow_undeclared_parameters(true) disables ROS 2 parameter validation. "
                    "Declare parameters explicitly to prevent unauthorized overrides."
                ),
            },
            {
                "name": "ROS2 Automatic Parameter Declaration",
                "rule_id": "ROS2-002",
                "cwe_id": "CWE-20",
                "pattern": r"\.automatically_declare_parameters_from_overrides\s*\(\s*true\s*\)",
                "severity": "medium",
                "description": (
                    "automatically_declare_parameters_from_overrides(true) implicitly accepts parameter overrides. "
                    "Validate parameter sources and use with caution."
                ),
            },
            {
                "name": "ROS2 Security Env Disabled in C++",
                "rule_id": "ROS2-004",
                "cwe_id": "CWE-284",
                # Rough heuristic: someone hardcoding env var string to false
                "pattern": r"ROS_SECURITY_ENABLE[^\n]*false",
                "severity": "high",
                "description": (
                    "ROS_SECURITY_ENABLE appears to be set to false in C++ code. "
                    "Avoid disabling SROS2 in production binaries."
                ),
            },
        ]

        # --- launch (Python/XML/YAML) patterns ---
        launch_patterns = [
            {
                "name": "ROS2 Security Explicitly Disabled",
                "rule_id": "ROS2-006",
                "cwe_id": "CWE-284",
                "pattern": r"ROS_SECURITY_ENABLE[^'\"]*['\"]?(false|0)['\"]?",
                "severity": "high",
                "description": (
                    "ROS_SECURITY_ENABLE is set to false. Disable this only in trusted, lab-only environments. "
                    "Enable SROS2 to protect DDS communications."
                ),
            },
            {
                "name": "ROS2 Permissive Security Strategy",
                "rule_id": "ROS2-007",
                "cwe_id": "CWE-284",
                "pattern": r"ROS_SECURITY_STRATEGY[^'\"]*['\"]?permissive['\"]?",
                "severity": "medium",
                "description": (
                    "ROS_SECURITY_STRATEGY is set to 'permissive', which accepts unsigned participants. "
                    "Use 'Enforce' to require authenticated peers."
                ),
            },
            {
                "name": "ROS2 Missing Keystore Hint",
                "rule_id": "ROS2-008",
                "cwe_id": "CWE-16",  # Configuration
                "pattern": r"ROS_SECURITY_ENABLE[^'\"]*['\"]?(true|1)['\"]?",
                "severity": "info",
                "description": (
                    "ROS security is enabled, but ensure ROS_SECURITY_KEYSTORE is set and points to a valid keystore. "
                    "Without it, DDS security may silently fall back."
                ),
            },
        ]

        # --- YAML (params/config) patterns ---
        yaml_patterns = [
            {
                "name": "ROS2 Undeclared Parameters Enabled",
                "rule_id": "ROS2-001",
                "cwe_id": "CWE-20",
                "pattern": r"allow_undeclared_parameters\s*:\s*true",
                "severity": "high",
                "description": (
                    "allow_undeclared_parameters: true disables ROS 2 parameter declaration safety. "
                    "Declare parameters explicitly instead."
                ),
            },
            {
                "name": "ROS2 Automatic Parameter Declaration",
                "rule_id": "ROS2-002",
                "cwe_id": "CWE-20",
                "pattern": r"automatically_declare_parameters_from_overrides\s*:\s*true",
                "severity": "medium",
                "description": (
                    "automatically_declare_parameters_from_overrides: true allows external overrides to implicitly "
                    "create parameters. This can be abused in shared environments."
                ),
            },
            {
                "name": "ROS2 Security Disabled In Parameters",
                "rule_id": "ROS2-004",
                "cwe_id": "CWE-284",
                "pattern": r"ros_security_enable\s*:\s*(false|0)",
                "severity": "high",
                "description": (
                    "ros_security_enable is set to false. Enable ROS 2 security unless you are in a strictly "
                    "isolated lab environment."
                ),
            },
            {
                "name": "ROS2 Permissive Security Strategy",
                "rule_id": "ROS2-007",
                "cwe_id": "CWE-284",
                "pattern": r"ros_security_strategy\s*:\s*permissive",
                "severity": "medium",
                "description": (
                    "ros_security_strategy is 'permissive', allowing unauthenticated peers. "
                    "Use 'enforce' for production deployments."
                ),
            },
            {
                "name": "ROS2 Security Keystore Potentially Missing",
                "rule_id": "ROS2-008",
                "cwe_id": "CWE-16",
                "pattern": r"ros_security_enable\s*:\s*(true|1)",
                "severity": "info",
                "description": (
                    "ROS 2 security is enabled. Ensure ros_security_keystore is configured and points to a valid keystore."
                ),
            },
        ]

        # Precompile regexes for performance and consistency
        self.python_node_patterns = self._compile_patterns(python_node_patterns)
        self.cpp_node_patterns = self._compile_patterns(cpp_node_patterns)
        self.launch_patterns = self._compile_patterns(launch_patterns)
        self.yaml_patterns = self._compile_patterns(yaml_patterns)

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------

    def scan_code(
        self,
        code: str,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan ROS 2 nodes and config files for common security misconfigurations.

        Returns a list of vulnerability dicts.
        """
        if not code:
            return []

        ros2_type = self._determine_ros2_type(code, file_path, language)
        if not ros2_type:
            return []

        pattern_sets = {
            "python_node": self.python_node_patterns,
            "cpp_node": self.cpp_node_patterns,
            "launch": self.launch_patterns,
            "ros2_yaml": self.yaml_patterns,
        }

        patterns = pattern_sets.get(ros2_type, [])
        vulnerabilities: List[Dict[str, Any]] = []
        lines = code.splitlines()

        for pattern_info in patterns:
            regex = pattern_info["compiled"]
            for match in regex.finditer(code):
                line_number = code[: match.start()].count("\n") + 1
                vulnerabilities.append(
                    {
                        "type": pattern_info["name"],
                        "rule_id": pattern_info.get("rule_id"),
                        "cwe_id": pattern_info.get("cwe_id"),
                        "severity": pattern_info["severity"],
                        "description": pattern_info["description"],
                        "line_number": line_number,
                        "code_snippet": self._get_code_snippet(lines, line_number),
                        "match": match.group(0),
                        "scanner": self.SCANNER_NAME,
                        "scanner_version": self.SCANNER_VERSION,
                        "ros2_type": ros2_type,
                        "file_path": file_path,
                    }
                )

        return vulnerabilities

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------

    def _compile_patterns(self, raw_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attach a compiled regex to each pattern dict."""
        compiled: List[Dict[str, Any]] = []
        for p in raw_patterns:
            rule = dict(p)  # shallow copy
            rule["compiled"] = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
            compiled.append(rule)
        return compiled

    def _determine_ros2_type(
        self,
        code: str,
        file_path: Optional[str],
        language: Optional[str],
    ) -> Optional[str]:
        """
        Determine whether this looks like:
        - a ROS2 python node
        - a ROS2 C++ node
        - a launch file
        - a ROS 2 YAML config
        """
        path = (file_path or "").lower()
        suffix = Path(path).suffix if path else ""
        lowered = code.lower()

        # Launch file heuristics
        if path.endswith(".launch.py") or (suffix == ".py" and "launch" in path):
            return "launch"
        if path.endswith(".launch.xml") or (
            suffix == ".xml" and ("launch" in path or path.endswith("package.xml"))
        ):
            return "launch"
        if path.endswith(".launch.yaml") or path.endswith(".launch.yml"):
            return "launch"

        # YAML / config heuristics
        if suffix in {".yaml", ".yml"} and any(
            token in path for token in ["param", "config", "ros", "dds", "launch"]
        ):
            return "ros2_yaml"

        # Code files (python / C++)
        if (language == "python" or suffix == ".py") and self._looks_like_ros2_python(lowered):
            return "python_node"
        if (language == "cpp" or suffix in {".cpp", ".cc", ".cxx", ".hpp", ".h"}) and self._looks_like_ros2_cpp(lowered):
            return "cpp_node"

        return None

    def _looks_like_ros2_python(self, lowered_code: str) -> bool:
        return any(
            token in lowered_code
            for token in [
                "import rclpy",
                "from rclpy",
                "from launch",           # python launch files / nodes
                "launchdescription",     # LaunchDescription
                "rclpy.node",            # explicit node usage
            ]
        )

    def _looks_like_ros2_cpp(self, lowered_code: str) -> bool:
        return any(
            token in lowered_code
            for token in [
                "#include <rclcpp",      # common include style
                "#include \"rclcpp",     # alt include style
                "rclcpp::node",          # Node usage
                "rclcpp::nodeoptions",   # NodeOptions usage
            ]
        )

    def _get_code_snippet(self, lines: List[str], line_number: int, context: int = 3) -> str:
        """Get code snippet around a line number."""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return "\n".join(lines[start:end])
