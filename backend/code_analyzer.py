import ast
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class CodeStructure:
    functions: List[Dict[str, Any]]
    classes: List[Dict[str, Any]]
    imports: List[str]
    variables: List[Dict[str, Any]]
    metadata: Dict[str, Any] = None


class CodeAnalyzer:
    """
    Production-grade code analyzer for Python and C++.
    Python is analyzed using AST.
    C++ is analyzed using a hybrid regex + lightweight tokenizer approach.
    """

    # ---------------------------------------------------------
    # Public API
    # ---------------------------------------------------------

    def parse_code(self, code: str, language: str) -> CodeStructure:
        language = language.lower().strip()

        if language == "python":
            return self._parse_python(code)

        elif language == "cpp":
            return self._parse_cpp(code)

        else:
            raise ValueError(f"Unsupported language: {language}")

    # ---------------------------------------------------------
    # Python Parsing (Strong, AST-based)
    # ---------------------------------------------------------

    def _parse_python(self, code: str) -> CodeStructure:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return CodeStructure([], [], [], [], {})

        functions = []
        classes = []
        imports = []
        variables = []

        for node in ast.walk(tree):
            # Functions (sync + async)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "end_line": getattr(node, "end_lineno", None),
                        "args": [arg.arg for arg in node.args.args],
                        "decorators": [
                            ast.unparse(d) for d in node.decorator_list
                        ]
                        if hasattr(ast, "unparse")
                        else [],
                        "is_async": isinstance(node, ast.AsyncFunctionDef),
                        "num_locals": len([n for n in ast.walk(node) if isinstance(n, ast.Name)]),
                    }
                )

            # Classes
            elif isinstance(node, ast.ClassDef):
                classes.append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                        "end_line": getattr(node, "end_lineno", None),
                        "methods": [
                            n.name
                            for n in node.body
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        ],
                        "bases": [
                            ast.unparse(b) for b in node.bases
                        ]
                        if hasattr(ast, "unparse")
                        else [],
                    }
                )

            # Imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)

            # Variables
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        variables.append(
                            {
                                "name": target.id,
                                "line": node.lineno,
                                "kind": "assign",
                            }
                        )

            elif isinstance(node, ast.AnnAssign):
                target = node.target
                if isinstance(target, ast.Name):
                    variables.append(
                        {
                            "name": target.id,
                            "line": node.lineno,
                            "kind": "annotated",
                            "annotation": (
                                ast.unparse(node.annotation)
                                if hasattr(ast, "unparse")
                                else None
                            ),
                        }
                    )

        metadata = {
            "num_lines": len(code.split("\n")),
            "num_functions": len(functions),
            "num_classes": len(classes),
        }

        return CodeStructure(functions, classes, imports, variables, metadata)

    # ---------------------------------------------------------
    # C++ Parsing (Improved, hybrid tokenizer + regex)
    # ---------------------------------------------------------

    def _parse_cpp(self, code: str) -> CodeStructure:
        functions: List[Dict[str, Any]] = []
        classes: List[Dict[str, Any]] = []
        imports: List[str] = []
        variables: List[Dict[str, Any]] = []

        lines = code.split("\n")

        # -------------------------
        # Includes
        # -------------------------
        include_pattern = re.compile(r'#include\s*[<"]([^>"]+)[>"]')
        for i, line in enumerate(lines, 1):
            match = include_pattern.search(line)
            if match:
                imports.append(match.group(1))

        # -------------------------
        # Class declarations
        # -------------------------
        class_pattern = re.compile(r'^\s*class\s+([A-Za-z_]\w*)')
        for i, line in enumerate(lines, 1):
            m = class_pattern.match(line)
            if m:
                classes.append(
                    {"name": m.group(1), "line": i, "methods": []}
                )

        # -------------------------
        # Function detection
        # -------------------------
        # This supports:
        # int foo()
        # auto foo(int a) -> int
        # std::vector<int> foo(...)
        function_pattern = re.compile(
            r"""
            ^\s*
            (?P<ret>[A-Za-z_][\w:\<\>\*&\s]+?)   # return type
            \s+
            (?P<name>[A-Za-z_]\w*)               # function name
            \s*\(                                # open bracket
            [^;{}]*                              # parameters
            \)\s*
            (const\s*)?
            (\{|->)                              # body begins or return type arrow
            """,
            re.VERBOSE,
        )

        for i, line in enumerate(lines, 1):
            m = function_pattern.match(line)
            if m:
                ret = m.group("ret").strip()
                name = m.group("name").strip()

                # Filter out false positives
                if ret in ["if", "for", "while", "switch"]:
                    continue

                functions.append(
                    {
                        "name": name,
                        "line": i,
                        "return_type": ret,
                    }
                )

        # -------------------------
        # Variable declarations
        # -------------------------
        var_pattern = re.compile(
            r"""
            ^\s*
            (?P<type>[A-Za-z_][\w:\<\>\*&\s]+?)  # type
            \s+
            (?P<name>[A-Za-z_]\w*)               # variable name
            \s*(=|;)                             # initializer or end
            """,
            re.VERBOSE,
        )
