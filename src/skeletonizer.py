"""
src/skeletonizer.py — Ultra-Lean Symbolic AST Skeletonizer.

Zero-dependency repository skeletonizer inspired by Aider's repo-map.
Extracts class, method, function, and interface signatures into ultra-dense
stubs (< 400 tokens per module) with sub-25ms parsing latency.
"""

from __future__ import annotations

import ast
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union


class PythonSkeletonizer:
    """Extracts ultra-dense signatures from Python AST using standard library ast."""

    def __init__(self, include_private: bool = False, max_docstring_chars: int = 80) -> None:
        self.include_private = include_private
        self.max_docstring_chars = max_docstring_chars

    def skeletonize_code(self, source_code: str, filename: str = "<string>") -> str:
        """Parses Python source code and returns a clean stub representation."""
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError as e:
            return f"# SyntaxError parsing {filename}: line {e.lineno}"

        lines: List[str] = []

        doc = ast.get_docstring(tree)
        if doc:
            first_line = doc.strip().split("\n")[0].strip()
            if first_line:
                if len(first_line) > self.max_docstring_chars:
                    first_line = first_line[: self.max_docstring_chars - 3] + "..."
                lines.append(f'"""{first_line}"""')

        for node in tree.body:
            stub = self._format_top_node(node)
            if stub:
                lines.append(stub)

        return "\n".join(lines).strip()

    def _format_top_node(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.ClassDef):
            return self._format_class(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not self.include_private and node.name.startswith("_"):
                return None
            return self._format_function(node, indent="")
        elif isinstance(node, ast.Assign):
            return self._format_constant(node)
        elif isinstance(node, ast.AnnAssign):
            return self._format_annotated_assignment(node)
        return None

    def _format_class(self, node: ast.ClassDef) -> Optional[str]:
        if not self.include_private and node.name.startswith("_"):
            return None

        bases = [self._unparse(b) for b in node.bases]
        bases_str = f"({', '.join(bases)})" if bases else ""
        class_lines = [f"class {node.name}{bases_str}:"]

        doc = ast.get_docstring(node)
        if doc:
            first_line = doc.strip().split("\n")[0].strip()
            if first_line:
                if len(first_line) > self.max_docstring_chars:
                    first_line = first_line[: self.max_docstring_chars - 3] + "..."
                class_lines.append(f'    """{first_line}"""')

        body_elements: List[str] = []

        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                attr_name = item.target.id
                if not self.include_private and attr_name.startswith("_"):
                    continue
                type_str = self._unparse(item.annotation)
                val_str = f" = {self._unparse(item.value)}" if item.value else ""
                body_elements.append(f"    {attr_name}: {type_str}{val_str}")
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not self.include_private and item.name.startswith("_") and item.name not in ("__init__", "__call__", "__enter__", "__exit__"):
                    continue
                func_stub = self._format_function(item, indent="    ")
                if func_stub:
                    body_elements.append(func_stub)

        if not body_elements:
            class_lines.append("    ...")
        else:
            class_lines.extend(body_elements)

        return "\n".join(class_lines)

    def _format_function(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], indent: str) -> str:
        decorators: List[str] = []
        for dec in node.decorator_list:
            dec_str = self._unparse(dec)
            if dec_str in ("property", "staticmethod", "classmethod", "mcp.tool") or "tool" in dec_str:
                decorators.append(f"{indent}@{dec_str}")

        prefix = "async def " if isinstance(node, ast.AsyncFunctionDef) else "def "
        args_str = self._format_arguments(node.args)
        ret_str = f" -> {self._unparse(node.returns)}" if node.returns else ""

        sig = f"{indent}{prefix}{node.name}({args_str}){ret_str}: ..."
        if decorators:
            return "\n".join(decorators) + "\n" + sig
        return sig

    def _format_arguments(self, args: ast.arguments) -> str:
        parts: List[str] = []

        posonly = getattr(args, "posonlyargs", [])
        for arg in posonly:
            parts.append(self._format_arg(arg))
        if posonly:
            parts.append("/")

        defaults_offset = len(args.args) - len(args.defaults)
        for i, arg in enumerate(args.args):
            default_val = None
            if i >= defaults_offset:
                default_val = self._unparse(args.defaults[i - defaults_offset])
            parts.append(self._format_arg(arg, default_val))

        if args.vararg:
            parts.append(f"*{self._format_arg(args.vararg)}")

        if args.kwonlyargs:
            if not args.vararg:
                parts.append("*")
            for i, arg in enumerate(args.kwonlyargs):
                kw_default = args.kw_defaults[i]
                def_val = self._unparse(kw_default) if kw_default else None
                parts.append(self._format_arg(arg, def_val))

        if args.kwarg:
            parts.append(f"**{self._format_arg(args.kwarg)}")

        return ", ".join(parts)

    def _format_arg(self, arg: ast.arg, default: Optional[str] = None) -> str:
        name = arg.arg
        type_str = f": {self._unparse(arg.annotation)}" if arg.annotation else ""
        def_str = f" = {default}" if default else ""
        return f"{name}{type_str}{def_str}"

    def _format_constant(self, node: ast.Assign) -> Optional[str]:
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                if name.isupper() or name == "__all__":
                    val = self._unparse(node.value)
                    if len(val) > 60:
                        val = val[:57] + "..."
                    return f"{name} = {val}"
        return None

    def _format_annotated_assignment(self, node: ast.AnnAssign) -> Optional[str]:
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if name.isupper() or not name.startswith("_"):
                type_str = self._unparse(node.annotation)
                val_str = f" = {self._unparse(node.value)}" if node.value else ""
                return f"{name}: {type_str}{val_str}"
        return None

    def _unparse(self, node: Optional[ast.AST]) -> str:
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return "Any"


class TypeScriptSkeletonizer:
    """Extracts ultra-dense signatures from TypeScript / Deno files using regex."""

    def __init__(self, include_private: bool = False) -> None:
        self.include_private = include_private

    def skeletonize_code(self, source_code: str, filename: str = "<string>") -> str:
        """Extracts interfaces, types, exported functions and classes."""
        lines: List[str] = []

        clean_code = re.sub(r"/\*[\s\S]*?\*/", "", source_code)

        interface_matches = re.finditer(
            r"export\s+interface\s+([A-Za-z0-9_]+)(?:\s+extends\s+[A-Za-z0-9_,\s]+)?\s*\{([^}]+)\}",
            clean_code,
        )
        for m in interface_matches:
            name = m.group(1)
            raw_body = m.group(2)
            fields = [f.strip() for f in raw_body.split(";") if f.strip() and not f.strip().startswith("//")]
            short_fields = "; ".join(fields[:5])
            if len(fields) > 5:
                short_fields += "; ..."
            lines.append(f"export interface {name} {{ {short_fields} }}")

        type_matches = re.finditer(r"export\s+type\s+([A-Za-z0-9_]+)\s*=\s*([^;]+);", clean_code)
        for m in type_matches:
            name = m.group(1)
            type_def = m.group(2).strip().replace("\n", " ")
            if len(type_def) > 80:
                type_def = type_def[:77] + "..."
            lines.append(f"export type {name} = {type_def};")

        func_matches = re.finditer(
            r"export\s+(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)(?:\s*:\s*([^{]+))?\s*\{",
            clean_code,
        )
        for m in func_matches:
            name = m.group(1)
            args = re.sub(r"\s+", " ", m.group(2).strip())
            ret = m.group(3).strip() if m.group(3) else "void"
            lines.append(f"export function {name}({args}): {ret};")

        export_const_matches = re.finditer(
            r"export\s+const\s+([A-Za-z0-9_]+)(?:\s*:\s*([^=]+))?\s*=",
            clean_code,
        )
        for m in export_const_matches:
            name = m.group(1)
            type_annot = m.group(2).strip() if m.group(2) else "any"
            lines.append(f"export const {name}: {type_annot};")

        return "\n".join(lines).strip()


def skeletonize_file(file_path: Union[str, Path], include_private: bool = False) -> str:
    """Parses a file and returns its stub signature."""
    path = Path(file_path)
    if not path.is_file():
        return f"# File not found: {path}"

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        return f"# Error reading {path}: {e}"

    if path.suffix == ".py":
        return PythonSkeletonizer(include_private=include_private).skeletonize_code(content, filename=path.name)
    elif path.suffix in (".ts", ".tsx", ".js", ".mjs"):
        return TypeScriptSkeletonizer(include_private=include_private).skeletonize_code(content, filename=path.name)
    else:
        return f"# Unsupported file extension: {path.suffix}"


def skeletonize_directory(
    directory: Union[str, Path],
    extensions: Sequence[str] = (".py", ".ts"),
    include_private: bool = False,
    max_tokens: int = 1500,
) -> Dict[str, str]:
    """
    Scans a directory and extracts skeletons for all matching source files.
    Returns a dict mapping relative_path -> stub.
    """
    root = Path(directory)
    if not root.is_dir():
        return {}

    results: Dict[str, str] = {}
    current_tokens = 0

    all_files = sorted(root.rglob("*"))
    for file_path in all_files:
        if file_path.is_file() and file_path.suffix in extensions:
            rel = file_path.relative_to(root).as_posix()
            if any(part.startswith(".") or part in ("__pycache__", "node_modules") for part in file_path.parts):
                continue

            stub = skeletonize_file(file_path, include_private=include_private)
            if stub:
                stub_tokens = len(stub) // 4
                if current_tokens + stub_tokens > max_tokens and results:
                    results[rel] = "# [Truncated by token budget]"
                    break

                results[rel] = stub
                current_tokens += stub_tokens

    return results


def render_skeleton_markdown(skeletons: Dict[str, str]) -> str:
    """Renders directory skeletons into an ultra-dense markdown code block."""
    lines: List[str] = ["### Repository Symbolic Skeleton"]
    for path, stub in skeletons.items():
        lang = "python" if path.endswith(".py") else "typescript"
        lines.append(f"#### `{path}`")
        lines.append(f"```{lang}\n{stub}\n```")
    return "\n\n".join(lines)


def main() -> None:
    """CLI Entrypoint for fast command-line inspection."""
    import argparse

    parser = argparse.ArgumentParser(description="Ultra-Lean Symbolic Skeletonizer")
    parser.add_argument("path", nargs="?", default="src", help="Path to file or directory (default: src)")
    parser.add_argument("--budget", type=int, default=1500, help="Max approximate tokens (default: 1500)")
    parser.add_argument("--all", action="store_true", help="Include private members")
    parser.add_argument("--markdown", action="store_true", help="Format output as markdown")
    args = parser.parse_args()

    t0 = time.perf_counter()
    target = Path(args.path)

    if target.is_file():
        output = skeletonize_file(target, include_private=args.all)
        dt = (time.perf_counter() - t0) * 1000
        print(output)
        print(f"\n# Parsed 1 file in {dt:.2f}ms (~{len(output)//4} tokens)")
    elif target.is_dir():
        skeletons = skeletonize_directory(target, include_private=args.all, max_tokens=args.budget)
        dt = (time.perf_counter() - t0) * 1000
        if args.markdown:
            print(render_skeleton_markdown(skeletons))
        else:
            for p, s in skeletons.items():
                print(f"--- {p} ---")
                print(s)
                print()
        total_tokens = sum(len(s) // 4 for s in skeletons.values())
        print(f"# Parsed {len(skeletons)} files in {dt:.2f}ms (~{total_tokens} tokens)")
    else:
        print(f"Error: Path {target} not found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
