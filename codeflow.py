"""CodeFlow: a small, AST-based Python taint tracker."""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SOURCE_FUNCTIONS = {
    "input",
    "raw_input",
    "open",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.stdin.readlines",
}

SOURCE_ATTRIBUTES = {
    "request.args",
    "request.form",
    "request.values",
    "request.json",
    "request.data",
    "request.cookies",
}

SINK_FUNCTIONS = {
    "eval": "code_execution",
    "exec": "code_execution",
    "compile": "code_execution",
    "os.system": "command_execution",
    "os.popen": "command_execution",
    "subprocess.run": "command_execution",
    "subprocess.call": "command_execution",
    "subprocess.Popen": "command_execution",
    "subprocess.check_call": "command_execution",
    "subprocess.check_output": "command_execution",
    "cursor.execute": "sql_query",
    "cursor.executemany": "sql_query",
    "connection.execute": "sql_query",
    "connection.executemany": "sql_query",
}

SANITIZER_FUNCTIONS = {
    "html.escape",
    "shlex.quote",
    "bleach.clean",
}


def dotted_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def called_name(node: ast.Call) -> str | None:
    name = dotted_name(node.func)
    if name is None:
        return None
    if name.startswith("builtins."):
        return name.removeprefix("builtins.")
    return name


@dataclass
class Flow:
    source_line: int
    source: str
    sink_line: int
    sink: str
    sink_kind: str
    path: list[str]

    def text(self) -> str:
        route = " -> ".join(self.path)
        return (
            f"[{self.sink_kind}] line {self.source_line} -> line {self.sink_line}\n"
            f"  source: {self.source}\n"
            f"  sink: {self.sink}\n"
            f"  path: {route}"
        )


class TaintAnalyzer:
    def __init__(self, tree: ast.Module, filename: str) -> None:
        self.tree = tree
        self.filename = filename
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
        self.flows: list[Flow] = []

    def analyze(self) -> list[Flow]:
        module_function = ast.FunctionDef(
            name="<module>",
            args=ast.arguments(
                posonlyargs=[],
                args=[],
                vararg=None,
                kwonlyargs=[],
                kw_defaults=[],
                kwarg=None,
                defaults=[],
            ),
            body=self.tree.body,
            decorator_list=[],
            lineno=1,
        )
        self._analyze_function(module_function, {}, 0)

        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, {}, 0)
        unique: dict[tuple[int, int, str, tuple[str, ...]], Flow] = {}
        for flow in self.flows:
            key = (
                flow.source_line,
                flow.sink_line,
                flow.sink,
                tuple(flow.path),
            )
            unique[key] = flow
        return sorted(
            unique.values(),
            key=lambda item: (item.source_line, item.sink_line, item.sink),
        )

    def _is_source_call(self, node: ast.Call) -> bool:
        name = called_name(node)
        if name in SOURCE_FUNCTIONS:
            return True
        if name and name.startswith("request."):
            base = name.rsplit(".", 1)[0] if name.count(".") >= 2 else name
            return name in SOURCE_ATTRIBUTES or base in SOURCE_ATTRIBUTES
        if name and name.startswith("flask.request."):
            suffix = name.removeprefix("flask.")
            return suffix in SOURCE_ATTRIBUTES
        return False

    def _is_source_attribute(self, node: ast.Attribute) -> bool:
        name = dotted_name(node)
        if name in SOURCE_ATTRIBUTES:
            return True
        if name and name.startswith("os.environ"):
            return True
        if name and name.startswith("environ"):
            return True
        return False

    def _tainted_names(
        self,
        node: ast.AST,
        tainted: set[str],
        source_lines: dict[str, int],
    ) -> tuple[bool, list[str]]:
        if isinstance(node, ast.Name):
            if node.id in tainted:
                return True, [source_lines.get(node.id, node.lineno).__str__()]
            return False, []

        if isinstance(node, ast.Attribute):
            name = dotted_name(node)
            if name and self._is_source_attribute(node):
                return True, [str(node.lineno)]
            if isinstance(node.value, ast.Name) and node.value.id in tainted:
                return True, [source_lines.get(node.value.id, node.lineno).__str__()]
            return self._tainted_names(node.value, tainted, source_lines)

        if isinstance(node, ast.Call):
            name = called_name(node)
            if name and name in SANITIZER_FUNCTIONS:
                return False, []
            if self._is_source_call(node):
                return True, [str(node.lineno)]

            # A method call on a tainted object (data.strip()) stays tainted.
            if isinstance(node.func, ast.Attribute):
                tainted_obj, lines = self._tainted_names(
                    node.func.value, tainted, source_lines
                )
                if tainted_obj:
                    return True, lines

            # Arguments make a call tainted, regardless of whether the callee
            # is known. This catches eval(s), os.system(s), and .execute(s).
            for arg in [*node.args, *[kw.value for kw in node.keywords]]:
                tainted_arg, lines = self._tainted_names(arg, tainted, source_lines)
                if tainted_arg:
                    return True, lines
            return False, []

        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.JoinedStr,
                             ast.IfExp, ast.FormattedValue, ast.Subscript,
                             ast.Index, ast.List, ast.Tuple, ast.Set, ast.Dict,
                             ast.UnaryOp)):
            for child in ast.iter_child_nodes(node):
                tainted_child, lines = self._tainted_names(child, tainted, source_lines)
                if tainted_child:
                    return True, lines
        return False, []

    def _target_names(self, target: ast.AST) -> Iterable[str]:
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                yield from self._target_names(item)

    def _analyze_function(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        seed_taints: dict[str, int],
        depth: int,
    ) -> dict[str, int]:
        taint = dict(seed_taints)
        self._visit(function.body, taint, function, depth)
        return taint

    # ---- ordered (flow-sensitive) walk over statements ----

    def _visit(self, body, taint, function, depth) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            self._scan_calls(stmt, taint, function, depth)
            self._apply(stmt, taint)

            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                # Two passes so taint created late in a loop reaches its start.
                for _ in range(2):
                    self._visit(stmt.body, taint, function, depth)
                self._visit(stmt.orelse, taint, function, depth)
            elif isinstance(stmt, ast.If):
                self._branches([stmt.body, stmt.orelse], taint, function, depth)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._visit(stmt.body, taint, function, depth)
            elif isinstance(stmt, ast.Try):
                self._visit(stmt.body, taint, function, depth)
                bodies = [handler.body for handler in stmt.handlers] + [stmt.orelse]
                self._branches(bodies, taint, function, depth)
                self._visit(stmt.finalbody, taint, function, depth)
            elif isinstance(stmt, ast.Match):
                self._branches([case.body for case in stmt.cases], taint, function, depth)

    def _branches(self, bodies, taint, function, depth) -> None:
        """Run each branch from the same start; afterwards a name is tainted
        if it is tainted in ANY branch (conservative)."""
        snapshot = dict(taint)
        merged: dict[str, int] = {}
        for body in bodies:
            branch = dict(snapshot)
            self._visit(body, branch, function, depth)
            for name, line in branch.items():
                merged.setdefault(name, line)
        taint.clear()
        taint.update(merged)

    def _apply(self, stmt, taint) -> None:
        """Update the taint state for one statement (assignment, for, with)."""
        if isinstance(stmt, ast.Assign):
            is_tainted, lines = self._tainted_names(stmt.value, taint, taint)
            for target in stmt.targets:
                self._set_taint(target, is_tainted, lines, stmt.lineno, taint)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            is_tainted, lines = self._tainted_names(stmt.value, taint, taint)
            self._set_taint(stmt.target, is_tainted, lines, stmt.lineno, taint)
        elif isinstance(stmt, ast.AugAssign):
            is_tainted, lines = self._tainted_names(stmt.value, taint, taint)
            if is_tainted:  # x += tainted taints x; x += "safe" keeps old taint
                self._set_taint(stmt.target, True, lines, stmt.lineno, taint)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            is_tainted, lines = self._tainted_names(stmt.iter, taint, taint)
            self._set_taint(stmt.target, is_tainted, lines, stmt.lineno, taint)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    is_tainted, lines = self._tainted_names(
                        item.context_expr, taint, taint
                    )
                    self._set_taint(
                        item.optional_vars, is_tainted, lines, stmt.lineno, taint
                    )

    def _set_taint(self, target, is_tainted, lines, lineno, taint) -> None:
        for name in self._target_names(target):
            if is_tainted:
                taint[name] = int(lines[0]) if lines else lineno
            else:
                taint.pop(name, None)  # overwritten with a clean value

    def _scan_calls(self, stmt, taint, function, depth) -> None:
        """Check every call that belongs to this statement itself (not to
        nested statements, which _visit handles in order)."""
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                continue
            for node in ast.walk(child):
                if isinstance(node, ast.Call):
                    self._check_call(node, taint, function, depth)

    def _check_call(self, call, taint, function, depth) -> None:
        call_name = called_name(call)

        if call_name in SINK_FUNCTIONS:
            kind = SINK_FUNCTIONS[call_name]
            args = list(call.args)
            keywords = [kw.value for kw in call.keywords]
            if kind == "sql_query":
                # Only the query text matters. Bound parameters (2nd argument)
                # are exactly what a parameterized query makes safe.
                args = args[:1]
                keywords = [
                    kw.value for kw in call.keywords
                    if kw.arg in ("sql", "query", "operation", "statement")
                ]
            if (
                call_name.startswith("subprocess.")
                and args
                and isinstance(args[0], (ast.List, ast.Tuple))
                and not any(
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                    for kw in call.keywords
                )
            ):
                # Argument list without shell=True: no shell injection.
                args = []
                keywords = []
            for arg in [*args, *keywords]:
                is_tainted, refs = self._tainted_names(arg, taint, taint)
                if is_tainted:
                    source_line = int(refs[0]) if refs else call.lineno
                    self.flows.append(Flow(
                        source_line=source_line,
                        source=f"tainted argument to {call_name}",
                        sink_line=call.lineno,
                        sink=f"{call_name}(...)",
                        sink_kind=kind,
                        path=self._flow_path(
                            function.name, taint, taint, source_line, call
                        ),
                    ))
                    break

        # One-level cross-function analysis (functions and methods).
        callee = None
        offset = 0
        if isinstance(call.func, ast.Attribute):
            # obj.method(...) / self.method(...) / Cls().method(...)
            if call.func.attr in self.functions and call_name not in SINK_FUNCTIONS:
                callee = self.functions[call.func.attr]
                params = list(callee.args.posonlyargs) + list(callee.args.args)
                if params and params[0].arg in ("self", "cls"):
                    offset = 1  # the object itself fills self/cls
        elif call_name in self.functions:
            callee = self.functions[call_name]

        if callee is not None and depth == 0:
            positional = list(callee.args.posonlyargs) + list(callee.args.args)
            for index, argument in enumerate(call.args):
                if index + offset >= len(positional):
                    break
                is_tainted, lines = self._tainted_names(argument, taint, taint)
                if is_tainted:
                    seed = {positional[index + offset].arg:
                            int(lines[0]) if lines else argument.lineno}
                    self._analyze_function(callee, seed, depth + 1)

    def _flow_path(
        self,
        function_name: str,
        tainted: set[str],
        source_lines: dict[str, int],
        source_line: int,
        sink: ast.Call,
    ) -> list[str]:
        names = sorted(
            name for name in tainted
            if source_lines.get(name) == source_line
        )
        prefix = f"{function_name}()"
        if names:
            return [f"source line {source_line}", prefix, f"variables: {', '.join(names)}",
                    f"sink line {sink.lineno}: {called_name(sink)}(...)"]
        return [f"source line {source_line}", prefix,
                f"sink line {sink.lineno}: {called_name(sink)}(...)"]


def parse_file(path: Path) -> tuple[ast.Module, str]:
    source = path.read_text(encoding="utf-8")
    return ast.parse(source, filename=str(path)), source


def print_functions(tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            print(f"{node.name}:{node.lineno}")


def render_text(filename: str, flows: list[Flow]) -> str:
    lines = [f"CodeFlow report: {filename}", f"Flows found: {len(flows)}", ""]
    if not flows:
        lines.append("No tainted flows detected.")
    else:
        lines.extend(flow.text() for flow in flows)
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace tainted Python data from sources to dangerous sinks."
    )
    parser.add_argument("source", type=Path, help="Python source file to analyze")
    parser.add_argument(
        "-o", "--output", type=Path, default=Path("codeflow_report.txt"),
        help="report output file (default: codeflow_report.txt)",
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="report format",
    )
    parser.add_argument(
        "--print-functions", action="store_true",
        help="print function definitions and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.source.is_file():
        print(f"error: source file not found: {args.source}", file=sys.stderr)
        return 2

    try:
        tree, _ = parse_file(args.source)
    except (SyntaxError, UnicodeDecodeError) as exc:
        print(f"error: cannot parse {args.source}: {exc}", file=sys.stderr)
        return 2

    if args.print_functions:
        print_functions(tree)
        return 0

    flows = TaintAnalyzer(tree, str(args.source)).analyze()
    if args.format == "json":
        payload = {
            "file": str(args.source),
            "flows": [asdict(flow) for flow in flows],
        }
        report = json.dumps(payload, indent=2) + "\n"
    else:
        report = render_text(str(args.source), flows)

    args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    print(f"\nReport saved to {args.output}")
    return 1 if flows else 0


if __name__ == "__main__":
    raise SystemExit(main())
