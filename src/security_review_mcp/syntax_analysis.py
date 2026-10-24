"""Tree-sitter based structural checks for source code."""

import re
from dataclasses import dataclass, replace

import tree_sitter_c_sharp
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_rust
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

_PYTHON = Language(tree_sitter_python.language())
_JAVA = Language(tree_sitter_java.language())
_SQL_RE = re.compile(r"\b(select|insert|update|delete|replace)\b", re.IGNORECASE)
_REQUEST_RE = re.compile(r"\brequest\.(?:args|form|values|GET|POST|query_params|json|data)\b")
_JAVA_REQUEST_RE = re.compile(
    r"\b(?:request|req|httpRequest)\.(?:getParameter|getHeader|getQueryString|getPathInfo)\s*\("
)
_JAVA_REQUEST_ANNOTATION_RE = re.compile(
    r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader)\b"
)
_SQL_SINKS = {"execute", "executemany", "text"}
_JAVA_SQL_SINKS = {
    "execute",
    "executeQuery",
    "executeUpdate",
    "prepareStatement",
    "createQuery",
    "createNativeQuery",
}
_TYPESCRIPT = Language(tree_sitter_typescript.language_typescript())
_JAVASCRIPT = Language(tree_sitter_javascript.language())
_UNTRUSTED_WEB_INPUT = re.compile(
    r"(?:queryParamMap|paramMap|URLSearchParams|location\.(?:search|hash)|document\.URL)"
)
_ANGULAR_TRUST_BYPASSES = re.compile(r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)$")


def _line(node: Node) -> int:
    """Return the 1-based line of a node.

    ``start_point[0]`` rather than ``start_point.row``: with tree-sitter 0.26.0, the integers
    read through ``Point.row`` are released too early and crash the interpreter at the next
    garbage collection once the file has more than 256 lines.
    """
    return node.start_point[0] + 1


class _PythonSqlAnalyzer:
    """Track local flows from request data into dynamic SQL expressions."""

    def __init__(self, source: bytes) -> None:
        self.source = source
        self.tainted: set[str] = set()
        self.dynamic: set[str] = set()
        self.sql_candidates: set[str] = set()
        self.lines: set[int] = set()
        self.functions: dict[str, Node] = {}
        self.call_stack: set[str] = set()
        self.return_stack: list[list[bool]] = []
        self.summaries: dict[tuple, tuple[bool, bool, bool]] = {}

    def analyze(self, node: Node) -> None:
        if node.type == "module":
            self._collect_functions(node)
        if node.type == "function_definition":
            self._function(node, set(), set(), set())
            return
        if node.type == "return_statement" and self.return_stack and node.named_children:
            value = node.named_children[-1]
            summary = self.return_stack[-1]
            summary[0] |= self._tainted(value)
            summary[1] |= self._dynamic(value)
            summary[2] |= self._sql_candidate(value)
        if node.type in {"assignment", "augmented_assignment"}:
            self._assignment(node)
            return
        if node.type == "call":
            self._call(node)
        for child in node.named_children:
            self.analyze(child)

    def _collect_functions(self, node: Node) -> None:
        if node.type == "function_definition":
            name = node.child_by_field_name("name")
            if name is not None:
                self.functions[self._text(name)] = node
        for child in node.named_children:
            self._collect_functions(child)

    def _function(
        self,
        node: Node,
        tainted: set[str],
        dynamic: set[str],
        sql_candidates: set[str],
    ) -> tuple[bool, bool, bool]:
        name_node = node.child_by_field_name("name")
        name = self._text(name_node) if name_node is not None else ""
        if name in self.call_stack:
            return False, False, False
        state = self.tainted, self.dynamic, self.sql_candidates
        self.tainted, self.dynamic, self.sql_candidates = tainted, dynamic, sql_candidates
        self.call_stack.add(name)
        summary = [False, False, False]
        self.return_stack.append(summary)
        body = node.child_by_field_name("body")
        if body is not None:
            self.analyze(body)
        self.return_stack.pop()
        self.call_stack.discard(name)
        self.tainted, self.dynamic, self.sql_candidates = state
        return tuple(summary)

    def _assignment(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type == "identifier":
            name = self._text(left)
            is_tainted = self._tainted(right)
            if is_tainted:
                self.tainted.add(name)
            else:
                self.tainted.discard(name)
            if is_tainted and self._dynamic(right):
                self.dynamic.add(name)
            else:
                self.dynamic.discard(name)
            if self._sql_candidate(right):
                self.sql_candidates.add(name)
            else:
                self.sql_candidates.discard(name)
        self.analyze(right)

    def _call(self, node: Node) -> None:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is not None and arguments is not None:
            name = self._text(function).rsplit(".", maxsplit=1)[-1]
            args = [child for child in arguments.named_children if child.type != "keyword_argument"]
            if name in _SQL_SINKS and args:
                query = args[0]
                if self._tainted(query) and self._dynamic(query) and self._sql_candidate(query):
                    self.lines.add(_line(node))
            elif name in self.functions and name not in self.call_stack:
                self._analyze_callee(self.functions[name], args)
        for child in node.named_children:
            self.analyze(child)

    def _analyze_callee(self, function: Node, arguments: list[Node]) -> tuple[bool, bool, bool]:
        parameters = function.child_by_field_name("parameters")
        if parameters is None:
            return False, False, False
        parameter_names: list[str] = []
        for parameter in parameters.named_children:
            name = (
                parameter
                if parameter.type == "identifier"
                else parameter.child_by_field_name("name")
            )
            if name is not None and name.type == "identifier":
                parameter_names.append(self._text(name))
        tainted: set[str] = set()
        dynamic: set[str] = set()
        sql_candidates: set[str] = set()
        for parameter, argument in zip(parameter_names, arguments, strict=False):
            if self._tainted(argument):
                tainted.add(parameter)
            if self._dynamic(argument):
                dynamic.add(parameter)
            if self._sql_candidate(argument):
                sql_candidates.add(parameter)
        key = (
            function.start_byte,
            frozenset(tainted),
            frozenset(dynamic),
            frozenset(sql_candidates),
        )
        if key not in self.summaries:  # a chain of calls is analyzed once per input state
            self.summaries[key] = self._function(function, tainted, dynamic, sql_candidates)
        return self.summaries[key]

    def _tainted(self, node: Node) -> bool:
        text = self._text(node)
        if node.type == "identifier" and text in self.tainted:
            return True
        if node.type == "call":
            function = node.child_by_field_name("function")
            if function is not None:
                function_text = self._text(function)
                if function_text == "input" or _REQUEST_RE.search(function_text):
                    return True
                name = function_text.rsplit(".", maxsplit=1)[-1]
                if name in self.functions and name not in self.call_stack:
                    arguments = node.child_by_field_name("arguments")
                    args = arguments.named_children if arguments is not None else []
                    return self._analyze_callee(self.functions[name], args)[0]
        if node.type == "subscript" and _REQUEST_RE.search(text):
            return True
        return any(self._tainted(child) for child in node.named_children)

    def _dynamic(self, node: Node) -> bool:
        if node.type == "identifier":
            return self._text(node) in self.dynamic
        if node.type == "string" and any(
            child.type == "interpolation" for child in node.named_children
        ):
            return self._tainted(node)
        if node.type == "binary_operator":
            operator = next((child for child in node.children if not child.is_named), None)
            return (
                operator is not None and self._text(operator) in {"+", "%"} and self._tainted(node)
            )
        if node.type == "call":
            function = node.child_by_field_name("function")
            if function is not None:
                name = self._text(function).rsplit(".", maxsplit=1)[-1]
                if name in self.functions and name not in self.call_stack:
                    arguments = node.child_by_field_name("arguments")
                    args = arguments.named_children if arguments is not None else []
                    return self._analyze_callee(self.functions[name], args)[1]
            return (
                function is not None
                and self._text(function).endswith(".format")
                and self._tainted(node)
            )
        return False

    def _sql_candidate(self, node: Node) -> bool:
        if node.type == "identifier":
            return self._text(node) in self.sql_candidates
        if node.type == "call":
            function = node.child_by_field_name("function")
            name = self._text(function).rsplit(".", maxsplit=1)[-1] if function else ""
            if name in self.functions and name not in self.call_stack:
                arguments = node.child_by_field_name("arguments")
                args = arguments.named_children if arguments is not None else []
                return self._analyze_callee(self.functions[name], args)[2]
        if _SQL_RE.search(self._text(node)):
            return True
        return any(self._sql_candidate(child) for child in node.named_children)

    def _text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def python_sql_taint_lines(content: str) -> list[int]:
    """Return SQL sink lines where a simple local flow carries request data."""
    source = content.encode("utf-8")
    tree = Parser(_PYTHON).parse(source)
    analyzer = _PythonSqlAnalyzer(source)
    analyzer.analyze(tree.root_node)
    return sorted(analyzer.lines)


class _JavaSqlAnalyzer:
    """Track local Java request-to-SQL flows across method arguments and returns."""

    def __init__(self, source: bytes) -> None:
        self.source = source
        self.tainted: set[str] = set()
        self.dynamic: set[str] = set()
        self.sql_candidates: set[str] = set()
        self.lines: set[int] = set()
        self.methods: dict[str, Node] = {}
        self.call_stack: set[str] = set()
        self.return_stack: list[list[bool]] = []
        self.summaries: dict[tuple, tuple[bool, bool, bool]] = {}

    def analyze(self, node: Node) -> None:
        if node.type == "program":
            self._collect_methods(node)
        if node.type == "method_declaration":
            self._method(node, set(), set(), set())
            return
        if node.type == "local_variable_declaration":
            self._declaration(node)
            return
        if node.type == "assignment_expression":
            self._assignment(node)
            return
        if node.type == "return_statement" and self.return_stack and node.named_children:
            value = node.named_children[0]
            summary = self.return_stack[-1]
            summary[0] |= self._tainted(value)
            summary[1] |= self._dynamic(value)
            summary[2] |= self._sql_candidate(value)
        if node.type == "method_invocation":
            self._invocation(node)
        for child in node.named_children:
            self.analyze(child)

    def _collect_methods(self, node: Node) -> None:
        if node.type == "method_declaration":
            name = node.child_by_field_name("name")
            if name is not None:
                self.methods[self._text(name)] = node
        for child in node.named_children:
            self._collect_methods(child)

    def _method(
        self,
        node: Node,
        tainted: set[str],
        dynamic: set[str],
        sql_candidates: set[str],
    ) -> tuple[bool, bool, bool]:
        name_node = node.child_by_field_name("name")
        name = self._text(name_node) if name_node is not None else ""
        if name in self.call_stack:
            return False, False, False
        state = self.tainted, self.dynamic, self.sql_candidates
        self.tainted, self.dynamic, self.sql_candidates = tainted, dynamic, sql_candidates
        parameters = node.child_by_field_name("parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                parameter_name = parameter.child_by_field_name("name")
                if parameter_name is not None and _JAVA_REQUEST_ANNOTATION_RE.search(
                    self._text(parameter)
                ):
                    self.tainted.add(self._text(parameter_name))
        self.call_stack.add(name)
        summary = [False, False, False]
        self.return_stack.append(summary)
        body = node.child_by_field_name("body")
        if body is not None:
            self.analyze(body)
        self.return_stack.pop()
        self.call_stack.discard(name)
        self.tainted, self.dynamic, self.sql_candidates = state
        return tuple(summary)

    def _declaration(self, node: Node) -> None:
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is None or name.type != "identifier" or value is None:
                continue
            identifier = self._text(name)
            self._update_state(identifier, value)
            self.analyze(value)

    def _assignment(self, node: Node) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            return
        if left.type == "identifier":
            self._update_state(self._text(left), right)
        self.analyze(right)

    def _update_state(self, name: str, value: Node) -> None:
        if self._tainted(value):
            self.tainted.add(name)
        else:
            self.tainted.discard(name)
        if self._dynamic(value):
            self.dynamic.add(name)
        else:
            self.dynamic.discard(name)
        if self._sql_candidate(value):
            self.sql_candidates.add(name)
        else:
            self.sql_candidates.discard(name)

    def _invocation(self, node: Node) -> None:
        name_node = node.child_by_field_name("name")
        arguments = node.child_by_field_name("arguments")
        if name_node is None or arguments is None:
            return
        name = self._text(name_node)
        args = arguments.named_children
        receiver = node.child_by_field_name("object")
        if name == "append" and receiver is not None and receiver.type == "identifier":
            receiver_name = self._text(receiver)
            if any(self._tainted(argument) for argument in args):
                self.tainted.add(receiver_name)
                self.dynamic.add(receiver_name)
                if self._sql_candidate(receiver) or any(
                    self._sql_candidate(argument) for argument in args
                ):
                    self.sql_candidates.add(receiver_name)
        if name in self.methods and name not in self.call_stack:
            self._analyze_callee(self.methods[name], args)
        elif name in _JAVA_SQL_SINKS:
            for query in args:
                if self._tainted(query) and self._dynamic(query) and self._sql_candidate(query):
                    self.lines.add(_line(node))
                    break

    def _analyze_callee(self, method: Node, arguments: list[Node]) -> tuple[bool, bool, bool]:
        parameters = method.child_by_field_name("parameters")
        if parameters is None:
            return False, False, False
        parameter_names = [
            self._text(name)
            for parameter in parameters.named_children
            if (name := parameter.child_by_field_name("name")) is not None
        ]
        tainted: set[str] = set()
        dynamic: set[str] = set()
        sql_candidates: set[str] = set()
        for parameter, argument in zip(parameter_names, arguments, strict=False):
            if self._tainted(argument):
                tainted.add(parameter)
            if self._dynamic(argument):
                dynamic.add(parameter)
            if self._sql_candidate(argument):
                sql_candidates.add(parameter)
        key = (method.start_byte, frozenset(tainted), frozenset(dynamic), frozenset(sql_candidates))
        if key not in self.summaries:  # a chain of calls is analyzed once per input state
            self.summaries[key] = self._method(method, tainted, dynamic, sql_candidates)
        return self.summaries[key]

    def _tainted(self, node: Node) -> bool:
        if node.type == "identifier" and self._text(node) in self.tainted:
            return True
        if node.type == "method_invocation":
            name = node.child_by_field_name("name")
            invocation_name = self._text(name) if name is not None else ""
            if _JAVA_REQUEST_RE.search(self._text(node)):
                return True
            if invocation_name in self.methods and invocation_name not in self.call_stack:
                arguments = node.child_by_field_name("arguments")
                args = arguments.named_children if arguments is not None else []
                return self._analyze_callee(self.methods[invocation_name], args)[0]
        return any(self._tainted(child) for child in node.named_children)

    def _dynamic(self, node: Node) -> bool:
        if node.type == "identifier":
            return self._text(node) in self.dynamic
        if node.type == "binary_expression":
            operator = next((child for child in node.children if not child.is_named), None)
            return operator is not None and self._text(operator) == "+" and self._tainted(node)
        if node.type == "method_invocation":
            name = node.child_by_field_name("name")
            invocation_name = self._text(name) if name is not None else ""
            if invocation_name in {"format", "concat", "append"} and self._tainted(node):
                return True
            if invocation_name == "toString":
                receiver = node.child_by_field_name("object")
                if receiver is not None and self._dynamic(receiver):
                    return True
            if invocation_name in self.methods and invocation_name not in self.call_stack:
                arguments = node.child_by_field_name("arguments")
                args = arguments.named_children if arguments is not None else []
                return self._analyze_callee(self.methods[invocation_name], args)[1]
        return False

    def _sql_candidate(self, node: Node) -> bool:
        if node.type == "identifier":
            return self._text(node) in self.sql_candidates
        if node.type == "method_invocation":
            name = node.child_by_field_name("name")
            invocation_name = self._text(name) if name is not None else ""
            if invocation_name in self.methods and invocation_name not in self.call_stack:
                arguments = node.child_by_field_name("arguments")
                args = arguments.named_children if arguments is not None else []
                return self._analyze_callee(self.methods[invocation_name], args)[2]
        if _SQL_RE.search(self._text(node)):
            return True
        return any(self._sql_candidate(child) for child in node.named_children)

    def _text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def java_sql_taint_lines(content: str) -> list[int]:
    """Return Java SQL sink lines reached by a request-controlled dynamic query."""
    source = content.encode("utf-8")
    tree = Parser(_JAVA).parse(source)
    analyzer = _JavaSqlAnalyzer(source)
    analyzer.analyze(tree.root_node)
    return sorted(analyzer.lines)


class _WebTaintAnalyzer:
    """Track local flows from URL input to Angular HTML trust/DOM sinks."""

    def __init__(self, source: bytes) -> None:
        self.source = source
        self.tainted: set[str] = set()
        self.xss_lines: set[int] = set()
        self.message_lines: set[int] = set()
        self.functions: dict[str, Node] = {}
        self.function_keys: dict[tuple[int, int], str] = {}
        self.call_stack: set[str] = set()
        self.return_stack: list[list[bool]] = []
        self.summaries: dict[tuple[str, frozenset[str]], bool] = {}

    def analyze(self, node: Node) -> None:
        if node.type == "program":
            self._collect_functions(node)
        if node.type in {"function_declaration", "method_definition", "arrow_function"}:
            previous = self.tainted
            self.tainted = set()
            function_key = self.function_keys.get((node.start_byte, node.end_byte), "")
            function_name = node.child_by_field_name("name")
            if not function_key and function_name is not None:
                function_key = self._text(function_name)
            self.call_stack.add(function_key)
            summary = [False]
            self.return_stack.append(summary)
            for child in node.named_children:
                self.analyze(child)
            self.return_stack.pop()
            self.call_stack.discard(function_key)
            self.tainted = previous
            return
        if node.type == "return_statement" and self.return_stack and node.named_children:
            self.return_stack[-1][0] |= self._is_tainted(node.named_children[-1])
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and name.type == "identifier" and value is not None:
                if self._is_tainted(value):
                    self.tainted.add(self._text(name))
                else:
                    self.tainted.discard(self._text(name))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if left.type == "identifier":
                    name = self._text(left)
                    if self._is_tainted(right):
                        self.tainted.add(name)
                    else:
                        self.tainted.discard(name)
                if self._is_tainted(right) and self._is_dom_sink(left):
                    self.xss_lines.add(_line(node))
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                method = self._text(function).rsplit(".", maxsplit=1)[-1]
                if _ANGULAR_TRUST_BYPASSES.fullmatch(method) and self._is_tainted(arguments):
                    self.xss_lines.add(_line(node))
                if method == "addEventListener" and arguments.named_children:
                    event_name = self._text(arguments.named_children[0]).strip("'\"` ")
                    if event_name == "message" and len(arguments.named_children) > 1:
                        self._check_message_handler(arguments.named_children[1], node)
                elif method in self.functions and method not in self.call_stack:
                    self._analyze_callee(self.functions[method], arguments.named_children, method)
        for child in node.named_children:
            self.analyze(child)

    def _collect_functions(self, node: Node) -> None:
        if node.type == "function_declaration":
            name = node.child_by_field_name("name")
            if name is not None:
                function_name = self._text(name)
                self.functions[function_name] = node
                self.function_keys[(node.start_byte, node.end_byte)] = function_name
        elif node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                name is not None
                and name.type == "identifier"
                and value is not None
                and value.type == "arrow_function"
            ):
                function_name = self._text(name)
                self.functions[function_name] = value
                self.function_keys[(value.start_byte, value.end_byte)] = function_name
        for child in node.named_children:
            self._collect_functions(child)

    def _analyze_callee(self, function: Node, arguments: list[Node], function_key: str) -> bool:
        parameters = function.child_by_field_name("parameters")
        if parameters is None:
            parameter = function.child_by_field_name("parameter")
            parameter_names = [self._text(parameter)] if parameter is not None else []
        else:
            parameter_names = []
            for parameter in parameters.named_children:
                name = parameter
                if parameter.type != "identifier":
                    name = parameter.child_by_field_name("pattern")
                    if name is None:
                        name = parameter.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    parameter_names.append(self._text(name))
        tainted_arguments = {
            parameter
            for parameter, argument in zip(parameter_names, arguments, strict=False)
            if self._is_tainted(argument)
        }
        if function_key in self.call_stack:
            return False
        key = (function_key, frozenset(tainted_arguments))
        if key in self.summaries:  # a chain of calls is analyzed once per input state
            return self.summaries[key]
        previous = self.tainted
        self.tainted = tainted_arguments
        self.call_stack.add(function_key)
        summary = [False]
        self.return_stack.append(summary)
        body = function.child_by_field_name("body")
        if body is not None:
            self.analyze(body)
            if function.type == "arrow_function" and body.type != "statement_block":
                summary[0] |= self._is_tainted(body)
        self.return_stack.pop()
        self.call_stack.discard(function_key)
        self.tainted = previous
        self.summaries[key] = summary[0]
        return summary[0]

    def _check_message_handler(self, callback: Node, call: Node) -> None:
        if callback.type not in {"arrow_function", "function_expression"}:
            return
        parameters = callback.child_by_field_name("parameters")
        if parameters is None:
            parameter = callback.child_by_field_name("parameter")
            parameter_name = self._text(parameter) if parameter is not None else "event"
        else:
            first_parameter = next(iter(parameters.named_children), None)
            parameter_name = self._text(first_parameter) if first_parameter is not None else "event"
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", parameter_name):
            return
        body = callback.child_by_field_name("body")
        body_text = self._text(body) if body is not None else self._text(callback)
        origin = rf"\b{re.escape(parameter_name)}\.origin\b"
        origin_check = re.search(
            rf"(?:{origin}\s*(?:===?|!==?)|(?:===?|!==?)\s*{origin}|"
            rf"\b(?:includes|startsWith)\s*\([^)]*{origin})",
            body_text,
        )
        if re.search(rf"\b{re.escape(parameter_name)}\.data\b", body_text) and not origin_check:
            self.message_lines.add(_line(call))

    def _is_tainted(self, node: Node) -> bool:
        # DomSanitizer.sanitize applies the selected Angular security context and
        # returns a safe value. Bypass APIs intentionally do not count as barriers.
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                method = self._text(function).rsplit(".", maxsplit=1)[-1]
                args = arguments.named_children
                if (
                    method == "sanitize"
                    and len(args) >= 2
                    and self._text(args[0]).strip() == "SecurityContext.HTML"
                ):
                    return False
                function_name = self._text(function).rsplit(".", maxsplit=1)[-1]
                if function_name in self.functions:
                    return self._analyze_callee(
                        self.functions[function_name], arguments.named_children, function_name
                    )
        if node.type == "identifier" and self._text(node) in self.tainted:
            return True
        return bool(_UNTRUSTED_WEB_INPUT.search(self._text(node))) or any(
            self._is_tainted(child) for child in node.named_children
        )

    def _is_dom_sink(self, node: Node) -> bool:
        return node.type == "member_expression" and self._text(node).endswith(".innerHTML")

    def _text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def angular_xss_taint_lines(content: str, language: str) -> list[int]:
    """Return URL-input flows into Angular HTML sinks in TS or JavaScript."""
    grammar = _JAVASCRIPT if language == "javascript" else _TYPESCRIPT
    source = content.encode("utf-8")
    tree = Parser(grammar).parse(source)
    analyzer = _WebTaintAnalyzer(source)
    analyzer.analyze(tree.root_node)
    return sorted(analyzer.xss_lines)


def message_origin_check_lines(content: str, language: str) -> list[int]:
    """Return message listener lines that read event data without inspecting its origin."""
    grammar = _JAVASCRIPT if language == "javascript" else _TYPESCRIPT
    source = content.encode("utf-8")
    tree = Parser(grammar).parse(source)
    analyzer = _WebTaintAnalyzer(source)
    analyzer.analyze(tree.root_node)
    return sorted(analyzer.message_lines)


# ── Request-to-SQL flows: Go, C#, Rust, TypeScript / JavaScript backends ─────


@dataclass(frozen=True)
class _SqlFlowProfile:
    """How request data, SQL sinks and string building look in one grammar."""

    language: Language
    functions: frozenset[str]  # declarations with name, parameters and body fields
    calls: frozenset[str]  # call nodes with function and arguments fields
    sources: re.Pattern[str]  # an expression that reads request data
    sinks: frozenset[str]  # callee names that run a SQL text
    formatters: frozenset[str] = frozenset()  # callee names building a string from arguments
    appenders: frozenset[str] = frozenset()  # methods appending their argument to the receiver
    receiver_fields: tuple[str, ...] = ()  # field of a member node that holds the receiver
    request_parameters: re.Pattern[str] | None = None  # a parameter bound to request data
    interpolations: frozenset[str] = frozenset()  # interpolated string nodes
    format_macros: frozenset[str] = frozenset()  # Rust macros building a string
    sink_types: frozenset[str] = frozenset()  # constructors taking a SQL text (new SqlCommand)
    sink_properties: frozenset[str] = frozenset()  # properties holding a SQL text (CommandText)
    tail_return: bool = False  # the last expression of a block is the returned value


_WRAPPERS = frozenset(
    {
        "argument",
        "await_expression",
        "expression_list",
        "parenthesized_expression",
        "reference_expression",
        "try_expression",
        "unary_expression",
    }
)
_BINDINGS = (
    # Go, C#, Rust, TypeScript: (node type, target field, value field)
    ("short_var_declaration", "left", "right"),
    ("assignment_statement", "left", "right"),
    ("var_spec", "name", "value"),
    ("assignment_expression", "left", "right"),
    ("augmented_assignment_expression", "left", "right"),
    ("compound_assignment_expr", "left", "right"),
    ("let_declaration", "pattern", "value"),
    ("variable_declarator", "name", "value"),
)
_NAME_NODES = frozenset({"identifier", "shorthand_property_identifier_pattern"})
_STATEMENT_SUFFIXES = ("_statement", "_declaration", "_item")

_TS_FLOW = _SqlFlowProfile(
    language=_TYPESCRIPT,
    functions=frozenset({"function_declaration", "method_definition"}),
    calls=frozenset({"call_expression"}),
    sources=re.compile(
        r"\b(?:req|request)\.(?:query|params|body|headers|cookies)\b"
        r"|\bctx\.(?:query|params|request\.body)\b"
    ),
    sinks=frozenset(
        {
            "query",
            "execute",
            "raw",
            "$queryRawUnsafe",
            "$executeRawUnsafe",
            "literal",
            "whereRaw",
            "orderByRaw",
            "havingRaw",
            "joinRaw",
        }
    ),
    formatters=frozenset({"concat", "join", "format"}),
    receiver_fields=("object",),
    request_parameters=re.compile(r"@(?:Query|Param|Body|Headers)\s*\("),
    interpolations=frozenset({"template_string"}),
)
_SQL_FLOW_PROFILES = {
    "go": _SqlFlowProfile(
        language=Language(tree_sitter_go.language()),
        functions=frozenset({"function_declaration", "method_declaration"}),
        calls=frozenset({"call_expression"}),
        sources=re.compile(
            r"\.URL\.(?:Query\(\)|Path\b|RawQuery\b)|\.(?:FormValue|PostFormValue|PathValue)\("
            r"|\.Header\.Get\(|\bmux\.Vars\("
            r"|\bc\.(?:Param|Params|Query|DefaultQuery|PostForm|DefaultPostForm|GetHeader"
            r"|QueryParam|FormValue)\("
        ),
        sinks=frozenset(
            {
                "Query",
                "QueryRow",
                "QueryContext",
                "QueryRowContext",
                "Exec",
                "ExecContext",
                "Prepare",
                "PrepareContext",
                "Raw",
                "Select",
                "Get",
                "NamedExec",
                "NamedQuery",
                "MustExec",
            }
        ),
        formatters=frozenset({"Sprintf", "Sprint", "Sprintln", "Join"}),
        appenders=frozenset({"WriteString"}),
        receiver_fields=("operand",),
    ),
    "csharp": _SqlFlowProfile(
        language=Language(tree_sitter_c_sharp.language()),
        functions=frozenset(
            {"method_declaration", "local_function_statement", "constructor_declaration"}
        ),
        calls=frozenset({"invocation_expression"}),
        sources=re.compile(r"\bRequest\.(?:Query|Form|Headers|RouteValues|Cookies)\b"),
        sinks=frozenset(
            {
                "ExecuteSqlRaw",
                "ExecuteSqlRawAsync",
                "FromSqlRaw",
                "SqlQueryRaw",
                "Query",
                "QueryAsync",
                "QueryFirst",
                "QueryFirstAsync",
                "QueryFirstOrDefault",
                "QueryFirstOrDefaultAsync",
                "QuerySingle",
                "QuerySingleAsync",
                "QuerySingleOrDefault",
                "QuerySingleOrDefaultAsync",
                "QueryMultiple",
                "QueryMultipleAsync",
                "Execute",
                "ExecuteAsync",
                "ExecuteScalar",
                "ExecuteScalarAsync",
                "ExecuteReader",
                "ExecuteReaderAsync",
            }
        ),
        formatters=frozenset({"Format", "Concat", "Join"}),
        appenders=frozenset({"Append", "AppendFormat", "AppendLine"}),
        receiver_fields=("expression",),
        request_parameters=re.compile(r"\[\s*From(?:Query|Route|Body|Form|Header)\b"),
        interpolations=frozenset({"interpolated_string_expression"}),
        sink_types=frozenset(
            {
                "SqlCommand",
                "NpgsqlCommand",
                "MySqlCommand",
                "SqliteCommand",
                "OracleCommand",
                "OleDbCommand",
                "OdbcCommand",
                "SqlDataAdapter",
            }
        ),
        sink_properties=frozenset({"CommandText"}),
    ),
    "rust": _SqlFlowProfile(
        language=Language(tree_sitter_rust.language()),
        functions=frozenset({"function_item"}),
        calls=frozenset({"call_expression"}),
        sources=re.compile(r"\.match_info\(\)|\.query_string\(\)|\breq\.uri\(\)"),
        sinks=frozenset(
            {
                "query",
                "query_as",
                "query_scalar",
                "query_with",
                "sql_query",
                "execute",
                "batch_execute",
                "prepare",
                "prepare_cached",
                "query_row",
                "query_one",
                "query_opt",
                "raw_sql",
                "simple_query",
            }
        ),
        formatters=frozenset({"concat", "join"}),
        appenders=frozenset({"push_str", "push"}),
        receiver_fields=("value",),
        # Extractors of axum and actix-web; numeric paths and UUIDs cannot carry SQL
        request_parameters=re.compile(
            r"\b(?:Query|Path|Json|Form)\s*<"
            r"(?!\s*(?:[iu](?:8|16|32|64|128|size)|f32|f64|bool|Uuid)\s*>)"
        ),
        format_macros=frozenset({"format", "concat"}),
        tail_return=True,
    ),
    "typescript": _TS_FLOW,
    "javascript": replace(_TS_FLOW, language=_JAVASCRIPT),
}


class _SqlFlowAnalyzer:
    """Track local request-to-SQL flows through variables, function arguments and returns.

    A sink is reported when one of its arguments carries request data (tainted), is built
    dynamically (concatenation, interpolation, formatting) and looks like SQL.
    """

    def __init__(self, source: bytes, profile: _SqlFlowProfile) -> None:
        self.source = source
        self.profile = profile
        self.tainted: set[str] = set()
        self.dynamic: set[str] = set()
        self.sql_candidates: set[str] = set()
        self.lines: set[int] = set()
        self.functions: dict[str, Node] = {}
        self.call_stack: set[str] = set()
        self.return_stack: list[list[bool]] = []
        self.summaries: dict[tuple, tuple[bool, bool, bool]] = {}

    def analyze(self, node: Node) -> None:
        if node.type in self.profile.functions:
            self._function(node, set(), set(), set())
            return
        if (binding := self._binding_fields(node)) is not None:
            self._binding(node, *binding)
            return
        if node.type in ("return_statement", "return_expression") and self.return_stack:
            self._returned(node.named_children)
        if node.type in self.profile.calls:
            self._call(node)
        elif node.type == "object_creation_expression":
            self._creation(node)
        for child in node.named_children:
            self.analyze(child)

    def _collect_functions(self, node: Node) -> None:
        if node.type in self.profile.functions:
            name = node.child_by_field_name("name")
            if name is not None:
                self.functions[self._text(name)] = node
        for child in node.named_children:
            self._collect_functions(child)

    # ── Functions ────────────────────────────────────────────────────────────

    def _function(
        self, node: Node, tainted: set[str], dynamic: set[str], sql_candidates: set[str]
    ) -> tuple[bool, bool, bool]:
        name_node = node.child_by_field_name("name")
        name = self._text(name_node) if name_node is not None else ""
        if name in self.call_stack:
            return False, False, False
        state = self.tainted, self.dynamic, self.sql_candidates
        self.tainted, self.dynamic, self.sql_candidates = tainted, dynamic, sql_candidates
        pattern = self.profile.request_parameters
        if pattern is not None:
            for names, parameter in self._parameters(node):
                if pattern.search(self._text(parameter)):
                    self.tainted.update(names)
        self.call_stack.add(name)
        summary = [False, False, False]
        self.return_stack.append(summary)
        body = node.child_by_field_name("body")
        if body is not None:
            self.analyze(body)
            if body.type == "arrow_expression_clause":  # C#: int F() => expression;
                self._returned(body.named_children)
            elif self.profile.tail_return and body.named_children:
                tail = body.named_children[-1]
                if not tail.type.endswith(_STATEMENT_SUFFIXES):
                    self._returned([tail])
        self.return_stack.pop()
        self.call_stack.discard(name)
        self.tainted, self.dynamic, self.sql_candidates = state
        return summary[0], summary[1], summary[2]

    def _parameters(self, function: Node) -> list[tuple[list[str], Node]]:
        """Return the names bound by each positional parameter (several in Go: a, b string)."""
        parameters = function.child_by_field_name("parameters")
        found: list[tuple[list[str], Node]] = []
        for parameter in parameters.named_children if parameters is not None else []:
            names = parameter.children_by_field_name("name")
            if names and parameter.type == "parameter_declaration":  # Go: one position per name
                found.extend(([self._text(name)], parameter) for name in names)
                continue
            target = (
                names[0]
                if names
                else parameter.child_by_field_name("pattern")
                or (parameter if parameter.type in _NAME_NODES else None)
            )
            if target is not None:
                found.append((self._pattern_names(target), parameter))
        return found

    def _returned(self, values: list[Node]) -> None:
        if len(values) == 1 and values[0].type == "expression_list":
            values = values[0].named_children
        summary = self.return_stack[-1]
        for value in values:
            summary[0] |= self._tainted(value)
            summary[1] |= self._dynamic(value)
            summary[2] |= self._sql_candidate(value)

    def _analyze_callee(self, name: str, arguments: list[Node]) -> tuple[bool, bool, bool]:
        function = self.functions[name]
        tainted: set[str] = set()
        dynamic: set[str] = set()
        sql_candidates: set[str] = set()
        for (names, _), argument in zip(self._parameters(function), arguments, strict=False):
            if self._tainted(argument):
                tainted.update(names)
            if self._dynamic(argument):
                dynamic.update(names)
            if self._sql_candidate(argument):
                sql_candidates.update(names)
        key = (name, frozenset(tainted), frozenset(dynamic), frozenset(sql_candidates))
        if key not in self.summaries:  # a chain of calls is analyzed once per input state
            self.summaries[key] = self._function(function, tainted, dynamic, sql_candidates)
        return self.summaries[key]

    def _callee_summary(self, node: Node) -> tuple[bool, bool, bool] | None:
        name = self._callee(node)
        if name not in self.functions or name in self.call_stack:
            return None
        return self._analyze_callee(name, self._arguments(node))

    # ── Bindings and sinks ───────────────────────────────────────────────────

    def _binding_fields(self, node: Node) -> tuple[Node, Node] | None:
        for node_type, target_field, value_field in _BINDINGS:
            if node.type != node_type:
                continue
            target = node.child_by_field_name(target_field)
            value = node.child_by_field_name(value_field)
            if value is None and node_type == "variable_declarator":  # C#: no value field
                value = next((c for c in reversed(node.named_children) if c != target), None)
            if target is None or value is None:
                return None
            return target, value
        return None

    def _binding(self, node: Node, target: Node, value: Node) -> None:
        operator = next((self._text(c) for c in node.children if not c.is_named), "=")
        augmented = operator not in ("=", ":=")
        if target.type == "expression_list" and value.type == "expression_list":
            pairs = list(zip(target.named_children, value.named_children, strict=False))
        else:
            pairs = [(target, value)]
        for left, right in pairs:
            prop = left.child_by_field_name("name")
            if prop is not None and self._text(prop) in self.profile.sink_properties:
                self._check_sink(node, [right])
            for name in self._pattern_names(left) if left.type not in _MEMBER_NODES else []:
                self._update(name, right, augmented)
        self.analyze(value)

    def _update(self, name: str, value: Node, augmented: bool) -> None:
        for known, check in (
            (self.tainted, self._tainted),
            (self.dynamic, self._dynamic),
            (self.sql_candidates, self._sql_candidate),
        ):
            if check(value) or (augmented and name in known):
                known.add(name)
            else:
                known.discard(name)
        if augmented and name in self.tainted:
            self.dynamic.add(name)  # q += input: concatenation

    def _call(self, node: Node) -> None:
        name = self._callee(node)
        arguments = self._arguments(node)
        receiver = self._receiver(node)
        if (
            name in self.profile.appenders
            and receiver is not None
            and receiver.type == "identifier"
        ):
            receiver_name = self._text(receiver)
            if any(self._sql_candidate(a) for a in arguments):
                self.sql_candidates.add(receiver_name)  # sb.WriteString("SELECT ...")
            if any(self._tainted(a) for a in arguments):
                self.tainted.add(receiver_name)
                self.dynamic.add(receiver_name)
        if name in self.functions and name not in self.call_stack:
            self._analyze_callee(name, arguments)
        elif name in self.profile.sinks:
            self._check_sink(node, arguments)

    def _creation(self, node: Node) -> None:
        kind = node.child_by_field_name("type")
        if kind is not None and self._text(kind).rsplit(".", 1)[-1] in self.profile.sink_types:
            self._check_sink(node, self._arguments(node))

    def _check_sink(self, node: Node, arguments: list[Node]) -> None:
        for query in arguments:
            if self._tainted(query) and self._dynamic(query) and self._sql_candidate(query):
                self.lines.add(_line(node))
                return

    # ── Value properties ─────────────────────────────────────────────────────

    def _tainted(self, node: Node) -> bool:
        if node.type in _NAME_NODES:
            return self._text(node) in self.tainted
        if node.type in self.profile.calls:
            summary = self._callee_summary(node)
            if summary is not None:
                return summary[0]
        if node.type in self.profile.calls | _MEMBER_NODES and self.profile.sources.search(
            self._text(node)
        ):
            return True
        return any(self._tainted(child) for child in node.named_children)

    def _dynamic(self, node: Node) -> bool:
        if node.type in _NAME_NODES:
            return self._text(node) in self.dynamic
        if node.type in _WRAPPERS:
            return any(self._dynamic(child) for child in node.named_children)
        if node.type == "binary_expression":
            operator = node.child_by_field_name("operator")
            text = self._text(operator) if operator is not None else ""
            if not text:
                text = next((self._text(c) for c in node.children if not c.is_named), "")
            return text == "+" and self._tainted(node)
        if node.type in self.profile.interpolations:
            return self._tainted(node)
        if node.type == "macro_invocation":
            macro = node.child_by_field_name("macro")
            name = self._text(macro) if macro is not None else ""
            return name in self.profile.format_macros and self._tainted(node)
        if node.type in self.profile.calls:
            summary = self._callee_summary(node)
            if summary is not None:
                return summary[1]
            if self._callee(node) in self.profile.formatters and self._tainted(node):
                return True
            receiver = self._receiver(node)  # q.to_string(), sb.ToString()
            return receiver is not None and self._dynamic(receiver)
        return False

    def _sql_candidate(self, node: Node) -> bool:
        if node.type in _NAME_NODES:
            return self._text(node) in self.sql_candidates
        if node.type in self.profile.calls:
            summary = self._callee_summary(node)
            if summary is not None:
                return summary[2]
        if _SQL_RE.search(self._text(node)):
            return True
        return any(self._sql_candidate(child) for child in node.named_children)

    # ── Syntax helpers ───────────────────────────────────────────────────────

    def _callee(self, node: Node) -> str:
        function = node.child_by_field_name("function")
        if function is None:
            return ""
        text = self._text(function).strip()
        if text.endswith(">"):  # generic arguments: conn.Query<User>, sqlx::query_as::<_, User>
            text = text.split("<", 1)[0].removesuffix("::")
        return re.split(r"\.|::", text)[-1]

    def _arguments(self, node: Node) -> list[Node]:
        arguments = node.child_by_field_name("arguments")
        return arguments.named_children if arguments is not None else []

    def _receiver(self, node: Node) -> Node | None:
        function = node.child_by_field_name("function")
        if function is None:
            return None
        for field_name in self.profile.receiver_fields:
            receiver = function.child_by_field_name(field_name)
            if receiver is not None:
                return receiver
        return None

    def _pattern_names(self, node: Node) -> list[str]:
        """Return the variable names bound by a target (identifier or destructuring)."""
        if node.type in _NAME_NODES:
            return [self._text(node)]
        names: list[str] = []
        for index, child in enumerate(node.children):
            if child.is_named and node.field_name_for_child(index) not in ("type", "key"):
                names.extend(self._pattern_names(child))
        return names

    def _text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


_MEMBER_NODES = frozenset(
    {
        "selector_expression",
        "member_access_expression",
        "element_access_expression",
        "field_expression",
        "member_expression",
        "subscript_expression",
        "index_expression",
    }
)


def sql_taint_lines(content: str, language: str) -> list[int]:
    """Return the SQL sink lines reached by a request-controlled dynamic query.

    Args:
        content: Source code.
        language: go, csharp, rust, typescript or javascript.
    """
    profile = _SQL_FLOW_PROFILES[language]
    source = content.encode("utf-8")
    tree = Parser(profile.language).parse(source)
    analyzer = _SqlFlowAnalyzer(source, profile)
    analyzer._collect_functions(tree.root_node)
    analyzer.analyze(tree.root_node)
    return sorted(analyzer.lines)
