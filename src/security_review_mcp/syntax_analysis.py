"""Tree-sitter based structural checks for source code."""

import re

import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

_PYTHON = Language(tree_sitter_python.language())
_JAVA = Language(tree_sitter_java.language())
_SQL_RE = re.compile(r"\b(select|insert|update|delete|replace)\b", re.IGNORECASE)
_REQUEST_RE = re.compile(r"\brequest\.(?:args|form|values|GET|POST|query_params|json|data)\b")
_JAVA_REQUEST_RE = re.compile(
    r"\b(?:request|req|httpRequest)\.(?:getParameter|getHeader|getQueryString|getPathInfo)\s*\("
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
                    self.lines.add(node.start_point.row + 1)
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
        return self._function(function, tainted, dynamic, sql_candidates)

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
        if name in _JAVA_SQL_SINKS:
            for query in args:
                if self._tainted(query) and self._dynamic(query) and self._sql_candidate(query):
                    self.lines.add(node.start_point.row + 1)
                    break
        elif name in self.methods and name not in self.call_stack:
            self._analyze_callee(self.methods[name], args)

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
        return self._method(method, tainted, dynamic, sql_candidates)

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
                    self.xss_lines.add(node.start_point.row + 1)
        elif node.type == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            if function is not None and arguments is not None:
                method = self._text(function).rsplit(".", maxsplit=1)[-1]
                if _ANGULAR_TRUST_BYPASSES.fullmatch(method) and self._is_tainted(arguments):
                    self.xss_lines.add(node.start_point.row + 1)
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
        previous = self.tainted
        self.tainted = tainted_arguments
        if function_key in self.call_stack:
            self.tainted = previous
            return False
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
            self.message_lines.add(call.start_point.row + 1)

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
