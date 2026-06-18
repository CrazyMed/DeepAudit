"""
调用图构建器（基于 tree-sitter）

轻量级调用图提取：
- 函数/方法定义节点
- 函数调用边
- import 关系边
- 用于跨文件漏洞追踪
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionNode:
    """函数定义节点"""
    file_path: str
    function_name: str
    line_number: int
    parameters: List[str] = field(default_factory=list)
    is_class_method: bool = False
    class_name: Optional[str] = None


@dataclass
class CallEdge:
    """函数调用边"""
    caller_file: str
    caller_function: str
    callee_file: str
    callee_function: str
    line_number: int


@dataclass
class ImportEdge:
    """导入关系边"""
    from_file: str
    imported_module: str
    imported_name: Optional[str] = None
    line_number: int = 0


@dataclass
class CallGraph:
    """调用图"""
    functions: List[FunctionNode] = field(default_factory=list)
    calls: List[CallEdge] = field(default_factory=list)
    imports: List[ImportEdge] = field(default_factory=list)

    def get_callers(self, file_path: str, function_name: str) -> List[CallEdge]:
        """查询谁调了这个函数"""
        return [c for c in self.calls if c.callee_file == file_path and c.callee_function == function_name]

    def get_callees(self, file_path: str, function_name: str) -> List[CallEdge]:
        """查询这个函数调了谁"""
        return [c for c in self.calls if c.caller_file == file_path and c.caller_function == function_name]

    def get_functions_in_file(self, file_path: str) -> List[FunctionNode]:
        """获取文件中的所有函数"""
        return [f for f in self.functions if f.file_path == file_path]

    def get_related_files(self, file_path: str, max_depth: int = 3) -> Set[str]:
        """给定文件，返回调用链上的所有相关文件（BFS，深度限制）"""
        related: Set[str] = {file_path}
        frontier: Set[str] = {file_path}

        for _ in range(max_depth):
            if not frontier:
                break
            next_frontier: Set[str] = set()

            for fp in frontier:
                # 找出这个文件调用的函数（跨文件调用）
                callee_files = {c.callee_file for c in self.calls if c.caller_file == fp and c.callee_file != fp}
                # 找出调用这个文件的函数
                caller_files = {c.caller_file for c in self.calls if c.callee_file == fp and c.caller_file != fp}

                next_frontier.update(callee_files)
                next_frontier.update(caller_files)

            new_files = next_frontier - related
            related.update(new_files)
            frontier = new_files

        return related


class CallGraphBuilder:
    """基于 tree-sitter 的调用图构建器"""

    def __init__(self):
        self._parser_cache: Dict[str, any] = {}

    def _get_parser(self, language: str):
        """延迟导入 tree-sitter，获取语言解析器"""
        if language in self._parser_cache:
            return self._parser_cache[language]

        try:
            from tree_sitter_language_pack import get_parser
            parser = get_parser(language)
            self._parser_cache[language] = parser
            return parser
        except ImportError:
            logger.warning("tree-sitter-language-pack not installed")
            return None
        except Exception as e:
            logger.warning(f"Failed to load tree-sitter parser for {language}: {e}")
            return None

    def build(self, files: List[Tuple[str, str, str]]) -> CallGraph:
        """
        构建调用图

        Args:
            files: [(file_path, language, content)] 列表

        Returns:
            CallGraph 对象
        """
        graph = CallGraph()

        for file_path, language, content in files:
            parser = self._get_parser(language)
            if not parser:
                continue

            tree = parser.parse(content.encode())
            root = tree.root_node

            # 1. 提取函数定义
            functions = self._extract_functions(file_path, root, content)
            graph.functions.extend(functions)

            # 2. 提取函数调用
            calls = self._extract_calls(file_path, root, content, functions)
            graph.calls.extend(calls)

            # 3. 提取 import
            imports = self._extract_imports(file_path, root, content)
            graph.imports.extend(imports)

        logger.info(f"CallGraph built: {len(graph.functions)} functions, {len(graph.calls)} calls, {len(graph.imports)} imports")
        return graph

    def _extract_functions(self, file_path: str, root: any, content: str) -> List[FunctionNode]:
        """提取函数定义（支持 Python、Java、JavaScript）"""
        functions = []

        def walk(node, depth=0):
            node_type = node.type

            # Python: function_definition, async_function_definition
            if node_type in ('function_definition', 'async_function_definition'):
                name_node = node.child_by_field_name('name')
                if name_node:
                    name = content[name_node.start_byte:name_node.end_byte]
                    line = content[:name_node.start_byte].count('\n') + 1
                    parameters = self._extract_parameters(node, content)

                    functions.append(FunctionNode(
                        file_path=file_path,
                        function_name=name,
                        line_number=line,
                        parameters=parameters,
                        is_class_method=False
                    ))

            # Java: method_declaration
            elif node_type == 'method_declaration':
                name_node = node.child_by_field_name('name')
                if name_node:
                    name = content[name_node.start_byte:name_node.end_byte]
                    line = content[:name_node.start_byte].count('\n') + 1
                    parameters = self._extract_parameters(node, content)

                    # 检查是否是类方法（查找父类 node）
                    class_name = None
                    parent = node.parent
                    while parent:
                        if parent.type == 'class_declaration':
                            class_name_node = parent.child_by_field_name('name')
                            if class_name_node:
                                class_name = content[class_name_node.start_byte:class_name_node.end_byte]
                            break
                        parent = parent.parent

                    functions.append(FunctionNode(
                        file_path=file_path,
                        function_name=name,
                        line_number=line,
                        parameters=parameters,
                        is_class_method=bool(class_name),
                        class_name=class_name
                    ))

            # JavaScript/TypeScript: function_declaration, arrow_function
            elif node_type in ('function_declaration', 'function_expression'):
                name_node = node.child_by_field_name('name')
                if name_node:
                    name = content[name_node.start_byte:name_node.end_byte]
                    line = content[:name_node.start_byte].count('\n') + 1
                    parameters = self._extract_parameters(node, content)

                    functions.append(FunctionNode(
                        file_path=file_path,
                        function_name=name,
                        line_number=line,
                        parameters=parameters,
                        is_class_method=False
                    ))

            for child in node.children:
                walk(child, depth + 1)

        walk(root)
        return functions

    def _extract_parameters(self, node: any, content: str) -> List[str]:
        """提取函数参数列表"""
        params_node = node.child_by_field_name('parameters')
        if not params_node:
            return []

        parameters = []
        for child in params_node.children:
            if child.type in ('identifier', 'parameter', 'typed_parameter', 'required_parameter'):
                param_text = content[child.start_byte:child.end_byte].strip()
                if param_text and param_text not in (',', '(', ')'):
                    # 去掉类型注解（如 `name: str` → `name`）
                    param_text = param_text.split(':')[0].strip()
                    parameters.append(param_text)

        return parameters

    def _extract_calls(self, file_path: str, root: any, content: str, functions: List[FunctionNode]) -> List[CallEdge]:
        """提取函数调用（简化版，只识别直接调用）"""
        calls = []
        function_map = {f.function_name: f for f in functions}

        def walk(node, depth=0):
            node_type = node.type

            # Python: call_expression
            if node_type == 'call_expression':
                func_node = node.child_by_field_name('function')
                if func_node:
                    # 处理 `module.function()` 或 `obj.method()`
                    if func_node.type in ('identifier', 'attribute_expression'):
                        if func_node.type == 'identifier':
                            callee_name = content[func_node.start_byte:func_node.end_byte]
                        else:  # attribute_expression
                            # 取最后一部分作为函数名（如 `module.function` → `function`）
                            identifier = func_node.child_by_field_name('attribute')
                            if identifier:
                                callee_name = content[identifier.start_byte:identifier.end_byte]
                            else:
                                callee_name = None

                        if callee_name and callee_name in function_map:
                            line = content[:func_node.start_byte].count('\n') + 1

                            # 简化：假设 caller 是当前文件中的某个函数（需要更精确的上下文）
                            # 实际实现需要追踪当前所在的函数定义节点
                            for func in functions:
                                if func.line_number < line:
                                    # 假设最近定义的函数是 caller（简化）
                                    calls.append(CallEdge(
                                        caller_file=file_path,
                                        caller_function=func.function_name,
                                        callee_file=function_map[callee_name].file_path,
                                        callee_function=callee_name,
                                        line_number=line
                                    ))
                                    break

            for child in node.children:
                walk(child, depth + 1)

        walk(root)
        return calls

    def _extract_imports(self, file_path: str, root: any, content: str) -> List[ImportEdge]:
        """提取 import 语句"""
        imports = []

        def walk(node):
            node_type = node.type

            # Python: import_statement, import_from_statement
            if node_type == 'import_statement':
                name_node = node.child_by_field_name('name')
                if name_node:
                    module = content[name_node.start_byte:name_node.end_byte]
                    line = content[:name_node.start_byte].count('\n') + 1
                    imports.append(ImportEdge(
                        from_file=file_path,
                        imported_module=module,
                        line_number=line
                    ))

            elif node_type == 'import_from_statement':
                # from X import Y
                module_node = node.child_by_field_name('source')
                name_node = node.child_by_field_name('name')

                if module_node:
                    module = content[module_node.start_byte:module_node.end_byte]
                    line = content[:module_node.start_byte].count('\n') + 1

                    if name_node and name_node.type == 'dotted_name':
                        # 处理 from X import a, b, c
                        imported_names = []
                        for child in name_node.children:
                            if child.type == 'identifier':
                                imported_names.append(content[child.start_byte:child.end_byte])

                        for imp_name in imported_names:
                            imports.append(ImportEdge(
                                from_file=file_path,
                                imported_module=module,
                                imported_name=imp_name,
                                line_number=line
                            ))

            for child in node.children:
                walk(child)

        walk(root)
        return imports