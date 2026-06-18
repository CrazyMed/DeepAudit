"""
跨文件数据流分析器

结合调用图追踪数据流传播路径：
- 从污点源到危险汇的跨文件路径
- 基于调用关系的上下文提取
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

from .call_graph import CallGraph, FunctionNode, CallEdge

logger = logging.getLogger(__name__)


@dataclass
class TaintPath:
    """污点传播路径"""
    source_file: str
    source_function: str
    source_variable: str
    sink_file: str
    sink_function: str
    sink_line: int
    propagation_path: List[str] = field(default_factory=list)  # [file1, file2, ...]
    confidence: float = 0.0


@dataclass
class CrossFileContext:
    """跨文件上下文"""
    target_file: str
    related_files: Set[str] = field(default_factory=set)
    relevant_functions: List[Tuple[str, str]] = field(default_factory=list)  # [(file, function), ...]
    caller_chain: List[Tuple[str, str]] = field(default_factory=list)  # 谁调了这个文件


class CrossFileAnalyzer:
    """跨文件数据流分析器"""

    def __init__(self, call_graph: CallGraph):
        self.graph = call_graph

    def get_relevant_context(self, file_path: str, target_function: Optional[str] = None) -> CrossFileContext:
        """
        获取目标文件的跨文件相关上下文

        Args:
            file_path: 目标文件路径
            target_function: 目标函数（可选，用于更精确的上下文）

        Returns:
            CrossFileContext 对象
        """
        # 1. 找出调用链上的所有相关文件
        related_files = self.graph.get_related_files(file_path, max_depth=3)

        # 2. 找出所有相关函数（跨文件调用的函数）
        relevant_functions: List[Tuple[str, str]] = []

        # 找出这个文件调用的外部函数
        for call in self.graph.calls:
            if call.caller_file == file_path and call.callee_file != file_path:
                relevant_functions.append((call.callee_file, call.callee_function))

        # 找出调用这个文件的函数
        for call in self.graph.calls:
            if call.callee_file == file_path:
                relevant_functions.append((call.caller_file, call.caller_function))

        # 3. 找出调用者链（谁调了这个文件的函数）
        caller_chain: List[Tuple[str, str]] = []
        if target_function:
            callers = self.graph.get_callers(file_path, target_function)
            for caller in callers:
                caller_chain.append((caller.caller_file, caller.caller_function))

        return CrossFileContext(
            target_file=file_path,
            related_files=related_files,
            relevant_functions=list(set(relevant_functions)),  # 去重
            caller_chain=caller_chain
        )

    def trace_taint(self, source_file: str, source_var: str, sink_patterns: Set[str]) -> List[TaintPath]:
        """
        追踪污点从源到汇的跨文件路径（简化版启发式算法）

        注意：真实的数据流分析需要程序切片或符号执行，这里提供基于调用图的近似路径。

        Args:
            source_file: 污点源文件路径
            source_var: 污点变量名
            sink_patterns: 危险函数模式集合（如 `execute`, `eval`, `os.system`）

        Returns:
            污点传播路径列表
        """
        paths = []

        # 1. 找出 source_file 中定义的函数
        source_functions = self.graph.get_functions_in_file(source_file)

        for source_func in source_functions:
            # 2. BFS 追踪调用链，寻找 sink
            queue = [(source_file, source_func.function_name, [source_file])]
            visited = set()

            while queue:
                current_file, current_func, path = queue.pop(0)
                state = (current_file, current_func)

                if state in visited:
                    continue
                visited.add(state)

                # 检查当前函数是否是 sink
                if self._is_sink_function(current_func, sink_patterns):
                    # 找到汇，构建路径
                    paths.append(TaintPath(
                        source_file=source_file,
                        source_function=source_func.function_name,
                        source_variable=source_var,
                        sink_file=current_file,
                        sink_function=current_func,
                        sink_line=0,  # 需要从 AST 提取
                        propagation_path=path,
                        confidence=0.6  # 简化版置信度
                    ))
                    continue

                # 继续追踪调用的函数
                callees = self.graph.get_callees(current_file, current_func)
                for callee in callees:
                    if callee.callee_file not in path:  # 避免循环
                        queue.append((
                            callee.callee_file,
                            callee.callee_function,
                            path + [callee.callee_file]
                        ))

        return paths

    def _is_sink_function(self, function_name: str, sink_patterns: Set[str]) -> bool:
        """检查函数名是否匹配 sink 模式"""
        for pattern in sink_patterns:
            if pattern.lower() in function_name.lower():
                return True
        return False

    def get_function_context(self, file_path: str, function_name: str) -> Optional[Dict]:
        """
        获取函数的跨文件调用上下文

        Args:
            file_path: 文件路径
            function_name: 函数名

        Returns:
            上下文字典：{callers: [...], callees: [...], related_files: [...]}
        """
        callers = self.graph.get_callers(file_path, function_name)
        callees = self.graph.get_callees(file_path, function_name)

        related_files = {c.caller_file for c in callers} | {c.callee_file for c in callees}
        related_files.discard(file_path)

        return {
            'function_name': function_name,
            'file_path': file_path,
            'callers': [{'file': c.caller_file, 'function': c.caller_function} for c in callers],
            'callees': [{'file': c.callee_file, 'function': c.callee_function} for c in callees],
            'related_files': list(related_files),
            'call_depth': len(callers)
        }