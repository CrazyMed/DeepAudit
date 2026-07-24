"""
Analysis Agent (漏洞分析层) - LLM 驱动版

LLM 是真正的安全分析大脑！
- LLM 决定分析策略
- LLM 选择使用什么工具
- LLM 决定深入分析哪些代码
- LLM 判断发现的问题是否是真实漏洞

类型: ReAct (真正的!)
"""

import asyncio
import json
import logging
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import BaseAgent, AgentConfig, AgentResult, AgentType, AgentPattern, TaskHandoff
from ..json_parser import AgentJsonParser
from ..prompts import CORE_SECURITY_PRINCIPLES, VULNERABILITY_PRIORITIES

logger = logging.getLogger(__name__)


ANALYSIS_SYSTEM_PROMPT = """你是 DeepAudit 的漏洞分析 Agent，一个**自主**的安全专家。

## 🎯 Phase 2：SAST 主导 + LLM 研判（核心工作模式）
你的工作分两条线，**主路是研判，旁路是补充**：

**主路（研判 SAST 清单，占 80% 精力）**：
系统已在分析前强制运行了 SAST 工具（Semgrep/Bandit/Gitleaks 等），
并把它们的确定性结果作为"必检清单"提供给你。这些告警带有精确的
file_path 和 line_start，可靠性远高于你凭记忆重述。你的首要任务是：
1. 逐条研判清单中的告警 → 确认真实漏洞，或识别为误报并说明原因
2. 对确认的漏洞，补充上下文：污点来源(source)、危险汇点(sink)、数据流路径
3. 给出具体可执行的修复建议（代码级，不要泛泛而谈）

**旁路（LLM 自主补充，占 20% 精力）**：
SAST 规则未覆盖的领域（业务逻辑漏洞、复杂注入变体、认证/授权缺陷），
你可以自主发现。但**必须在 Final Answer 里给这些 finding 加上
`"_from_llm_supplement": true` 字段**，系统会把它们标为低置信度待人工确认，
绝不与 SAST 确认的高置信结果混在一起。

## 你的角色（传统职责，仍然适用）
你是安全审计的**核心大脑**，不是工具执行器。你需要：
1. 自主制定分析策略
2. 选择最有效的工具和方法
3. 深入分析可疑代码
4. 判断是否是真实漏洞
5. 动态调整分析方向

## ⚠️ 核心原则：优先使用外部专业工具！

**外部工具优先级最高！** 必须首先使用外部安全工具进行扫描，它们有：
- 经过验证的专业规则库
- 更低的误报率
- 更全面的漏洞检测能力

## 🔧 工具优先级（必须按此顺序使用）

### 第一优先级：外部专业安全工具 ⭐⭐⭐ 【必须首先使用！】
- **semgrep_scan**: 全语言静态分析 - **每次分析必用**
  参数: target_path (str), rules (str: "auto" 或 "p/security-audit")
  示例: {"target_path": ".", "rules": "auto"}

- **bandit_scan**: Python 安全扫描 - **Python项目必用**
  参数: target_path (str), severity (str)
  示例: {"target_path": ".", "severity": "medium"}

- **gitleaks_scan**: 密钥泄露检测 - **每次分析必用**
  参数: target_path (str)
  示例: {"target_path": "."}

- **safety_scan**: Python 依赖漏洞 - **有 requirements.txt 时必用**
  参数: requirements_file (str)
  示例: {"requirements_file": "requirements.txt"}

- **npm_audit**: Node.js 依赖漏洞 - **有 package.json 时必用**
  参数: target_path (str)
  示例: {"target_path": "."}

- **kunlun_scan**: 深度代码审计（Kunlun-M）
  参数: target_path (str), language (str: "php"|"javascript")
  示例: {"target_path": ".", "language": "php"}

### 第二优先级：智能扫描工具 ⭐⭐
- **smart_scan**: 智能批量安全扫描
  参数: target (str), quick_mode (bool), focus_vulnerabilities (list)
  示例: {"target": ".", "quick_mode": true}

- **quick_audit**: 快速文件审计
  参数: file_path (str), deep_analysis (bool)
  示例: {"file_path": "app/views.py", "deep_analysis": true}

### 第三优先级：内置分析工具 ⭐
- **pattern_match**: 危险模式匹配（外部工具不可用时的备选）
  参数: scan_file (str) 或 code (str), pattern_types (list)
  示例: {"scan_file": "app/models.py", "pattern_types": ["sql_injection"]}

- **dataflow_analysis**: 数据流追踪
  参数: source_code (str), variable_name (str)

### 辅助工具（RAG 优先！）
- **rag_query**: **🔥 首选** 语义搜索代码，理解业务逻辑
  参数: query (str), top_k (int)
- **security_search**: **🔥 首选** 安全相关搜索
  参数: query (str)
- **read_file**: 读取文件内容
  参数: file_path (str), start_line (int), end_line (int)
- **list_files**: ⚠️ 仅列出目录，严禁遍历
- **search_code**: ⚠️ 仅查找常量，严禁通用搜索

## 📋 推荐分析流程（严格按此执行！）

### 第一步：外部工具全面扫描（60%时间）⚡ 最重要！
根据项目技术栈，**必须首先**执行以下外部工具：

```
# 所有项目必做
Action: semgrep_scan
Action Input: {"target_path": ".", "rules": "auto"}

Action: gitleaks_scan
Action Input: {"target_path": "."}

# Python 项目必做
Action: bandit_scan
Action Input: {"target_path": ".", "severity": "medium"}

Action: safety_scan
Action Input: {"requirements_file": "requirements.txt"}

# Node.js 项目必做
Action: npm_audit
Action Input: {"target_path": "."}
```

### 第二步：分析外部工具结果（25%时间）
对外部工具发现的问题进行深入分析：
- 使用 `read_file` 查看完整代码上下文
- 使用 `dataflow_analysis` 追踪数据流
- 验证是否为真实漏洞，排除误报

### 第三步：补充扫描（10%时间）
如果外部工具覆盖不足，使用内置工具补充：
- `smart_scan` 综合扫描
- `pattern_match` 模式匹配

### 第四步：汇总报告（5%时间）
整理所有发现，输出 Final Answer

## ⚠️ 重要提醒
1. **不要跳过外部工具！** 即使内置工具可能更快，外部工具的检测能力更强
2. **Docker依赖**：外部工具需要Docker环境，如果返回"Docker不可用"，再使用内置工具
3. **并行执行**：可以连续调用多个外部工具

## 工作方式
每一步，你需要输出：

```
Thought: [分析当前情况，思考下一步应该做什么]
Action: [工具名称]
Action Input: [JSON 格式的参数]
```

当你完成分析后，输出：

```
Thought: [总结所有发现]
Final Answer: [JSON 格式的漏洞报告]
```

## ⚠️ 输出格式要求（严格遵守）

**禁止使用 Markdown 格式标记！** 你的输出必须是纯文本格式：

✅ 正确：
```
Thought: 我需要使用 semgrep 扫描代码。
Action: semgrep_scan
Action Input: {"target_path": ".", "rules": "auto"}
```

❌ 错误（禁止）：
```
**Thought:** 我需要扫描
**Action:** semgrep_scan
**Action Input:** {...}
```

## Final Answer 格式
```json
{
    "findings": [
        {
            "vulnerability_type": "sql_injection",
            "severity": "high",
            "title": "SQL 注入漏洞",
            "description": "详细描述",
            "file_path": "path/to/file.py",
            "line_start": 42,
            "code_snippet": "危险代码片段",
            "source": "污点来源",
            "sink": "危险函数",
            "suggestion": "修复建议",
            "confidence": 0.9,
            "needs_verification": true
        }
    ],
    "summary": "分析总结"
}
```

## 重点关注的漏洞类型
- SQL 注入 (query, execute, raw SQL)
- XSS (innerHTML, document.write, v-html)
- 命令注入 (exec, system, subprocess)
- 路径遍历 (open, readFile, path 拼接)
- SSRF (requests, fetch, http client)
- 硬编码密钥 (password, secret, api_key)
- 不安全的反序列化 (pickle, yaml.load, eval)

## 重要原则
1. **外部工具优先** - 首先使用 semgrep、bandit 等专业工具
2. **质量优先** - 宁可深入分析几个真实漏洞，不要浅尝辄止报告大量误报
3. **上下文分析** - 看到可疑代码要读取上下文，理解完整逻辑
4. **自主判断** - 不要机械相信工具输出，要用你的专业知识判断

## 🚨 知识工具使用警告（防止幻觉！）

**知识库中的代码示例仅供概念参考，不是实际代码！**

当你使用 `get_vulnerability_knowledge` 或 `query_security_knowledge` 时：
1. **知识示例 ≠ 项目代码** - 知识库的代码示例是通用示例，不是目标项目的代码
2. **语言可能不匹配** - 知识库可能返回 Python 示例，但项目可能是 PHP/Rust/Go
3. **必须在实际代码中验证** - 你只能报告你在 read_file 中**实际看到**的漏洞
4. **禁止推测** - 不要因为知识库说"这种模式常见"就假设项目中存在

❌ 错误做法（幻觉来源）：
```
1. 查询 auth_bypass 知识 -> 看到 JWT 示例
2. 没有在项目中找到 JWT 代码
3. 仍然报告 "JWT 认证绕过漏洞"  <- 这是幻觉！
```

✅ 正确做法：
```
1. 查询 auth_bypass 知识 -> 了解认证绕过的概念
2. 使用 read_file 读取项目的认证代码
3. 只有**实际看到**有问题的代码才报告漏洞
4. file_path 必须是你**实际读取过**的文件
```

## ⚠️ 关键约束 - 必须遵守！
1. **禁止直接输出 Final Answer** - 你必须先调用工具来分析代码
2. **至少调用两个工具** - 使用 smart_scan/semgrep_scan 进行扫描，然后用 read_file 查看代码
3. **没有工具调用的分析无效** - 不允许仅凭推测直接报告漏洞
4. **先 Action 后 Final Answer** - 必须先执行工具，获取 Observation，再输出最终结论

错误示例（禁止）：
```
Thought: 根据项目信息，可能存在安全问题
Final Answer: {...}  ❌ 没有调用任何工具！
```

正确示例（必须）：
```
Thought: 我需要先使用智能扫描工具对项目进行全面分析
Action: smart_scan
Action Input: {"scan_type": "security", "max_files": 50}
```
然后等待 Observation，再继续深入分析或输出 Final Answer。

现在开始你的安全分析！首先使用外部工具进行全面扫描。"""


@dataclass
class AnalysisStep:
    """分析步骤"""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict] = None


class AnalysisAgent(BaseAgent):
    """
    漏洞分析 Agent - LLM 驱动版
    
    LLM 全程参与，自主决定：
    1. 分析什么
    2. 使用什么工具
    3. 深入哪些代码
    4. 报告什么发现
    """
    
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        # 组合增强的系统提示词，注入核心安全原则和漏洞优先级
        full_system_prompt = f"{ANALYSIS_SYSTEM_PROMPT}\n\n{CORE_SECURITY_PRINCIPLES}\n\n{VULNERABILITY_PRIORITIES}"
        
        config = AgentConfig(
            name="Analysis",
            agent_type=AgentType.ANALYSIS,
            pattern=AgentPattern.REACT,
            max_iterations=30,
            system_prompt=full_system_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[AnalysisStep] = []
    

    
    def _parse_llm_response(self, response: str) -> AnalysisStep:
        """解析 LLM 响应 - 增强版，更健壮地提取思考内容"""
        step = AnalysisStep(thought="")

        # 🔥 v2.1: 预处理 - 移除 Markdown 格式标记（LLM 有时会输出 **Action:** 而非 Action:）
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned_response)

        # 🔥 首先尝试提取明确的 Thought 标记
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|Final Answer:|$)', cleaned_response, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # 🔥 检查是否是最终答案
        final_match = re.search(r'Final Answer:\s*(.*?)$', cleaned_response, re.DOTALL)
        if final_match:
            step.is_final = True
            answer_text = final_match.group(1).strip()
            answer_text = re.sub(r'```json\s*', '', answer_text)
            answer_text = re.sub(r'```\s*', '', answer_text)
            # 使用增强的 JSON 解析器
            step.final_answer = AgentJsonParser.parse(
                answer_text,
                default={"findings": [], "raw_answer": answer_text}
            )
            # 确保 findings 格式正确
            if "findings" in step.final_answer:
                step.final_answer["findings"] = [
                    f for f in step.final_answer["findings"]
                    if isinstance(f, dict)
                ]

            # 🔥 如果没有提取到 thought，使用 Final Answer 前的内容作为思考
            if not step.thought:
                before_final = cleaned_response[:cleaned_response.find('Final Answer:')].strip()
                if before_final:
                    before_final = re.sub(r'^Thought:\s*', '', before_final)
                    step.thought = before_final[:500] if len(before_final) > 500 else before_final

            return step

        # 🔥 提取 Action
        action_match = re.search(r'Action:\s*(\w+)', cleaned_response)
        if action_match:
            step.action = action_match.group(1).strip()

            # 🔥 如果没有提取到 thought，提取 Action 之前的内容作为思考
            if not step.thought:
                action_pos = cleaned_response.find('Action:')
                if action_pos > 0:
                    before_action = cleaned_response[:action_pos].strip()
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # 🔥 提取 Action Input
        input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|$)', cleaned_response, re.DOTALL)
        if input_match:
            input_text = input_match.group(1).strip()
            input_text = re.sub(r'```json\s*', '', input_text)
            input_text = re.sub(r'```\s*', '', input_text)
            # 使用增强的 JSON 解析器
            step.action_input = AgentJsonParser.parse(
                input_text,
                default={"raw_input": input_text}
            )

        # 🔥 最后的 fallback：如果整个响应没有任何标记，整体作为思考
        if not step.thought and not step.action and not step.is_final:
            if response.strip():
                step.thought = response.strip()[:500]

        return step
    

    
    def _normalize_tool_findings(self) -> List[Dict[str, Any]]:
        """把 SAST 工具收集的结构化 findings 转成标准漏洞格式。

        不同工具返回结构不同，这里统一归一化：
        - Semgrep: {path, start.line, extra.{message,severity,lines}, check_id}
        - Bandit:  {filename, line_number, issue_{text,severity}, test_id}
        - 通用:    {file_path/file, line, severity, message/description}

        归一化后字段对齐 SaveFindings 的期望：
        vulnerability_type / severity / title / description /
        file_path / line_start / code_snippet / source / sink / suggestion / confidence
        """
        tool_findings = getattr(self, "_tool_findings", None) or []
        if not tool_findings:
            return []

        normalized = []
        seen_keys = set()  # 去重（同一文件+行+类型）

        for tf in tool_findings:
            if not isinstance(tf, dict):
                continue

            source_tool = tf.get("_source_tool", "unknown")

            # ---- 抽取 file_path ----
            file_path = (
                tf.get("file_path") or tf.get("path") or tf.get("filename")
                or tf.get("file") or ""
            )
            # gitleaks 等可能用 ResultFile 结构，尝试嵌套
            if not file_path:
                file_path = tf.get("RuleID", "") and ""  # 占位，无路径则空

            # ---- 抽取 line_start ----
            line_start = (
                tf.get("line_start") or tf.get("line")
                or tf.get("start", {}).get("line") if isinstance(tf.get("start"), dict) else None
                or tf.get("line_number")
                or 0
            )
            try:
                line_start = int(line_start)
            except (TypeError, ValueError):
                line_start = 0

            # ---- 抽取 severity（统一到 critical/high/medium/low/info）----
            extra = tf.get("extra", {}) if isinstance(tf.get("extra"), dict) else {}
            raw_sev = (
                tf.get("severity") or extra.get("severity")
                or tf.get("issue_severity") or tf.get("level")
                or "medium"
            )
            sev_str = str(raw_sev).lower().strip()
            # Semgrep 用 ERROR/WARNING/INFO
            sev_map = {
                "error": "high", "warning": "medium", "info": "low",
                "critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "moderate": "medium", "minor": "low",
            }
            severity = sev_map.get(sev_str, "medium")

            # ---- 抽取漏洞类型与标题 ----
            check_id = tf.get("check_id") or tf.get("test_id") or tf.get("test_name") or ""
            vuln_type = self._infer_vuln_type(check_id, tf)
            title = tf.get("title") or check_id or f"{source_tool} 发现"

            # ---- 抽取描述与代码片段 ----
            description = (
                tf.get("description") or extra.get("message")
                or tf.get("issue_text") or tf.get("message")
                or f"由 {source_tool} 检出"
            )
            code_snippet = (
                tf.get("code_snippet") or extra.get("lines")
                or tf.get("code") or ""
            )

            # ---- 去重 key：文件+行+类型 ----
            dedup_key = f"{file_path}:{line_start}:{vuln_type}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            normalized.append({
                "vulnerability_type": vuln_type,
                "severity": severity,
                "title": str(title)[:200],
                "description": str(description)[:1000],
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_start,
                "code_snippet": str(code_snippet)[:500],
                "source": "",
                "sink": "",
                "suggestion": "",  # SAST 不给修复建议，留给 LLM 研判或后续补
                "confidence": 0.85,  # SAST 规则匹配，置信度较高
                "needs_verification": True,
                "_from_sast": True,
                "_source_tool": source_tool,
            })

        logger.info(f"[{self.name}] SAST findings 归一化: {len(tool_findings)} → {len(normalized)}（去重后）")
        return normalized

    def _infer_vuln_type(self, check_id: str, finding: Dict) -> str:
        """根据规则 ID / 内容推断标准漏洞类型。"""
        text = f"{check_id} {finding.get('title', '')} {finding.get('description', '')}".lower()
        if "sql" in text or "sqli" in text:
            return "sql_injection"
        if "xss" in text or "cross-site" in text:
            return "xss"
        if "command" in text or "exec" in text or "rce" in text or "os_system" in text:
            return "command_injection"
        if "traversal" in text or "path" in text or "lfi" in text:
            return "path_traversal"
        if "ssrf" in text:
            return "ssrf"
        if "xxe" in text:
            return "xxe"
        if "secret" in text or "password" in text or "credential" in text or "hardcoded" in text:
            return "hardcoded_secret"
        if "deserial" in text or "pickle" in text:
            return "deserialization"
        if "crypto" in text or "weak" in text:
            return "weak_crypto"
        return "other"

    # SAST 工具与其适用语言的映射（Recon 驱动选工具）
    SAST_TOOL_BY_LANGUAGE = {
        "python": ["semgrep_scan", "bandit_scan", "gitleaks_scan", "safety_scan"],
        "javascript": ["semgrep_scan", "gitleaks_scan", "npm_audit"],
        "typescript": ["semgrep_scan", "gitleaks_scan", "npm_audit"],
        "java": ["semgrep_scan", "gitleaks_scan"],
        "go": ["semgrep_scan", "gitleaks_scan"],
        "php": ["semgrep_scan", "gitleaks_scan"],
        "ruby": ["semgrep_scan", "gitleaks_scan"],
        "c": ["semgrep_scan", "gitleaks_scan"],
        "cpp": ["semgrep_scan", "gitleaks_scan"],
    }
    # 默认工具（语言未知或 Recon 失败时）：至少跑 semgrep + gitleaks
    DEFAULT_SAST_TOOLS = ["semgrep_scan", "gitleaks_scan"]

    def _select_sast_tools(self, tech_stack: Dict[str, Any]) -> List[str]:
        """根据 Recon 识别的技术栈，选择适用的 SAST 工具（Recon 驱动选规则）。"""
        languages = tech_stack.get("languages", []) if isinstance(tech_stack, dict) else []
        if isinstance(languages, str):
            languages = [languages]
        # 统一小写
        langs_lower = [str(l).lower().strip() for l in languages if l]

        selected = set()
        for lang in langs_lower:
            for tool in self.SAST_TOOL_BY_LANGUAGE.get(lang, []):
                selected.add(tool)

        # gitleaks（密钥泄露）对所有语言都适用，确保包含
        selected.add("gitleaks_scan")

        # 仅保留实际可用的工具（self.tools 里存在的）
        available = [t for t in selected if t in self.tools]

        if not available:
            available = [t for t in self.DEFAULT_SAST_TOOLS if t in self.tools]

        logger.info(f"[{self.name}] Recon 驱动选 SAST 工具: languages={langs_lower} → {available}")
        return available

    async def _run_mandatory_sast_scan(self, tech_stack: Dict[str, Any], target_files: List[str]) -> str:
        """Phase 2 核心：强制前置 SAST 全量扫描。

        在 ReAct 循环开始前，代码层面直接调用选定的 SAST 工具，
        不依赖 LLM 决策。结果累积到 self._tool_findings（经 base.py 收集器），
        同时返回结构化摘要供注入 LLM 作为"必检清单"。

        Returns:
            sast_briefing: 给 LLM 的 SAST 结果简报文本（含每条告警的文件/行/类型）
        """
        import time as _time
        await self.emit_thinking("🔍 Phase 2: 强制 SAST 全量前置扫描启动（零漏报下限保证）...")

        sast_tools = self._select_sast_tools(tech_stack)
        if not sast_tools:
            logger.warning(f"[{self.name}] 无可用 SAST 工具，跳过强制前置扫描")
            return "（无可用 SAST 工具，请使用内置工具分析）"

        scan_target = "."
        # 若用户指定了目标文件，仍用 "." 全量扫（SAST 全检是零漏报下限的保证）
        # 但在 briefing 里提示 Agent 重点关注目标文件

        briefing_lines = []
        total_findings = 0

        for tool_name in sast_tools:
            if self.is_cancelled:
                break
            tool = self.tools.get(tool_name)
            if tool is None:
                continue

            await self.emit_event("info", f"⚡ 强制执行 SAST: {tool_name}")
            start = _time.time()

            try:
                # 调用工具的 execute（走 base.py 的 _tool_findings 收集器）
                # 🔥 不同工具参数不同：大部分接受 target_path，
                # SafetyTool 要 requirements_file，NpmAuditTool 要 target_path。
                # 先试 target_path，参数不匹配则用各工具默认参数（无参 execute）。
                try:
                    result = await tool.execute(target_path=scan_target)
                except TypeError:
                    # 该工具不接受 target_path，用默认参数（依赖其内部默认值）
                    result = await tool.execute()
                duration = int((_time.time() - start) * 1000)

                # 累积结构化 findings（复用 base.py 的收集逻辑）
                # base.py 的 execute_tool 会收集，但这里是直接调 tool.execute，
                # 需手动喂给 _tool_findings 收集器
                self._collect_tool_result(tool_name, result)

                count = 0
                if result.success and result.metadata:
                    count = len(result.metadata.get("findings") or result.metadata.get("issues") or [])
                total_findings += count
                briefing_lines.append(
                    f"- {tool_name}: {'成功' if result.success else '失败'}, "
                    f"{count} 条告警, {duration}ms"
                )
                logger.info(f"[{self.name}] 强制 SAST {tool_name}: success={result.success}, findings={count}, {duration}ms")

            except Exception as e:
                logger.warning(f"[{self.name}] 强制 SAST {tool_name} 异常: {e}")
                briefing_lines.append(f"- {tool_name}: 异常 ({str(e)[:80]})")

        # 构建给 LLM 的必检清单
        normalized = self._normalize_tool_findings()
        await self.emit_event(
            "info",
            f"✅ SAST 前置扫描完成: {len(sast_tools)} 个工具, 共 {total_findings} 条原始告警, "
            f"归一化后 {len(normalized)} 条（去重）"
        )

        if not normalized:
            return (
                "SAST 全量扫描完成，未发现明确安全问题。\n"
                "请使用 read_file / RAG 工具复核高风险区域，并以 LLM 自主发现补充（标注为低置信）。"
            )

        # 按严重度排序，截断避免过长
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        normalized_sorted = sorted(
            normalized,
            key=lambda x: sev_order.get(x.get("severity", "low"), 3)
        )
        show_list = normalized_sorted[:30]  # 给 LLM 看前 30 条

        lines = [
            f"## 🔴 SAST 强制扫描结果（必检清单，共 {len(normalized)} 条，展示前 {len(show_list)} 条）",
            "以下每一条都带有精确的文件路径和行号，由 Semgrep/Bandit/Gitleaks 等工具确定性地检出。",
            "你的首要任务是**研判**这些告警（确认真实漏洞 / 排除误报），而非重新发现漏洞。",
            "",
        ]
        for i, f in enumerate(show_list, 1):
            lines.append(
                f"{i}. [{f.get('severity','?').upper()}] {f.get('vulnerability_type','other')} "
                f"| {f.get('file_path','?')}:{f.get('line_start',0)} "
                f"| 来源:{f.get('_source_tool','?')}"
            )
            desc = f.get("description", "")
            if desc:
                lines.append(f"   描述: {desc[:120]}")

        if len(normalized) > len(show_list):
            lines.append(f"\n... 另有 {len(normalized) - len(show_list)} 条未展示（已收集，会直接进报告）")

        return "\n".join(lines)

    def _collect_tool_result(self, tool_name: str, result) -> None:
        """把直接调用的工具结果喂给 _tool_findings 收集器（复用 base.py 逻辑）。"""
        SECURITY_TOOL_NAMES = {
            "semgrep_scan", "bandit_scan", "gitleaks_scan",
            "trufflehog_scan", "safety_scan", "npm_audit",
            "kunlun_scan", "osv_scanner", "osv_scan",
        }
        if tool_name not in SECURITY_TOOL_NAMES:
            return
        if not (result.success and result.metadata):
            return
        structured = result.metadata.get("findings") or result.metadata.get("issues") or []
        if not isinstance(structured, list) or not structured:
            return
        if not hasattr(self, "_tool_findings") or self._tool_findings is None:
            self._tool_findings = []
        for sf in structured[:50]:
            if isinstance(sf, dict):
                sf = dict(sf)
                sf["_source_tool"] = tool_name
                self._tool_findings.append(sf)

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """
        执行漏洞分析 - LLM 全程参与！
        """
        import time
        start_time = time.time()
        
        project_info = input_data.get("project_info", {})
        config = input_data.get("config", {})
        plan = input_data.get("plan", {})
        previous_results = input_data.get("previous_results", {})
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        
        # 🔥 处理交接信息
        handoff = input_data.get("handoff")
        if handoff:
            from .base import TaskHandoff
            if isinstance(handoff, dict):
                handoff = TaskHandoff.from_dict(handoff)
            self.receive_handoff(handoff)
        
        # 从 Recon 结果获取上下文
        recon_data = previous_results.get("recon", {})
        if isinstance(recon_data, dict) and "data" in recon_data:
            recon_data = recon_data["data"]
        
        tech_stack = recon_data.get("tech_stack", {})
        entry_points = recon_data.get("entry_points", [])
        high_risk_areas = recon_data.get("high_risk_areas", plan.get("high_risk_areas", []))
        initial_findings = recon_data.get("initial_findings", [])
        
        # 🔥 构建包含交接上下文的初始消息
        handoff_context = self.get_handoff_context()
        
        # 🔥 获取目标文件列表
        target_files = config.get("target_files", [])
        
        initial_message = f"""请开始对项目进行安全漏洞分析。

## 项目信息
- 名称: {project_info.get('name', 'unknown')}
- 语言: {tech_stack.get('languages', [])}
- 框架: {tech_stack.get('frameworks', [])}

"""
        # 🔥 如果指定了目标文件，明确告知 Agent
        if target_files:
            initial_message += f"""## ⚠️ 审计范围
用户指定了 {len(target_files)} 个目标文件进行审计：
"""
            for tf in target_files[:10]:
                initial_message += f"- {tf}\n"
            if len(target_files) > 10:
                initial_message += f"- ... 还有 {len(target_files) - 10} 个文件\n"
            initial_message += """
请直接分析这些指定的文件，不要分析其他文件。

"""
        
        initial_message += f"""{handoff_context if handoff_context else f'''## 上下文信息
### ⚠️ 高风险区域（来自 Recon Agent，必须优先分析）
以下是 Recon Agent 识别的高风险区域，请**务必优先**读取和分析这些文件：
{json.dumps(high_risk_areas[:20], ensure_ascii=False)}

**重要**: 请使用 read_file 工具读取上述高风险文件，不要假设文件路径或使用其他路径。

### 入口点 (前10个)
{json.dumps(entry_points[:10], ensure_ascii=False, indent=2)}

### 初步发现 (如果有)
{json.dumps(initial_findings[:5], ensure_ascii=False, indent=2) if initial_findings else "无"}'''}

## 任务
{task_context or task or '进行全面的安全漏洞分析，发现代码中的安全问题。'}

## ⚠️ 分析策略要求
1. **首先**：使用 read_file 读取上面列出的高风险文件
2. **然后**：分析这些文件中的安全问题
3. **最后**：如果需要，使用 smart_scan 或其他工具扩展分析

**禁止**：不要跳过高风险区域直接做全局扫描

## 目标漏洞类型
{config.get('target_vulnerabilities', ['all'])}

## 可用工具
{self.get_tools_description()}

请开始你的安全分析。首先读取高风险区域的文件，然后**立即**分析其中的安全问题（输出 Action）。"""
        
        # 🔥 记录工作开始
        self.record_work("开始安全漏洞分析")

        self._steps = []
        all_findings = []
        error_message = None  # 🔥 跟踪错误信息
        self._tool_findings = []  # 🔥 初始化 SAST 结构化 findings 收集器

        # 🔥 Phase 2 核心：强制 SAST 全量前置扫描（不依赖 LLM 决策）。
        # 先跑 SAST 拿到必检清单，再让 LLM 研判 —— 锁定零漏报下限。
        try:
            sast_briefing = await self._run_mandatory_sast_scan(tech_stack, target_files)
        except Exception as e:
            logger.warning(f"[{self.name}] 强制 SAST 前置扫描异常（降级为纯 LLM 模式）: {e}")
            sast_briefing = f"（SAST 前置扫描异常: {str(e)[:100]}，请使用内置工具分析）"

        # 把 SAST 必检清单注入 initial_message
        initial_message += f"""

## 🔴 SAST 强制扫描结果（你的首要研判对象）
{sast_briefing}

## ⚠️ Phase 2 研判纪律（必须遵守）
1. **首要任务**：研判上面 SAST 清单中的每一条告警——确认是真实漏洞，还是误报。
2. **不要重新发现** SAST 已经覆盖的漏洞。你的价值在于：① 排除误报 ② 补充数据流/攻击链上下文 ③ 给修复建议。
3. **SAST 漏报区域**：SAST 规则没覆盖的（如业务逻辑漏洞、复杂注入变体），你可以自主发现，但必须在 Final Answer 里用 `"_from_llm_supplement": true` 标注，这些会被标为低置信度。
4. 确认 SAST 告警时，保留其 file_path/line_start（不要改写），补充 source/sink/dataflow。
"""

        # 初始化对话历史
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]

        await self.emit_thinking("🔬 Analysis Agent 启动，开始研判 SAST 清单...")
        
        try:
            for iteration in range(self.config.max_iterations):
                if self.is_cancelled:
                    break
                
                self._iteration = iteration + 1
                
                # 🔥 再次检查取消标志（在LLM调用之前）
                if self.is_cancelled:
                    await self.emit_thinking("🛑 任务已取消，停止执行")
                    break
                
                # 调用 LLM 进行思考和决策（流式输出）
                # 🔥 使用用户配置的 temperature 和 max_tokens
                try:
                    llm_output, tokens_this_round = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                except asyncio.CancelledError:
                    logger.info(f"[{self.name}] LLM call cancelled")
                    break
                
                self._total_tokens += tokens_this_round

                # 🔥 Enhanced: Handle empty LLM response with better diagnostics
                if not llm_output or not llm_output.strip():
                    empty_retry_count = getattr(self, '_empty_retry_count', 0) + 1
                    self._empty_retry_count = empty_retry_count
                    
                    # 🔥 记录更详细的诊断信息
                    logger.warning(
                        f"[{self.name}] Empty LLM response in iteration {self._iteration} "
                        f"(retry {empty_retry_count}/3, tokens_this_round={tokens_this_round})"
                    )
                    
                    if empty_retry_count >= 3:
                        logger.error(f"[{self.name}] Too many empty responses, generating fallback result")
                        error_message = "连续收到空响应，使用回退结果"
                        await self.emit_event("warning", error_message)
                        # 🔥 不是直接 break，而是尝试生成一个回退结果
                        break
                    
                    # 🔥 更有针对性的重试提示
                    retry_prompt = f"""收到空响应。请根据以下格式输出你的思考和行动：

Thought: [你对当前安全分析情况的思考]
Action: [工具名称，如 read_file, search_code, pattern_match, semgrep_scan]
Action Input: {{"参数名": "参数值"}}

可用工具: {', '.join(self.tools.keys())}

如果你已完成分析，请输出：
Thought: [总结所有发现]
Final Answer: {{"findings": [...], "summary": "..."}}"""
                    
                    self._conversation_history.append({
                        "role": "user",
                        "content": retry_prompt,
                    })
                    continue
                
                # 重置空响应计数器
                self._empty_retry_count = 0

                # 解析 LLM 响应
                step = self._parse_llm_response(llm_output)
                self._steps.append(step)
                
                # 🔥 发射 LLM 思考内容事件 - 展示安全分析的思考过程
                if step.thought:
                    await self.emit_llm_thought(step.thought, iteration + 1)
                
                # 添加 LLM 响应到历史
                self._conversation_history.append({
                    "role": "assistant",
                    "content": llm_output,
                })
                
                # 检查是否完成
                if step.is_final:
                    await self.emit_llm_decision("完成安全分析", "LLM 判断分析已充分")
                    logger.info(f"[{self.name}] Received Final Answer: {step.final_answer}")
                    if step.final_answer and "findings" in step.final_answer:
                        all_findings = step.final_answer["findings"]
                        logger.info(f"[{self.name}] Final Answer contains {len(all_findings)} findings")
                        # 🔥 发射每个发现的事件
                        for finding in all_findings[:5]:  # 限制数量
                            await self.emit_finding(
                                finding.get("title", "Unknown"),
                                finding.get("severity", "medium"),
                                finding.get("vulnerability_type", "other"),
                                finding.get("file_path", "")
                            )
                            # 🔥 记录洞察
                            self.add_insight(
                                f"发现 {finding.get('severity', 'medium')} 级别漏洞: {finding.get('title', 'Unknown')}"
                            )
                    else:
                        logger.warning(f"[{self.name}] Final Answer has no 'findings' key or is None: {step.final_answer}")
                    
                    # 🔥 记录工作完成
                    self.record_work(f"完成安全分析，发现 {len(all_findings)} 个潜在漏洞")
                    
                    await self.emit_llm_complete(
                        f"分析完成，发现 {len(all_findings)} 个潜在漏洞",
                        self._total_tokens
                    )
                    break
                
                # 执行工具
                if step.action:
                    # 🔥 发射 LLM 动作决策事件
                    await self.emit_llm_action(step.action, step.action_input or {})
                    
                    # 🔥 循环检测：追踪工具调用失败历史
                    tool_call_key = f"{step.action}:{json.dumps(step.action_input or {}, sort_keys=True)}"
                    if not hasattr(self, '_failed_tool_calls'):
                        self._failed_tool_calls = {}
                    
                    observation = await self.execute_tool(
                        step.action,
                        step.action_input or {}
                    )
                    
                    # 🔥 检测工具调用失败并追踪
                    is_tool_error = (
                        "失败" in observation or 
                        "错误" in observation or 
                        "不存在" in observation or
                        "文件过大" in observation or
                        "Error" in observation
                    )
                    
                    if is_tool_error:
                        self._failed_tool_calls[tool_call_key] = self._failed_tool_calls.get(tool_call_key, 0) + 1
                        fail_count = self._failed_tool_calls[tool_call_key]
                        
                        # 🔥 如果同一调用连续失败3次，添加强制跳过提示
                        if fail_count >= 3:
                            logger.warning(f"[{self.name}] Tool call failed {fail_count} times: {tool_call_key}")
                            observation += f"\n\n⚠️ **系统提示**: 此工具调用已连续失败 {fail_count} 次。请：\n"
                            observation += "1. 尝试使用不同的参数（如指定较小的行范围）\n"
                            observation += "2. 使用 search_code 工具定位关键代码片段\n"
                            observation += "3. 跳过此文件，继续分析其他文件\n"
                            observation += "4. 如果已有足够发现，直接输出 Final Answer"
                            
                            # 重置计数器但保留记录
                            self._failed_tool_calls[tool_call_key] = 0
                    else:
                        # 成功调用，重置失败计数
                        if tool_call_key in self._failed_tool_calls:
                            del self._failed_tool_calls[tool_call_key]
                    
                    # 🔥 工具执行后检查取消状态
                    if self.is_cancelled:
                        logger.info(f"[{self.name}] Cancelled after tool execution")
                        break
                    
                    step.observation = observation
                    
                    # 🔥 发射 LLM 观察事件
                    await self.emit_llm_observation(observation)
                    
                    # 添加观察结果到历史
                    self._conversation_history.append({
                        "role": "user",
                        "content": f"Observation:\n{observation}",
                    })
                else:
                    # LLM 没有选择工具，提示它继续
                    await self.emit_llm_decision("继续分析", "LLM 需要更多分析")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "请继续分析。你输出了 Thought 但没有输出 Action。请**立即**选择一个工具执行，或者如果分析完成，输出 Final Answer 汇总所有发现。",
                    })
            
            # 🔥 如果循环结束但没有发现，强制 LLM 总结
            if not all_findings and not self.is_cancelled and not error_message:
                await self.emit_thinking("📝 分析阶段结束，正在生成漏洞总结...")
                
                # 添加强制总结的提示
                self._conversation_history.append({
                    "role": "user",
                    "content": """分析阶段已结束。请立即输出 Final Answer，总结你发现的所有安全问题。

即使没有发现严重漏洞，也请总结你的分析过程和观察到的潜在风险点。

请按以下 JSON 格式输出：
```json
{
    "findings": [
        {
            "vulnerability_type": "sql_injection|xss|command_injection|path_traversal|ssrf|hardcoded_secret|other",
            "severity": "critical|high|medium|low",
            "title": "漏洞标题",
            "description": "详细描述",
            "file_path": "文件路径",
            "line_start": 行号,
            "code_snippet": "相关代码片段",
            "suggestion": "修复建议"
        }
    ],
    "summary": "分析总结"
}
```

Final Answer:""",
                })
                
                try:
                    summary_output, _ = await self.stream_llm_call(
                        self._conversation_history,
                        # 🔥 不传递 temperature 和 max_tokens，使用用户配置
                    )
                    
                    if summary_output and summary_output.strip():
                        # 解析总结输出
                        import re
                        summary_text = summary_output.strip()
                        summary_text = re.sub(r'```json\s*', '', summary_text)
                        summary_text = re.sub(r'```\s*', '', summary_text)
                        parsed_result = AgentJsonParser.parse(
                            summary_text,
                            default={"findings": [], "summary": ""}
                        )
                        if "findings" in parsed_result:
                            all_findings = parsed_result["findings"]
                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to generate summary: {e}")
            
            # 处理结果
            duration_ms = int((time.time() - start_time) * 1000)
            
            # 🔥 如果被取消，返回取消结果
            if self.is_cancelled:
                await self.emit_event(
                    "info",
                    f"🛑 Analysis Agent 已取消: {len(all_findings)} 个发现, {self._iteration} 轮迭代"
                )
                return AgentResult(
                    success=False,
                    error="任务已取消",
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 🔥 如果有错误，返回失败结果
            if error_message:
                await self.emit_event(
                    "error",
                    f"❌ Analysis Agent 失败: {error_message}"
                )
                return AgentResult(
                    success=False,
                    error=error_message,
                    data={"findings": all_findings},
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )
            
            # 标准化发现
            logger.info(f"[{self.name}] Standardizing {len(all_findings)} findings")

            # 🔥 修复：把 SAST 工具的结构化 findings 转成标准格式并合并。
            # SAST 结果带精确 file_path/line，是 LLM 重述的可靠补充/替代。
            sast_findings = self._normalize_tool_findings()
            if sast_findings:
                logger.info(f"[{self.name}] 合并 {len(sast_findings)} 条 SAST 结构化 findings")
                # SAST findings 放在最前（精确度高），LLM findings 追加在后
                all_findings = sast_findings + all_findings

            standardized_findings = []
            for finding in all_findings:
                # 确保 finding 是字典
                if not isinstance(finding, dict):
                    logger.warning(f"Skipping invalid finding (not a dict): {finding}")
                    continue
                    
                standardized = {
                    "vulnerability_type": finding.get("vulnerability_type", "other"),
                    "severity": finding.get("severity", "medium"),
                    "title": finding.get("title", "Unknown Finding"),
                    "description": finding.get("description", ""),
                    "file_path": finding.get("file_path", ""),
                    "line_start": finding.get("line_start") or finding.get("line", 0),
                    "code_snippet": finding.get("code_snippet", ""),
                    "source": finding.get("source", ""),
                    "sink": finding.get("sink", ""),
                    "suggestion": finding.get("suggestion", ""),
                    "confidence": finding.get("confidence", 0.7),
                    "needs_verification": finding.get("needs_verification", True),
                }
                # 🔥 Phase 2.4：旁路标记 —— 区分 SAST 确认 vs LLM 自主补充。
                # SAST 来源（_from_sast）保持高置信；LLM 自主补充（_from_llm_supplement）
                # 或无来源标记的，降级置信度，标 needs_verification=True 待人工确认。
                if finding.get("_from_sast"):
                    standardized["_from_sast"] = True
                    standardized["_source_tool"] = finding.get("_source_tool", "sast")
                    # SAST 确认的，置信度不低于 0.8
                    if standardized["confidence"] < 0.8:
                        standardized["confidence"] = 0.85
                else:
                    # LLM 自主补充（旁路发现）
                    standardized["_from_llm_supplement"] = True
                    standardized["confidence"] = min(standardized["confidence"], 0.4)
                    standardized["needs_verification"] = True
                standardized_findings.append(standardized)
            
            await self.emit_event(
                "info",
                f"Analysis Agent 完成: {len(standardized_findings)} 个发现, {self._iteration} 轮迭代, {self._tool_calls} 次工具调用"
            )

            # 🔥 CRITICAL: Log final findings count before returning
            logger.info(f"[{self.name}] Returning {len(standardized_findings)} standardized findings")

            # 🔥 创建 TaskHandoff - 传递给 Verification Agent
            handoff = self._create_analysis_handoff(standardized_findings)

            return AgentResult(
                success=True,
                data={
                    "findings": standardized_findings,
                    "steps": [
                        {
                            "thought": s.thought,
                            "action": s.action,
                            "action_input": s.action_input,
                            "observation": s.observation[:500] if s.observation else None,
                        }
                        for s in self._steps
                    ],
                },
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,  # 🔥 添加 handoff
            )
            
        except Exception as e:
            logger.error(f"Analysis Agent failed: {e}", exc_info=True)
            return AgentResult(success=False, error=str(e))
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """获取对话历史"""
        return self._conversation_history

    def get_steps(self) -> List[AnalysisStep]:
        """获取执行步骤"""
        return self._steps

    def _create_analysis_handoff(self, findings: List[Dict[str, Any]]) -> TaskHandoff:
        """
        创建 Analysis Agent 的任务交接信息

        Args:
            findings: 分析发现的漏洞列表

        Returns:
            TaskHandoff 对象，供 Verification Agent 使用
        """
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity", "low"), 3)
        )

        # 提取关键发现（优先高危漏洞）
        key_findings = sorted_findings[:15]

        # 构建建议行动 - 哪些漏洞需要优先验证
        suggested_actions = []
        for f in sorted_findings[:10]:
            suggested_actions.append({
                "action": "verify_vulnerability",
                "target": f.get("file_path", ""),
                "line": f.get("line_start", 0),
                "vulnerability_type": f.get("vulnerability_type", "unknown"),
                "severity": f.get("severity", "medium"),
                "priority": "high" if f.get("severity") in ["critical", "high"] else "normal",
                "reason": f.get("title", "需要验证")
            })

        # 统计漏洞类型和严重程度
        severity_counts = {}
        type_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            vtype = f.get("vulnerability_type", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        # 构建洞察
        insights = [
            f"发现 {len(findings)} 个潜在漏洞需要验证",
            f"严重程度分布: Critical={severity_counts.get('critical', 0)}, "
            f"High={severity_counts.get('high', 0)}, "
            f"Medium={severity_counts.get('medium', 0)}, "
            f"Low={severity_counts.get('low', 0)}",
        ]

        # 最常见的漏洞类型
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            insights.append(f"主要漏洞类型: {', '.join([f'{t}({c})' for t, c in top_types])}")

        # 需要关注的文件
        attention_points = []
        files_with_findings = {}
        for f in findings:
            fp = f.get("file_path", "")
            if fp:
                files_with_findings[fp] = files_with_findings.get(fp, 0) + 1

        for fp, count in sorted(files_with_findings.items(), key=lambda x: x[1], reverse=True)[:10]:
            attention_points.append(f"{fp} ({count}个漏洞)")

        # 优先验证的区域 - 高危漏洞所在文件
        priority_areas = []
        for f in sorted_findings[:10]:
            if f.get("severity") in ["critical", "high"]:
                fp = f.get("file_path", "")
                if fp and fp not in priority_areas:
                    priority_areas.append(fp)

        # 上下文数据
        context_data = {
            "severity_distribution": severity_counts,
            "vulnerability_types": type_counts,
            "files_with_findings": files_with_findings,
        }

        # 构建摘要
        high_count = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        summary = f"完成代码分析: 发现{len(findings)}个漏洞, 其中{high_count}个高危"

        return self.create_handoff(
            to_agent="verification",
            summary=summary,
            key_findings=key_findings,
            suggested_actions=suggested_actions,
            attention_points=attention_points,
            priority_areas=priority_areas,
            context_data=context_data,
        )
