"""Phase 2 SAST 主导流程的纯逻辑单元测试。

验证三个核心函数的行为（不依赖 LLM、不依赖 Docker）：
- _infer_vuln_type: 规则 ID/内容 → 标准漏洞类型
- _select_sast_tools: 技术栈 → 选定 SAST 工具
- _normalize_tool_findings: SAST 原始结果 → 标准漏洞格式

TDD 原则：测试定义"函数该做什么"（契约），不是"代码现在做了什么"。
"""

import pytest
from app.services.agent.agents.analysis import AnalysisAgent


# 所有 SAST 工具名（测试时构造完整 tools dict，避免被过滤）
ALL_SAST_TOOLS = {
    "semgrep_scan": object(),
    "bandit_scan": object(),
    "gitleaks_scan": object(),
    "safety_scan": object(),
    "npm_audit": object(),
    "trufflehog_scan": object(),
    "osv_scan": object(),
}


@pytest.fixture
def agent():
    """构造一个最小 AnalysisAgent（LLM=None），只为测纯逻辑方法。"""
    return AnalysisAgent(llm_service=None, tools=dict(ALL_SAST_TOOLS))


# ============================================================
# _infer_vuln_type：根据规则 ID + finding 内容推断漏洞类型
# ============================================================

class TestInferVulnType:
    """验证 _infer_vuln_type 能正确识别各漏洞类型。"""

    def test_sql_injection_from_check_id(self, agent):
        assert agent._infer_vuln_type("python.sql-injection", {}) == "sql_injection"

    def test_sql_injection_from_sqli_keyword(self, agent):
        assert agent._infer_vuln_type("", {"title": "SQLi vulnerability"}) == "sql_injection"

    def test_sql_injection_from_description(self, agent):
        assert agent._infer_vuln_type("some-rule", {"description": "unsafe SQL query"}) == "sql_injection"

    def test_xss(self, agent):
        assert agent._infer_vuln_type("xss-reflected", {}) == "xss"

    def test_xss_cross_site(self, agent):
        assert agent._infer_vuln_type("", {"title": "cross-site scripting"}) == "xss"

    def test_command_injection(self, agent):
        assert agent._infer_vuln_type("command-injection", {}) == "command_injection"

    def test_command_injection_rce(self, agent):
        assert agent._infer_vuln_type("", {"description": "remote code execution RCE"}) == "command_injection"

    def test_command_injection_os_system(self, agent):
        assert agent._infer_vuln_type("os_command_injection", {}) == "command_injection"

    def test_path_traversal(self, agent):
        assert agent._infer_vuln_type("path-traversal", {}) == "path_traversal"

    def test_path_traversal_lfi(self, agent):
        assert agent._infer_vuln_type("lfi-vulnerability", {}) == "path_traversal"

    def test_ssrf(self, agent):
        assert agent._infer_vuln_type("ssrf-request-forgery", {}) == "ssrf"

    def test_xxe(self, agent):
        assert agent._infer_vuln_type("xxe-external-entity", {}) == "xxe"

    def test_hardcoded_secret_from_secret(self, agent):
        assert agent._infer_vuln_type("hardcoded-secret", {}) == "hardcoded_secret"

    def test_hardcoded_secret_from_password(self, agent):
        assert agent._infer_vuln_type("", {"title": "hardcoded password detected"}) == "hardcoded_secret"

    def test_hardcoded_secret_from_credential(self, agent):
        assert agent._infer_vuln_type("", {"description": "credential in source"}) == "hardcoded_secret"

    def test_deserialization(self, agent):
        assert agent._infer_vuln_type("unsafe-deserialization", {}) == "deserialization"

    def test_deserialization_pickle(self, agent):
        assert agent._infer_vuln_type("pickle-load", {}) == "deserialization"

    def test_weak_crypto(self, agent):
        assert agent._infer_vuln_type("weak-crypto-md5", {}) == "weak_crypto"

    def test_other_when_no_match(self, agent):
        assert agent._infer_vuln_type("some-unknown-rule", {"title": "minor issue"}) == "other"

    def test_case_insensitive(self, agent):
        """规则 ID 大写也应能识别。"""
        assert agent._infer_vuln_type("SQL-INJECTION", {}) == "sql_injection"

    def test_empty_inputs(self, agent):
        assert agent._infer_vuln_type("", {}) == "other"


# ============================================================
# _select_sast_tools：根据技术栈选 SAST 工具
# ============================================================

class TestSelectSastTools:
    """验证 _select_sast_tools 能按语言正确选工具。"""

    def test_python_selects_bandit_and_safety(self, agent):
        """Python 项目应选 bandit（Python 专用）和 safety（依赖扫描）。"""
        tools = agent._select_sast_tools({"languages": ["python"]})
        assert "bandit_scan" in tools
        assert "safety_scan" in tools
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools  # gitleaks 对所有语言都适用

    def test_javascript_selects_npm_audit(self, agent):
        tools = agent._select_sast_tools({"languages": ["javascript"]})
        assert "npm_audit" in tools
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools
        # JS 项目不应选 bandit（Python 专用）
        assert "bandit_scan" not in tools

    def test_typescript_selects_npm_audit(self, agent):
        tools = agent._select_sast_tools({"languages": ["typescript"]})
        assert "npm_audit" in tools

    def test_java_no_bandit(self, agent):
        """Java 项目不应选 bandit/safety（Python 专用）。"""
        tools = agent._select_sast_tools({"languages": ["java"]})
        assert "bandit_scan" not in tools
        assert "safety_scan" not in tools
        assert "semgrep_scan" in tools

    def test_golang(self, agent):
        tools = agent._select_sast_tools({"languages": ["go"]})
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools

    def test_gitleaks_always_included(self, agent):
        """密钥泄露检测对所有语言都应包含。"""
        for lang in ["python", "java", "go", "c", "ruby"]:
            tools = agent._select_sast_tools({"languages": [lang]})
            assert "gitleaks_scan" in tools, f"gitleaks 缺失于语言 {lang}"

    def test_multiple_languages_union(self, agent):
        """多语言项目应选各语言工具的并集。"""
        tools = agent._select_sast_tools({"languages": ["python", "javascript"]})
        # Python 的
        assert "bandit_scan" in tools
        assert "safety_scan" in tools
        # JS 的
        assert "npm_audit" in tools

    def test_unknown_language_falls_back_to_default(self, agent):
        """未知语言应回退到默认工具（至少 semgrep + gitleaks）。"""
        tools = agent._select_sast_tools({"languages": ["rust"]})
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools

    def test_empty_languages(self, agent):
        """空语言列表应回退到默认。"""
        tools = agent._select_sast_tools({"languages": []})
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools

    def test_missing_languages_key(self, agent):
        """tech_stack 没有 languages 键时应回退到默认。"""
        tools = agent._select_sast_tools({})
        assert "semgrep_scan" in tools
        assert "gitleaks_scan" in tools

    def test_language_string_not_list(self, agent):
        """languages 是字符串而非列表时也能处理。"""
        tools = agent._select_sast_tools({"languages": "python"})
        assert "bandit_scan" in tools

    def test_language_case_insensitive(self, agent):
        """语言名大小写不敏感。"""
        tools = agent._select_sast_tools({"languages": ["Python", "JAVASCRIPT"]})
        assert "bandit_scan" in tools
        assert "npm_audit" in tools

    def test_filters_unavailable_tools(self, agent):
        """只选 self.tools 里实际存在的工具。"""
        # 构造一个只有 semgrep 的 agent
        limited_agent = AnalysisAgent(llm_service=None, tools={"semgrep_scan": object()})
        tools = limited_agent._select_sast_tools({"languages": ["python"]})
        # bandit 不在 tools 里，应被过滤
        assert "bandit_scan" not in tools
        assert "semgrep_scan" in tools


# ============================================================
# _normalize_tool_findings: SAST 原始结果 → 标准漏洞格式
# ============================================================

class TestNormalizeToolFindings:
    """验证 _normalize_tool_findings 能正确归一化不同工具的结果。"""

    def test_empty_returns_empty(self, agent):
        agent._tool_findings = []
        assert agent._normalize_tool_findings() == []

    def test_no_attribute_returns_empty(self, agent):
        """没有 _tool_findings 属性时应返回空列表，不报错。"""
        if hasattr(agent, "_tool_findings"):
            del agent._tool_findings
        assert agent._normalize_tool_findings() == []

    def test_semgrep_result_normalized(self, agent):
        """Semgrep 格式（path/start.line/extra.message/check_id）应正确归一化。"""
        agent._tool_findings = [{
            "_source_tool": "semgrep_scan",
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "app/server.py",
            "start": {"line": 42},
            "extra": {
                "severity": "ERROR",
                "message": "Dangerous subprocess use",
                "lines": "subprocess.call(user_input)",
            },
        }]
        result = agent._normalize_tool_findings()
        assert len(result) == 1
        f = result[0]
        assert f["file_path"] == "app/server.py"
        assert f["line_start"] == 42
        assert f["vulnerability_type"] == "command_injection"
        assert f["severity"] == "high"  # ERROR → high
        assert f["_from_sast"] is True
        assert f["_source_tool"] == "semgrep_scan"

    def test_bandit_result_normalized(self, agent):
        """Bandit 格式（filename/line_number/issue_text/issue_severity）。"""
        agent._tool_findings = [{
            "_source_tool": "bandit_scan",
            "test_id": "B608",
            "test_name": "hardcoded_sql_expressions",
            "filename": "db/queries.py",
            "line_number": 15,
            "issue_severity": "MEDIUM",
            "issue_text": "Possible SQL injection",
        }]
        result = agent._normalize_tool_findings()
        assert len(result) == 1
        f = result[0]
        assert f["file_path"] == "db/queries.py"
        assert f["line_start"] == 15
        assert f["vulnerability_type"] == "sql_injection"
        assert f["severity"] == "medium"

    def test_gitleaks_result_normalized(self, agent):
        """Gitleaks 格式（含 RuleID + Secret）。"""
        agent._tool_findings = [{
            "_source_tool": "gitleaks_scan",
            "RuleID": "hardcoded-password",
            "file": "config/settings.py",
            "StartLine": 8,
            "Secret": "password123",
            "Description": "hardcoded credential detected",
        }]
        result = agent._normalize_tool_findings()
        assert len(result) == 1
        f = result[0]
        assert f["file_path"] == "config/settings.py"
        assert f["line_start"] == 8
        assert f["vulnerability_type"] == "hardcoded_secret"

    def test_severity_mapping(self, agent):
        """Semgrep 的 ERROR/WARNING/INFO 应映射到 high/medium/low。"""
        cases = [
            ("ERROR", "high"),
            ("WARNING", "medium"),
            ("INFO", "low"),
            ("critical", "critical"),
            ("unknown", "medium"),  # 未知 → medium
        ]
        for raw, expected in cases:
            agent._tool_findings = [{
                "_source_tool": "semgrep_scan",
                "path": "x.py",
                "start": {"line": 1},
                "extra": {"severity": raw, "message": "test"},
            }]
            result = agent._normalize_tool_findings()
            assert result[0]["severity"] == expected, f"severity {raw} 应映射为 {expected}"

    def test_deduplication(self, agent):
        """相同 file_path + line + type 的应去重。"""
        agent._tool_findings = [
            {
                "_source_tool": "semgrep_scan",
                "path": "app.py", "start": {"line": 10},
                "extra": {"severity": "ERROR", "message": "sql injection"},
                "check_id": "sql-injection",
            },
            {
                "_source_tool": "bandit_scan",  # 不同工具但同位置同类型
                "filename": "app.py", "line_number": 10,
                "issue_severity": "HIGH", "issue_text": "SQL injection",
                "test_id": "B608",
            },
        ]
        result = agent._normalize_tool_findings()
        assert len(result) == 1, "应去重为 1 条"

    def test_preserves_code_snippet(self, agent):
        agent._tool_findings = [{
            "_source_tool": "semgrep_scan",
            "path": "app.py", "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": "test", "lines": "os.system(x)"},
        }]
        result = agent._normalize_tool_findings()
        assert result[0]["code_snippet"] == "os.system(x)"

    def test_confidence_high_for_sast(self, agent):
        """SAST 来源的 confidence 应 >= 0.8。"""
        agent._tool_findings = [{
            "_source_tool": "semgrep_scan",
            "path": "app.py", "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": "test"},
        }]
        result = agent._normalize_tool_findings()
        assert result[0]["confidence"] >= 0.8

    def test_skips_non_dict_findings(self, agent):
        """非字典类型的 finding 应被跳过，不报错。"""
        agent._tool_findings = ["invalid", None, 42]
        assert agent._normalize_tool_findings() == []

    def test_truncates_long_fields(self, agent):
        """超长字段应被截断，避免数据库溢出。"""
        long_desc = "A" * 2000
        agent._tool_findings = [{
            "_source_tool": "semgrep_scan",
            "path": "app.py", "start": {"line": 1},
            "extra": {"severity": "ERROR", "message": long_desc},
        }]
        result = agent._normalize_tool_findings()
        assert len(result[0]["description"]) <= 1000
