"""漏洞分类逻辑的单元测试。

验证 classify_vulnerability_type 能把各种 LLM/SAST 输出的漏洞类型字符串
正确映射到标准 VulnerabilityType。

TDD：测试定义期望行为，先红后绿。
"""

import pytest
from app.services.vuln_classifier import classify_vulnerability_type
from app.models.agent_task import VulnerabilityType


class TestClassifyExactMatch:
    """标准类型字符串应精确匹配。"""

    def test_sql_injection(self):
        assert classify_vulnerability_type("sql_injection") == VulnerabilityType.SQL_INJECTION

    def test_xss(self):
        assert classify_vulnerability_type("xss") == VulnerabilityType.XSS

    def test_command_injection(self):
        assert classify_vulnerability_type("command_injection") == VulnerabilityType.COMMAND_INJECTION

    def test_hardcoded_secret(self):
        assert classify_vulnerability_type("hardcoded_secret") == VulnerabilityType.HARDCODED_SECRET

    def test_path_traversal(self):
        assert classify_vulnerability_type("path_traversal") == VulnerabilityType.PATH_TRAVERSAL

    def test_ssrf(self):
        assert classify_vulnerability_type("ssrf") == VulnerabilityType.SSRF

    def test_deserialization(self):
        assert classify_vulnerability_type("deserialization") == VulnerabilityType.DESERIALIZATION

    def test_other(self):
        assert classify_vulnerability_type("other") == VulnerabilityType.OTHER


class TestClassifyNormalization:
    """大小写/空格/连字符变体应归一化后匹配。"""

    def test_uppercase(self):
        assert classify_vulnerability_type("SQL_INJECTION") == VulnerabilityType.SQL_INJECTION

    def test_mixed_case(self):
        assert classify_vulnerability_type("Sql_Injection") == VulnerabilityType.SQL_INJECTION

    def test_spaces(self):
        assert classify_vulnerability_type("sql injection") == VulnerabilityType.SQL_INJECTION

    def test_hyphens(self):
        assert classify_vulnerability_type("sql-injection") == VulnerabilityType.SQL_INJECTION

    def test_whitespace(self):
        assert classify_vulnerability_type("  sql_injection  ") == VulnerabilityType.SQL_INJECTION


class TestClassifyFuzzyMatch:
    """模糊匹配：含关键词的字符串应识别（但用单词边界，不误匹配）。"""

    def test_sqli_keyword(self):
        assert classify_vulnerability_type("sqli_vulnerability") == VulnerabilityType.SQL_INJECTION

    def test_command_injection_from_text(self):
        assert classify_vulnerability_type("dangerous_command_execution") == VulnerabilityType.COMMAND_INJECTION

    def test_hardcoded_password(self):
        assert classify_vulnerability_type("hardcoded_password") == VulnerabilityType.HARDCODED_SECRET

    def test_secret_in_source(self):
        assert classify_vulnerability_type("secret_exposure") == VulnerabilityType.HARDCODED_SECRET

    def test_path_traversal_keyword(self):
        assert classify_vulnerability_type("directory_traversal_bug") == VulnerabilityType.PATH_TRAVERSAL

    def test_deserialization_keyword(self):
        assert classify_vulnerability_type("unsafe_deserialization") == VulnerabilityType.DESERIALIZATION


class TestClassifyNoFalsePositive:
    """关键：短关键词不应误匹配正常单词（这是原代码的 bug）。"""

    def test_source_not_command_injection(self):
        """'source' 含 'rce' 子串但不应匹配为 command_injection。"""
        assert classify_vulnerability_type("data_source_config") == VulnerabilityType.OTHER

    def test_force_not_command_injection(self):
        """'force' 含 'rce' 不应匹配。"""
        assert classify_vulnerability_type("force_update") == VulnerabilityType.OTHER

    def test_author_not_auth_bypass(self):
        """'author' 含 'auth' 但不应匹配为 auth_bypass。"""
        assert classify_vulnerability_type("author_model") == VulnerabilityType.OTHER

    def test_resource_not_ssrf(self):
        """'resource' 含 'ssr' 不应匹配为 ssrf（但 'ssrf' 是精确词，这个应通过）。"""
        # resource 不含完整 ssrf，应不匹配
        assert classify_vulnerability_type("resource_handler") == VulnerabilityType.OTHER

    def test_empath_not_path_traversal(self):
        """'empath' 含 'path' 但不应匹配为 path_traversal。"""
        assert classify_vulnerability_type("empathy_module") == VulnerabilityType.OTHER


class TestClassifyEdgeCases:
    """边界情况。"""

    def test_empty_string(self):
        assert classify_vulnerability_type("") == VulnerabilityType.OTHER

    def test_none(self):
        assert classify_vulnerability_type(None) == VulnerabilityType.OTHER

    def test_unknown_type(self):
        assert classify_vulnerability_type("some_unknown_vuln") == VulnerabilityType.OTHER

    def test_business_logic(self):
        assert classify_vulnerability_type("business_logic") == VulnerabilityType.BUSINESS_LOGIC

    def test_weak_crypto(self):
        assert classify_vulnerability_type("weak_crypto") == VulnerabilityType.WEAK_CRYPTO

    def test_code_injection(self):
        assert classify_vulnerability_type("code_injection") == VulnerabilityType.CODE_INJECTION

    def test_nosql_injection(self):
        assert classify_vulnerability_type("nosql_injection") == VulnerabilityType.NOSQL_INJECTION

    def test_xxe(self):
        assert classify_vulnerability_type("xxe_vulnerability") == VulnerabilityType.XXE

    def test_idor(self):
        assert classify_vulnerability_type("idor") == VulnerabilityType.IDOR


class TestClassifyChineseKeywords:
    """中文关键词匹配（LLM 可能输出中文标题）。"""

    def test_chinese_command_injection(self):
        assert classify_vulnerability_type("命令注入 - subprocess shell=True拼接用户输入") == VulnerabilityType.COMMAND_INJECTION

    def test_chinese_hardcoded_secret(self):
        assert classify_vulnerability_type("硬编码密钥 - API密钥") == VulnerabilityType.HARDCODED_SECRET

    def test_chinese_hardcoded_password(self):
        assert classify_vulnerability_type("硬编码数据库密码") == VulnerabilityType.HARDCODED_SECRET

    def test_chinese_sql_injection(self):
        assert classify_vulnerability_type("SQL注入漏洞") == VulnerabilityType.SQL_INJECTION

    def test_chinese_path_traversal(self):
        assert classify_vulnerability_type("路径遍历漏洞") == VulnerabilityType.PATH_TRAVERSAL

    def test_chinese_deserialization(self):
        assert classify_vulnerability_type("不安全的反序列化") == VulnerabilityType.DESERIALIZATION

    def test_chinese_eval_injection(self):
        """eval 注入应归类为 code/command injection（含'注入'但不是SQL）"""
        result = classify_vulnerability_type("eval代码注入")
        assert result in (VulnerabilityType.CODE_INJECTION, VulnerabilityType.COMMAND_INJECTION)
