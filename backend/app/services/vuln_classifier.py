"""漏洞类型分类器。

把 LLM/SAST 输出的各种漏洞类型字符串，映射到标准 VulnerabilityType。

从 agent_tasks.py 提取，修复了原逻辑的子串误匹配 bug：
- "rce" 会匹配 "source"/"force" → 改用单词边界
- "auth" 会匹配 "author" → 改用单词边界
- "path" 会匹配 "empath" → 改用单词边界
"""

import re
import logging

from app.models.agent_task import VulnerabilityType

logger = logging.getLogger(__name__)

# 精确类型映射（归一化后的字符串 → 标准类型）
_EXACT_MAP = {
    "sql_injection": VulnerabilityType.SQL_INJECTION,
    "nosql_injection": VulnerabilityType.NOSQL_INJECTION,
    "xss": VulnerabilityType.XSS,
    "command_injection": VulnerabilityType.COMMAND_INJECTION,
    "code_injection": VulnerabilityType.CODE_INJECTION,
    "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
    "file_inclusion": VulnerabilityType.FILE_INCLUSION,
    "ssrf": VulnerabilityType.SSRF,
    "xxe": VulnerabilityType.XXE,
    "deserialization": VulnerabilityType.DESERIALIZATION,
    "auth_bypass": VulnerabilityType.AUTH_BYPASS,
    "idor": VulnerabilityType.IDOR,
    "sensitive_data_exposure": VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
    "hardcoded_secret": VulnerabilityType.HARDCODED_SECRET,
    "weak_crypto": VulnerabilityType.WEAK_CRYPTO,
    "race_condition": VulnerabilityType.RACE_CONDITION,
    "business_logic": VulnerabilityType.BUSINESS_LOGIC,
    "memory_corruption": VulnerabilityType.MEMORY_CORRUPTION,
    "other": VulnerabilityType.OTHER,
}

# 模糊匹配规则（关键词 → 类型），用单词边界匹配避免误匹配。
# 每条规则的关键词必须是漏洞的"特征词"，不会出现在正常单词里。
# 同时支持中文关键词（LLM 可能输出中文标题/描述）。
_FUZZY_RULES = [
    # SQL 注入
    ((r"\bsql\b", r"\bsqli\b", r"\bsql[ _-]?injection\b",
      r"sql注入", r"注入漏洞"), VulnerabilityType.SQL_INJECTION),
    # XSS
    ((r"\bxss\b", r"\bcross[ _-]?site\b", r"跨站脚本"), VulnerabilityType.XSS),
    # 命令注入（注意：不用 "rce" 短词，因为会匹配 source/force）
    ((r"\bcommand[ _-]?injection\b", r"\bcode[ _-]?injection\b",
      r"\bremote[ _-]?code[ _-]?execution\b",
      r"\bcommand[ _-]?execution\b", r"\bcode[ _-]?execution\b",
      r"\bos[ _-]?system\b", r"\bsubprocess\b",
      r"\bshell[ _-]?injection\b", r"\bcmd[ _-]?injection\b",
      r"命令注入", r"命令执行", r"系统命令", r"代码注入"), VulnerabilityType.COMMAND_INJECTION),
    # 路径遍历（不用裸 "path"，因为匹配 empath）
    ((r"\bpath[ _-]?traversal\b", r"\bdirectory[ _-]?traversal\b",
      r"\blfi\b", r"\brfi\b", r"路径遍历", r"目录遍历"), VulnerabilityType.PATH_TRAVERSAL),
    # SSRF
    ((r"\bssrf\b", r"\bserver[ _-]?side[ _-]?request[ _-]?forgery\b",
      r"请求伪造"), VulnerabilityType.SSRF),
    # XXE
    ((r"\bxxe\b", r"\bxml[ _-]?external[ _-]?entity\b", r"实体注入"), VulnerabilityType.XXE),
    # 认证绕过（不用裸 "auth"，因为匹配 author）
    ((r"\bauth[ _-]?bypass\b", r"\bauthentication[ _-]?bypass\b",
      r"\bauthz[ _-]?bypass\b", r"认证绕过", r"身份验证"), VulnerabilityType.AUTH_BYPASS),
    # 硬编码密钥
    ((r"\bhardcoded\b", r"\bhard[ _-]?coded\b", r"\bsecret\b",
      r"\bpassword\b", r"\bcredential\b", r"\bapi[ _-]?key\b",
      r"\bprivate[ _-]?key\b",
      r"硬编码", r"硬编码密钥", r"硬编码密码", r"密钥泄露", r"密码泄露",
      r"凭证泄露", r"敏感信息"), VulnerabilityType.HARDCODED_SECRET),
    # 反序列化
    ((r"\bdeserializ", r"\bunserializ", r"\bpickle\b", r"反序列化"), VulnerabilityType.DESERIALIZATION),
    # 弱加密
    ((r"\bweak[ _-]?crypto\b", r"\bweak[ _-]?hash\b", r"\bmd5\b", r"\bsha1\b",
      r"弱加密", r"弱哈希"), VulnerabilityType.WEAK_CRYPTO),
    # 敏感数据暴露
    ((r"\bsensitive[ _-]?data\b", r"\bdata[ _-]?exposure\b", r"敏感数据"), VulnerabilityType.SENSITIVE_DATA_EXPOSURE),
    # IDOR
    ((r"\bidor\b", r"越权访问"), VulnerabilityType.IDOR),
    # 竞态条件
    ((r"\brace[ _-]?condition\b", r"竞态条件"), VulnerabilityType.RACE_CONDITION),
    # 业务逻辑
    ((r"\bbusiness[ _-]?logic\b", r"业务逻辑"), VulnerabilityType.BUSINESS_LOGIC),
    # 内存损坏
    ((r"\bmemory[ _-]?corruption\b", r"\bbuffer[ _-]?overflow\b", r"缓冲区溢出"), VulnerabilityType.MEMORY_CORRUPTION),
]


def _normalize(raw: str) -> str:
    """归一化：小写 + 连字符/空格转下划线 + 去首尾空白。"""
    if not raw:
        return ""
    return raw.lower().strip().replace(" ", "_").replace("-", "_")


def classify_vulnerability_type(raw_type) -> str:
    """把漏洞类型字符串分类为标准 VulnerabilityType。

    Args:
        raw_type: LLM/SAST 输出的漏洞类型字符串（可能各种格式）

    Returns:
        VulnerabilityType 的字符串值
    """
    if not raw_type:
        return VulnerabilityType.OTHER

    raw_str = str(raw_type)
    normalized = _normalize(raw_str)

    # 第一级：精确匹配
    if normalized in _EXACT_MAP:
        return _EXACT_MAP[normalized]

    # 第二级：模糊匹配（单词边界，避免误匹配）
    # 用归一化后的文本（连字符/空格已转下划线）
    for patterns, vuln_type in _FUZZY_RULES:
        for pat in patterns:
            if re.search(pat, normalized):
                return vuln_type

    # 第三级：在原始文本（未归一化）上也试一次模糊匹配
    # （应对 check_id 含连字符、description 含自然语言的情况）
    raw_lower = raw_str.lower()
    raw_spaced = re.sub(r"[-_]", " ", raw_lower)
    for patterns, vuln_type in _FUZZY_RULES:
        for pat in patterns:
            pat_spaced = pat.replace("[ _-]?", " ?").replace("[ _]?", " ?")
            if re.search(pat_spaced, raw_spaced):
                return vuln_type

    return VulnerabilityType.OTHER
