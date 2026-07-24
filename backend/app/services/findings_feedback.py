"""findings 结果的前端反馈消息生成。

根据 findings 数量、保存数、过滤数、是否被内容审查拦截，
生成合适的前端提示消息。

解决"跑半小时得 0 findings 不知是干净还是失败"的体验问题。
"""

from app.models.agent_task import VulnerabilitySeverity


def build_findings_summary_message(
    total_findings: int,
    saved_findings: int,
    filtered_count: int,
    intercepted: bool,
) -> str:
    """生成 findings 统计的前端提示消息。

    Args:
        total_findings: LLM/SAST 总共报告的 findings 数
        saved_findings: 实际保存到数据库的数量
        filtered_count: 被过滤（幻觉/路径无效）的数量
        intercepted: 是否有内容审查拦截（LLM 返回"无法回答"）

    Returns:
        给前端的提示消息字符串
    """
    # 优先处理拦截（最可能让用户困惑的情况）
    if total_findings == 0 and intercepted:
        return (
            "未检出漏洞，但检测到部分代码分析被模型内容安全策略拦截。"
            "建议更换模型（如 DeepSeek-Coder / Qwen-Coder）后重新扫描，"
            "或检查后端日志确认拦截详情。"
        )

    # 0 findings 且无拦截：明确告知"干净"
    if total_findings == 0 and saved_findings == 0 and filtered_count == 0:
        return "扫描完成，未检出安全漏洞。代码相对干净。"

    # 全部被过滤为幻觉
    if saved_findings == 0 and filtered_count > 0:
        return (
            f"检出 {total_findings} 个疑似问题，但全部被判为幻觉/误报已过滤。"
            "建议人工复核后端日志中的过滤详情。"
        )

    # 正常情况：部分保存
    if filtered_count > 0:
        return (
            f"扫描完成：成功保存 {saved_findings} 个漏洞，"
            f"过滤 {filtered_count} 个幻觉/误报。"
        )

    # 全部保存
    return f"扫描完成，成功检出并保存 {saved_findings} 个安全漏洞。"
