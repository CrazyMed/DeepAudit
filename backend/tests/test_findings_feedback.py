"""空结果反馈逻辑的单元测试。

验证 build_findings_summary_message 能根据不同情况，
返回合适的前端提示消息（区分"干净""部分被拦截""全失败"）。
"""

import pytest
from app.services.findings_feedback import build_findings_summary_message


class TestBuildFindingsSummaryMessage:
    """根据 findings 数量和拦截记录，生成合适的提示。"""

    def test_has_findings(self):
        """有 findings 时，返回正常的统计消息。"""
        msg = build_findings_summary_message(
            total_findings=5, saved_findings=5, filtered_count=0, intercepted=False
        )
        assert "5" in msg
        assert "成功" in msg or "完成" in msg

    def test_zero_findings_clean(self):
        """0 findings 且无拦截：明确告知"未检出漏洞"。"""
        msg = build_findings_summary_message(
            total_findings=0, saved_findings=0, filtered_count=0, intercepted=False
        )
        assert "未检出" in msg or "未发现" in msg or "干净" in msg

    def test_zero_findings_with_interception(self):
        """0 findings 但有拦截：提示"部分分析被模型安全策略拦截"。"""
        msg = build_findings_summary_message(
            total_findings=0, saved_findings=0, filtered_count=0, intercepted=True
        )
        assert "拦截" in msg or "安全策略" in msg or "审查" in msg

    def test_all_filtered_as_hallucination(self):
        """全部被过滤为幻觉：提示"检出但被判为幻觉"。"""
        msg = build_findings_summary_message(
            total_findings=5, saved_findings=0, filtered_count=5, intercepted=False
        )
        assert "幻觉" in msg or "过滤" in msg or "误报" in msg

    def test_partial_saved(self):
        """部分保存：消息应含两个数字。"""
        msg = build_findings_summary_message(
            total_findings=10, saved_findings=7, filtered_count=3, intercepted=False
        )
        assert "7" in msg
        assert "3" in msg

    def test_interception_takes_priority_over_clean(self):
        """同时 0 findings + 拦截时，拦截消息优先于"干净"消息。"""
        msg = build_findings_summary_message(
            total_findings=0, saved_findings=0, filtered_count=0, intercepted=True
        )
        # 不应说"干净"，应提示拦截
        assert "干净" not in msg
