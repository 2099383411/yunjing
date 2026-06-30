"""Monitor Agent — 检测完成的扫描任务，自动触发分析并推送对话"""

import time
import logging
import httpx
import json
from sqlalchemy import create_engine, text

logger = logging.getLogger(__name__)

MONITOR_INTERVAL = 30  # 秒
MAX_RETRIES = 10

# 每个 task 的重试计数
_task_retries: dict[str, int] = {}


def monitor_loop():
    """后台守护线程：检测 COMPLETED + 未推送 → 分析 → 写消息"""
    from tasks.scan_helpers import DB_URL
    engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=2)
    while True:
        try:
            with engine.connect() as conn:
                rows = conn.execute(text(
                    "SELECT id, conversation_id FROM scan_tasks "
                    "WHERE status='COMPLETED' AND progress=100 AND "
                    "(notified IS NULL OR notified=false) AND "
                    "conversation_id IS NOT NULL "
                    "LIMIT 5"
                )).fetchall()
                for task_id, conv_id in rows:
                    task_key = str(task_id)
                    # 检查是否超过最大重试次数
                    if _task_retries.get(task_key, 0) >= MAX_RETRIES:
                        logger.warning(f"[Monitor] task {task_key[:12]} 超过最大重试次数({MAX_RETRIES})，跳过")
                        conn.execute(text(
                            "UPDATE scan_tasks SET notified=true WHERE id=:id"
                        ), {"id": task_id})
                        conn.commit()
                        _task_retries.pop(task_key, None)
                        continue
                    try:
                        # 调 /api/analyze
                        r = httpx.post(
                            "http://yunjing-backend:8000/api/analyze",
                            json={"task_id": str(task_id)},
                            timeout=30
                        )
                        if r.status_code == 200 and r.json().get("status") == "ok":
                            data = r.json()
                            summary = data.get("summary", "")
                            steps = data.get("next_steps", [])
                            findings = data.get("findings_count", "?")
                            text_content = f"✅ 扫描完成！发现 {findings} 个问题\n\n📊 **AI 渗透分析**\n{summary}\n"
                            if steps:
                                text_content += "\n🎯 **下一步建议**\n" + "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps[:5]))
                            text_content += "\n"
                            # 写消息
                            import uuid
                            conn.execute(text(
                                "INSERT INTO messages (id, conversation_id, role, content) "
                                "VALUES (:id, :conv, 'assistant', :content)"
                            ), {"id": str(uuid.uuid4()), "conv": str(conv_id), "content": text_content})
                            # 标记已通知
                            conn.execute(text(
                                "UPDATE scan_tasks SET notified=true WHERE id=:id"
                            ), {"id": str(task_id)})
                            conn.commit()
                            logger.info(f"[Monitor] 分析已推送到对话 {str(conv_id)[:12]} (task={task_key[:12]})")
                            # 成功后重置重试计数
                            _task_retries.pop(task_key, None)
                    except Exception as e:
                        _task_retries[task_key] = _task_retries.get(task_key, 0) + 1
                        retry = _task_retries[task_key]
                        logger.warning(f"[Monitor] task {task_key[:12]} 推送失败(第{retry}次): {e}")
                        conn.rollback()
        except Exception as e:
            logger.warning(f"[Monitor] 循环异常: {e}")
        # 退避：按当前最高重试次数计算 sleep 时间
        _retry_count = max(_task_retries.values()) if _task_retries else 0
        sleep_time = MONITOR_INTERVAL * min(_retry_count, 10)
        time.sleep(sleep_time)
